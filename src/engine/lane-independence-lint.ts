/**
 * Lane-independence footgun lint (issue #40.1 / red-blue round-1).
 *
 * Heuristic, defensive-only gate when customer gate code looks like
 * independent per-lane checks (e.g. an array of single-byte compares combined
 * with a shallow AND/OR reduction, or per-byte charCodeAt → wasm mix/seal).
 * Meridian / good designs use chained whole-key mixing so no per-lane oracle exists.
 *
 * Findings are severity **"error"** — CLI `bla lint-lanes` exits 2, and
 * harden/defend refuse the artifact unless `allowLaneIndependentGates` is set.
 * This does NOT give reverse-engineering advice.
 */


import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { walkBounded } from "../core/walk.js";
import { withoutKnownBlaOutputs } from "../core/output-registry.js";

export const LANE_INDEPENDENCE_SCHEMA = "bla-lane-independence-lint/v1" as const;

export type LaneIndependenceFindingId =
  | "per-lane-byte-compare-array"
  | "independent-lane-and-reduce"
  | "indexed-lane-oracle-loop"
  | "per-byte-wasm-lane-oracle"
  | "chained-per-index-compare"
  | "split-segment-lane-compare";

export type LaneIndependenceSeverity = "error";

export interface LaneIndependenceFinding {
  readonly id: LaneIndependenceFindingId;
  readonly severity: LaneIndependenceSeverity;
  readonly summary: string;
  readonly evidence: string;
}

export interface LaneIndependenceReport {
  readonly schema: typeof LANE_INDEPENDENCE_SCHEMA;
  readonly findings: readonly LaneIndependenceFinding[];
  readonly looksLaneIndependent: boolean;
  readonly oneLineAdvice: string;
}

/**
 * Precision note. This lint REFUSES an artifact, so a false positive stops the
 * product from doing its job. The first version fired on "an array of four
 * integers anywhere + the letters `key` anywhere" — that is every real bundle
 * (`Object.keys`, a days-per-month table). Each rule below therefore needs the
 * *shape* of a per-lane check: the table has to be compared element by element
 * against something read from the secret, not merely exist in the same file.
 */

const INT_LIST = String.raw`\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d+)\s*){3,},?\s*\]`;

/** `const lanes = [0x41, …]` / `lanes: [0x41, …]` / `lanes = [0x41, …]`. */
const NAMED_INT_TABLE = new RegExp(
  String.raw`(?:\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=|\b([A-Za-z_$][\w$]*)\s*[:=])\s*(${INT_LIST})`,
  "g",
);

/** `[0x41, …].every(` / `[0x41, …][i]` — a table used where it is written. */
const INLINE_INT_TABLE = new RegExp(
  String.raw`(${INT_LIST})\s*(?:\[|\.\s*(?:every|some|forEach|map|reduce|findIndex)\s*\()`,
  "g",
);

const MAX_TABLES_EXAMINED = 256;
const MAX_TABLE_USES_EXAMINED = 64;
const LANE_WINDOW = 240;

/** Reads one character / byte of a string — what a per-lane probe does. */
const PER_CHAR_READ = /\b(?:charCodeAt|codePointAt)\s*\(/;
const EQUALITY_OR_XOR = /===?|!==?|\^/;

/** Words that name the secret a gate checks. */
const SECRET_WORDS: ReadonlySet<string> = new Set([
  "guess",
  "serial",
  "license",
  "licence",
  "password",
  "passcode",
  "passphrase",
  "pin",
  "secret",
  "unlock",
  "activation",
  "voucher",
]);
/** `keyCode`, `keyDown`, `keyFrames` … are not secrets. */
const KEY_BENIGN_NEXT: ReadonlySet<string> = new Set([
  "code", "codes", "down", "up", "press", "pressed", "board", "boards", "frame", "frames",
  "name", "names", "path", "paths", "of", "by", "word", "words", "stroke", "strokes",
  "map", "binding", "bindings", "event", "events",
]);
/** `cacheKey`, `sortKey`, `objectKey` … are lookup keys, not secrets. */
const KEY_BENIGN_PREV: ReadonlySet<string> = new Set([
  "hot", "cache", "map", "sort", "primary", "foreign", "storage", "object", "prop", "property",
  "row", "column", "group", "partition", "env", "config", "json", "query", "i18n", "locale",
  "translation",
]);

function identifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z]+/)
    .filter((w) => w.length > 0)
    .map((w) => w.toLowerCase());
}

/** `key`, `licenseKey`, `userSerial`, `guess` — but not `keys`, `keyCode`, `cacheKey`. */
export function isSecretLikeIdentifier(identifier: string): boolean {
  const words = identifierWords(identifier);
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i]!;
    if (SECRET_WORDS.has(word)) return true;
    if (
      word === "key" &&
      !KEY_BENIGN_NEXT.has(words[i + 1] ?? "") &&
      !KEY_BENIGN_PREV.has(words[i - 1] ?? "")
    ) {
      return true;
    }
  }
  return false;
}

function mentionsSecretLikeIdentifier(window: string): boolean {
  for (const match of window.matchAll(/[A-Za-z_$][\w$]*/g)) {
    if (isSecretLikeIdentifier(match[0])) return true;
  }
  return false;
}

/** The window reads a character of something, or names the secret outright. */
function looksLikePerLaneProbe(window: string): boolean {
  return PER_CHAR_READ.test(window) || mentionsSecretLikeIdentifier(window);
}

function isAllZeroTable(literal: string): boolean {
  return /^\[\s*0\s*(?:,\s*0\s*)*,?\s*\]$/.test(literal);
}

function escapeForRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * An integer table that is compared element by element (`=== T[i]`, `T[i] ^`,
 * `T.every(…)`) next to a per-character read or a secret-named identifier.
 * Returns the table literal, or undefined.
 */
function findPerLaneCompareTable(text: string): string | undefined {
  let examined = 0;
  for (const match of text.matchAll(NAMED_INT_TABLE)) {
    if (examined >= MAX_TABLES_EXAMINED) break;
    examined += 1;
    const name = match[1] ?? match[2];
    const literal = match[3] ?? "";
    if (name === undefined || isAllZeroTable(literal)) continue;
    const id = escapeForRegExp(name);
    const uses = new RegExp(
      String.raw`(?:===?|!==?|\^)\s*\(?\s*${id}\s*\[|(?<![\w$.])${id}\s*\[[^\]\n]{1,40}\]\s*\)?\s*(?:===?|!==?|\^)|(?<![\w$.])${id}\s*\.\s*(?:every|some|forEach|map|reduce|findIndex)\s*\(`,
      "g",
    );
    let seen = 0;
    for (const use of text.matchAll(uses)) {
      if (seen >= MAX_TABLE_USES_EXAMINED) break;
      seen += 1;
      const at = use.index ?? 0;
      const window = text.slice(Math.max(0, at - LANE_WINDOW), at + use[0].length + LANE_WINDOW);
      // The table's own name does not count as naming the secret.
      if (looksLikePerLaneProbe(window.split(name).join(" "))) return literal;
    }
  }
  examined = 0;
  for (const match of text.matchAll(INLINE_INT_TABLE)) {
    if (examined >= MAX_TABLES_EXAMINED) break;
    examined += 1;
    const literal = match[1] ?? "";
    if (isAllZeroTable(literal)) continue;
    const at = (match.index ?? 0) + match[0].length;
    const window = text.slice(at, at + LANE_WINDOW);
    if (EQUALITY_OR_XOR.test(window) && looksLikePerLaneProbe(window)) return literal;
  }
  return undefined;
}

/** `lanes.every(` — the lint's own vocabulary, no further evidence needed. */
const LANE_AND_REDUCE =
  /\blanes?\s*(?:\.every\s*\(|\.all\s*\(|\.reduce\s*\([^)]*(?:&&|\band\b))/i;

/** `.every` / `.all` with a `lanes[i]` compare inside. */
const EVERY_INDEXED_LANE = /\.every\s*\([\s\S]{0,200}\blanes?\s*\[\s*[\w$]+\s*\]/i;

/**
 * `.every(… === targets[i])` on a generically named collection. `a.every((v, i)
 * => v === b[i])` is how ordinary code compares two arrays, so this needs a
 * per-character read or a secret-named identifier beside it.
 */
const EVERY_INDEXED_TARGET =
  /[\w$.)\]"'`]{0,60}\.\s*(?:every|all)\s*\([\s\S]{0,200}?(?:===?\s*[\w$.]*(?:targets?|expect\w*)\s*\[\s*[\w$]+\s*\]|(?:targets?|expect\w*)\s*\[\s*[\w$]+\s*\]\s*===?)/gi;
const GENERIC_COLLECTION_EVERY =
  /\b(?:bytes?|parts?|chunks?|segments?)\s*\.\s*(?:every|all)\s*\([\s\S]{0,200}?(?:===?\s*[\w$.]+\s*\[\s*[\w$]+\s*\]|\]\s*===?)/gi;

function findIndependentLaneReduce(text: string): string | undefined {
  const direct = text.match(LANE_AND_REDUCE) ?? text.match(EVERY_INDEXED_LANE);
  if (direct) return direct[0];
  for (const pattern of [EVERY_INDEXED_TARGET, GENERIC_COLLECTION_EVERY]) {
    pattern.lastIndex = 0;
    let examined = 0;
    for (const match of text.matchAll(pattern)) {
      if (examined >= MAX_TABLE_USES_EXAMINED) break;
      examined += 1;
      const at = match.index ?? 0;
      const window = text.slice(Math.max(0, at - 80), at + match[0].length + 80);
      if (looksLikePerLaneProbe(window)) return match[0];
    }
  }
  return undefined;
}

/** Secret-named identifier prefix shared by the per-index rules. */
const SECRET_ID = String.raw`\b(?:key|guess|serial|licen[sc]e|password|passcode|pin|secret)\w*`;

const INDEXED_ORACLE = new RegExp(
  String.raw`for\s*\(\s*(?:let|var|const)\s+\w+\s*=\s*0[^)]*\)\s*\{[^}]{0,200}${SECRET_ID}\s*\[\s*\w+\s*\][^}]{0,120}===\s*(?:target|expect|lane|ref)`,
  "i",
);

/**
 * Per-byte charCodeAt fed into mix/seal (or similar) with an indexed target
 * compare — CrackMe v6 / independent WASM-lane shape (XOR or !== fold OK).
 */
const PER_BYTE_WASM_LANE =
  /charCodeAt\s*\(\s*\w+\s*\)[\s\S]{0,240}(?:mix|seal)\s*\([\s\S]{0,320}(?:LANE_TARGETS|laneTargets|targets?|lanes?)\s*\[\s*\w+/i;

/** Indexed XOR/OR fold of per-lane results without whole-key mixing. */
const INDEXED_XOR_LANE_FOLD =
  /for\s*\(\s*(?:let|var|const)\s+\w+[^)]*\)\s*\{[\s\S]{0,400}charCodeAt[\s\S]{0,400}\^\s*\((?:LANE_TARGETS|laneTargets|targets?|lanes?)\s*\[/i;

/**
 * 3 or more constant-index charCodeAt / codePointAt / bracket comparisons on a
 * secret-named value chained with && / and (e.g. `key.charCodeAt(0) === 65 &&
 * key.charCodeAt(1) === 66 && key.charCodeAt(2) === 67`). Generic names
 * (`input`, `code`, `token`, `buf`) are left out: parsers sniff magic bytes and
 * quote characters exactly this way.
 */
const PER_INDEX_COMPARE = String.raw`${SECRET_ID}\s*(?:\.\s*(?:charCodeAt|codePointAt)\s*\(\s*\d+\s*\)|\[\s*\d+\s*\])\s*===?\s*(?:0x[0-9a-fA-F]+|\d+|['"][^'"]+['"])`;
const CHAINED_PER_INDEX_COMPARE = new RegExp(
  String.raw`(?:${PER_INDEX_COMPARE}\s*(?:&&|\band\b)\s*){2,}${PER_INDEX_COMPARE}`,
  "i",
);

/**
 * `.split(...)` followed by 2+ independent indexed segment equality checks
 * (e.g. `const parts = key.split("-"); return parts[0] === "AAAA" && parts[1] === "BBBB"`).
 * The value being split has to be secret-named: `version.split(".")` followed
 * by `parts[0] === "1" && parts[1] === "2"` is not a licence gate.
 */
const SPLIT_SEGMENT_LANE_COMPARE =
  /([A-Za-z_$][\w$]*)\s*(?:\)\s*)?\.\s*split\s*\(\s*['"][^'"]+['"]\s*\)[\s\S]{0,300}?\b(\w+)\s*\[\s*0\s*\]\s*===?\s*['"][^'"]+['"]\s*(?:&&|\band\b)[\s\S]{0,160}?\b\2\s*\[\s*1\s*\]\s*===?\s*['"][^'"]+['"]/gi;

function findSplitSegmentCompare(text: string): string | undefined {
  SPLIT_SEGMENT_LANE_COMPARE.lastIndex = 0;
  let examined = 0;
  for (const match of text.matchAll(SPLIT_SEGMENT_LANE_COMPARE)) {
    if (examined >= MAX_TABLE_USES_EXAMINED) break;
    examined += 1;
    if (isSecretLikeIdentifier(match[1] ?? "")) return match[0];
  }
  return undefined;
}

function finding(
  id: LaneIndependenceFindingId,
  summary: string,
  evidence: string,
): LaneIndependenceFinding {
  return {
    id,
    severity: "error",
    summary,
    evidence: evidence.slice(0, 120),
  };
}

/**
 * Scan UTF-8 source (JS/TS/Python-like) for lane-independence footguns.
 * Findings are severity "error" — callers decide whether to refuse (harden) or exit 2 (CLI).
 */
export function lintLaneIndependence(source: string): LaneIndependenceReport {
  const findings: LaneIndependenceFinding[] = [];
  const text = source.length > 400_000 ? source.slice(0, 400_000) : source;

  const compareTable = findPerLaneCompareTable(text);
  if (compareTable !== undefined) {
    findings.push(
      finding(
        "per-lane-byte-compare-array",
        "Literal multi-byte table compared element by element against a per-character read of the key — allows independent per-lane probes.",
        compareTable,
      ),
    );
  }

  const laneReduce = findIndependentLaneReduce(text);
  if (laneReduce !== undefined) {
    findings.push(
      finding(
        "independent-lane-and-reduce",
        "Lane/byte collection reduced with every/all/AND — suggests independent lane checks without whole-key mixing.",
        laneReduce,
      ),
    );
  }

  if (INDEXED_ORACLE.test(text)) {
    const m = text.match(INDEXED_ORACLE);
    findings.push(
      finding(
        "indexed-lane-oracle-loop",
        "Indexed loop comparing key[i] to a per-lane target — classic independent-lane oracle shape.",
        m?.[0] ?? "",
      ),
    );
  }

  if (PER_BYTE_WASM_LANE.test(text) || INDEXED_XOR_LANE_FOLD.test(text)) {
    const m = text.match(PER_BYTE_WASM_LANE) ?? text.match(INDEXED_XOR_LANE_FOLD);
    findings.push(
      finding(
        "per-byte-wasm-lane-oracle",
        "Per-byte charCodeAt → mix/seal (or XOR fold) against indexed lane targets — independent 1-byte WASM lanes collapse under RE.",
        m?.[0] ?? "",
      ),
    );
  }

  if (CHAINED_PER_INDEX_COMPARE.test(text)) {
    const m = text.match(CHAINED_PER_INDEX_COMPARE);
    findings.push(
      finding(
        "chained-per-index-compare",
        "Chained per-index charCodeAt/bracket comparisons joined with &&/and — allows byte-by-byte key recovery without whole-key mixing.",
        m?.[0] ?? "",
      ),
    );
  }

  const splitSegments = findSplitSegmentCompare(text);
  if (splitSegments !== undefined) {
    findings.push(
      finding(
        "split-segment-lane-compare",
        "Key split into segments compared independently (`parts[0] === ... && parts[1] === ...`) — allows segment-by-segment brute force.",
        splitSegments,
      ),
    );
  }

  return {
    schema: LANE_INDEPENDENCE_SCHEMA,
    findings,
    looksLaneIndependent: findings.length > 0,
    oneLineAdvice:
      findings.length === 0
        ? "No lane-independence footgun pattern detected (heuristic)."
        : "ERROR: Prefer whole-key chained mixing (no per-lane oracle). Harden refuses this gate unless allowLaneIndependentGates / --allow-lane-independent / allow_lane_independent. See issue #40.1 / Meridian DESIGN — defensive guidance only.",
  };
}

/** Formats where lane-independence lint applies before protect/defend/harden. */
export function formatSupportsLaneIndependenceLint(
  format: string,
): boolean {
  return format === "javascript" || format === "typescript";
}

/**
 * Build a refuse message for harden/defend when lane-independent gates are detected.
 */
export function laneIndependenceRefuseMessage(
  report: LaneIndependenceReport,
  inputPath: string,
): string {
  const ids = report.findings.map((f) => f.id).join(", ");
  return (
    `Refusing lane-independent gate at ${inputPath} [${ids}]. ` +
    `Prefer whole-key chained mixing. To override (intentional footgun / teaching fixture), ` +
    `pass allowLaneIndependentGates / --allow-lane-independent / allow_lane_independent:true.`
  );
}

const SKIP_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  ".bla-hardened",
  "coverage",
  ".turbo",
  ".cache",
  "__pycache__",
  ".venv",
  "venv",
]);

const JS_EXT = /\.(?:[cm]?[jt]s|tsx?)$/i;
const MAX_JS_FILES = 64;
const MAX_WALK_DEPTH = 8;

function walkJsGateCandidates(dir: string): string[] {
  return walkBounded(dir, {
    maxDepth: MAX_WALK_DEPTH,
    maxFiles: MAX_JS_FILES,
    skipDirs: SKIP_DIR_NAMES,
    skipHiddenDirs: true,
    accept: (_full, name) => JS_EXT.test(name),
  });
}

/** File wrapper matching other packaging lints. */
export function lintLaneIndependenceFile(filePath: string): LaneIndependenceReport & {
  readonly path: string;
} {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    throw new Error(`lane-independence target not found: ${abs}`);
  }
  const report = lintLaneIndependence(readFileSync(abs, "utf8"));
  return { ...report, path: abs };
}

/**
 * Discover JS/TS under a directory and lint each for lane-independence footguns.
 * Used by unified `bla lint` / packaging-gates (protect still refuses per-file).
 */
export function discoverAndLintLaneIndependence(
  directory: string,
): ReadonlyArray<LaneIndependenceReport & { readonly path: string }> {
  const abs = resolve(directory);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintLaneIndependenceFile(abs)];
  }
  // Hardened output is decoys by design; lint what it was built from.
  const candidates = withoutKnownBlaOutputs(walkJsGateCandidates(abs));
  return candidates.map((p) => lintLaneIndependenceFile(p));
}
