/**
 * Cross-build structural drift report (Direction-1: seeded polymorphism).
 *
 * Compares two hardened artifact directories and reports objective structural
 * differences. Does **not** claim "harder to reverse" — that stays with REA.
 * Honesty: driftScore only measures "how different"; functional equivalence
 * must be proven separately (bla_verify / REA).
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  readFileSync,
  statSync,
} from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { walkBounded } from "../core/walk.js";
import { inspectWasmBinary } from "../shields/formats/wasm.js";

export const POLYMORPH_REPORT_SCHEMA = "bla-polymorph-report/v1" as const;

const SKIP_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  ".bla-hardened",
  "coverage",
  ".next",
  ".turbo",
  "vendor",
  "__pycache__",
]);

const COMPARE_EXTS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".wasm",
  ".html",
  ".htm",
]);

/** Files whose intentional content may include timestamps / run ids — skip byte compare. */
const SKIP_BASENAMES = new Set([
  "package-lock.json",
  ".blarc",
  "bla.config.json",
]);

export type PolymorphExpectMode = "same" | "different" | "report";

export interface PolymorphReportOptions {
  readonly dirA: string;
  readonly dirB: string;
  /**
   * `same` → refuse when driftScore ≥ sameThreshold (default 0.01).
   * `different` → refuse when driftScore < differentThreshold (default 0.35).
   * `report` (default) → never refuse; just emit metrics.
   */
  readonly expect?: PolymorphExpectMode;
  readonly sameThreshold?: number;
  readonly differentThreshold?: number;
}


export interface FilePairMetric {
  readonly relativePath: string;
  readonly kind: "js" | "wasm" | "html" | "other";
  readonly byteEqual: boolean;
  readonly byteDiffRatio: number;
  readonly exportNameOverlap: number | null;
  readonly exportOrderDistance: number | null;
  readonly identifierOverlap: number | null;
}

export interface PolymorphReport {
  readonly schema: typeof POLYMORPH_REPORT_SCHEMA;
  readonly dirA: string;
  readonly dirB: string;
  readonly status: "ok" | "fail" | "error";
  readonly expect: PolymorphExpectMode;
  readonly driftScore: number;
  readonly reproducible: boolean;
  readonly polymorphic: boolean;
  readonly pairedFileCount: number;
  readonly onlyInA: readonly string[];
  readonly onlyInB: readonly string[];
  readonly files: readonly FilePairMetric[];
  readonly summary: string;
  readonly oneLineAdvice: string;
}

function walkFiles(root: string, maxDepth = 8): string[] {
  return walkBounded(resolve(root), {
    maxDepth,
    maxFiles: Number.MAX_SAFE_INTEGER,
    skipDirs: SKIP_DIR_NAMES,
    skipHiddenDirs: true,
    descendAtMaxDepth: false,
    accept: (_full, name) => {
      if (SKIP_BASENAMES.has(name)) return false;
      return COMPARE_EXTS.has(extname(name).toLowerCase());
    },
  }).sort();
}

function relKey(root: string, absFile: string): string {
  return relative(resolve(root), absFile).split(sep).join("/");
}

function jaccard(a: readonly string[], b: readonly string[]): number {
  if (a.length === 0 && b.length === 0) return 1;
  const sa = new Set(a);
  const sb = new Set(b);
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  const union = sa.size + sb.size - inter;
  return union === 0 ? 1 : inter / union;
}

/**
 * Kendall-tau distance normalized to [0,1] over the intersection order.
 * 0 = identical order among shared names; 1 = fully reversed (or no shared).
 */
function kendallTauDistance(
  orderA: readonly string[],
  orderB: readonly string[],
): number {
  const posB = new Map(orderB.map((n, i) => [n, i]));
  const shared = orderA.filter((n) => posB.has(n));
  const n = shared.length;
  if (n <= 1) return 0;
  let discordant = 0;
  let pairs = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      pairs++;
      const ai = i;
      const aj = j;
      const bi = posB.get(shared[i]!)!;
      const bj = posB.get(shared[j]!)!;
      const orderALess = ai < aj;
      const orderBLess = bi < bj;
      if (orderALess !== orderBLess) discordant++;
    }
  }
  return pairs === 0 ? 0 : discordant / pairs;
}

function byteDiffRatio(a: Buffer, b: Buffer): number {
  if (a.length === 0 && b.length === 0) return 0;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 0;
  // Fast path: equal lengths → count unequal bytes; unequal → size delta + prefix compare.
  let unequal = Math.abs(a.length - b.length);
  const lim = Math.min(a.length, b.length);
  // Sample full compare for files ≤ 2 MiB; otherwise chunked 64 KiB windows.
  if (maxLen <= 2 * 1024 * 1024) {
    for (let i = 0; i < lim; i++) {
      if (a[i] !== b[i]) unequal++;
    }
    return Math.min(1, unequal / maxLen);
  }
  const win = 64 * 1024;
  let compared = 0;
  let diff = unequal;
  for (let off = 0; off < lim; off += win) {
    const end = Math.min(off + win, lim);
    const ha = createHash("sha256").update(a.subarray(off, end)).digest("hex");
    const hb = createHash("sha256").update(b.subarray(off, end)).digest("hex");
    compared += end - off;
    if (ha !== hb) {
      // Conservative: treat whole window as different when hashes diverge.
      diff += end - off;
    }
  }
  return Math.min(1, diff / Math.max(maxLen, compared));
}

const IDENT_RE =
  /\b(?:function|const|let|var|class)\s+([A-Za-z_$][\w$]*)\b/g;
const EXPORT_NAME_RE =
  /\bexport\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)\b/g;
const EXPORT_LIST_RE = /\bexport\s*\{([^}]+)\}/g;

function extractJsIdentifiers(source: string): string[] {
  const names = new Set<string>();
  for (const re of [IDENT_RE, EXPORT_NAME_RE]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
      names.add(m[1]!);
    }
  }
  EXPORT_LIST_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = EXPORT_LIST_RE.exec(source)) !== null) {
    for (const part of m[1]!.split(",")) {
      const bit = part.trim().split(/\s+as\s+/i).pop()?.trim();
      if (bit && /^[A-Za-z_$][\w$]*$/.test(bit)) names.add(bit);
    }
  }
  return [...names].sort();
}

function extractJsExportOrder(source: string): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  const push = (n: string) => {
    if (!seen.has(n)) {
      seen.add(n);
      order.push(n);
    }
  };
  EXPORT_NAME_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = EXPORT_NAME_RE.exec(source)) !== null) push(m[1]!);
  EXPORT_LIST_RE.lastIndex = 0;
  while ((m = EXPORT_LIST_RE.exec(source)) !== null) {
    for (const part of m[1]!.split(",")) {
      const bit = part.trim().split(/\s+as\s+/i).pop()?.trim();
      if (bit && /^[A-Za-z_$][\w$]*$/.test(bit)) push(bit);
    }
  }
  return order;
}

function classify(path: string): FilePairMetric["kind"] {
  const ext = extname(path).toLowerCase();
  if (ext === ".wasm") return "wasm";
  if (ext === ".html" || ext === ".htm") return "html";
  if ([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"].includes(ext)) return "js";
  return "other";
}

function comparePair(
  rel: string,
  pathA: string,
  pathB: string,
): FilePairMetric {
  const bufA = readFileSync(pathA);
  const bufB = readFileSync(pathB);
  const kind = classify(rel);
  const ratio = byteDiffRatio(bufA, bufB);
  let exportNameOverlap: number | null = null;
  let exportOrderDistance: number | null = null;
  let identifierOverlap: number | null = null;

  if (kind === "wasm") {
    try {
      const ia = inspectWasmBinary(bufA);
      const ib = inspectWasmBinary(bufB);
      exportNameOverlap = jaccard(ia.exportNames, ib.exportNames);
      exportOrderDistance = kendallTauDistance(ia.exportNames, ib.exportNames);
    } catch {
      // malformed wasm — leave nulls
    }
  } else if (kind === "js") {
    const sa = bufA.toString("utf8");
    const sb = bufB.toString("utf8");
    const idA = extractJsIdentifiers(sa);
    const idB = extractJsIdentifiers(sb);
    identifierOverlap = jaccard(idA, idB);
    const exA = extractJsExportOrder(sa);
    const exB = extractJsExportOrder(sb);
    if (exA.length + exB.length > 0) {
      exportNameOverlap = jaccard(exA, exB);
      exportOrderDistance = kendallTauDistance(exA, exB);
    }
  }

  return {
    relativePath: rel,
    kind,
    byteEqual: bufA.equals(bufB),
    byteDiffRatio: ratio,
    exportNameOverlap,
    exportOrderDistance,
    identifierOverlap,
  };
}

/**
 * Aggregate driftScore ∈ [0,1]: higher = more structural difference.
 * Mixes byte diff, export-name divergence, order distance, identifier divergence.
 */
/**
 * Weighted drift per file. Byte + identifier divergence dominate because
 * public export *names* are often ABI-stable by design (preserving them must
 * not dilute a real body/rename shuffle into a false "same structure" signal).
 * Export-order distance still counts when rename+shuffle actually reorders.
 */
function aggregateDrift(files: readonly FilePairMetric[]): number {
  if (files.length === 0) return 0;
  let acc = 0;
  for (const f of files) {
    let weighted = 0;
    let weightSum = 0;
    const add = (value: number, w: number) => {
      weighted += value * w;
      weightSum += w;
    };
    add(f.byteDiffRatio, 0.45);
    if (f.identifierOverlap !== null) add(1 - f.identifierOverlap, 0.3);
    if (f.exportOrderDistance !== null) add(f.exportOrderDistance, 0.15);
    if (f.exportNameOverlap !== null) add(1 - f.exportNameOverlap, 0.1);
    acc += weightSum === 0 ? 0 : weighted / weightSum;
  }
  return Math.min(1, acc / files.length);
}

export function comparePolymorphArtifacts(
  options: PolymorphReportOptions,
): PolymorphReport {
  const expect: PolymorphExpectMode = options.expect ?? "report";
  const sameThreshold = options.sameThreshold ?? 0.01;
  const differentThreshold = options.differentThreshold ?? 0.25;
  const dirA = resolve(options.dirA);
  const dirB = resolve(options.dirB);

  if (!existsSync(dirA) || !statSync(dirA).isDirectory()) {
    return errorReport(dirA, dirB, expect, `dirA is not a directory: ${dirA}`);
  }
  if (!existsSync(dirB) || !statSync(dirB).isDirectory()) {
    return errorReport(dirA, dirB, expect, `dirB is not a directory: ${dirB}`);
  }

  const filesA = walkFiles(dirA);
  const filesB = walkFiles(dirB);
  const mapA = new Map(filesA.map((f) => [relKey(dirA, f), f]));
  const mapB = new Map(filesB.map((f) => [relKey(dirB, f), f]));
  const onlyInA = [...mapA.keys()].filter((k) => !mapB.has(k)).sort();
  const onlyInB = [...mapB.keys()].filter((k) => !mapA.has(k)).sort();
  const shared = [...mapA.keys()].filter((k) => mapB.has(k)).sort();

  const files = shared.map((rel) =>
    comparePair(rel, mapA.get(rel)!, mapB.get(rel)!),
  );

  // Unpaired files contribute full drift (structure not shared).
  const unpairedPenalty =
    onlyInA.length + onlyInB.length === 0
      ? 0
      : Math.min(
          1,
          (onlyInA.length + onlyInB.length) /
            Math.max(1, shared.length + onlyInA.length + onlyInB.length),
        );

  const baseDrift = aggregateDrift(files);
  const driftScore = Math.min(1, baseDrift * 0.85 + unpairedPenalty * 0.15);
  const reproducible = driftScore < sameThreshold && onlyInA.length === 0 && onlyInB.length === 0;
  const polymorphic = driftScore >= differentThreshold;

  let status: PolymorphReport["status"] = "ok";
  if (expect === "same" && !reproducible) status = "fail";
  if (expect === "different" && !polymorphic) status = "fail";

  const summary =
    `driftScore=${driftScore.toFixed(4)} paired=${files.length} ` +
    `onlyA=${onlyInA.length} onlyB=${onlyInB.length} ` +
    `reproducible=${reproducible} polymorphic=${polymorphic}`;

  return {
    schema: POLYMORPH_REPORT_SCHEMA,
    dirA,
    dirB,
    status,
    expect,
    driftScore,
    reproducible,
    polymorphic,
    pairedFileCount: files.length,
    onlyInA,
    onlyInB,
    files,
    summary,
    oneLineAdvice:
      "driftScore measures structural difference only — prove functional equivalence with bla_verify / REA; do not treat drift as a cracking-resistance claim.",
  };
}

function errorReport(
  dirA: string,
  dirB: string,
  expect: PolymorphExpectMode,
  message: string,
): PolymorphReport {
  return {
    schema: POLYMORPH_REPORT_SCHEMA,
    dirA,
    dirB,
    status: "error",
    expect,
    driftScore: 0,
    reproducible: false,
    polymorphic: false,
    pairedFileCount: 0,
    onlyInA: [],
    onlyInB: [],
    files: [],
    summary: message,
    oneLineAdvice: message,
  };
}
