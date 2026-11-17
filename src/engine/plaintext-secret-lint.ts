/**
 * Plaintext sensitive-literal lint (Direction-2).
 *
 * Flags structural / high-entropy secrets that still sit as cleartext string
 * literals in panel.html / license.cjs (and sibling JS). Does **not** claim
 * encrypted strings are unrecoverable — only that cleartext footguns are gone.
 *
 * Sensitive (hit → finding):
 *   1. Shannon entropy ≥ 4.0 bit/char AND length ≥ 16 (key/token-shaped)
 *   2. FLAG{…}, http(s):// endpoints, -----BEGIN…, base64/hex ≥ 24
 *   3. Derive/unlock contract key-name literals outside a small allowlist
 *
 * Avoid false positives:
 *   - length < 8 → skip
 *   - pure UI copy (no high entropy, no structural markers) → skip
 *   - strings already behind the XOR decrypt stub (_blaS(i) / table) → skip
 *   - allowPlaintextString escapes bankrupt refuse
 *
 * DEFENSIVE ONLY.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { parse } from "@babel/parser";
import type { ProtectionIntensity } from "../core/types.js";
import { withoutKnownBlaOutputs } from "../core/output-registry.js";

export const PLAINTEXT_SECRET_SCHEMA = "bla-plaintext-secret-lint/v1" as const;

export type PlaintextSecretFindingId =
  | "plaintext-flag-literal"
  | "plaintext-high-entropy"
  | "plaintext-url-endpoint"
  | "plaintext-pem-header"
  | "plaintext-b64-or-hex"
  | "plaintext-derive-keyname";

export type PlaintextSecretSeverity = "warning" | "error";

export interface PlaintextSecretFinding {
  readonly id: PlaintextSecretFindingId;
  readonly severity: PlaintextSecretSeverity;
  readonly summary: string;
  readonly evidence: string;
  readonly literal: string;
  /** 1-based source line of the literal, when the extractor could place it. */
  readonly line?: number;
  /**
   * The value sits inside a regular-expression literal. No BLA tool encodes
   * those: build the pattern from a string literal, or move the value out.
   */
  readonly inRegex?: true;
}

export interface PlaintextSecretReport {
  readonly schema: typeof PLAINTEXT_SECRET_SCHEMA;
  readonly path: string;
  readonly sha256Prefix: string;
  readonly findings: readonly PlaintextSecretFinding[];
  readonly looksExposed: boolean;
  readonly shouldRefuseBankrupt: boolean;
  readonly oneLineAdvice: string;
}

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

const MAX_WALK_DEPTH = 6;
const MAX_FILES = 48;
const MAX_SCAN_CHARS = 800_000;

const TARGET_BASENAME =
  /^(?:panel\.html?|license\.cjs|license\.js|vault\.cjs|vault\.js|gate\.cjs|gate\.js|auth\.cjs|auth\.js|entitlement\.cjs|entitlement\.js|activate\.cjs|activate\.js)$/i;
const SCAN_EXT = /\.(?:html?|[cm]?js|tsx?|mts|cts)$/i;

/** Safe UI / ABI tokens that must stay greppable. */
const KEYNAME_ALLOWLIST = new Set([
  "exports",
  "module",
  "require",
  "default",
  "length",
  "message",
  "error",
  "name",
  "type",
  "value",
  "status",
  "ok",
  "sha256",
  "digest",
]);

const DERIVE_KEYNAME =
  /\b(?:deriveLocal|panelTokenSha256|unwrapKey|unlockFlag|secretKey|masterKey|licenseKey)\b/;

function sha256Prefix(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex").slice(0, 16);
}

/** Shannon entropy in bits/char. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isHexish(s: string): boolean {
  return s.length >= 24 && /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
}

function isBase64ish(s: string): boolean {
  if (s.length < 24) return false;
  if (!/^[A-Za-z0-9+/]+=*$/.test(s)) return false;
  // Reject mostly-alpha words that happen to match base64 charset.
  const digitOrPlus = (s.match(/[0-9+/=]/g) ?? []).join("").length;
  return digitOrPlus / s.length >= 0.15;
}

/**
 * An alphabet, not a secret: most neighbouring characters are consecutive code
 * points (`ABC…xyz0123…`, a Base58 table, the hex digits). A random token
 * almost never has two neighbours in sequence, let alone most of them — while
 * every Base64 / Base32 / Base58 / nanoid implementation ships such a table.
 */
export function isSequentialAlphabet(s: string): boolean {
  if (s.length < 8) return false;
  let ascending = 0;
  for (let i = 1; i < s.length; i++) {
    if (s.charCodeAt(i) - s.charCodeAt(i - 1) === 1) ascending += 1;
  }
  return ascending / (s.length - 1) >= 0.6;
}

/**
 * The hundred or so most frequent English letter pairs. Words, identifiers,
 * file names and sentences are built from them; a random token lands on one
 * only by chance (105 of the 676 possible pairs).
 */
const COMMON_BIGRAMS: ReadonlySet<string> = new Set(
  (
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur " +
    "ca el ta la ns ge ec ct pe ol un il us ss ac em tr pr po fi ad lo ut id pa so mo wi no di ee ul et ai rs oo ex"
  ).split(" "),
);
const COMMON_BIGRAM_CHANCE = COMMON_BIGRAMS.size / 676;
/**
 * Standard deviations above chance at which a string counts as written rather
 * than generated. Calibrated, together with the charset and path tests below,
 * on ordinary library code and on generated tokens of 16–64 characters: at 3.5
 * the three clear 99.7% of what the entropy rule used to flag there (prose,
 * identifiers, file names) and still flag 99.9% of the tokens.
 */
const NATURAL_TEXT_Z = 3.5;

function isAsciiLetter(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

/**
 * Written text — a sentence, a camelCase identifier, a header name — rather
 * than a generated value. High Shannon entropy cannot tell the two apart
 * (English runs at about 4.2 bits per character); letter-pair statistics can.
 */
export function looksLikeNaturalText(s: string): boolean {
  let pairs = 0;
  let hits = 0;
  const lower = s.toLowerCase();
  for (let i = 1; i < s.length; i++) {
    const a = s.charCodeAt(i - 1);
    const b = s.charCodeAt(i);
    if (!isAsciiLetter(a) || !isAsciiLetter(b)) continue;
    pairs += 1;
    // Inside a word the case never rises ("ab", "Ab", "AB" — not "aB"), so a
    // rise is a word boundary, and in a mixed-case token it is half the pairs.
    if (a >= 97 && b <= 90) continue;
    if (COMMON_BIGRAMS.has(lower[i - 1]! + lower[i]!)) hits += 1;
  }
  if (pairs < 4) return false;
  const expected = COMMON_BIGRAM_CHANCE * pairs;
  const deviation = Math.sqrt(pairs * COMMON_BIGRAM_CHANCE * (1 - COMMON_BIGRAM_CHANCE));
  return (hits - expected) / deviation >= NATURAL_TEXT_Z;
}

/** What an API key, a token or an encoded blob is spelled with: no spaces, brackets or quotes. */
const TOKEN_CHARSET_RE = /^[A-Za-z0-9_\-+/=.~:@!#$%^&*]+$/;
/** A module specifier or file name. A hashed chunk name is random, and public. */
const PATH_LIKE_RE =
  /^(?:\.{1,2}\/|@[\w.-]+\/)|\.(?:[cm]?[jt]sx?|json|css|map|wasm|html?|node|svg|png|jpe?g|gif|woff2?|ttf|md|txt|ya?ml|toml|lock)$/i;

/**
 * A generated value: token-shaped, not a path, and not made of words. This is
 * what the entropy rule is for — on its own that rule fires on every error
 * message of sixteen characters or more.
 */
export function looksLikeRandomToken(s: string): boolean {
  // A token wrapped over lines (or written with a `\n` escape) is still a token.
  const compact = s.replace(/[\t\n\r]/g, "");
  return (
    TOKEN_CHARSET_RE.test(compact) && !PATH_LIKE_RE.test(compact) && !looksLikeNaturalText(compact)
  );
}

/** A string literal recovered from source, with where it starts when known. */
export interface ExtractedLiteral {
  readonly value: string;
  /** 1-based line of the literal's opening quote; absent when unknown. */
  readonly line?: number;
  /** Set when the value is a run inside a regular-expression literal. */
  readonly inRegex?: true;
}

interface LiteralExtraction {
  readonly literals: readonly ExtractedLiteral[];
  /**
   * True when every literal came from a real parse, so each one is verbatim
   * cleartext in the file by construction (no "is it still in the source?"
   * guesswork needed).
   */
  readonly exact: boolean;
}

/** Undo the handful of escapes the hand scanner can meet; mirrors the legacy behaviour. */
function unescapeCommon(inner: string): string {
  return inner
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\'/g, "'")
    .replace(/\\"/g, '"')
    .replace(/\\`/g, "`")
    .replace(/\\\\/g, "\\");
}

const AST_PARSE_ATTEMPTS: ReadonlyArray<ReadonlyArray<"typescript" | "jsx">> = [
  ["typescript"],
  ["typescript", "jsx"],
  ["jsx"],
];

/**
 * Parse-accurate extraction for JavaScript / TypeScript. Returns null when the
 * text is not parseable (HTML, a truncated file, a fragment), so the caller can
 * fall back to the tolerant scanner.
 */
function extractLiteralsFromJsAst(source: string): ExtractedLiteral[] | null {
  let program: unknown;
  for (const plugins of AST_PARSE_ATTEMPTS) {
    try {
      program = parse(source, {
        sourceType: "unambiguous",
        plugins: [...plugins],
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        errorRecovery: false,
      }).program;
      break;
    } catch {
      program = undefined;
    }
  }
  if (program === undefined) return null;

  const found: Array<ExtractedLiteral & { readonly start: number }> = [];
  const push = (value: unknown, node: Record<string, unknown>, inRegex = false): void => {
    if (typeof value !== "string") return;
    const loc = node.loc as { start?: { line?: number } } | null | undefined;
    const line = loc?.start?.line;
    found.push({
      value,
      start: typeof node.start === "number" ? node.start : found.length,
      ...(typeof line === "number" ? { line } : {}),
      ...(inRegex ? { inRegex: true as const } : {}),
    });
  };
  // Iterative walk: bundled code nests far deeper than the JS stack allows.
  const stack: unknown[] = [program];
  while (stack.length > 0) {
    const node = stack.pop();
    if (Array.isArray(node)) {
      for (const child of node) stack.push(child);
      continue;
    }
    if (typeof node !== "object" || node === null) continue;
    const rec = node as Record<string, unknown>;
    switch (rec.type) {
      case "StringLiteral":
        push(rec.value, rec);
        break;
      case "DirectiveLiteral":
        // Babel keeps a directive's text raw; cook it like the scanner would.
        if (typeof rec.value === "string") push(unescapeCommon(rec.value), rec);
        break;
      case "TemplateElement": {
        // Each static chunk of a template is cleartext on its own, whether or
        // not the template also interpolates expressions.
        const cooked = (rec.value as { cooked?: unknown } | undefined)?.cooked;
        if (typeof cooked === "string" && cooked.length > 0) push(cooked, rec);
        break;
      }
      case "RegExpLiteral": {
        // A pattern is cleartext too, and nothing encodes it. Its
        // metacharacters would trip the entropy rule on any ordinary
        // expression, so only a run that is unmistakably a digest or an
        // encoded blob is offered as a literal.
        if (typeof rec.pattern === "string") {
          // Character classes spell out alphabets and ranges, not values.
          const outsideClasses = rec.pattern.replace(/\[(?:\\[\s\S]|[^\]\\])*\]/g, " ");
          for (const run of outsideClasses.split(/[^A-Za-z0-9+/]+/)) {
            if ((isHexish(run) || isBase64ish(run)) && !isSequentialAlphabet(run)) {
              push(run, rec, true);
            }
          }
        }
        break;
      }
      default:
        break;
    }
    for (const [key, child] of Object.entries(rec)) {
      if (key === "loc" || key === "extra" || key === "leadingComments" ||
          key === "trailingComments" || key === "innerComments") {
        continue;
      }
      if (typeof child === "object" && child !== null) stack.push(child);
    }
  }
  found.sort((a, b) => a.start - b.start);
  return found.map(({ value, line, inRegex }) => ({
    value,
    ...(line !== undefined ? { line } : {}),
    ...(inRegex === true ? { inRegex: true as const } : {}),
  }));
}

/** Characters after which a `/` starts a regex literal rather than a division. */
const REGEX_PRECEDER = new Set("(,=:[!&|?{};+-*%<>~^".split(""));
const REGEX_PRECEDING_KEYWORD =
  /(?:^|[^\w$])(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;

/**
 * Tolerant fallback scanner for text Babel cannot parse. Unlike a flat regex it
 * tracks comments, regex literals, and `${…}` nesting, so the code *between*
 * two template literals is never mistaken for a string.
 */
function scanStringLiterals(source: string, baseLine = 1): ExtractedLiteral[] {
  const out: ExtractedLiteral[] = [];
  const n = source.length;
  let line = baseLine;
  let lastSignificant = "";
  let tail = "";

  const note = (ch: string): void => {
    if (ch === "\n") line += 1;
  };

  /** Scans code until `stopAtBrace` depth closes (or EOF); returns the new index. */
  const scanCode = (from: number, stopAtBrace: boolean): number => {
    let i = from;
    let depth = 0;
    while (i < n) {
      const c = source[i]!;
      const next = source[i + 1];
      if (c === "/" && next === "/") {
        while (i < n && source[i] !== "\n") i += 1;
        continue;
      }
      if (c === "/" && next === "*") {
        const end = source.indexOf("*/", i + 2);
        const stop = end < 0 ? n : end + 2;
        for (let k = i; k < stop; k++) note(source[k]!);
        i = stop;
        continue;
      }
      if (c === "'" || c === '"') {
        const startLine = line;
        let j = i + 1;
        let closed = false;
        while (j < n) {
          const d = source[j]!;
          if (d === "\\") {
            j += 2;
            continue;
          }
          // An unescaped newline means this quote was prose (don't), not a string.
          if (d === "\n") break;
          if (d === c) {
            closed = true;
            break;
          }
          j += 1;
        }
        if (closed) {
          out.push({ value: unescapeCommon(source.slice(i + 1, j)), line: startLine });
          i = j + 1;
          lastSignificant = c;
          tail = "";
          continue;
        }
        i += 1;
        continue;
      }
      if (c === "`") {
        i = scanTemplate(i + 1);
        lastSignificant = "`";
        tail = "";
        continue;
      }
      if (c === "/") {
        const looksRegex =
          lastSignificant === "" ||
          REGEX_PRECEDER.has(lastSignificant) ||
          REGEX_PRECEDING_KEYWORD.test(tail);
        if (looksRegex) {
          let j = i + 1;
          let inClass = false;
          let closed = false;
          while (j < n) {
            const d = source[j]!;
            if (d === "\\") {
              j += 2;
              continue;
            }
            if (d === "\n") break;
            if (d === "[") inClass = true;
            else if (d === "]") inClass = false;
            else if (d === "/" && !inClass) {
              closed = true;
              break;
            }
            j += 1;
          }
          if (closed) {
            i = j + 1;
            lastSignificant = "/";
            tail = "";
            continue;
          }
        }
      }
      if (stopAtBrace) {
        if (c === "{") depth += 1;
        else if (c === "}") {
          if (depth === 0) return i + 1;
          depth -= 1;
        }
      }
      note(c);
      if (!/\s/.test(c)) {
        lastSignificant = c;
        tail = (tail + c).slice(-12);
      } else if (tail.length > 0 && !tail.endsWith(" ")) {
        tail = (tail + " ").slice(-12).trimEnd();
      }
      i += 1;
    }
    return i;
  };

  /** Scans a template body starting just after the opening backtick. */
  const scanTemplate = (from: number): number => {
    let i = from;
    let chunk = "";
    let chunkLine = line;
    const flush = (): void => {
      if (chunk.length > 0) out.push({ value: unescapeCommon(chunk), line: chunkLine });
      chunk = "";
    };
    while (i < n) {
      const c = source[i]!;
      if (c === "\\") {
        chunk += source.slice(i, i + 2);
        if (source[i + 1] === "\n") line += 1;
        i += 2;
        continue;
      }
      if (c === "`") {
        flush();
        return i + 1;
      }
      if (c === "$" && source[i + 1] === "{") {
        flush();
        i = scanCode(i + 2, true);
        chunkLine = line;
        continue;
      }
      note(c);
      chunk += c;
      i += 1;
    }
    flush();
    return i;
  };

  scanCode(0, false);
  return out;
}

const HTML_SNIFF_RE = /^﻿?\s*<(?:!doctype\b|html\b|head\b|body\b|script\b|!--)/i;
const HTML_SCRIPT_BLOCK_RE = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const HTML_ATTRIBUTE_VALUE_RE = /=\s*(?:"([^"]*)"|'([^']*)')/g;

function lineOfOffset(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

/**
 * HTML carries secrets in two places: inline `<script>` bodies (real JS, parsed
 * as such) and attribute values. Prose text between tags is not a literal.
 */
function extractLiteralsFromHtml(source: string): ExtractedLiteral[] {
  const out: ExtractedLiteral[] = [];
  let markup = "";
  let cursor = 0;
  for (const match of source.matchAll(HTML_SCRIPT_BLOCK_RE)) {
    const whole = match[0]!;
    const attrs = match[1] ?? "";
    const body = match[2] ?? "";
    const index = match.index ?? 0;
    const openTagLength = whole.indexOf(">") + 1;
    markup += source.slice(cursor, index + openTagLength);
    // Keep line numbers stable for everything after the script body.
    markup += body.replace(/[^\n]/g, " ");
    cursor = index + openTagLength + body.length;
    if (/\bsrc\s*=/i.test(attrs) || body.trim().length === 0) continue;
    const bodyLine = lineOfOffset(source, index + openTagLength);
    const viaAst = extractLiteralsFromJsAst(body);
    const scriptLiterals = viaAst ?? scanStringLiterals(body);
    for (const lit of scriptLiterals) {
      out.push({
        value: lit.value,
        ...(lit.line !== undefined ? { line: bodyLine + lit.line - 1 } : {}),
      });
    }
  }
  markup += source.slice(cursor);
  for (const match of markup.matchAll(HTML_ATTRIBUTE_VALUE_RE)) {
    const value = match[1] ?? match[2] ?? "";
    out.push({ value, line: lineOfOffset(markup, match.index ?? 0) });
  }
  return out;
}

function extractLiteralsDetailed(source: string): LiteralExtraction {
  if (HTML_SNIFF_RE.test(source) || /<script\b/i.test(source)) {
    return { literals: extractLiteralsFromHtml(source), exact: false };
  }
  const viaAst = extractLiteralsFromJsAst(source);
  if (viaAst !== null) return { literals: viaAst, exact: true };
  return { literals: scanStringLiterals(source), exact: false };
}

/**
 * Extract the string literals of a JS / TS / HTML source. Parse-accurate for
 * valid JavaScript and TypeScript (template chunks, comments, and regex
 * literals are handled by the real grammar); a tolerant scanner covers
 * fragments, truncated files, and inline HTML scripts.
 */
export function extractStringLiterals(source: string): string[] {
  return extractLiteralsDetailed(source).literals.map((lit) => lit.value);
}

/**
 * Re-escape a literal the way `extractStringLiterals` unescapes it, so a
 * literal written with `\\n`-style escapes in the raw source can still be
 * recognized as present. Order matters: backslashes first.
 */
function escapeForSourceSearch(literal: string): string {
  return literal
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/`/g, "\\`");
}

/**
 * True when a literal already lives inside the XOR encrypt-strings table
 * (opaque payload / index calls) — do not re-flag.
 */
export function looksAlreadyEncrypted(source: string, literal: string): boolean {
  if (source.includes("_blaS(") && source.includes("_blaT")) {
    // After encrypt, cleartext literal should be absent from source.
    if (!source.includes(JSON.stringify(literal)) && !source.includes(`'${literal}'`) && !source.includes(`"${literal}"`)) {
      return true;
    }
  }
  // Combinatorial AST leaves chunks but not the full literal as one piece ≥8.
  // The literal was unescaped on extraction, so also accept its escaped
  // spelling — otherwise a secret written with one escape sequence would be
  // treated as "absent from source" and silently skipped.
  if (
    literal.length >= 8 &&
    !source.includes(literal) &&
    !source.includes(escapeForSourceSearch(literal))
  ) {
    return true;
  }
  return false;
}

export function classifySensitiveLiteral(
  literal: string,
): PlaintextSecretFindingId | null {
  if (literal.length < 8) return null;

  if (/^FLAG\{[\s\S]*\}$/.test(literal) || /FLAG\{[A-Za-z0-9_\-]{8,}\}/.test(literal)) {
    return "plaintext-flag-literal";
  }
  if (/-----BEGIN [A-Z0-9 ]+-----/.test(literal)) {
    return "plaintext-pem-header";
  }
  if (/https?:\/\/[^\s"'<>]+/i.test(literal)) {
    return "plaintext-url-endpoint";
  }
  // The statistical rules below fire on any long, varied string — which is
  // exactly what an encoding alphabet is.
  const alphabet = isSequentialAlphabet(literal);
  // The Base64 alphabet includes "/", so a lowercase path such as
  // "/proc/sys/kernel/osrelease" passes the charset test; its words give it away.
  if (
    !alphabet &&
    (isHexish(literal) || (isBase64ish(literal) && !looksLikeNaturalText(literal)))
  ) {
    return "plaintext-b64-or-hex";
  }
  if (
    !alphabet &&
    literal.length >= 16 &&
    shannonEntropy(literal) >= 4.0 &&
    looksLikeRandomToken(literal)
  ) {
    return "plaintext-high-entropy";
  }
  if (DERIVE_KEYNAME.test(literal) && !KEYNAME_ALLOWLIST.has(literal)) {
    return "plaintext-derive-keyname";
  }
  return null;
}

function severityFor(id: PlaintextSecretFindingId): PlaintextSecretSeverity {
  switch (id) {
    case "plaintext-url-endpoint":
      return "warning";
    default:
      return "error";
  }
}

export function lintPlaintextSecretsSource(
  source: string,
  options: { readonly path?: string; readonly allowPlaintextString?: boolean } = {},
): PlaintextSecretReport {
  const path = options.path ?? "<memory>";
  const truncated =
    source.length > MAX_SCAN_CHARS ? source.slice(0, MAX_SCAN_CHARS) : source;
  const findings: PlaintextSecretFinding[] = [];
  const seen = new Set<string>();

  const extraction = extractLiteralsDetailed(truncated);
  for (const { value: lit, line, inRegex } of extraction.literals) {
    // A parsed literal is verbatim cleartext in the file; the "no longer in the
    // source" suppression only makes sense for the tolerant scanner's guesses.
    if (!extraction.exact && looksAlreadyEncrypted(truncated, lit)) continue;
    const id = classifySensitiveLiteral(lit);
    if (!id) continue;
    const key = `${id}:${lit}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      id,
      severity: severityFor(id),
      summary:
        inRegex === true
          ? `Cleartext sensitive value inside a regular expression (${id}) — nothing encodes a regex literal: build it with new RegExp(<string literal>) or move the value out of the shipped file`
          : `Cleartext sensitive literal (${id})`,
      evidence: lit.slice(0, 120),
      literal: lit.length > 200 ? `${lit.slice(0, 200)}…` : lit,
      ...(line !== undefined ? { line } : {}),
      ...(inRegex === true ? { inRegex: true as const } : {}),
    });
  }

  const errorFindings = findings.filter((f) => f.severity === "error");
  const looksExposed = findings.length > 0;
  const shouldRefuseBankrupt =
    errorFindings.length > 0 && options.allowPlaintextString !== true;

  const oneLineAdvice = shouldRefuseBankrupt
    ? "ERROR: Cleartext sensitive literals remain — run bla_encrypt_strings (XOR/combinatorial; never JS AES) or pass allow_plaintext_string (lab only)."
    : looksExposed
      ? "WARNING: Non-refusing sensitive literals (e.g. URLs) still in cleartext — prefer bla_encrypt_strings."
      : "No cleartext sensitive-literal findings (heuristic).";

  return {
    schema: PLAINTEXT_SECRET_SCHEMA,
    path,
    sha256Prefix: sha256Prefix(truncated),
    findings,
    looksExposed,
    shouldRefuseBankrupt,
    oneLineAdvice,
  };
}

export function lintPlaintextSecretsFile(
  filePath: string,
  options: { readonly allowPlaintextString?: boolean } = {},
): PlaintextSecretReport {
  const abs = resolve(filePath);
  const source = readFileSync(abs, "utf8");
  return lintPlaintextSecretsSource(source, {
    path: abs,
    allowPlaintextString: options.allowPlaintextString,
  });
}

function walkTargets(root: string, depth: number, out: string[]): void {
  if (depth > MAX_WALK_DEPTH || out.length >= MAX_FILES) return;
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (out.length >= MAX_FILES) return;
    if (ent.name.startsWith(".") && ent.name !== ".fixture") continue;
    const full = join(root, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIR_NAMES.has(ent.name)) continue;
      walkTargets(full, depth + 1, out);
    } else if (ent.isFile()) {
      if (
        /\.d\.ts$/i.test(ent.name) ||
        /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(ent.name)
      ) {
        continue;
      }
      if (TARGET_BASENAME.test(ent.name) || SCAN_EXT.test(ent.name)) {
        // Prefer entitlement-shaped basenames; still accept other JS/HTML but
        // only if basename matches target OR path contains panel/license/vault/auth/gate/entitlement.
        if (
          TARGET_BASENAME.test(ent.name) ||
          /(?:^|\/)(?:panel|license|vault|auth|gate|entitlement)[^/]*$/i.test(ent.name)
        ) {
          out.push(full);
        }
      }
    }
  }
}

export function discoverAndLintPlaintextSecrets(
  directory: string,
  options: { readonly allowPlaintextString?: boolean } = {},
): PlaintextSecretReport[] {
  const abs = resolve(directory);
  const reports: PlaintextSecretReport[] = [];
  if (!existsSync(abs)) return reports;
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintPlaintextSecretsFile(abs, options)];
  }
  const files: string[] = [];
  walkTargets(abs, 0, files);
  // Hardened output is decoys by design; lint what it was built from.
  for (const f of withoutKnownBlaOutputs(files)) {
    try {
      reports.push(lintPlaintextSecretsFile(f, options));
    } catch {
      /* skip unreadable */
    }
  }
  return reports;
}

export function plaintextSecretRefuseMessage(
  report: PlaintextSecretReport,
  filePath: string,
): string {
  const ids = [...new Set(report.findings.map((f) => f.id))].join(", ");
  return (
    `Plaintext sensitive literals in ${basename(filePath)} (${ids}). ` +
    `Encrypt with bla_encrypt_strings (seed-derived XOR — never JS-side AES wrap-key) ` +
    `or pass allowPlaintextString / --allow-plaintext-string / allow_plaintext_string (lab only).`
  );
}

export function intensityEnforcesPlaintextSecretRefusal(
  intensity: ProtectionIntensity,
): boolean {
  return intensity === "bankrupt";
}
