/**
 * Structural Python decoy weave — entangle tarpit decoys into customer `def` bodies.
 *
 * Modeled on JS `ast-shield.ts` §3: walk real function bodies, always-touch shared
 * state, and unshift opaque-false guarded decoy calls so xref from customer entry
 * reaches decoys. Selection is structural (FunctionDef sites minus injected tarpit
 * names by identity) + seeded PRNG — not keyword/business-name rule tables.
 *
 * No greppable `_bla_` / `BLA-SHIELD` banners. No Python AST dependency: indent-stack
 * scan with string/comment awareness, preserving encoding and EOL.
 */

import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generatePythonOpaqueFalseExpression } from "../tarpit/opaque-predicates.js";

export interface PythonAstWeaveInput {
  readonly source: string;
  /** Injected tarpit / warm-init names — skipped by identity, not by regex heuristics. */
  readonly skipDefNames: readonly string[];
  readonly decoyFunctionNames: readonly string[];
  readonly sharedSlotName: string;
  readonly stateVarName: string;
  /** Warm-init def identity to exclude from the call pool. */
  readonly warmInitName?: string;
  readonly prng: SeededPrng;
  readonly intensity?: ProtectionIntensity;
}

export interface PythonAstWeaveResult {
  readonly code: string;
  readonly customerDefsWoven: number;
  readonly crossReferenceEdgesAdded: number;
}

interface WeaveSite {
  readonly name: string;
  readonly insertOffset: number;
  readonly bodyIndent: string;
}

const VALID_STRING_PREFIXES = new Set([
  "",
  "r",
  "u",
  "f",
  "b",
  "fr",
  "rf",
  "br",
  "rb",
]);

function matchStringStart(
  source: string,
  offset: number,
): { readonly quote: string; readonly contentStart: number } | null {
  if (offset > 0 && /[A-Za-z0-9_]/.test(source[offset - 1]!)) return null;
  const slice = source.slice(offset, offset + 5);
  const m = /^([A-Za-z]{0,2})("""|'''|"|')/.exec(slice);
  if (!m) return null;
  const rawPrefix = m[1] ?? "";
  if (!VALID_STRING_PREFIXES.has(rawPrefix.toLowerCase())) return null;
  const afterPrefix = offset + rawPrefix.length;
  const quote = source.startsWith('"""', afterPrefix)
    ? '"""'
    : source.startsWith("'''", afterPrefix)
      ? "'''"
      : source[afterPrefix]!;
  return { quote, contentStart: afterPrefix + quote.length };
}

function scanStringEnd(source: string, startOffset: number): number {
  const match = matchStringStart(source, startOffset);
  if (!match) return startOffset + 1;
  const { quote, contentStart } = match;
  let i = contentStart;
  if (quote.length === 3) {
    while (i < source.length) {
      if (source.startsWith(quote, i)) return i + 3;
      if (source[i] === "\\") {
        if (i + 1 >= source.length) return source.length;
        if (source[i + 1] === "\r" && source[i + 2] === "\n") i += 3;
        else i += 2;
        continue;
      }
      i += 1;
    }
    return source.length;
  }
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === quote) return i + 1;
    if (ch === "\n" || ch === "\r") return i;
    if (ch === "\\") {
      if (i + 1 >= source.length) return source.length;
      if (source[i + 1] === "\r" && source[i + 2] === "\n") i += 3;
      else i += 2;
      continue;
    }
    i += 1;
  }
  return source.length;
}

function matchKeywordAt(source: string, offset: number, keyword: string): boolean {
  if (!source.startsWith(keyword, offset)) return false;
  if (offset > 0 && /[A-Za-z0-9_]/.test(source[offset - 1]!)) return false;
  const after = source[offset + keyword.length];
  if (after !== undefined && /[A-Za-z0-9_]/.test(after)) return false;
  return true;
}

function lineIndentAt(source: string, lineStart: number): string {
  let i = lineStart;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === " " || ch === "\t") i += 1;
    else break;
  }
  return source.slice(lineStart, i);
}

function advanceToNextLineStart(source: string, offset: number): number {
  let i = offset;
  while (i < source.length) {
    if (source[i] === "\r" && source[i + 1] === "\n") return i + 2;
    if (source[i] === "\n" || source[i] === "\r") return i + 1;
    i += 1;
  }
  return source.length;
}

function isBlankOrCommentLine(source: string, lineStart: number): boolean {
  let i = lineStart;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === " " || ch === "\t" || ch === "\f") {
      i += 1;
      continue;
    }
    if (ch === "#" || ch === "\n" || ch === "\r") return true;
    return false;
  }
  return true;
}

/**
 * Find the colon that ends a `def` / `async def` header, respecting nested
 * brackets and strings (structural, not a business-name regex table).
 */
function findHeaderColon(source: string, defKeywordOffset: number): number | null {
  let i = defKeywordOffset;
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  while (i < source.length) {
    const str = matchStringStart(source, i);
    if (str) {
      i = scanStringEnd(source, i);
      continue;
    }
    const ch = source[i]!;
    if (ch === "#") {
      i = advanceToNextLineStart(source, i);
      continue;
    }
    if (ch === "(") {
      paren += 1;
      i += 1;
      continue;
    }
    if (ch === ")") {
      paren = Math.max(0, paren - 1);
      i += 1;
      continue;
    }
    if (ch === "[") {
      bracket += 1;
      i += 1;
      continue;
    }
    if (ch === "]") {
      bracket = Math.max(0, bracket - 1);
      i += 1;
      continue;
    }
    if (ch === "{") {
      brace += 1;
      i += 1;
      continue;
    }
    if (ch === "}") {
      brace = Math.max(0, brace - 1);
      i += 1;
      continue;
    }
    if (ch === ":" && paren === 0 && bracket === 0 && brace === 0) {
      return i;
    }
    i += 1;
  }
  return null;
}

function skipDocstringAfterColon(
  source: string,
  afterColon: number,
  bodyIndent: string,
): number {
  // Skip horizontal space / comment on the def line, then newline.
  let i = afterColon + 1;
  while (i < source.length && (source[i] === " " || source[i] === "\t")) i += 1;
  if (source[i] === "#") {
    i = advanceToNextLineStart(source, i);
  } else if (source[i] === "\r" || source[i] === "\n") {
    i = advanceToNextLineStart(source, i);
  } else {
    // One-liner suite on the same line as colon — caller should skip site.
    return afterColon + 1;
  }

  while (i < source.length && isBlankOrCommentLine(source, i)) {
    i = advanceToNextLineStart(source, i);
  }
  if (i >= source.length) return i;

  const indent = lineIndentAt(source, i);
  if (indent !== bodyIndent) return i;

  const contentStart = i + indent.length;
  const lit = matchStringStart(source, contentStart);
  if (!lit) return i;

  // Docstring only when the first body statement is a bare string literal.
  const end = scanStringEnd(source, contentStart);
  let j = end;
  while (j < source.length && (source[j] === " " || source[j] === "\t")) j += 1;
  if (source[j] === "#") {
    j = advanceToNextLineStart(source, j);
  } else if (source[j] === "\r" || source[j] === "\n") {
    j = advanceToNextLineStart(source, j);
  } else if (source[j] === ";") {
    j += 1;
    while (j < source.length && (source[j] === " " || source[j] === "\t")) j += 1;
    if (source[j] === "\r" || source[j] === "\n") {
      j = advanceToNextLineStart(source, j);
    }
  } else {
    // Compound expression starting with a string — not a docstring statement.
    return i;
  }
  return j;
}

function detectBodyIndent(
  source: string,
  afterColon: number,
  defIndent: string,
): { readonly bodyIndent: string; readonly oneLiner: boolean } | null {
  let i = afterColon + 1;
  while (i < source.length && (source[i] === " " || source[i] === "\t")) i += 1;
  if (source[i] === "#") {
    i = advanceToNextLineStart(source, i);
  } else if (source[i] === "\r" || source[i] === "\n") {
    i = advanceToNextLineStart(source, i);
  } else {
    return { bodyIndent: defIndent + "    ", oneLiner: true };
  }

  while (i < source.length && isBlankOrCommentLine(source, i)) {
    i = advanceToNextLineStart(source, i);
  }
  if (i >= source.length) {
    return { bodyIndent: defIndent + "    ", oneLiner: false };
  }
  const indent = lineIndentAt(source, i);
  if (indent.length <= defIndent.length) {
    // Empty / ellipsis body edge — still allow insert with synthetic indent.
    return { bodyIndent: defIndent + (defIndent.includes("\t") ? "\t" : "    "), oneLiner: false };
  }
  return { bodyIndent: indent, oneLiner: false };
}

/**
 * Structural scan: every customer FunctionDef / AsyncFunctionDef whose name is
 * not in the tarpit identity skip-set. No keyword classifiers on business names.
 */
export function findCustomerPythonFunctionDefs(
  source: string,
  skipDefNames: ReadonlySet<string>,
): WeaveSite[] {
  const sites: WeaveSite[] = [];
  let i = 0;
  let lineStart = 0;
  let atLineStart = true;

  while (i < source.length) {
    if (atLineStart) {
      const indent = lineIndentAt(source, lineStart);
      let cur = lineStart + indent.length;
      if (
        cur < source.length &&
        source[cur] !== "#" &&
        source[cur] !== "\n" &&
        source[cur] !== "\r"
      ) {
        let asyncDef = false;
        if (matchKeywordAt(source, cur, "async")) {
          let afterAsync = cur + 5;
          while (
            afterAsync < source.length &&
            (source[afterAsync] === " " || source[afterAsync] === "\t")
          ) {
            afterAsync += 1;
          }
          if (matchKeywordAt(source, afterAsync, "def")) {
            asyncDef = true;
            cur = afterAsync;
          }
        }
        if (asyncDef || matchKeywordAt(source, cur, "def")) {
          const defKw = cur;
          cur = defKw + 3;
          while (cur < source.length && (source[cur] === " " || source[cur] === "\t")) {
            cur += 1;
          }
          const nameMatch = /^[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(cur));
          if (nameMatch) {
            const name = nameMatch[0]!;
            const colon = findHeaderColon(source, defKw);
            if (colon !== null && !skipDefNames.has(name)) {
              const bodyInfo = detectBodyIndent(source, colon, indent);
              if (bodyInfo && !bodyInfo.oneLiner) {
                const insertOffset = skipDocstringAfterColon(
                  source,
                  colon,
                  bodyInfo.bodyIndent,
                );
                sites.push({
                  name,
                  insertOffset,
                  bodyIndent: bodyInfo.bodyIndent,
                });
              }
            }
          }
        }
      }
    }

    const str = matchStringStart(source, i);
    if (str) {
      i = scanStringEnd(source, i);
      atLineStart = false;
      continue;
    }
    if (source[i] === "#") {
      i = advanceToNextLineStart(source, i);
      lineStart = i;
      atLineStart = true;
      continue;
    }
    if (source[i] === "\r" && source[i + 1] === "\n") {
      i += 2;
      lineStart = i;
      atLineStart = true;
      continue;
    }
    if (source[i] === "\n" || source[i] === "\r") {
      i += 1;
      lineStart = i;
      atLineStart = true;
      continue;
    }
    atLineStart = false;
    i += 1;
  }

  return sites;
}

function decoyPoolForWeave(
  decoyFunctionNames: readonly string[],
  warmInitName: string | undefined,
): string[] {
  // Prefer tarpit decoys over the warm-init helper by identity (not name heuristics).
  const pure = warmInitName
    ? decoyFunctionNames.filter((n) => n !== warmInitName)
    : [...decoyFunctionNames];
  return pure.length >= 1 ? pure : [...decoyFunctionNames];
}

/**
 * Weave shared-slot touch + opaque-false decoy calls into customer function bodies.
 */
export function weavePythonDecoyCalls(input: PythonAstWeaveInput): PythonAstWeaveResult {
  const {
    source,
    skipDefNames,
    decoyFunctionNames,
    sharedSlotName,
    stateVarName,
    warmInitName,
    prng,
    intensity = "balanced",
  } = input;

  if (decoyFunctionNames.length === 0) {
    return { code: source, customerDefsWoven: 0, crossReferenceEdgesAdded: 0 };
  }

  const skip = new Set(skipDefNames);
  const sites = findCustomerPythonFunctionDefs(source, skip);
  if (sites.length === 0) {
    return { code: source, customerDefsWoven: 0, crossReferenceEdgesAdded: 0 };
  }

  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const pool = decoyPoolForWeave(decoyFunctionNames, warmInitName);
  if (pool.length === 0) {
    return { code: source, customerDefsWoven: 0, crossReferenceEdgesAdded: 0 };
  }

  const deepCalls =
    intensity === "stealth" ? 1 : intensity === "balanced" ? 1 : 2;

  let crossReferenceEdgesAdded = 0;
  // Apply from end to start so earlier offsets stay valid.
  const ordered = [...sites].sort((a, b) => b.insertOffset - a.insertOffset);
  let code = source;
  let woven = 0;

  for (const site of ordered) {
    const dTouch = prng.pick(pool);
    const lines: string[] = [];
    // Always-executed shared-state touch — cheap, no deep recursion (JS §3 stepper analog).
    lines.push(
      `${site.bodyIndent}${sharedSlotName}["epoch"] = (${sharedSlotName}.get("epoch", 0) ^ hash(${dTouch}.__name__)) & 0xFFFFFFFF`,
    );
    crossReferenceEdgesAdded += 1;

    if (pool.length >= 1 && intensity !== "stealth") {
      const d1 = prng.pick(pool);
      const d2 = pool.length >= 2 ? prng.pick(pool) : d1;
      const seed1 = prng.nextInt(1, 255);
      const seed2 = prng.nextInt(1, 255);
      const opaque = generatePythonOpaqueFalseExpression(prng, stateVarName);
      lines.push(`${site.bodyIndent}if ${opaque}:`);
      if (deepCalls >= 2 && pool.length >= 2) {
        lines.push(
          `${site.bodyIndent}    _ = ${d1}(${seed1}, 0) ^ ${d2}(${seed2}, 0)`,
        );
        crossReferenceEdgesAdded += 2;
      } else {
        lines.push(`${site.bodyIndent}    _ = ${d1}(${seed1}, 0)`);
        crossReferenceEdgesAdded += 1;
      }
    } else if (intensity === "stealth") {
      // Stealth: always-touch only (still creates customer→decoy xref via __name__).
    }

    const block = lines.join(eol) + eol;
    code = code.slice(0, site.insertOffset) + block + code.slice(site.insertOffset);
    woven += 1;
  }

  return {
    code,
    customerDefsWoven: woven,
    crossReferenceEdgesAdded,
  };
}
