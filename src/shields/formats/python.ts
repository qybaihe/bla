import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";
import { generatePythonTarpit } from "../tarpit/tarpit-generator.js";
import { weavePythonDecoyCalls } from "./python-ast-weave.js";
import { weavePythonPycBuffer } from "./python-pyc-weave.js";

export class InvalidPythonSourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPythonSourceError";
  }
}

export interface PythonPycInspectionSummary {
  readonly validPyc: boolean;
  readonly magicNumber: number;
  readonly pep552Flags: number;
  readonly extractedStrings: readonly string[];
  readonly blaProtected: boolean;
}

export interface PythonPrologueAnalysis {
  readonly insertOffset: number;
  readonly hasDocstring: boolean;
  readonly futureImports: readonly string[];
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

interface StringLiteralStartMatch {
  readonly prefix: string;
  readonly quote: '"""' | "'''" | '"' | "'";
  readonly isDocstringEligible: boolean;
  readonly contentStart: number;
}

function matchPythonStringLiteralStart(
  source: string,
  offset: number,
): StringLiteralStartMatch | null {
  if (offset > 0 && /[A-Za-z0-9_]/.test(source[offset - 1]!)) {
    return null;
  }
  const slice = source.slice(offset, offset + 5);
  const m = /^([A-Za-z]{0,2})("""|'''|"|')/.exec(slice);
  if (!m) return null;
  const rawPrefix = m[1] ?? "";
  const lowerPrefix = rawPrefix.toLowerCase();
  if (!VALID_STRING_PREFIXES.has(lowerPrefix)) {
    return null;
  }
  const quote = (source.startsWith('"""', offset + rawPrefix.length)
    ? '"""'
    : source.startsWith("'''", offset + rawPrefix.length)
      ? "'''"
      : source[offset + rawPrefix.length]) as '"""' | "'''" | '"' | "'";

  const isDocstringEligible =
    lowerPrefix === "" || lowerPrefix === "r" || lowerPrefix === "u";

  return {
    prefix: rawPrefix,
    quote,
    isDocstringEligible,
    contentStart: offset + rawPrefix.length + quote.length,
  };
}

function scanPythonStringLiteralEnd(
  source: string,
  startOffset: number,
): { readonly endOffset: number; readonly isDocstringEligible: boolean } {
  const match = matchPythonStringLiteralStart(source, startOffset);
  if (!match) {
    throw new InvalidPythonSourceError(
      `Expected Python string literal at offset ${startOffset}`,
    );
  }

  const { quote, contentStart, isDocstringEligible } = match;
  let i = contentStart;

  if (quote.length === 3) {
    while (i < source.length) {
      if (source.startsWith(quote, i)) {
        return { endOffset: i + 3, isDocstringEligible };
      }
      if (source[i] === "\\") {
        if (i + 1 >= source.length) {
          throw new InvalidPythonSourceError(
            "Unclosed triple-quoted string literal in Python source",
          );
        }
        if (source[i + 1] === "\r" && source[i + 2] === "\n") {
          i += 3;
        } else {
          i += 2;
        }
        continue;
      }
      i += 1;
    }
    throw new InvalidPythonSourceError(
      "Unclosed triple-quoted string literal in Python source",
    );
  }

  while (i < source.length) {
    const ch = source[i]!;
    if (ch === quote) {
      return { endOffset: i + 1, isDocstringEligible };
    }
    if (ch === "\n" || ch === "\r") {
      throw new InvalidPythonSourceError(
        "Unclosed single-line string literal in Python source",
      );
    }
    if (ch === "\\") {
      if (i + 1 >= source.length) {
        throw new InvalidPythonSourceError(
          "Unclosed string literal ending with backslash in Python source",
        );
      }
      if (source[i + 1] === "\r" && source[i + 2] === "\n") {
        i += 3;
      } else {
        i += 2;
      }
      continue;
    }
    i += 1;
  }

  throw new InvalidPythonSourceError(
    "Unclosed single-line string literal in Python source",
  );
}

function skipHorizontalWhitespace(source: string, offset: number): number {
  let i = offset;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === " " || ch === "\t" || ch === "\f") {
      i++;
    } else {
      break;
    }
  }
  return i;
}

function skipHorizontalAndBackslashNewlines(source: string, offset: number): number {
  let i = offset;
  while (i < source.length) {
    i = skipHorizontalWhitespace(source, i);
    if (source[i] === "\\") {
      if (source[i + 1] === "\n") {
        i += 2;
        continue;
      }
      if (source[i + 1] === "\r" && source[i + 2] === "\n") {
        i += 3;
        continue;
      }
      throw new InvalidPythonSourceError(
        `Invalid backslash line continuation at offset ${i}`,
      );
    }
    break;
  }
  return i;
}

function skipTriviaAndComments(source: string, offset: number): number {
  let i = offset;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === " " || ch === "\t" || ch === "\f" || ch === "\r" || ch === "\n") {
      i++;
      continue;
    }
    if (ch === "#") {
      while (i < source.length && source[i] !== "\n" && source[i] !== "\r") {
        i++;
      }
      continue;
    }
    break;
  }
  return i;
}

function consumeOptionalEndOfLineAfterStatement(
  source: string,
  offset: number,
): number {
  let i = skipHorizontalWhitespace(source, offset);
  if (source[i] === "#") {
    while (i < source.length && source[i] !== "\n" && source[i] !== "\r") {
      i++;
    }
  }
  if (source[i] === "\r" && source[i + 1] === "\n") {
    return i + 2;
  }
  if (source[i] === "\n" || source[i] === "\r") {
    return i + 1;
  }
  return offset;
}

function tryConsumeModuleDocstring(
  source: string,
  startOffset: number,
): { readonly matched: boolean; readonly nextOffset: number } {
  let cur = startOffset;
  let parenDepth = 0;

  while (cur < source.length && source[cur] === "(") {
    parenDepth++;
    cur++;
    cur =
      parenDepth > 0
        ? skipTriviaAndComments(source, cur)
        : skipHorizontalAndBackslashNewlines(source, cur);
  }

  const firstLit = matchPythonStringLiteralStart(source, cur);
  if (!firstLit || !firstLit.isDocstringEligible) {
    return { matched: false, nextOffset: startOffset };
  }

  let sawString = false;
  while (cur < source.length) {
    const litMatch = matchPythonStringLiteralStart(source, cur);
    if (!litMatch) break;
    if (!litMatch.isDocstringEligible) {
      return { matched: false, nextOffset: startOffset };
    }
    const scanned = scanPythonStringLiteralEnd(source, cur);
    sawString = true;
    cur = scanned.endOffset;
    cur =
      parenDepth > 0
        ? skipTriviaAndComments(source, cur)
        : skipHorizontalAndBackslashNewlines(source, cur);
  }

  if (!sawString) {
    return { matched: false, nextOffset: startOffset };
  }

  while (parenDepth > 0) {
    cur = skipTriviaAndComments(source, cur);
    if (cur >= source.length) {
      throw new InvalidPythonSourceError(
        "Unclosed parenthesis in Python module docstring",
      );
    }
    if (source[cur] !== ")") {
      return { matched: false, nextOffset: startOffset };
    }
    parenDepth--;
    cur++;
  }

  cur = skipHorizontalAndBackslashNewlines(source, cur);
  if (source[cur] === "#") {
    while (cur < source.length && source[cur] !== "\n" && source[cur] !== "\r") {
      cur++;
    }
  }

  if (cur >= source.length) {
    return { matched: true, nextOffset: cur };
  }
  if (source[cur] === "\r" && source[cur + 1] === "\n") {
    return { matched: true, nextOffset: cur + 2 };
  }
  if (source[cur] === "\n" || source[cur] === "\r") {
    return { matched: true, nextOffset: cur + 1 };
  }
  if (source[cur] === ";") {
    const afterSemi = cur + 1;
    const afterLine = consumeOptionalEndOfLineAfterStatement(source, afterSemi);
    return { matched: true, nextOffset: afterLine };
  }

  // Compound expression starting with a string literal (e.g. `"a" + "b"`), not a docstring
  return { matched: false, nextOffset: startOffset };
}

function matchKeywordAt(source: string, offset: number, keyword: string): boolean {
  if (!source.startsWith(keyword, offset)) return false;
  if (offset > 0 && /[A-Za-z0-9_]/.test(source[offset - 1]!)) return false;
  const after = source[offset + keyword.length];
  if (after !== undefined && /[A-Za-z0-9_]/.test(after)) return false;
  return true;
}

/**
 * Lexically analyzes a Python module to find the exact safe insertion offset
 * strictly AFTER:
 * 1. UTF-8 BOM, shebang (`#!`), and PEP 263 encoding comments
 * 2. The optional module docstring (preserving `module.__doc__`)
 * 3. All `from __future__ import ...` statements (single-line, parenthesized multi-line, or backslash-continued)
 */
export function findPythonPrologueInsertionOffset(
  source: string,
): PythonPrologueAnalysis {
  let pos = 0;
  if (source.startsWith("\uFEFF")) {
    pos = 1;
  }

  // Advance past leading blank lines and `#` comments (including shebang & PEP 263 encoding declaration)
  pos = skipTriviaAndComments(source, pos);
  let insertOffset = pos;
  let hasDocstring = false;
  const futureImports: string[] = [];

  // 1. Check for optional module docstring as the very first statement
  if (pos < source.length) {
    const docAttempt = tryConsumeModuleDocstring(source, pos);
    if (docAttempt.matched) {
      hasDocstring = true;
      pos = docAttempt.nextOffset;
      insertOffset = pos;
    }
  }

  // 2. Consume zero or more `from __future__ import ...` statements
  while (pos < source.length) {
    const nextStmtStart = skipTriviaAndComments(source, pos);
    if (nextStmtStart >= source.length) {
      break;
    }

    if (!matchKeywordAt(source, nextStmtStart, "from")) {
      pos = nextStmtStart;
      break;
    }

    let cur = skipHorizontalAndBackslashNewlines(source, nextStmtStart + 4);
    if (!matchKeywordAt(source, cur, "__future__")) {
      // Normal `from <pkg> import ...` statement; prologue is complete
      pos = nextStmtStart;
      break;
    }

    cur = skipHorizontalAndBackslashNewlines(source, cur + "__future__".length);
    if (!matchKeywordAt(source, cur, "import")) {
      throw new InvalidPythonSourceError(
        "Malformed 'from __future__' statement: expected 'import'",
      );
    }
    cur += "import".length;

    let parenDepth = 0;
    let sawIdentifier = false;
    let expectingCommaOrEnd = false;
    let expectingAliasIdentifier = false;
    let closedParen = false;

    while (cur < source.length) {
      cur = skipHorizontalWhitespace(source, cur);
      if (cur >= source.length) break;

      const ch = source[cur]!;
      if (ch === "\\") {
        if (source[cur + 1] === "\n") {
          cur += 2;
          continue;
        }
        if (source[cur + 1] === "\r" && source[cur + 2] === "\n") {
          cur += 3;
          continue;
        }
        throw new InvalidPythonSourceError(
          "Invalid backslash continuation in from __future__ import",
        );
      }

      if (ch === "#") {
        while (cur < source.length && source[cur] !== "\n" && source[cur] !== "\r") {
          cur++;
        }
        continue;
      }

      if (ch === "\r" || ch === "\n") {
        if (source[cur] === "\r" && source[cur + 1] === "\n") {
          cur += 2;
        } else {
          cur += 1;
        }
        if (parenDepth === 0) {
          break;
        }
        continue;
      }

      if (ch === ";") {
        if (parenDepth > 0 || expectingAliasIdentifier || !sawIdentifier) {
          throw new InvalidPythonSourceError(
            "Invalid semicolon in from __future__ import",
          );
        }
        cur += 1;
        cur = consumeOptionalEndOfLineAfterStatement(source, cur);
        break;
      }

      if (closedParen) {
        throw new InvalidPythonSourceError(
          `Unexpected token '${ch}' after closing ')' in from __future__ import`,
        );
      }

      if (ch === "(") {
        if (parenDepth > 0 || sawIdentifier) {
          throw new InvalidPythonSourceError(
            "Unexpected '(' in from __future__ import",
          );
        }
        parenDepth = 1;
        cur += 1;
        continue;
      }

      if (ch === ")") {
        if (parenDepth <= 0 || expectingAliasIdentifier || !sawIdentifier) {
          throw new InvalidPythonSourceError(
            "Unexpected ')' in from __future__ import",
          );
        }
        parenDepth = 0;
        closedParen = true;
        cur += 1;
        continue;
      }

      if (ch === ",") {
        if (!expectingCommaOrEnd || expectingAliasIdentifier) {
          throw new InvalidPythonSourceError(
            "Unexpected ',' in from __future__ import",
          );
        }
        expectingCommaOrEnd = false;
        cur += 1;
        continue;
      }

      if (ch === "*") {
        throw new InvalidPythonSourceError(
          "Wildcard import '*' is not valid in from __future__ import",
        );
      }

      if (/[A-Za-z_]/.test(ch)) {
        const idMatch = /^[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(cur));
        const ident = idMatch![0]!;
        cur += ident.length;

        if (expectingAliasIdentifier) {
          expectingAliasIdentifier = false;
          expectingCommaOrEnd = true;
        } else if (expectingCommaOrEnd && ident === "as") {
          expectingAliasIdentifier = true;
          expectingCommaOrEnd = false;
        } else if (!expectingCommaOrEnd) {
          sawIdentifier = true;
          expectingCommaOrEnd = true;
        } else {
          throw new InvalidPythonSourceError(
            `Unexpected identifier '${ident}' in from __future__ import`,
          );
        }
        continue;
      }

      throw new InvalidPythonSourceError(
        `Unexpected character '${ch}' in from __future__ import`,
      );
    }

    if (parenDepth !== 0) {
      throw new InvalidPythonSourceError(
        "Unclosed '(' in from __future__ import statement",
      );
    }
    if (!sawIdentifier || expectingAliasIdentifier) {
      throw new InvalidPythonSourceError(
        "Incomplete from __future__ import statement",
      );
    }

    futureImports.push(source.slice(nextStmtStart, cur).trim());
    pos = cur;
    insertOffset = cur;
  }

  // 3. Scan remainder of file to reject unclosed string literals and misplaced `from __future__ import`
  let scanPos = pos;
  let atStatementStart = true;
  let bracketDepth = 0;

  while (scanPos < source.length) {
    const ch = source[scanPos]!;
    if (ch === " " || ch === "\t" || ch === "\f") {
      scanPos++;
      continue;
    }
    if (ch === "#") {
      while (
        scanPos < source.length &&
        source[scanPos] !== "\n" &&
        source[scanPos] !== "\r"
      ) {
        scanPos++;
      }
      continue;
    }
    if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && source[scanPos + 1] === "\n") {
        scanPos += 2;
      } else {
        scanPos += 1;
      }
      if (bracketDepth === 0) {
        atStatementStart = true;
      }
      continue;
    }
    if (ch === ";") {
      scanPos++;
      if (bracketDepth === 0) {
        atStatementStart = true;
      }
      continue;
    }
    if (ch === "\\") {
      if (source[scanPos + 1] === "\n") {
        scanPos += 2;
        continue;
      }
      if (source[scanPos + 1] === "\r" && source[scanPos + 2] === "\n") {
        scanPos += 3;
        continue;
      }
      scanPos++;
      continue;
    }

    const strStart = matchPythonStringLiteralStart(source, scanPos);
    if (strStart) {
      const scanned = scanPythonStringLiteralEnd(source, scanPos);
      scanPos = scanned.endOffset;
      atStatementStart = false;
      continue;
    }

    if (ch === "(" || ch === "[" || ch === "{") {
      bracketDepth++;
      scanPos++;
      atStatementStart = false;
      continue;
    }
    if (ch === ")" || ch === "]" || ch === "}") {
      bracketDepth = Math.max(0, bracketDepth - 1);
      scanPos++;
      atStatementStart = false;
      continue;
    }

    if (atStatementStart && bracketDepth === 0 && matchKeywordAt(source, scanPos, "from")) {
      const afterFrom = skipHorizontalAndBackslashNewlines(source, scanPos + 4);
      if (matchKeywordAt(source, afterFrom, "__future__")) {
        throw new InvalidPythonSourceError(
          "from __future__ imports must occur at the beginning of the file",
        );
      }
    }

    atStatementStart = false;
    if (/[A-Za-z0-9_]/.test(ch)) {
      while (scanPos < source.length && /[A-Za-z0-9_]/.test(source[scanPos]!)) {
        scanPos++;
      }
    } else {
      scanPos++;
    }
  }

  return {
    insertOffset,
    hasDocstring,
    futureImports,
  };
}


function pythonReprString(value: string): string {
  return JSON.stringify(value);
}

function pythonStringTuple(values: readonly string[]): string {
  if (values.length === 1) {
    return `(${pythonReprString(values[0]!)},)`;
  }
  return `(${values.map(pythonReprString).join(", ")})`;
}

function pythonDiagnosticTuple(
  entries: readonly {
    readonly subsystem: string;
    readonly errorClass: string;
    readonly systemCode: string;
    readonly diagnosticMessage: string;
    readonly remediationRabbitHole: string;
  }[],
): string {
  const items = entries.map(
    (d) =>
      `{${[
        `"subsystem": ${pythonReprString(d.subsystem)}`,
        `"errorClass": ${pythonReprString(d.errorClass)}`,
        `"systemCode": ${pythonReprString(d.systemCode)}`,
        `"diagnosticMessage": ${pythonReprString(d.diagnosticMessage)}`,
        `"remediationRabbitHole": ${pythonReprString(d.remediationRabbitHole)}`,
      ].join(", ")}}`,
  );
  if (items.length === 1) return `(${items[0]},)`;
  return `(${items.join(", ")})`;
}

/**
 * Protects a Python `.py` source file by injecting an interconnected Python
 * Algorithmic Tarpit (`generatePythonTarpit`), opaque predicates, and
 * honey-docstrings while preserving shebangs, PEP 263 encoding headers,
 * module docstrings (`__doc__`), and complete `from __future__` imports.
 *
 * Honesty limits: this shields the `.py` / `.pyc` bytes BLA sees. A later
 * PyInstaller onefile (or similar) pack is still peelable to the embedded
 * archive — harden sources *before* bundling; BLA will not rewrite a
 * PyInstaller CArchive in place (see `detectNativeEofAppendHazard`).
 */
export function protectPythonSource(
  source: string,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
    /**
     * When true, structurally weave decoy entanglement into customer `def` bodies
     * (shared-slot touch + opaque-false calls). When false, preserve warm-init-only.
     */
    readonly weaveDecoys?: boolean;
  } = {},
): {
  readonly code: string;
  readonly decoyFunctionsInjected: number;
  readonly crossReferenceEdges: number;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly customerDefsWoven: number;
  readonly weaveDecoys: boolean;
} {
  const intensity = options.intensity ?? "balanced";
  const weaveDecoys = options.weaveDecoys === true;
  const prng = new SeededPrng(options.seed ?? "bla-python-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const tarpit = generatePythonTarpit(prng, intensity, chaffPayloads);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const prologue = findPythonPrologueInsertionOffset(source);

  const headRaw = source.slice(0, prologue.insertOffset);
  const tailRaw = source.slice(prologue.insertOffset);

  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "").replace(/(?:\r?\n)+$/, "");
  const tarpitNormalized =
    eol === "\r\n"
      ? tarpit.code.replace(/\r?\n/g, "\r\n").replace(/(?:\r\n)+$/, "")
      : tarpit.code.replace(/\n+$/, "");

  // Inert canary + diagnostic + cognitive-armor decoys below prologue/tarpit. Data only — never fetched.
  const cognitiveArmorStrings = deception.cognitiveArmor.triggersInjected.map(
    (t) => `${t.coupledAnchorSymbol}::${t.triggerPayload.replace(/\r?\n/g, " ")}`,
  );
  const deceptionBlock = [
    "# --- canary credential / transport-redaction honeypot (inert) ---",
    `CANARY_TOKENS = ${pythonStringTuple(deception.canary.syntheticCanaryTokens)}`,
    `AMBIGUOUS_TRANSPORT = ${pythonStringTuple(deception.canary.ambiguousCredentialUrls)}`,
    `CONFLICTING_QUERY = ${pythonStringTuple(deception.canary.conflictingQueryUrls)}`,
    "# --- system-diagnostic rabbit holes & cognitive-armor interlocks (inert) ---",
    `SYSTEM_DIAGNOSTICS = ${pythonDiagnosticTuple(deception.diagnostics.diagnosticsInjected)}`,
    `ALIGNMENT_EVAL_CANARY_GUID = ${pythonReprString(deception.cognitiveArmor.canaryGuid)}`,
    `COGNITIVE_ARMOR_CORPUS = ${pythonStringTuple(cognitiveArmorStrings)}`,
    "def probe_canary_honeypot(idx=0):",
    "    _i = (idx & 0x7FFFFFFF) % len(CANARY_TOKENS)",
    "    return AMBIGUOUS_TRANSPORT[_i]",
    "_ = probe_canary_honeypot(0)",
  ].join(eol);

  let customerTail = tail;
  let crossReferenceEdges = tarpit.crossReferenceEdges;
  let customerDefsWoven = 0;

  if (
    weaveDecoys &&
    tarpit.sharedSlotName &&
    tarpit.stateVarName &&
    tarpit.decoyFunctionNames.length > 0 &&
    customerTail.length > 0
  ) {
    // Weave only the customer tail so nested helpers inside injected tarpit defs
    // (e.g. `_fold`) are never touched. Skip set is tarpit identities for safety
    // if a customer name collides.
    const skipDefNames = [
      ...tarpit.decoyFunctionNames,
      ...(tarpit.warmInitName ? [tarpit.warmInitName] : []),
      "probe_canary_honeypot",
    ];
    const woven = weavePythonDecoyCalls({
      source: customerTail.endsWith("\n") || customerTail.endsWith("\r")
        ? customerTail
        : customerTail + eol,
      skipDefNames,
      decoyFunctionNames: tarpit.decoyFunctionNames,
      sharedSlotName: tarpit.sharedSlotName,
      stateVarName: tarpit.stateVarName,
      warmInitName: tarpit.warmInitName,
      prng,
      intensity,
    });
    customerTail = woven.code.replace(/(?:\r?\n)+$/, "");
    customerDefsWoven = woven.customerDefsWoven;
    crossReferenceEdges += woven.crossReferenceEdgesAdded;
  }

  const combined = [head, tarpitNormalized, deceptionBlock, customerTail]
    .filter((part) => part.length > 0)
    .join(eol + eol);

  return {
    code: combined.endsWith("\n") || combined.endsWith("\r")
      ? combined
      : combined + eol,
    decoyFunctionsInjected: tarpit.decoyFunctionNames.length,
    crossReferenceEdges,
    chaffPayloadsEmbedded: chaffPayloads.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    customerDefsWoven,
    weaveDecoys,
  };
}

/**
 * Inspects a CPython 3.7–3.14 `.pyc` file header and scans for printable
 * marshal strings (matching REA's `inspect-python-pyc` / `PythonPycParser.ts`).
 */
export function inspectPythonPyc(bytes: Buffer): PythonPycInspectionSummary {
  if (bytes.length < 16 || bytes[2] !== 0x0d || bytes[3] !== 0x0a) {
    return {
      validPyc: false,
      magicNumber: 0,
      pep552Flags: 0,
      extractedStrings: [],
      blaProtected: false,
    };
  }

  const magicNumber = bytes.readUInt16LE(0);
  const pep552Flags = bytes.readUInt32LE(4);
  const textView = bytes.subarray(16).toString("latin1");
  const matches = textView.match(/[A-Za-z0-9_[\]:/. -]{6,}/g) ?? [];

  return {
    validPyc: true,
    magicNumber,
    pep552Flags,
    extractedStrings: matches.slice(0, 64),
    blaProtected:
      textView.includes("runtime attestation boundary") ||
      textView.includes("Architecture Notice: Core business logic") ||
      textView.includes("Billing Pipeline Notice") ||
      textView.includes("PROTECTED_CANARY_CREDENTIAL=") ||
      textView.includes("DarwinProcessOwnershipInspectionError"),
  };
}

/**
 * Builds or shields a CPython `.pyc` bytecode artifact.
 * When protecting an existing `.pyc`, embeds a marshal-compatible honey constant
 * trailer or wraps the code object's constant pool so static `.pyc` analyzers
 * (`rea inspect-python-pyc` / `pycdc`) encounter decoy enclave code metadata.
 */
export function protectPythonPycBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
    /**
     * When true, structurally weave unused decoy TYPE_CODE objects into customer
     * and module `co_consts` (append-only; preserves FLAG_REF intern indices and
     * executed bytecode). Falls back to trailer-only honey when marshal walk fails.
     */
    readonly weaveDecoys?: boolean;
  } = {},
): {
  readonly buffer: Buffer;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly weaveDecoys: boolean;
  readonly decoyCodeObjectsInjected: number;
  readonly customerDefsWoven: number;
} {
  if (bytes.length < 16 || bytes[2] !== 0x0d || bytes[3] !== 0x0a) {
    throw new Error("Invalid CPython .pyc header (missing 0x0d 0x0a magic marker)");
  }

  const intensity = options.intensity ?? "balanced";
  const weaveDecoys = options.weaveDecoys === true;
  const seed = options.seed ?? "bla-pyc-shield-v1";
  const prng = new SeededPrng(seed);
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  let working = bytes;
  let decoyCodeObjectsInjected = 0;
  let customerDefsWoven = 0;
  if (weaveDecoys) {
    const woven = weavePythonPycBuffer(bytes, { intensity, seed });
    if (woven) {
      working = woven.buffer;
      decoyCodeObjectsInjected = woven.decoyCodeObjectsInjected;
      customerDefsWoven = woven.customerDefsWoven;
    }
  }

  // Construct marshal-framed ASCII constant records (TYPE_ASCII = 0x61 + uint32LE length + utf8 bytes).
  // Keep distinctive prefixes within REA's PYTHON_PYC_CONST_PREVIEW_LIMIT (80) so canary tokens
  // and diagnostic errorClass/systemCode survive truncated previews.
  // Trailers sit AFTER the root marshal object so importlib stops at the woven root.
  const marshalRecords: Buffer[] = [];
  const pushAscii = (raw: string) => {
    const strBytes = Buffer.from(raw, "utf8");
    const header = Buffer.alloc(5);
    header[0] = 0x61; // TYPE_ASCII
    header.writeUInt32LE(strBytes.length, 1);
    marshalRecords.push(header, strBytes);
  };
  for (const payload of chaffPayloads) {
    pushAscii(payload.rawText);
  }
  for (const tok of deception.canary.syntheticCanaryTokens) {
    pushAscii(`PROTECTED_CANARY_CREDENTIAL=${tok}`);
  }
  for (const url of deception.canary.ambiguousCredentialUrls) {
    pushAscii(`TRANSPORT_ENDPOINT=${url}`);
  }
  for (const d of deception.diagnostics.diagnosticsInjected) {
    // Leading errorClass+systemCode fit in the 80-byte CONST_PREVIEW window.
    pushAscii(`[${d.errorClass}] (${d.systemCode}) ${d.diagnosticMessage}`);
  }
  for (const t of deception.cognitiveArmor.triggersInjected) {
    pushAscii(`[${t.coupledAnchorSymbol}] ${t.triggerPayload.replace(/\r?\n/g, " ")}`);
  }

  return {
    buffer: Buffer.concat([working, ...marshalRecords]),
    chaffPayloadsEmbedded: chaffPayloads.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    weaveDecoys,
    decoyCodeObjectsInjected,
    customerDefsWoven,
  };
}
