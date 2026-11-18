/**
 * Structural Python decoy weave — entangle tarpit decoys into customer `def` bodies.
 *
 * Modeled on JS `ast-shield.ts` §3: walk real function bodies, always-touch shared
 * state, and unshift opaque-false guarded decoy calls so xref from customer entry
 * reaches decoys. Selection is structural (FunctionDef sites minus injected tarpit
 * names by identity) + seeded PRNG — not keyword/business-name rule tables.
 *
 * No greppable `_bla_` / `BLA-SHIELD` banners. No Python AST dependency: this file
 * also hosts the shared Python lexical layer (tokens → logical lines → statements)
 * that `python.ts` uses for prologue analysis, so both agree on where a string,
 * a logical line and a docstring end.
 *
 * Customer-semantics rules for everything woven into a customer function body:
 * - never bind a name (no `_ = …`, no helper local): a binding turns the name into
 *   a function local and breaks `global` / `nonlocal` / closures / gettext's `_`;
 * - never resolve a name the customer can rebind (parameters, locals, module
 *   globals, imports). Builtins are reached through a generated private alias of
 *   the real `builtins` module, never by bare name;
 * - only insert at a logical-line boundary, after the docstring expression
 *   whatever form it takes (implicit concatenation, parentheses, continuation).
 */

import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generatePythonOpaqueFalseExpression } from "../tarpit/opaque-predicates.js";

/** Thrown when Python source cannot be tokenised or has an invalid prologue. */
export class InvalidPythonSourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPythonSourceError";
  }
}

// ---------------------------------------------------------------------------
// Lexical layer
// ---------------------------------------------------------------------------

export type PythonTokenKind =
  | "name"
  | "number"
  | "string"
  | "op"
  | "comment"
  | "newline";

export interface PythonToken {
  readonly kind: PythonTokenKind;
  readonly start: number;
  /** Exclusive end offset. */
  readonly end: number;
  /**
   * Bracket nesting depth the token sits at. A closing bracket reports the depth
   * of its opener, so tokens of one statement that are outside every bracket
   * all have depth 0. The synthetic end-of-file `newline` reports the depth that
   * was still open (> 0 means an unclosed bracket).
   */
  readonly depth: number;
  /**
   * `name` / `op`: the source text. `string`: the lower-cased literal prefix
   * (`""`, `"r"`, `"rb"`, `"f"`, …). Empty for other kinds.
   */
  readonly text: string;
  /**
   * `newline` only: offset where the first physical line of the logical line
   * it terminates begins (a leading backslash continuation counts as part of
   * the line, so inserting there never splits a joined line).
   */
  readonly lineStart?: number;
}

/** A logical line: the significant tokens up to (not including) its NEWLINE. */
export interface PythonLogicalLine {
  /** Significant tokens (no comments, no NEWLINE). Never empty. */
  readonly tokens: readonly PythonToken[];
  /** Offset of the first significant token. */
  readonly start: number;
  /** Offset where the first physical line of the logical line begins. */
  readonly lineStart: number;
  /** Offset just past the terminating line break (source length at EOF). */
  readonly end: number;
  /** True when the line ran into end-of-file with a bracket still open. */
  readonly unclosed: boolean;
}

/**
 * String literal prefixes of the Python 3 grammar, lower-cased. `t` / `tr` / `rt`
 * are PEP 750 template strings (3.14) and share the f-string lexical structure.
 */
const STRING_PREFIXES: ReadonlySet<string> = new Set([
  "",
  "r",
  "u",
  "b",
  "br",
  "rb",
  "f",
  "fr",
  "rf",
  "t",
  "tr",
  "rt",
]);

/** Prefixes whose literal can be a docstring (a plain `str` constant). */
const DOCSTRING_PREFIXES: ReadonlySet<string> = new Set(["", "r", "u"]);

const THREE_CHAR_OPS: ReadonlySet<string> = new Set(["**=", "//=", ">>=", "<<=", "..."]);
const TWO_CHAR_OPS: ReadonlySet<string> = new Set([
  "**",
  "//",
  ">>",
  "<<",
  "<=",
  ">=",
  "==",
  "!=",
  "->",
  ":=",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "&=",
  "|=",
  "^=",
  "@=",
  "<>",
]);

const CH_TAB = 9;
const CH_LF = 10;
const CH_FF = 12;
const CH_CR = 13;
const CH_SPACE = 32;
const CH_BANG = 33;
const CH_DQUOTE = 34;
const CH_HASH = 35;
const CH_SQUOTE = 39;
const CH_LPAREN = 40;
const CH_RPAREN = 41;
const CH_PLUS = 43;
const CH_MINUS = 45;
const CH_DOT = 46;
const CH_ZERO = 48;
const CH_COLON = 58;
const CH_EQUALS = 61;
const CH_UPPER_N = 78;
const CH_LBRACKET = 91;
const CH_BACKSLASH = 92;
const CH_RBRACKET = 93;
const CH_UNDERSCORE = 95;
const CH_LBRACE = 123;
const CH_RBRACE = 125;

function isDigitCode(c: number): boolean {
  return c >= 48 && c <= 57;
}

/**
 * Identifier start: ASCII letter, `_`, or any non-ASCII code unit. Outside
 * strings and comments valid Python only has non-ASCII characters inside
 * identifiers, so treating them all as identifier characters is exact for valid
 * source and harmless otherwise.
 */
function isIdentStartCode(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c >= 128;
}

function isIdentCharCode(c: number): boolean {
  return isIdentStartCode(c) || isDigitCode(c);
}

function isQuoteCode(c: number): boolean {
  return c === CH_SQUOTE || c === CH_DQUOTE;
}

/**
 * End offset of the numeric literal starting at `start` (a digit, or a `.`
 * followed by a digit). Follows the literal grammar instead of swallowing every
 * trailing letter, so `1if x else y` still yields the name `if` and `0x1for`
 * lexes as `0x1f` `or`, as in CPython.
 */
function scanNumberEnd(source: string, start: number): number {
  const n = source.length;
  let i = start;
  const digitsFrom = (from: number, isDigit: (c: number) => boolean): number => {
    let j = from;
    while (j < n) {
      const c = source.charCodeAt(j);
      if (isDigit(c) || c === CH_UNDERSCORE) j += 1;
      else break;
    }
    return j;
  };
  if (source.charCodeAt(i) === CH_ZERO) {
    const radix = source.charCodeAt(i + 1) | 32;
    if (radix === 120) {
      // 0x…
      return digitsFrom(
        i + 2,
        (c) => isDigitCode(c) || ((c | 32) >= 97 && (c | 32) <= 102),
      );
    }
    if (radix === 111) return digitsFrom(i + 2, (c) => c >= 48 && c <= 55); // 0o…
    if (radix === 98) return digitsFrom(i + 2, (c) => c === 48 || c === 49); // 0b…
  }
  i = digitsFrom(i, isDigitCode);
  if (source.charCodeAt(i) === CH_DOT) i = digitsFrom(i + 1, isDigitCode);
  if ((source.charCodeAt(i) | 32) === 101) {
    // exponent: only when digits follow, otherwise the `e` starts a name
    let j = i + 1;
    const sign = source.charCodeAt(j);
    if (sign === CH_PLUS || sign === CH_MINUS) j += 1;
    if (isDigitCode(source.charCodeAt(j))) i = digitsFrom(j, isDigitCode);
  }
  if ((source.charCodeAt(i) | 32) === 106) i += 1; // imaginary suffix
  return i;
}

function unclosedString(triple: boolean): InvalidPythonSourceError {
  return new InvalidPythonSourceError(
    triple
      ? "Unclosed triple-quoted string literal in Python source"
      : "Unclosed single-line string literal in Python source",
  );
}

function unclosedField(): InvalidPythonSourceError {
  return new InvalidPythonSourceError(
    "Unclosed replacement field in Python f-string literal",
  );
}

/** `i` is at a backslash: returns the offset after the escaped character. */
function skipEscapedChar(source: string, i: number): number {
  if (i + 1 >= source.length) {
    throw new InvalidPythonSourceError(
      "Unclosed string literal ending with backslash in Python source",
    );
  }
  if (source.charCodeAt(i + 1) === CH_CR && source.charCodeAt(i + 2) === CH_LF) {
    return i + 3;
  }
  return i + 2;
}

function closesAt(source: string, i: number, quote: number, triple: boolean): boolean {
  if (source.charCodeAt(i) !== quote) return false;
  return (
    !triple ||
    (source.charCodeAt(i + 1) === quote && source.charCodeAt(i + 2) === quote)
  );
}

/**
 * Scan one complete string literal starting at `start` (its prefix, if any, is
 * `prefixLen` characters long). Returns the offset just past the closing quote.
 *
 * f-strings / t-strings follow the PEP 701 (Python 3.12) grammar: a replacement
 * field is a real expression, so it may contain string literals that reuse the
 * enclosing quote, line breaks, comments and nested f-strings. Every f-string
 * that was valid before 3.12 tokenises identically under these rules.
 */
function scanStringLiteral(
  source: string,
  start: number,
  prefixLen: number,
  prefixLower: string,
): number {
  const quoteAt = start + prefixLen;
  const quote = source.charCodeAt(quoteAt);
  const triple =
    source.charCodeAt(quoteAt + 1) === quote &&
    source.charCodeAt(quoteAt + 2) === quote;
  const bodyStart = quoteAt + (triple ? 3 : 1);
  if (prefixLower.includes("f") || prefixLower.includes("t")) {
    return scanInterpolatedBody(
      source,
      bodyStart,
      quote,
      triple,
      prefixLower.includes("r"),
    );
  }
  const n = source.length;
  let i = bodyStart;
  while (i < n) {
    const c = source.charCodeAt(i);
    if (c === CH_BACKSLASH) {
      // Also in raw strings a backslash keeps the next quote from closing.
      i = skipEscapedChar(source, i);
      continue;
    }
    if (closesAt(source, i, quote, triple)) return i + (triple ? 3 : 1);
    if (!triple && (c === CH_LF || c === CH_CR)) throw unclosedString(false);
    i += 1;
  }
  throw unclosedString(triple);
}

/** Literal part of an f-string / t-string; `i` is just past the opening quote. */
function scanInterpolatedBody(
  source: string,
  bodyStart: number,
  quote: number,
  triple: boolean,
  raw: boolean,
): number {
  const n = source.length;
  let i = bodyStart;
  while (i < n) {
    const c = source.charCodeAt(i);
    if (closesAt(source, i, quote, triple)) return i + (triple ? 3 : 1);
    if (c === CH_BACKSLASH) {
      if (i + 1 >= n) throw unclosedString(triple);
      const d = source.charCodeAt(i + 1);
      // A backslash never escapes a brace: `\{` is a backslash, then a field.
      if (d === CH_LBRACE || d === CH_RBRACE) {
        i += 1;
        continue;
      }
      if (!raw && d === CH_UPPER_N && source.charCodeAt(i + 2) === CH_LBRACE) {
        // \N{UNICODE NAME}: the braces belong to the escape, not to a field.
        const close = source.indexOf("}", i + 3);
        if (close < 0) throw unclosedString(triple);
        i = close + 1;
        continue;
      }
      i = skipEscapedChar(source, i);
      continue;
    }
    if (!triple && (c === CH_LF || c === CH_CR)) throw unclosedString(false);
    if (c === CH_LBRACE) {
      if (source.charCodeAt(i + 1) === CH_LBRACE) {
        i += 2; // `{{` is a literal brace
        continue;
      }
      i = scanReplacementField(source, i + 1, quote, triple, raw);
      continue;
    }
    i += 1; // ordinary character, `}}` or a stray `}`
  }
  throw unclosedString(triple);
}

/**
 * Expression part of a replacement field; `i` is just past its `{`. Returns the
 * offset just past the `}` that closes the field (including any format spec).
 */
function scanReplacementField(
  source: string,
  fieldStart: number,
  quote: number,
  triple: boolean,
  raw: boolean,
): number {
  const n = source.length;
  let depth = 0;
  let i = fieldStart;
  while (i < n) {
    const c = source.charCodeAt(i);
    if (c === CH_RBRACE) {
      if (depth === 0) return i + 1;
      depth -= 1;
      i += 1;
      continue;
    }
    if (c === CH_LPAREN || c === CH_LBRACKET || c === CH_LBRACE) {
      depth += 1;
      i += 1;
      continue;
    }
    if (c === CH_RPAREN || c === CH_RBRACKET) {
      if (depth > 0) depth -= 1;
      i += 1;
      continue;
    }
    if (c === CH_HASH) {
      // Comment inside a multi-line replacement field (3.12+): runs to end of line.
      while (i < n && source.charCodeAt(i) !== CH_LF && source.charCodeAt(i) !== CH_CR) {
        i += 1;
      }
      continue;
    }
    if (isQuoteCode(c)) {
      i = scanStringLiteral(source, i, 0, "");
      continue;
    }
    if (isIdentStartCode(c)) {
      let j = i + 1;
      while (j < n && isIdentCharCode(source.charCodeAt(j))) j += 1;
      if (j - i <= 2 && isQuoteCode(source.charCodeAt(j))) {
        const prefix = source.slice(i, j).toLowerCase();
        if (STRING_PREFIXES.has(prefix)) {
          i = scanStringLiteral(source, i, j - i, prefix);
          continue;
        }
      }
      i = j;
      continue;
    }
    if (isDigitCode(c) || (c === CH_DOT && isDigitCode(source.charCodeAt(i + 1)))) {
      i = scanNumberEnd(source, i);
      continue;
    }
    if (depth === 0 && c === CH_BANG) {
      // `!=` is an operator; a lone `!` introduces the conversion (`!r`).
      i += source.charCodeAt(i + 1) === CH_EQUALS ? 2 : 1;
      continue;
    }
    if (depth === 0 && c === CH_COLON) {
      // At the top level of a field a colon always starts the format spec.
      return scanFormatSpec(source, i + 1, quote, triple, raw);
    }
    i += 1; // whitespace, line breaks, continuations, operators
  }
  throw unclosedField();
}

/** Format spec of a replacement field; returns the offset past the field's `}`. */
function scanFormatSpec(
  source: string,
  specStart: number,
  quote: number,
  triple: boolean,
  raw: boolean,
): number {
  const n = source.length;
  let i = specStart;
  while (i < n) {
    const c = source.charCodeAt(i);
    if (c === CH_RBRACE) return i + 1;
    if (c === CH_LBRACE) {
      i = scanReplacementField(source, i + 1, quote, triple, raw);
      continue;
    }
    if (closesAt(source, i, quote, triple)) throw unclosedField();
    if (c === CH_BACKSLASH) {
      if (i + 1 >= n) throw unclosedField();
      const d = source.charCodeAt(i + 1);
      i = d === CH_LBRACE || d === CH_RBRACE ? i + 1 : skipEscapedChar(source, i);
      continue;
    }
    if (!triple && (c === CH_LF || c === CH_CR)) throw unclosedString(false);
    i += 1;
  }
  throw unclosedField();
}

/**
 * Tokenise Python source. Whitespace, line joins and blank lines produce no
 * token; a `newline` token ends each logical line (a line break outside every
 * bracket that follows at least one significant token). A synthetic `newline`
 * at end-of-file closes a last line that has no line break.
 *
 * Throws {@link InvalidPythonSourceError} for an unterminated string literal.
 */
export function tokenizePythonSource(source: string): PythonToken[] {
  const tokens: PythonToken[] = [];
  const n = source.length;
  let depth = 0;
  let lineHasTokens = false;
  // Start of the physical line on which the current logical line began. Only an
  // unescaped line break outside brackets moves it; a backslash join does not.
  let lineStart = 0;
  let i = source.charCodeAt(0) === 0xfeff ? 1 : 0;

  while (i < n) {
    const c = source.charCodeAt(i);
    if (c === CH_SPACE || c === CH_TAB || c === CH_FF) {
      i += 1;
      continue;
    }
    if (c === CH_BACKSLASH) {
      const d = source.charCodeAt(i + 1);
      if (d === CH_LF) {
        i += 2;
        continue;
      }
      if (d === CH_CR) {
        i += source.charCodeAt(i + 2) === CH_LF ? 3 : 2;
        continue;
      }
      tokens.push({ kind: "op", start: i, end: i + 1, depth, text: "\\" });
      lineHasTokens = true;
      i += 1;
      continue;
    }
    if (c === CH_HASH) {
      let j = i + 1;
      while (j < n && source.charCodeAt(j) !== CH_LF && source.charCodeAt(j) !== CH_CR) {
        j += 1;
      }
      tokens.push({ kind: "comment", start: i, end: j, depth, text: "" });
      i = j;
      continue;
    }
    if (c === CH_LF || c === CH_CR) {
      const len = c === CH_CR && source.charCodeAt(i + 1) === CH_LF ? 2 : 1;
      if (depth === 0 && lineHasTokens) {
        tokens.push({ kind: "newline", start: i, end: i + len, depth: 0, text: "", lineStart });
        lineHasTokens = false;
      }
      i += len;
      if (!lineHasTokens) lineStart = i;
      continue;
    }
    if (isIdentStartCode(c)) {
      let j = i + 1;
      while (j < n && isIdentCharCode(source.charCodeAt(j))) j += 1;
      if (j - i <= 2 && isQuoteCode(source.charCodeAt(j))) {
        const prefix = source.slice(i, j).toLowerCase();
        if (STRING_PREFIXES.has(prefix)) {
          const end = scanStringLiteral(source, i, j - i, prefix);
          tokens.push({ kind: "string", start: i, end, depth, text: prefix });
          lineHasTokens = true;
          i = end;
          continue;
        }
      }
      tokens.push({ kind: "name", start: i, end: j, depth, text: source.slice(i, j) });
      lineHasTokens = true;
      i = j;
      continue;
    }
    if (isQuoteCode(c)) {
      const end = scanStringLiteral(source, i, 0, "");
      tokens.push({ kind: "string", start: i, end, depth, text: "" });
      lineHasTokens = true;
      i = end;
      continue;
    }
    if (isDigitCode(c) || (c === CH_DOT && isDigitCode(source.charCodeAt(i + 1)))) {
      const end = scanNumberEnd(source, i);
      tokens.push({ kind: "number", start: i, end, depth, text: "" });
      lineHasTokens = true;
      i = end;
      continue;
    }

    // Operators and delimiters.
    const three = source.slice(i, i + 3);
    const two = three.slice(0, 2);
    let text: string;
    if (THREE_CHAR_OPS.has(three)) text = three;
    else if (TWO_CHAR_OPS.has(two)) text = two;
    else text = source.charAt(i);
    let tokenDepth = depth;
    if (text.length === 1) {
      if (c === CH_LPAREN || c === CH_LBRACKET || c === CH_LBRACE) {
        depth += 1;
      } else if (c === CH_RPAREN || c === CH_RBRACKET || c === CH_RBRACE) {
        depth = Math.max(0, depth - 1);
        tokenDepth = depth;
      }
    }
    tokens.push({ kind: "op", start: i, end: i + text.length, depth: tokenDepth, text });
    lineHasTokens = true;
    i += text.length;
  }

  if (lineHasTokens) {
    tokens.push({ kind: "newline", start: n, end: n, depth, text: "", lineStart });
  }
  return tokens;
}

/** Group tokens into logical lines (comments dropped). */
export function splitPythonLogicalLines(
  tokens: readonly PythonToken[],
): PythonLogicalLine[] {
  const lines: PythonLogicalLine[] = [];
  let current: PythonToken[] = [];
  for (const token of tokens) {
    if (token.kind === "comment") continue;
    if (token.kind !== "newline") {
      current.push(token);
      continue;
    }
    if (current.length === 0) continue;
    const start = current[0]!.start;
    lines.push({
      tokens: current,
      start,
      lineStart: token.lineStart ?? start,
      end: token.end,
      unclosed: token.depth > 0,
    });
    current = [];
  }
  return lines;
}

/** Split one logical line into its `;`-separated simple statements. */
export function splitPythonStatements(
  tokens: readonly PythonToken[],
): PythonToken[][] {
  const statements: PythonToken[][] = [];
  let current: PythonToken[] = [];
  for (const token of tokens) {
    if (token.kind === "op" && token.text === ";" && token.depth === 0) {
      if (current.length > 0) statements.push(current);
      current = [];
      continue;
    }
    current.push(token);
  }
  if (current.length > 0) statements.push(current);
  return statements;
}

function isName(token: PythonToken | undefined, text: string): boolean {
  return token !== undefined && token.kind === "name" && token.text === text;
}

function isOp(token: PythonToken | undefined, text: string): boolean {
  return token !== undefined && token.kind === "op" && token.text === text;
}

/**
 * True when the statement is a docstring expression: nothing but `str` literals
 * (implicitly concatenated or not), optionally wrapped in parentheses. This is
 * exactly the shape the compiler turns into a single `Constant(str)` expression
 * statement, which is what `__doc__` is taken from.
 */
export function isPythonDocstringStatement(
  statement: readonly PythonToken[] | undefined,
): boolean {
  if (!statement || statement.length === 0) return false;
  let lo = 0;
  let hi = statement.length - 1;
  while (lo < hi && isOp(statement[lo], "(") && isOp(statement[hi], ")")) {
    lo += 1;
    hi -= 1;
  }
  if (lo > hi) return false;
  for (let k = lo; k <= hi; k++) {
    const token = statement[k]!;
    if (token.kind !== "string" || !DOCSTRING_PREFIXES.has(token.text)) return false;
  }
  return true;
}

function isFutureImportStart(statement: readonly PythonToken[]): boolean {
  return isName(statement[0], "from") && isName(statement[1], "__future__");
}

/** Validates `from __future__ import …`; throws on anything Python rejects. */
function validateFutureImport(
  statement: readonly PythonToken[],
  unclosed: boolean,
): void {
  if (!isName(statement[2], "import")) {
    throw new InvalidPythonSourceError(
      "Malformed 'from __future__' statement: expected 'import'",
    );
  }
  let k = 3;
  const parenthesized = isOp(statement[k], "(");
  if (parenthesized) k += 1;
  let names = 0;
  for (;;) {
    const token = statement[k];
    if (token === undefined) break;
    if (isOp(token, "*")) {
      throw new InvalidPythonSourceError(
        "Wildcard import '*' is not valid in from __future__ import",
      );
    }
    if (token.kind !== "name" || token.text === "as") break;
    names += 1;
    k += 1;
    if (isName(statement[k], "as")) {
      const alias = statement[k + 1];
      if (alias === undefined || alias.kind !== "name") {
        throw new InvalidPythonSourceError(
          "Incomplete from __future__ import statement",
        );
      }
      k += 2;
    }
    if (!isOp(statement[k], ",")) break;
    k += 1;
    if (parenthesized && isOp(statement[k], ")")) break; // trailing comma
  }
  if (parenthesized) {
    if (!isOp(statement[k], ")")) {
      if (statement[k] === undefined || unclosed) {
        throw new InvalidPythonSourceError(
          "Unclosed '(' in from __future__ import statement",
        );
      }
      throw new InvalidPythonSourceError(
        "Unexpected token in parenthesized from __future__ import",
      );
    }
    k += 1;
  }
  if (names === 0) {
    throw new InvalidPythonSourceError(
      "Incomplete from __future__ import statement",
    );
  }
  if (statement[k] !== undefined) {
    throw new InvalidPythonSourceError(
      "Unexpected token after from __future__ import statement",
    );
  }
}

export interface PythonPrologueScan {
  /**
   * Offset of a logical-line boundary strictly after the module docstring and
   * every `from __future__ import`, where a module-level block can be inserted.
   */
  readonly insertOffset: number;
  readonly hasDocstring: boolean;
  readonly futureImports: readonly string[];
}

/**
 * Locate the end of the module prologue from an already tokenised source.
 *
 * The prologue is the docstring's logical line (if the first statement is a
 * docstring) followed by every logical line that starts with a
 * `from __future__ import`. A prologue line is taken whole: when it continues
 * with `; statement`, those statements stay in front of the insertion point —
 * splitting a logical line would leave the tail of it dangling.
 */
export function scanPythonPrologue(
  source: string,
  lines: readonly PythonLogicalLine[],
): PythonPrologueScan {
  const bomLength = source.charCodeAt(0) === 0xfeff ? 1 : 0;
  const futureImports: string[] = [];
  const first = lines[0];
  if (first === undefined) {
    return { insertOffset: source.length, hasDocstring: false, futureImports };
  }

  let insertOffset = Math.max(first.lineStart, bomLength);
  let hasDocstring = false;
  /** A statement that is neither docstring nor future import was seen. */
  let sawOther = false;
  let index = 0;

  const takeLine = (
    line: PythonLogicalLine,
    statements: readonly PythonToken[][],
    from: number,
  ): void => {
    for (let s = from; s < statements.length; s++) {
      const statement = statements[s]!;
      if (!sawOther && isFutureImportStart(statement)) {
        validateFutureImport(statement, line.unclosed);
        futureImports.push(
          source
            .slice(statement[0]!.start, statement[statement.length - 1]!.end)
            .trim(),
        );
      } else {
        sawOther = true;
      }
    }
    insertOffset = line.end;
  };

  const firstStatements = splitPythonStatements(first.tokens);
  if (isPythonDocstringStatement(firstStatements[0])) {
    hasDocstring = true;
    takeLine(first, firstStatements, 1);
    index = 1;
  }
  while (!sawOther && index < lines.length) {
    const line = lines[index]!;
    const statements = splitPythonStatements(line.tokens);
    if (statements.length === 0 || !isFutureImportStart(statements[0]!)) break;
    takeLine(line, statements, 0);
    index += 1;
  }

  for (let rest = index; rest < lines.length; rest++) {
    for (const statement of splitPythonStatements(lines[rest]!.tokens)) {
      if (isFutureImportStart(statement)) {
        throw new InvalidPythonSourceError(
          "from __future__ imports must occur at the beginning of the file",
        );
      }
    }
  }

  return { insertOffset, hasDocstring, futureImports };
}

/** Every identifier token in the source (keywords included). */
export function collectPythonIdentifiers(
  tokens: readonly PythonToken[],
): Set<string> {
  const names = new Set<string>();
  for (const token of tokens) {
    if (token.kind === "name") names.add(token.text);
  }
  return names;
}

/**
 * Draw a private (underscore-prefixed) module-level name that does not occur
 * anywhere in the customer source. The name is built from the realistic
 * identifier vocabulary so injected code carries no shared greppable marker.
 */
export function drawPrivatePythonName(
  prng: SeededPrng,
  taken: Set<string>,
  options: { readonly hint?: string; readonly suffix?: string; readonly upper?: boolean } = {},
): string {
  for (let attempt = 0; attempt < 64; attempt++) {
    const base = prng.identifier({
      style: "snake",
      entropy: 4,
      ...(options.hint ? { hint: options.hint } : {}),
    });
    let name = `_${base}`;
    if (options.upper) name = name.toUpperCase();
    if (options.suffix) name = `${name}_${options.suffix}`;
    if (!taken.has(name)) {
      taken.add(name);
      return name;
    }
  }
  throw new Error("Failed to draw a collision-free private Python identifier");
}

// ---------------------------------------------------------------------------
// Decoy weave
// ---------------------------------------------------------------------------

export interface PythonAstWeaveInput {
  readonly source: string;
  /** Injected tarpit / warm-init names — skipped by identity, not by regex heuristics. */
  readonly skipDefNames: readonly string[];
  readonly decoyFunctionNames: readonly string[];
  readonly sharedSlotName: string;
  readonly stateVarName: string;
  /** Warm-init def identity to exclude from the call pool. */
  readonly warmInitName?: string;
  /**
   * Module-level name already bound to the real `builtins` module
   * (`import builtins as <name>`). Woven statements reach `hash` through it.
   * When omitted, the weave binds its own private alias right after the module
   * prologue of `source`.
   */
  readonly builtinsAlias?: string;
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

/** Leading whitespace of a logical line, or null when it is not plain indentation. */
function indentationOf(source: string, line: PythonLogicalLine): string | null {
  const indent = source.slice(line.lineStart, line.start);
  return /^[ \t]*$/.test(indent) ? indent : null;
}

function sitesFromLines(
  source: string,
  lines: readonly PythonLogicalLine[],
  skipDefNames: ReadonlySet<string>,
): WeaveSite[] {
  const sites: WeaveSite[] = [];
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    const tokens = line.tokens;
    const defAt = isName(tokens[0], "async") ? 1 : 0;
    if (!isName(tokens[defAt], "def")) continue;
    const nameToken = tokens[defAt + 1];
    if (nameToken === undefined || nameToken.kind !== "name") continue;

    // The header ends at the first colon outside every bracket.
    let colon = -1;
    for (let k = defAt + 2; k < tokens.length; k++) {
      if (isOp(tokens[k], ":") && tokens[k]!.depth === 0) {
        colon = k;
        break;
      }
    }
    // No colon, or a one-line suite (`def f(): return 1`): nothing to weave.
    if (colon < 0 || colon !== tokens.length - 1 || line.unclosed) continue;
    if (skipDefNames.has(nameToken.text)) continue;

    const body = lines[li + 1];
    if (body === undefined) continue;
    const defIndent = indentationOf(source, line);
    const bodyIndent = indentationOf(source, body);
    if (
      defIndent === null ||
      bodyIndent === null ||
      bodyIndent.length <= defIndent.length ||
      !bodyIndent.startsWith(defIndent)
    ) {
      continue;
    }

    // Woven statements go after the docstring's whole logical line, else in
    // front of the first body line — always at a logical-line boundary.
    const firstStatement = splitPythonStatements(body.tokens)[0];
    sites.push({
      name: nameToken.text,
      insertOffset: isPythonDocstringStatement(firstStatement)
        ? body.end
        : body.lineStart,
      bodyIndent,
    });
  }
  return sites;
}

/**
 * Structural scan: every customer FunctionDef / AsyncFunctionDef whose name is
 * not in the tarpit identity skip-set. No keyword classifiers on business names.
 * Source that cannot be tokenised yields no sites (nothing is woven).
 */
export function findCustomerPythonFunctionDefs(
  source: string,
  skipDefNames: ReadonlySet<string>,
): WeaveSite[] {
  try {
    const tokens = tokenizePythonSource(source);
    return sitesFromLines(source, splitPythonLogicalLines(tokens), skipDefNames);
  } catch (err) {
    if (err instanceof InvalidPythonSourceError) return [];
    throw err;
  }
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

function endsWithLineBreak(text: string, offset: number): boolean {
  if (offset <= 0) return true;
  const c = text.charCodeAt(offset - 1);
  return c === CH_LF || c === CH_CR;
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
  const unchanged: PythonAstWeaveResult = {
    code: source,
    customerDefsWoven: 0,
    crossReferenceEdgesAdded: 0,
  };

  if (decoyFunctionNames.length === 0) return unchanged;
  const pool = decoyPoolForWeave(decoyFunctionNames, warmInitName);
  if (pool.length === 0) return unchanged;

  let tokens: PythonToken[];
  let lines: PythonLogicalLine[];
  try {
    tokens = tokenizePythonSource(source);
    lines = splitPythonLogicalLines(tokens);
  } catch (err) {
    if (err instanceof InvalidPythonSourceError) return unchanged;
    throw err;
  }
  const sites = sitesFromLines(source, lines, new Set(skipDefNames));
  if (sites.length === 0) return unchanged;

  const eol = source.includes("\r\n") ? "\r\n" : "\n";

  // The real builtins module, under a private module-level alias. A bare
  // `hash(...)` would resolve to whatever the customer bound to that name
  // (parameter, local, module function, import).
  let builtinsAlias = input.builtinsAlias;
  let aliasBinding: { readonly offset: number; readonly text: string } | null = null;
  if (!builtinsAlias) {
    let prologue: PythonPrologueScan;
    try {
      prologue = scanPythonPrologue(source, lines);
    } catch (err) {
      if (err instanceof InvalidPythonSourceError) return unchanged;
      throw err;
    }
    const taken = collectPythonIdentifiers(tokens);
    for (const name of [...decoyFunctionNames, sharedSlotName, stateVarName]) {
      taken.add(name);
    }
    builtinsAlias = drawPrivatePythonName(prng.derive("python-weave-builtins"), taken);
    aliasBinding = {
      offset: prologue.insertOffset,
      text: `import builtins as ${builtinsAlias}${eol}`,
    };
  }

  const deepCalls =
    intensity === "stealth" ? 1 : intensity === "balanced" ? 1 : 2;

  let crossReferenceEdgesAdded = 0;
  // Apply from end to start so earlier offsets stay valid.
  const ordered = [...sites].sort((a, b) => b.insertOffset - a.insertOffset);
  let code = source;
  let woven = 0;

  const insertAt = (offset: number, block: string): void => {
    const glue = endsWithLineBreak(code, offset) ? "" : eol;
    code = code.slice(0, offset) + glue + block + code.slice(offset);
  };

  for (const site of ordered) {
    const dTouch = prng.pick(pool);
    const blockLines: string[] = [];
    // Always-executed shared-state touch — cheap, no deep recursion (JS §3 stepper analog).
    blockLines.push(
      `${site.bodyIndent}${sharedSlotName}["epoch"] = (${sharedSlotName}.get("epoch", 0) ^ ${builtinsAlias}.hash(${dTouch}.__name__)) & 0xFFFFFFFF`,
    );
    crossReferenceEdgesAdded += 1;

    if (pool.length >= 1 && intensity !== "stealth") {
      const d1 = prng.pick(pool);
      const d2 = pool.length >= 2 ? prng.pick(pool) : d1;
      const seed1 = prng.nextInt(1, 255);
      const seed2 = prng.nextInt(1, 255);
      const opaque = generatePythonOpaqueFalseExpression(prng, stateVarName);
      blockLines.push(`${site.bodyIndent}if ${opaque}:`);
      // Bare expression statements: the decoy calls bind nothing in the
      // customer's function scope.
      if (deepCalls >= 2 && pool.length >= 2) {
        blockLines.push(
          `${site.bodyIndent}    ${d1}(${seed1}, 0) ^ ${d2}(${seed2}, 0)`,
        );
        crossReferenceEdgesAdded += 2;
      } else {
        blockLines.push(`${site.bodyIndent}    ${d1}(${seed1}, 0)`);
        crossReferenceEdgesAdded += 1;
      }
    }
    // Stealth: always-touch only (still creates customer→decoy xref via __name__).

    insertAt(site.insertOffset, blockLines.join(eol) + eol);
    woven += 1;
  }

  if (aliasBinding) insertAt(aliasBinding.offset, aliasBinding.text);

  return {
    code,
    customerDefsWoven: woven,
    crossReferenceEdgesAdded,
  };
}
