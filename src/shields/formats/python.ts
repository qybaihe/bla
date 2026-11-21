import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";
import { generatePythonTarpit } from "../tarpit/tarpit-generator.js";
import {
  InvalidPythonSourceError,
  collectPythonIdentifiers,
  drawPrivatePythonName,
  scanPythonPrologue,
  splitPythonLogicalLines,
  tokenizePythonSource,
  weavePythonDecoyCalls,
  type PythonPrologueScan,
  type PythonToken,
} from "./python-ast-weave.js";
import { weavePythonPycBuffer } from "./python-pyc-weave.js";
import { SELF_DIGEST_PLACEHOLDER } from "../runtime/self-seal.js";

export { InvalidPythonSourceError };

export interface PythonPycInspectionSummary {
  readonly validPyc: boolean;
  readonly magicNumber: number;
  readonly pep552Flags: number;
  readonly extractedStrings: readonly string[];
  readonly blaProtected: boolean;
}

export interface PythonPrologueAnalysis {
  /**
   * Where a module-level block can be inserted: a logical-line boundary after
   * the module docstring and every `from __future__ import`. It indexes the
   * `source` that was passed in (string index, or byte offset for bytes).
   */
  readonly insertOffset: number;
  readonly hasDocstring: boolean;
  readonly futureImports: readonly string[];
}

// ---------------------------------------------------------------------------
// Source encoding (PEP 263)
// ---------------------------------------------------------------------------
//
// CPython decodes a module with the encoding it declares (UTF-8 BOM, else a
// `coding[:=]` comment on line 1 or 2, else UTF-8) and only then tokenises it.
// The shield has to read the file the same way: reading a Latin-1 or GBK file
// as UTF-8 replaces every non-ASCII byte and silently changes the program's
// strings. Hardened output is always written as UTF-8, so a non-UTF-8
// declaration is rewritten to `utf-8` — the declared encoding always matches
// the bytes on disk.
//
// A file is hardened only when it can be decoded exactly as CPython decodes
// it; anything else (unknown codec, bytes invalid in the declared codec, a
// decoder that does not match CPython's table) is refused with an error.

interface MultiByteCodecSpec {
  /** WHATWG label of the `TextDecoder` that supplies the character table. */
  readonly label: string;
  /** Whether bytes 0x80..0xFF can be complete one-byte characters. */
  readonly singles: boolean;
  readonly leads: readonly (readonly [number, number])[];
  readonly trails: readonly (readonly [number, number])[];
  /** Lead byte of three-byte characters (EUC-JP's JIS X 0212 plane). */
  readonly triple: number | null;
  /**
   * Run lengths over the codec's units in enumeration order, alternating
   * "CPython rejects" / "CPython accepts" and starting with a rejected run.
   */
  readonly runs: string;
  /** Units CPython maps differently from the WHATWG table: hex bytes → code point. */
  readonly fix: Readonly<Record<string, number>>;
  /** SHA-256 over CPython's characters for the accepted units (UTF-16LE). */
  readonly sha256: string;
}

interface PythonSourceCodecData {
  /** Charmap codecs: 128 characters for bytes 0x80..0xFF, U+FFFF = undefined. */
  readonly single: ReadonlyMap<string, string>;
  readonly multi: ReadonlyMap<string, MultiByteCodecSpec>;
  /** ASCII-compatible codecs without a decoder here: pure-ASCII files only. */
  readonly asciiOnly: ReadonlySet<string>;
  /** CPython alias → codec name (`encodings.aliases`). */
  readonly alias: ReadonlyMap<string, string>;
}

type PythonSourceCodec =
  | { readonly kind: "utf-8" | "ascii" | "latin-1" | "ascii-only"; readonly name: string }
  | { readonly kind: "single"; readonly name: string; readonly table: string }
  | { readonly kind: "multi"; readonly name: string; readonly spec: MultiByteCodecSpec };

interface LoadedPythonSource {
  /**
   * The module text exactly as CPython reads it, except that a non-UTF-8
   * coding declaration now names `utf-8` (what the output is written in).
   */
  readonly text: string;
  /** Encoding the source declared, in CPython's codec spelling. */
  readonly encoding: string;
}

const UNDEFINED_CHARMAP_UNIT = 0xffff;
const UTF8_CODEC: PythonSourceCodec = { kind: "utf-8", name: "utf-8" };
const LATIN1_CODEC: PythonSourceCodec = { kind: "latin-1", name: "latin-1" };
const ASCII_CODEC: PythonSourceCodec = { kind: "ascii", name: "ascii" };

let codecDataCache: PythonSourceCodecData | undefined;

function pythonSourceCodecData(): PythonSourceCodecData {
  if (!codecDataCache) {
    const raw = JSON.parse(
      inflateRawSync(Buffer.from(PYTHON_SOURCE_CODEC_DATA, "base64")).toString("utf8"),
    ) as {
      single: Record<string, string>;
      multi: Record<string, MultiByteCodecSpec>;
      pass: string[];
      alias: Record<string, string>;
    };
    codecDataCache = {
      single: new Map(Object.entries(raw.single)),
      multi: new Map(Object.entries(raw.multi)),
      asciiOnly: new Set(raw.pass),
      alias: new Map(Object.entries(raw.alias)),
    };
  }
  return codecDataCache;
}

/**
 * Resolve the codec named by a coding declaration the way CPython does:
 * the tokenizer's own short list for UTF-8 / Latin-1 spellings first, then
 * the codec registry's normalisation and alias table. `null` = unknown here.
 */
function resolvePythonSourceCodec(declared: string): PythonSourceCodec | null {
  const normal = declared.slice(0, 12).toLowerCase().replace(/_/g, "-");
  if (normal === "utf-8" || normal.startsWith("utf-8-")) return UTF8_CODEC;
  for (const spelling of ["latin-1", "iso-8859-1", "iso-latin-1"]) {
    if (normal === spelling || normal.startsWith(`${spelling}-`)) return LATIN1_CODEC;
  }
  const data = pythonSourceCodecData();
  const key = declared
    .toLowerCase()
    .replace(/[^a-z0-9.]+/g, "_")
    .replace(/^_+|_+$/g, "");
  const name = data.alias.get(key) ?? data.alias.get(key.replace(/\./g, "_")) ?? key;
  if (name === "utf_8") return UTF8_CODEC;
  if (name === "latin_1") return LATIN1_CODEC;
  if (name === "ascii") return ASCII_CODEC;
  const table = data.single.get(name);
  if (table !== undefined) return { kind: "single", name, table };
  const spec = data.multi.get(name);
  if (spec !== undefined) return { kind: "multi", name, spec };
  if (data.asciiOnly.has(name)) return { kind: "ascii-only", name };
  return null;
}

interface CodingDeclaration {
  /** Codec name exactly as written. */
  readonly name: string;
  /** Span of the name in the scanned text. */
  readonly start: number;
  readonly end: number;
}

/**
 * Find the PEP 263 declaration: a comment on the first line, or on the second
 * when the first is blank or a comment. The declaration is ASCII, so `text`
 * may be decoded source or a one-character-per-byte view of the raw bytes.
 */
function findCodingDeclaration(text: string, from: number): CodingDeclaration | null {
  let lineStart = from;
  for (let lineNumber = 1; lineNumber <= 2; lineNumber++) {
    let lineEnd = lineStart;
    while (lineEnd < text.length) {
      const c = text.charCodeAt(lineEnd);
      if (c === 10 || c === 13) break;
      lineEnd += 1;
    }
    const line = text.slice(lineStart, lineEnd);
    const match = /^[ \t\f]*#[\s\S]*?coding[:=][ \t]*([-\w.]+)/.exec(line);
    if (match) {
      const end = lineStart + match[0].length;
      return { name: match[1]!, start: end - match[1]!.length, end };
    }
    if (!/^[ \t\f]*(?:#|$)/.test(line) || lineEnd >= text.length) return null;
    lineStart =
      lineEnd + (text.charCodeAt(lineEnd) === 13 && text.charCodeAt(lineEnd + 1) === 10 ? 2 : 1);
  }
  return null;
}

function unsupportedEncoding(declared: string): InvalidPythonSourceError {
  return new InvalidPythonSourceError(
    `Python source declares encoding "${declared}", which the shield cannot decode exactly as ` +
      "CPython does. Re-save the file as UTF-8 (and update or remove its coding declaration) before hardening.",
  );
}

function undecodableByte(codec: string, offset: number): InvalidPythonSourceError {
  return new InvalidPythonSourceError(
    `Python source declares encoding "${codec}" but the bytes at offset ${offset} are not valid in it`,
  );
}

function latin1Text(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("latin1");
}

function firstNonAsciiByte(bytes: Uint8Array): number {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i]! >= 0x80) return i;
  }
  return -1;
}

function decodeUtf8Strict(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new InvalidPythonSourceError(
      "Python source is not valid UTF-8 and declares no other encoding",
    );
  }
}

function decodeCharmap(bytes: Uint8Array, name: string, table: string): string {
  const units = new Uint16Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]!;
    if (byte < 0x80) {
      units[i] = byte;
      continue;
    }
    const unit = table.charCodeAt(byte - 0x80);
    if (unit === UNDEFINED_CHARMAP_UNIT) throw undecodableByte(name, i);
    units[i] = unit;
  }
  let text = "";
  for (let i = 0; i < units.length; i += 0x2000) {
    text += String.fromCharCode(...units.subarray(i, i + 0x2000));
  }
  return text;
}

const multiByteTables = new Map<string, ReadonlyMap<number, string>>();

function multiByteKey(unit: readonly number[]): number {
  if (unit.length === 1) return unit[0]!;
  if (unit.length === 2) return 0x10000 | (unit[0]! << 8) | unit[1]!;
  return 0x1000000 + ((unit[0]! << 16) | (unit[1]! << 8) | unit[2]!);
}

/**
 * Character table of a multi-byte codec: every unit CPython accepts → its
 * character. The characters come from this runtime's `TextDecoder` (plus the
 * few recorded CPython differences); the table is used only if it hashes to
 * CPython's table, because legacy decoder tables vary between runtimes.
 */
function multiByteTable(name: string, spec: MultiByteCodecSpec): ReadonlyMap<number, string> {
  const cached = multiByteTables.get(name);
  if (cached) return cached;

  const runs = spec.runs.split(",").map(Number);
  let runIndex = 0;
  let runLeft = runs[0] ?? 0;
  let accepted = false;
  const keys: number[] = [];
  const stream: number[] = [];
  const visit = (unit: readonly number[]): void => {
    while (runLeft === 0 && runIndex < runs.length - 1) {
      runIndex += 1;
      runLeft = runs[runIndex]!;
      accepted = !accepted;
    }
    runLeft -= 1;
    if (!accepted) return;
    keys.push(multiByteKey(unit));
    stream.push(...unit, 0x0a);
  };
  if (spec.singles) {
    for (let b = 0x80; b <= 0xff; b++) visit([b]);
  }
  for (const [leadLow, leadHigh] of spec.leads) {
    for (let lead = leadLow; lead <= leadHigh; lead++) {
      for (const [trailLow, trailHigh] of spec.trails) {
        for (let trail = trailLow; trail <= trailHigh; trail++) visit([lead, trail]);
      }
    }
  }
  if (spec.triple !== null) {
    for (let b = 0xa1; b <= 0xfe; b++) {
      for (let c = 0xa1; c <= 0xfe; c++) visit([spec.triple, b, c]);
    }
  }

  const mismatch = new InvalidPythonSourceError(
    `Python source declares encoding "${name}", but this Node.js runtime's "${spec.label}" decoder ` +
      "does not reproduce CPython's table for it. Re-save the file as UTF-8 before hardening.",
  );
  let decoded: string[];
  try {
    // One unit per line: an ASCII line break is never part of a multi-byte unit.
    decoded = new TextDecoder(spec.label).decode(Uint8Array.from(stream)).split("\n");
  } catch {
    throw mismatch;
  }
  if (decoded.length !== keys.length + 1) throw mismatch;
  const fixes = new Map<number, string>();
  for (const [hex, codePoint] of Object.entries(spec.fix)) {
    fixes.set(multiByteKey([...Buffer.from(hex, "hex")]), String.fromCharCode(codePoint));
  }
  const table = new Map<number, string>();
  let characters = "";
  for (let i = 0; i < keys.length; i++) {
    const character = fixes.get(keys[i]!) ?? decoded[i]!;
    if (character.length !== 1) throw mismatch;
    table.set(keys[i]!, character);
    characters += character;
  }
  const digest = createHash("sha256").update(Buffer.from(characters, "utf16le")).digest("hex");
  if (digest !== spec.sha256) throw mismatch;

  multiByteTables.set(name, table);
  return table;
}

function decodeMultiByte(bytes: Uint8Array, name: string, spec: MultiByteCodecSpec): string {
  const table = multiByteTable(name, spec);
  const parts: string[] = [];
  const length = bytes.length;
  let i = 0;
  while (i < length) {
    const byte = bytes[i]!;
    if (byte < 0x80) {
      let end = i + 1;
      while (end < length && bytes[end]! < 0x80) end += 1;
      parts.push(latin1Text(bytes.subarray(i, end)));
      i = end;
      continue;
    }
    // CPython picks the unit length from the first byte alone.
    let width = 1;
    let character = spec.singles ? table.get(byte) : undefined;
    if (character === undefined) {
      width = byte === spec.triple ? 3 : 2;
      if (i + width <= length) {
        character = table.get(multiByteKey([...bytes.subarray(i, i + width)]));
      }
    }
    if (character === undefined) throw undecodableByte(name, i);
    parts.push(character);
    i += width;
  }
  return parts.join("");
}

function decodeWithCodec(bytes: Uint8Array, codec: PythonSourceCodec, declared: string): string {
  switch (codec.kind) {
    case "utf-8":
      return decodeUtf8Strict(bytes);
    case "latin-1":
      return latin1Text(bytes);
    case "ascii": {
      const bad = firstNonAsciiByte(bytes);
      if (bad >= 0) throw undecodableByte(codec.name, bad);
      return latin1Text(bytes);
    }
    case "ascii-only":
      // ASCII bytes mean ASCII in this codec; anything else needs its real table.
      if (firstNonAsciiByte(bytes) >= 0) throw unsupportedEncoding(declared);
      return latin1Text(bytes);
    case "single":
      return decodeCharmap(bytes, codec.name, codec.table);
    case "multi":
      return decodeMultiByte(bytes, codec.name, codec.spec);
  }
}

/** Decode raw module bytes as CPython would, declaring UTF-8 in the result. */
function decodePythonSourceBytes(bytes: Uint8Array): LoadedPythonSource {
  const hasBom =
    bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
  // Only the first two lines can hold the declaration.
  let headEnd = hasBom ? 3 : 0;
  for (let lineBreaks = 0; headEnd < bytes.length && lineBreaks < 2; headEnd++) {
    const byte = bytes[headEnd]!;
    if (byte === 10 || (byte === 13 && bytes[headEnd + 1] !== 10)) lineBreaks += 1;
  }
  const declaration = findCodingDeclaration(latin1Text(bytes.subarray(0, headEnd)), hasBom ? 3 : 0);
  if (!declaration) return { text: decodeUtf8Strict(bytes), encoding: "utf-8" };

  const codec = resolvePythonSourceCodec(declaration.name);
  if (!codec) throw unsupportedEncoding(declaration.name);
  if (codec.kind === "utf-8") return { text: decodeUtf8Strict(bytes), encoding: "utf-8" };
  if (hasBom) {
    throw new InvalidPythonSourceError(
      `Python source starts with a UTF-8 BOM but declares encoding "${declaration.name}"`,
    );
  }
  // The declaration is ASCII and starts on a character boundary, so it can be
  // renamed in the bytes before they are decoded with the original codec.
  const redeclared = Buffer.concat([
    bytes.subarray(0, declaration.start),
    Buffer.from("utf-8", "ascii"),
    bytes.subarray(declaration.end),
  ]);
  return { text: decodeWithCodec(redeclared, codec, declaration.name), encoding: codec.name };
}

const LONE_SURROGATE_RE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Load module source for hardening.
 *
 * Bytes are decoded with the encoding the module declares. A string is taken
 * to be the file read as UTF-8 (what the engine passes): it is already right
 * unless the module declares another encoding — then the original bytes are
 * recovered from it when that is lossless, and the file is refused when the
 * UTF-8 read already destroyed them (U+FFFD).
 */
function loadPythonSource(source: string | Uint8Array): LoadedPythonSource {
  if (typeof source !== "string") return decodePythonSourceBytes(source);

  const hasBom = source.charCodeAt(0) === 0xfeff;
  const declaration = findCodingDeclaration(source, hasBom ? 1 : 0);
  if (!declaration) return { text: source, encoding: "utf-8" };
  const codec = resolvePythonSourceCodec(declaration.name);
  if (!codec) throw unsupportedEncoding(declaration.name);
  if (codec.kind === "utf-8") return { text: source, encoding: "utf-8" };
  if (hasBom) {
    throw new InvalidPythonSourceError(
      `Python source starts with a UTF-8 BOM but declares encoding "${declaration.name}"`,
    );
  }
  if (source.includes("\uFFFD") || LONE_SURROGATE_RE.test(source)) {
    throw new InvalidPythonSourceError(
      `Python source declares encoding "${declaration.name}", but it was read as UTF-8 text and the ` +
        "bytes that are not valid UTF-8 are already lost. Hardening it would corrupt its strings. " +
        "Pass the raw file bytes to the shield, or re-save the file as UTF-8 " +
        "(and update or remove its coding declaration).",
    );
  }
  return decodePythonSourceBytes(Buffer.from(source, "utf8"));
}

/**
 * Translate a line-boundary offset in decoded text to the caller's own
 * `source`. Line breaks are single ASCII bytes in every supported encoding,
 * so the n-th line break is the same place in both.
 */
function mapLineBoundaryOffset(
  text: string,
  offset: number,
  source: string | Uint8Array,
): number {
  if (offset >= text.length) return source.length;
  let lineBreaks = 0;
  for (let i = 0; i < offset; i++) {
    const c = text.charCodeAt(i);
    if (c === 10 || c === 13) lineBreaks += 1;
  }
  const unitAt = (i: number): number =>
    typeof source === "string" ? source.charCodeAt(i) : source[i]!;
  if (lineBreaks === 0) {
    // Start of the file, or just past a BOM (one character, three bytes).
    return offset === 0 || typeof source === "string" ? offset : 3;
  }
  for (let i = 0; i < source.length; i++) {
    const c = unitAt(i);
    if ((c === 10 || c === 13) && --lineBreaks === 0) return i + 1;
  }
  return source.length;
}

function scanPrologueOf(text: string): {
  readonly tokens: PythonToken[];
  readonly prologue: PythonPrologueScan;
} {
  const tokens = tokenizePythonSource(text);
  return { tokens, prologue: scanPythonPrologue(text, splitPythonLogicalLines(tokens)) };
}

/**
 * Lexically analyzes a Python module to find the exact safe insertion offset
 * strictly AFTER:
 * 1. UTF-8 BOM, shebang (`#!`), and PEP 263 encoding comments
 * 2. The optional module docstring (preserving `module.__doc__`), in any form
 *    the compiler accepts (implicit concatenation, parentheses, continuation)
 * 3. All `from __future__ import ...` statements (single-line, parenthesized multi-line, or backslash-continued)
 *
 * The offset is always a logical-line boundary: a docstring or future import
 * that shares its line with further `; statements` keeps them in front of it.
 *
 * `source` is the module's raw bytes, or its text when the file is UTF-8.
 * Throws {@link InvalidPythonSourceError} for source that cannot be tokenised,
 * has a misplaced `from __future__` import, or cannot be decoded faithfully.
 */
export function findPythonPrologueInsertionOffset(
  source: string | Uint8Array,
): PythonPrologueAnalysis {
  const loaded = loadPythonSource(source);
  const { prologue } = scanPrologueOf(loaded.text);
  return {
    insertOffset:
      loaded.text === source
        ? prologue.insertOffset
        : mapLineBoundaryOffset(loaded.text, prologue.insertOffset, source),
    hasDocstring: prologue.hasDocstring,
    futureImports: prologue.futureImports,
  };
}

// ---------------------------------------------------------------------------
// Injected module preamble
// ---------------------------------------------------------------------------

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
 * Public names of the `builtins` module (CPython 3.9 – 3.14). The injected
 * preamble must not reach any of them by bare name: a module may bind its own
 * `len`, `range`, `hash`, `print`, … and the preamble shares its namespace
 * (most visibly on `importlib.reload()`, when those bindings already exist).
 * `super` is left out — its zero-argument form only works as a bare name.
 */
const PYTHON_BUILTIN_NAMES: ReadonlySet<string> = new Set(
  (
    "ArithmeticError AssertionError AttributeError BaseException BaseExceptionGroup BlockingIOError " +
    "BrokenPipeError BufferError BytesWarning ChildProcessError ConnectionAbortedError ConnectionError " +
    "ConnectionRefusedError ConnectionResetError DeprecationWarning EOFError Ellipsis EncodingWarning " +
    "EnvironmentError Exception ExceptionGroup FileExistsError FileNotFoundError FloatingPointError " +
    "FutureWarning GeneratorExit IOError ImportError ImportWarning IndentationError IndexError " +
    "InterruptedError IsADirectoryError KeyError KeyboardInterrupt LookupError MemoryError " +
    "ModuleNotFoundError NameError NotADirectoryError NotImplemented NotImplementedError OSError " +
    "OverflowError PendingDeprecationWarning PermissionError ProcessLookupError PythonFinalizationError " +
    "RecursionError ReferenceError ResourceWarning RuntimeError RuntimeWarning StopAsyncIteration " +
    "StopIteration SyntaxError SyntaxWarning SystemError SystemExit TabError TimeoutError TypeError " +
    "UnboundLocalError UnicodeDecodeError UnicodeEncodeError UnicodeError UnicodeTranslateError " +
    "UnicodeWarning UserWarning ValueError Warning WindowsError ZeroDivisionError abs aiter all anext any " +
    "ascii bin bool breakpoint bytearray bytes callable chr classmethod compile complex copyright " +
    "credits delattr dict dir divmod enumerate eval exec exit filter float format frozenset getattr " +
    "globals hasattr hash help hex id input int isinstance issubclass iter len license list locals map " +
    "max memoryview min next object oct open ord pow print property quit range repr reversed round set " +
    "setattr slice sorted staticmethod str sum tuple type vars zip"
  ).split(" "),
);

const PYTHON_KEYWORDS: ReadonlySet<string> = new Set(
  (
    "False None True and as assert async await break class continue def del elif else except finally " +
    "for from global if import in is lambda nonlocal not or pass raise return try while with yield"
  ).split(" "),
);

function isNameToken(token: PythonToken | undefined, text: string): boolean {
  return token !== undefined && token.kind === "name" && token.text === text;
}

function isOpToken(token: PythonToken | undefined, text: string): boolean {
  return token !== undefined && token.kind === "op" && token.text === text;
}

/**
 * Tokens of one logical line that sit in annotation position: parameter and
 * return annotations of a `def`, and the annotation of `name: annotation = …`.
 * A name there is only looked up, never called, and the auditor recognises
 * tarpit decoys by their `(seed: int = 0, depth: int = 0)` signature — so
 * annotations are the one place injected code keeps a bare builtin name.
 */
function annotationTokens(line: readonly PythonToken[]): Set<PythonToken> {
  const found = new Set<PythonToken>();
  const defAt = isNameToken(line[0], "async") ? 1 : 0;
  if (isNameToken(line[defAt], "def")) {
    let k = defAt + 2;
    if (!isOpToken(line[k], "(")) return found;
    const outer = line[k]!.depth;
    let slot: "name" | "annotation" | "default" = "name";
    for (k += 1; k < line.length; k++) {
      const token = line[k]!;
      if (isOpToken(token, ")") && token.depth === outer) break;
      if (token.kind === "op" && token.depth === outer + 1) {
        if (token.text === ",") {
          slot = "name";
          continue;
        }
        if (token.text === ":" && slot === "name") {
          slot = "annotation";
          continue;
        }
        if (token.text === "=" && slot !== "default") {
          slot = "default";
          continue;
        }
      }
      if (slot === "annotation") found.add(token);
    }
    if (isOpToken(line[k + 1], "->")) {
      for (let m = k + 2; m < line.length; m++) {
        const token = line[m]!;
        if (isOpToken(token, ":") && token.depth === outer) break;
        found.add(token);
      }
    }
    return found;
  }
  const target = line[0];
  if (
    target !== undefined &&
    target.kind === "name" &&
    !PYTHON_KEYWORDS.has(target.text) &&
    isOpToken(line[1], ":") &&
    line[1]!.depth === 0
  ) {
    for (let k = 2; k < line.length; k++) {
      const token = line[k]!;
      if (isOpToken(token, "=") && token.depth === 0) break;
      found.add(token);
    }
  }
  return found;
}

function pythonUnicodeEscape(codePoint: number): string {
  return codePoint > 0xffff
    ? `\\U${codePoint.toString(16).padStart(8, "0")}`
    : `\\u${codePoint.toString(16).padStart(4, "0")}`;
}

/** Re-spell a plain `str` literal with every non-ASCII character escaped. */
function asciiPythonStringLiteral(literal: string, prefixLength: number): string {
  const quote = literal.charAt(prefixLength);
  const quoteLength = literal.startsWith(quote.repeat(3), prefixLength) && literal.length >= prefixLength + 6 ? 3 : 1;
  const bodyStart = prefixLength + quoteLength;
  const bodyEnd = literal.length - quoteLength;
  let out = literal.slice(0, bodyStart);
  let i = bodyStart;
  while (i < bodyEnd) {
    const codePoint = literal.codePointAt(i)!;
    if (codePoint === 0x5c && i + 1 < bodyEnd) {
      const escaped = literal.codePointAt(i + 1)!;
      if (escaped >= 0x80) {
        // `\é` is not an escape sequence: the value keeps both characters.
        out += `\\\\${pythonUnicodeEscape(escaped)}`;
      } else {
        out += literal.slice(i, i + 2);
      }
      i += 1 + (escaped > 0xffff ? 2 : 1);
      continue;
    }
    out += codePoint < 0x80 ? literal.charAt(i) : pythonUnicodeEscape(codePoint);
    i += codePoint > 0xffff ? 2 : 1;
  }
  return out + literal.slice(bodyEnd);
}

function templateDrift(detail: string): Error {
  return new Error(
    `Python shield preamble: ${detail}. The preamble generator emitted something the ` +
      "isolation pass cannot make independent of the customer's module namespace.",
  );
}

/**
 * Make generated module-level Python safe to share a namespace — and a file —
 * with customer code:
 *
 * - every builtin it calls or dereferences (`len(…)`, `int.from_bytes`,
 *   `except Exception`) is reached through `builtinsAlias`, a private name
 *   bound to the real `builtins` module, so a customer `def len(…)` /
 *   `hash = …` cannot be picked up instead;
 * - the text is pure ASCII (non-ASCII characters in string literals become
 *   `\u` escapes with the same value), so it reads the same under any
 *   ASCII-compatible source encoding.
 *
 * A builtin name in any position this pass does not recognise is an error
 * rather than a guess.
 */
function isolateInjectedPythonCode(code: string, builtinsAlias: string): string {
  const tokens = tokenizePythonSource(code);
  const qualify = new Set<PythonToken>();
  for (const { tokens: line } of splitPythonLogicalLines(tokens)) {
    const annotations = annotationTokens(line);
    const isImport = isNameToken(line[0], "import") || isNameToken(line[0], "from");
    let exceptHeader = isNameToken(line[0], "except");
    for (let k = 0; k < line.length; k++) {
      const token = line[k]!;
      if (k > 0 && exceptHeader && (isNameToken(token, "as") || (isOpToken(token, ":") && token.depth === 0))) {
        exceptHeader = false;
      }
      if (token.kind !== "name" || !PYTHON_BUILTIN_NAMES.has(token.text)) continue;
      const previous = line[k - 1];
      const next = line[k + 1];
      if (isOpToken(previous, ".") || annotations.has(token)) continue;
      const isDefinition = isNameToken(previous, "def") || isNameToken(previous, "class");
      const isLoad = isOpToken(next, "(") || isOpToken(next, ".") || (exceptHeader && k > 0);
      if (isImport || isDefinition || !isLoad) {
        throw templateDrift(`builtin name '${token.text}' is used in an unrecognised position`);
      }
      qualify.add(token);
    }
  }

  let out = "";
  let cursor = 0;
  for (const token of tokens) {
    if (token.kind === "newline") continue;
    out += code.slice(cursor, token.start);
    cursor = token.end;
    const text = code.slice(token.start, token.end);
    if (qualify.has(token)) {
      out += `${builtinsAlias}.${text}`;
    } else if (/^[\x00-\x7f]*$/.test(text)) {
      out += text;
    } else if (token.kind === "comment") {
      out += [...text].map((ch) => (ch.codePointAt(0)! < 0x80 ? ch : pythonUnicodeEscape(ch.codePointAt(0)!))).join("");
    } else if (token.kind === "string" && (token.text === "" || token.text === "u")) {
      out += asciiPythonStringLiteral(text, token.text.length);
    } else {
      throw templateDrift("non-ASCII text outside a plain string literal or comment");
    }
  }
  return out + code.slice(cursor);
}

/**
 * Protects a Python `.py` source file by injecting an interconnected Python
 * Algorithmic Tarpit (`generatePythonTarpit`), opaque predicates, and
 * honey-docstrings while preserving shebangs, PEP 263 encoding headers,
 * module docstrings (`__doc__`), and complete `from __future__` imports.
 *
 * `source` is the module's raw bytes (decoded with the encoding the module
 * declares) or its text when the file is UTF-8. The result is always meant to
 * be written as UTF-8; a non-UTF-8 coding declaration is rewritten to match.
 *
 * What the injected code may touch in the customer's module:
 * - it binds only generated names — the tarpit's own and private
 *   (`_`-prefixed) ones that do not occur in the customer source. It never
 *   binds `_` or any other conventional name;
 * - it resolves no name the customer can rebind: builtins are reached through
 *   a private alias of the `builtins` module (annotations excepted, see
 *   `annotationTokens`), so the preamble also survives `importlib.reload()`
 *   of a module that defines its own `range`, `len`, `hash`, …;
 * - it is inserted at a logical-line boundary after the docstring and future
 *   imports, and is pure ASCII.
 *
 * Honesty limits: this shields the `.py` / `.pyc` bytes BLA sees. A later
 * PyInstaller onefile (or similar) pack is still peelable to the embedded
 * archive — harden sources *before* bundling; BLA will not rewrite a
 * PyInstaller CArchive in place (see `detectNativeEofAppendHazard`).
 */
export function protectPythonSource(
  source: string | Uint8Array,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
    /**
     * When true, structurally weave decoy entanglement into customer `def` bodies
     * (shared-slot touch + opaque-false calls). When false, preserve warm-init-only.
     */
    readonly weaveDecoys?: boolean;
    /**
     * When true, embed a canonical SHA-256 self-digest verification block that
     * fails closed (`RuntimeError("integrity check failed")`) if the module's
     * own bytes on disk are altered after hardening.
     */
    readonly selfSeal?: boolean;
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
  /** Encoding the source declared (CPython codec spelling); `code` is UTF-8 text. */
  readonly sourceEncoding: string;
} {
  const intensity = options.intensity ?? "balanced";
  const weaveDecoys = options.weaveDecoys === true;
  const loaded = loadPythonSource(source);
  const text = loaded.text;
  const { tokens: customerTokens, prologue } = scanPrologueOf(text);

  // Derive a per-file PRNG seed from `(options.seed, sha256(text))` — mirrors
  // JS `ast-shield.ts` so sibling `.py` modules never share identical decoy
  // preambles that can be stripped with a 2-file `diff`, while staying 100%
  // deterministic for the same file and seed.
  const contentHash = createHash("sha256").update(text).digest("hex").slice(0, 16);
  const prng = new SeededPrng(`${options.seed ?? "bla-python-shield-v1"}:${contentHash}`);
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const tarpit = generatePythonTarpit(prng, intensity, chaffPayloads);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const eol = text.includes("\r\n") ? "\r\n" : "\n";

  const headRaw = text.slice(0, prologue.insertOffset);
  const tailRaw = text.slice(prologue.insertOffset);

  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "").replace(/(?:\r?\n)+$/, "");

  // Module-level names for everything injected besides the tarpit: private,
  // drawn from an independent substream (the tarpit / weave draws stay as they
  // were), and never a name that occurs in the customer source or the tarpit.
  const taken = collectPythonIdentifiers(customerTokens);
  for (const name of collectPythonIdentifiers(tokenizePythonSource(tarpit.code))) {
    taken.add(name);
  }
  const naming = prng.derive("python-shield-private-names");
  const builtinsAlias = drawPrivatePythonName(naming, taken);
  const constantName = (stem: string): string =>
    drawPrivatePythonName(naming, taken, { upper: true, suffix: stem });
  const canaryTokensName = constantName("CANARY_TOKENS");
  const ambiguousTransportName = constantName("AMBIGUOUS_TRANSPORT");
  const conflictingQueryName = constantName("CONFLICTING_QUERY");
  const systemDiagnosticsName = constantName("SYSTEM_DIAGNOSTICS");
  const canaryGuidName = constantName("ALIGNMENT_EVAL_CANARY_GUID");
  const armorCorpusName = constantName("COGNITIVE_ARMOR_CORPUS");
  const probeName = drawPrivatePythonName(naming, taken, { hint: "probe_canary_honeypot" });

  // Inert canary + diagnostic + cognitive-armor decoys below prologue/tarpit. Data only — never fetched.
  const cognitiveArmorStrings = deception.cognitiveArmor.triggersInjected.map(
    (t) => `${t.coupledAnchorSymbol}::${t.triggerPayload.replace(/\r?\n/g, " ")}`,
  );
  const selfSealFnName = options.selfSeal === true
    ? drawPrivatePythonName(naming, taken, { hint: "verify_module_digest" })
    : undefined;
  const selfSealBlock =
    selfSealFnName !== undefined
      ? [
          `def ${selfSealFnName}():`,
          `    self_expected = ${JSON.stringify(SELF_DIGEST_PLACEHOLDER)}`,
          `    _ph = "~self-digest-" + "pending-finalize" + ("~" * 35)`,
          `    if self_expected == _ph:`,
          `        return`,
          `    if len(self_expected) != 64 or any(c not in "0123456789abcdef" for c in self_expected):`,
          `        raise RuntimeError("integrity check failed")`,
          `    _fp = globals().get("__file__")`,
          `    if type(_fp) is not type("") or not _fp or _fp.endswith((".pyc", ".pyo")):`,
          `        return`,
          `    _sha256 = None`,
          `    try:`,
          `        _sha256 = getattr(__import__("_hashlib"), "openssl_sha256", None)`,
          `    except Exception:`,
          `        _sha256 = None`,
          `    if _sha256 is None:`,
          `        try:`,
          `            _sha256 = getattr(__import__("_sha256"), "sha256", None)`,
          `        except Exception:`,
          `            _sha256 = None`,
          `    if _sha256 is None:`,
          `        _sha256 = __import__("hashlib").sha256`,
          `    try:`,
          `        with open(_fp, "rb") as _fh:`,
          `            _raw = _fh.read()`,
          `    except Exception:`,
          `        raise RuntimeError("integrity check failed") from None`,
          `    _canon = _raw.replace(self_expected.encode("latin-1"), b"0" * 64)`,
          `    if _sha256(_canon).hexdigest() != self_expected:`,
          `        raise RuntimeError("integrity check failed")`,
          `${selfSealFnName}()`,
        ].join("\n")
      : "";

  const deceptionBlock = [
    `${canaryTokensName} = ${pythonStringTuple(deception.canary.syntheticCanaryTokens)}`,
    `${ambiguousTransportName} = ${pythonStringTuple(deception.canary.ambiguousCredentialUrls)}`,
    `${conflictingQueryName} = ${pythonStringTuple(deception.canary.conflictingQueryUrls)}`,
    `${systemDiagnosticsName} = ${pythonDiagnosticTuple(deception.diagnostics.diagnosticsInjected)}`,
    `${canaryGuidName} = ${pythonReprString(deception.cognitiveArmor.canaryGuid)}`,
    `${armorCorpusName} = ${pythonStringTuple(cognitiveArmorStrings)}`,
    `def ${probeName}(idx=0):`,
    `    _i = (idx & 0x7FFFFFFF) % len(${canaryTokensName})`,
    `    return ${ambiguousTransportName}[_i]`,
    // A bare call: the probe stays referenced without binding its result.
    `${probeName}(0)`,
  ].join("\n");

  const preamble = [
    `import builtins as ${builtinsAlias}`,
    isolateInjectedPythonCode(
      [
        ...(selfSealBlock ? [selfSealBlock] : []),
        tarpit.code.replace(/\n+$/, ""),
        deceptionBlock,
      ].join("\n\n"),
      builtinsAlias,
    ),
  ]
    .join("\n")
    .replace(/\r?\n/g, eol);

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
      probeName,
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
      builtinsAlias,
      prng,
      intensity,
    });
    customerTail = woven.code.replace(/(?:\r?\n)+$/, "");
    customerDefsWoven = woven.customerDefsWoven;
    crossReferenceEdges += woven.crossReferenceEdgesAdded;
  }

  const combined = [head, preamble, customerTail]
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
    sourceEncoding: loaded.encoding,
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

  const hasChaff =
    textView.includes("runtime attestation boundary") ||
    textView.includes("Architecture Notice: Core business logic") ||
    textView.includes("ENCLAVE_ATTESTATION_CONTRACT_") ||
    textView.includes("SYMBOL_OFFSET_MANIFEST_");
  const hasCanaryCred = textView.includes("PROTECTED_CANARY_CREDENTIAL=");
  const hasTransportEndpoint = textView.includes("TRANSPORT_ENDPOINT=");
  const hasDiagnosticRecord =
    /\[[A-Za-z0-9_]+Error\]\s*\([A-Z0-9_-]+\)/.test(textView) ||
    textView.includes("DarwinProcessOwnershipInspectionError");
  const indicatorCount = [
    hasChaff,
    hasCanaryCred,
    hasTransportEndpoint,
    hasDiagnosticRecord,
  ].filter(Boolean).length;

  return {
    validPyc: true,
    magicNumber,
    pep552Flags,
    extractedStrings: matches.slice(0, 64),
    blaProtected: bytes.length >= 128 && indicatorCount >= 3,
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

/**
 * Source-encoding tables for {@link decodePythonSourceBytes}, generated from
 * CPython 3.14's codecs (the `single` / `multi` tables are byte-identical in
 * CPython 3.9, 3.11, 3.12 and 3.13): base64 of raw-deflated JSON
 * `{ single, multi, pass, alias }` — see {@link PythonSourceCodecData}.
 * `tests/fuzz-regression-python.test.ts` re-derives every table from the local
 * CPython and compares it with what this module decodes.
 */
const PYTHON_SOURCE_CODEC_DATA = [
  "7XxrU+PImuZf2WE2dndmmbO2fJM7ZvfzftzYr+ecJYyxu+iiqggMe3rnTEfYYMAGczFgY+73+/0u2wUVIWV2dAS9QnJFFHbVF6E/",
  "oL8wb6YsLNmGorvpM3Uu0bRLma8sKZ988sn3zXzlPzaEWl9/3RZo+OqPDf52u83mbviqgQ/zEb6b7+GjfC/fx/fzMT7OD/CDfIIf",
  "4of5EX6UT/Jj/Dg/waf4ND/JZ/gpfpqf4Wf5OX6eX+AXPx1+Ovp0/Onk0+mns0/nny4+cZ+yxURxht8rLmi5iJYb0nLD9G9EyyW1",
  "vbS2l9Fy41oupeUmtb11bW9Ty01puRktN6flFrS9nLb3VsstabkVLbem5Ta03Ja2H9VyO1puT9tPaLkDbX9Ayx1puRMtd6blLrRc",
  "Vsvltdyllnun5SNavlfLx7X8gJYf1PIJLT+k5Ye1/IiWH9XySS0/ruVTWn5Sy09p+Rltf0zbn9Dyc1p+QcsvavklLb+i7c9r+TUt",
  "D7eGS8FN17X9TW0fHmNby4W1XFzLwQPAxY+0/LGWP9H2D7X9fS37VsteNjQScO2MC8CVRqWkNCaNSxNSSkpLk1JGmpKmpRlpVpqT",
  "5qUFaVFakpalFWlVWpPWpQ1pU9qStqUdaVfak/alA+lQOpKOpRPpVDqTzqULiZOyUk7KS2+lS+lKeqemk2p6TE2PqxPd6sSqmlpS",
  "U8tqKq2mUmpqRU0l1dSkmppTU7NqakadGFUnJtSJU3ViV52YVSfC6sRbNTWvphbU1LSamlBTW2pqXU0tqqlRNbWrpjbU1Kaagsuu",
  "qakpNZVRU2NqalxN7aipbXUio04k1HRMTUfVNByMqumwHJYjcrfcI0flXrlP7pdjclwekAflhDwkD8sjUkROFkYLSSkqT0h9clrq",
  "lyf5CzU2rUbT/KqaXuQXdfgYlw3gU7t3tXfv1PA0/ZxXw+tqeFENL9HiIYbDLJ7Gq/gSZ2lVRg1PqeFZNTynhpfV8LganiD10WW8",
  "pIZzeAav4Suc4xev+68zOMKvoii/zm/wm/wWnud3+F1+j9/Hef6QP7qewd38KX/Gn/MXPId68QKfR5fXc+gKv8UTQkToRt1CFGVR",
  "n9CPEkIcZYRBNC0MCcNoGI3iHtwvjAsTeFRIC5M4g/eFaXwozApzeFlYwClhSVhGPcIqyqF+YQMNCVtoSthBM8KesI9GUBJHcUw4",
  "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",
  "QBR6+ObX993w3Xf/Bg==",
].join("");
