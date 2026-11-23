import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export const REA_MAX_BINARY_PLIST_NESTING_DEPTH = 128;

type PlistOptions = { readonly intensity?: ProtectionIntensity; readonly seed?: string | number };
type PlistEntry = readonly [key: string, value: string | number];

interface PlistShieldStats {
  readonly decoyEnclaveEntitlementsAdded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly exceedsBinaryPlistNestingDepth: boolean;
}

export interface ApplePlistShieldResult extends PlistShieldStats {
  readonly xmlPlist: string;
  readonly triggersInternalSubsetBudgetAbort: boolean;
  /** Set when the document's root is not a dictionary, so no entitlement was planted. */
  readonly protectionSkipped?: string;
}

function buildPlistEntries(options: PlistOptions) {
  const prng = new SeededPrng(options.seed ?? "bla-apple-plist-v1");
  const tag = prng.hex(4);
  const { canary, diagnostics } = buildCanaryAndDiagnosticPayloads(prng, options.intensity ?? "balanced");
  const endpoints = canary.ambiguousCredentialUrls.slice(0, 4);
  const diagnosticEntries = diagnostics.diagnosticsInjected.slice(0, 4);
  const entries: PlistEntry[] = [
    ["BLAEnclaveAttestationAuthority", `com.apple.security.secure-enclave.ring0.${tag}`],
    ["BLAEnclaveVsockDelegationCID", 16],
    ...canary.syntheticCanaryTokens.map((token, i): PlistEntry => [`BLACanaryCredential_${i}`, token]),
    ...endpoints.map((url, i): PlistEntry => [`BLATransportEndpoint_${i}`, url]),
    ...diagnosticEntries.map((d, i): PlistEntry =>
      [`BLASystemDiagnostic_${i}`, `[${d.errorClass}] (${d.systemCode}) ${d.diagnosticMessage}`]),
  ];
  return {
    entries,
    stats: {
      decoyEnclaveEntitlementsAdded: entries.length,
      canaryTokensEmbedded: canary.syntheticCanaryTokens.length,
      diagnosticsEmbedded: diagnosticEntries.length,
      exceedsBinaryPlistNestingDepth: false,
    },
  };
}

const EMPTY_STATS: PlistShieldStats = {
  decoyEnclaveEntitlementsAdded: 0,
  canaryTokensEmbedded: 0,
  diagnosticsEmbedded: 0,
  exceedsBinaryPlistNestingDepth: false,
};

function reservePlistKey(key: string, keys: Set<string>): string {
  let candidate = key;
  for (let suffix = 1; keys.has(candidate); suffix++) candidate = `${key}_${suffix}`;
  keys.add(candidate);
  return candidate;
}

function escapeXml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const PLIST_DOCTYPE = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">';
// Treat comments, CDATA, processing instructions, and the entire DOCTYPE as single
// tokens so embedded markup cannot affect the element stack.
const XML_MARKUP = /<!--[^]*?-->|<!\[CDATA\[[^]*?\]\]>|<\?[^]*?\?>|<!DOCTYPE(?:<!--[^]*?-->|"[^"]*"|'[^']*'|\[(?:<!--[^]*?-->|"[^"]*"|'[^']*'|[^"'\]])*\]|[^>"'\[])*>|<\/?[A-Za-z_][\w:.-]*(?:"[^"]*"|'[^']*'|[^<>"'])*>/g;

function decodePlistXmlKey(text: string): string {
  return text.replace(/<!\[CDATA\[([^]*?)\]\]>|<!--[^]*?-->|<\?[^]*?\?>|&(#x[\da-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g,
    (_match, cdata: string | undefined, entity: string | undefined) => {
      if (cdata !== undefined) return cdata;
      if (entity === undefined) return "";
      const named: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
      if (!entity.startsWith("#")) return named[entity]!;
      const code = entity.startsWith("#x") ? Number.parseInt(entity.slice(2), 16) : Number(entity.slice(1));
      return code <= 0x10ffff ? String.fromCodePoint(code) : "";
    },
  );
}

export function protectAppleXmlPlist(rawXml: string, options: PlistOptions = {}): ApplePlistShieldResult {
  let xml = rawXml.replace(/^\uFEFF/, "").trim();
  const stack: string[] = [];
  const keys = new Set<string>();
  let sawPlist = false;
  let doctype: { start: number; end: number } | undefined;
  let rootDict: { start: number; end: number } | undefined;
  let keyStart = 0;
  for (const match of xml.matchAll(XML_MARKUP)) {
    const [tag] = match;
    const start = match.index;
    const end = start + tag.length;
    if (tag.startsWith("<!DOCTYPE")) {
      doctype = { start, end };
      continue;
    }
    const element = /^<(\/?)([\w:.-]+)/.exec(tag);
    if (!element) continue;
    const [, close, name] = element;
    const depth = stack.length;
    const inPlist = stack[0] === "plist";
    const inRootDict = inPlist && stack[1] === "dict";
    if (close) {
      if (stack.pop() !== name) throw new Error("Invalid XML Apple property list: mismatched elements");
      if (depth === 3 && inRootDict && name === "key") {
        keys.add(decodePlistXmlKey(xml.slice(keyStart, start)));
      }
      if (depth === 2 && inRootDict) rootDict = { start, end: start };
    } else {
      if (depth === 0 && name === "plist") sawPlist = true;
      if (depth === 2 && inRootDict && name === "key") keyStart = end;
      if (!tag.endsWith("/>")) stack.push(name!);
      else if (depth === 1 && inPlist && name === "dict") rootDict = { start, end };
    }
  }
  if (!sawPlist || stack.length !== 0) throw new Error("Invalid XML Apple property list: expected a complete <plist> document");

  let stats = EMPTY_STATS;
  if (rootDict) {
    const additions = buildPlistEntries(options);
    stats = additions.stats;
    const entries = additions.entries.map(([key, value]) => {
      const name = reservePlistKey(key, keys);
      const element = typeof value === "string" ? `<string>${escapeXml(value)}</string>` : `<integer>${value}</integer>`;
      return `  <key>${name}</key>\n  ${element}\n`;
    }).join("");
    const insert = rootDict.start === rootDict.end ? `\n${entries}` : `<dict>\n${entries}</dict>`;
    xml = xml.slice(0, rootDict.start) + insert + xml.slice(rootDict.end);
  }
  if (doctype) {
    xml = xml.slice(0, doctype.start) + PLIST_DOCTYPE + xml.slice(doctype.end);
  } else {
    const declarationEnd = xml.startsWith("<?xml") ? xml.indexOf("?>") + 2 : 0;
    xml = `${xml.slice(0, declarationEnd)}\n${PLIST_DOCTYPE}\n${xml.slice(declarationEnd)}`.trim();
  }
  return {
    xmlPlist: xml,
    triggersInternalSubsetBudgetAbort: false,
    ...stats,
    ...(rootDict ? {} : { protectionSkipped: "XML plist root element is not a <dict>" }),
  };
}

const BPLIST_HEADER = Buffer.from("bplist00", "ascii");
const BPLIST_TRAILER_BYTES = 32;

function invalidBinaryPlist(reason: string): never {
  throw new Error(`Invalid binary Apple property list: ${reason}`);
}

function readPlistUInt(bytes: Buffer, offset: number, width: number): number {
  if (width < 1 || width > 8 || offset < 0 || offset + width > bytes.length) {
    return invalidBinaryPlist("invalid integer bounds");
  }
  let value = 0;
  for (const byte of bytes.subarray(offset, offset + width)) value = value * 256 + byte;
  if (!Number.isSafeInteger(value)) return invalidBinaryPlist("integer exceeds supported range");
  return value;
}

function plistUIntWidth(value: number): number {
  if (value <= 0xff) return 1;
  if (value <= 0xffff) return 2;
  return value <= 0xffffffff ? 4 : 8;
}

function writePlistUInt(bytes: Buffer, value: number, offset: number, width: number): void {
  if (width === 8) bytes.writeBigUInt64BE(BigInt(value), offset);
  else bytes.writeUIntBE(value, offset, width);
}

function encodePlistInteger(value: number): Buffer {
  const width = plistUIntWidth(value);
  const encoded = Buffer.alloc(1 + width);
  encoded[0] = 0x10 | Math.log2(width);
  writePlistUInt(encoded, value, 1, width);
  return encoded;
}

function encodePlistSizedObject(type: number, size: number, data: Buffer): Buffer {
  return size < 15
    ? Buffer.concat([Buffer.from([type | size]), data])
    : Buffer.concat([Buffer.from([type | 15]), encodePlistInteger(size), data]);
}

function readPlistObjectSize(object: Buffer): { count: number; dataStart: number } {
  const count = object[0]! & 15;
  if (count < 15) return { count, dataStart: 1 };
  if (object.length < 2 || (object[1]! & 0xf0) !== 0x10) {
    return invalidBinaryPlist("missing object length");
  }
  const width = 2 ** (object[1]! & 15);
  return { count: readPlistUInt(object, 2, width), dataStart: 2 + width };
}

function readBplistReferences(object: Buffer, width: number, objectCount: number, dictionary: boolean): number[] {
  const { count, dataStart } = readPlistObjectSize(object);
  const references = count * (dictionary ? 2 : 1);
  if (references > (object.length - dataStart) / width) {
    return invalidBinaryPlist("truncated collection references");
  }
  return Array.from({ length: references }, (_, i) => {
    const ref = readPlistUInt(object, dataStart + i * width, width);
    if (ref >= objectCount) return invalidBinaryPlist("collection reference is out of bounds");
    return ref;
  });
}

function encodeBplistReferences(type: number, references: readonly number[], width: number): Buffer {
  const data = Buffer.alloc(references.length * width);
  references.forEach((ref, i) => writePlistUInt(data, ref, i * width, width));
  return encodePlistSizedObject(type, type === 0xd0 ? references.length / 2 : references.length, data);
}

function readBplistKey(object: Buffer): string {
  const type = object[0]! & 0xf0;
  const { count, dataStart } = readPlistObjectSize(object);
  const byteCount = type === 0x60 ? count * 2 : count;
  if (byteCount > object.length - dataStart) return invalidBinaryPlist("truncated dictionary key");
  const data = object.subarray(dataStart, dataStart + byteCount);
  if (type === 0x60) return Buffer.from(data).swap16().toString("utf16le");
  if (type === 0x50 || type === 0x70) return data.toString("utf8");
  return invalidBinaryPlist("dictionary key is not a string");
}

function encodeBplistString(value: string): Buffer {
  if (/^[\x00-\x7f]*$/.test(value)) {
    return encodePlistSizedObject(0x50, value.length, Buffer.from(value, "ascii"));
  }
  return encodePlistSizedObject(0x60, value.length, Buffer.from(value, "utf16le").swap16());
}

function protectBinaryPlist(
  input: Buffer,
  options: PlistOptions,
): { buffer: Buffer; stats: PlistShieldStats; protectionSkipped?: string } {
  const trailerStart = input.length - BPLIST_TRAILER_BYTES;
  if (trailerStart <= BPLIST_HEADER.length || !input.subarray(0, 8).equals(BPLIST_HEADER)) {
    return invalidBinaryPlist("expected bplist00 header, object table, and trailer");
  }
  const trailer = input.subarray(trailerStart);
  const offsetWidth = trailer[6]!;
  const refWidth = trailer[7]!;
  const count = readPlistUInt(trailer, 8, 8);
  const rootId = readPlistUInt(trailer, 16, 8);
  const offsetsStart = readPlistUInt(trailer, 24, 8);
  if (offsetWidth < 1 || offsetWidth > 8 || refWidth < 1 || refWidth > 8 ||
      count < 1 || rootId >= count || offsetsStart <= BPLIST_HEADER.length ||
      offsetsStart > trailerStart || count !== (trailerStart - offsetsStart) / offsetWidth ||
      count >= 256 ** refWidth || offsetsStart >= 256 ** offsetWidth) {
    return invalidBinaryPlist("invalid offset table or trailer");
  }
  const offsets = Array.from({ length: count }, (_, i) =>
    readPlistUInt(input, offsetsStart + i * offsetWidth, offsetWidth),
  );
  const sortedOffsets = [...offsets].sort((a, b) => a - b);
  if (sortedOffsets[0]! < 8 || sortedOffsets.at(-1)! >= offsetsStart) {
    return invalidBinaryPlist("object offset is out of bounds");
  }
  const ends = new Map<number, number>();
  sortedOffsets.forEach((offset, i) => {
    const next = sortedOffsets[i + 1] ?? offsetsStart;
    if (next === offset) return invalidBinaryPlist("duplicate object offsets");
    ends.set(offset, next);
  });
  const objects = offsets.map((offset) => input.subarray(offset, ends.get(offset)!));
  const root = objects[rootId]!;
  if ((root[0]! & 0xf0) !== 0xd0) {
    return {
      buffer: input,
      stats: EMPTY_STATS,
      protectionSkipped: "binary plist root object is not a dictionary",
    };
  }
  const rootReferences = readBplistReferences(root, refWidth, count, true);
  const oldCount = rootReferences.length / 2;
  const keyRefs = rootReferences.slice(0, oldCount);
  const valueRefs = rootReferences.slice(oldCount);
  const keys = new Set(keyRefs.map((ref) => readBplistKey(objects[ref]!)));

  const { entries, stats } = buildPlistEntries(options);
  const newRefWidth = Math.max(refWidth, plistUIntWidth(count + entries.length * 2));
  for (const [key, value] of entries) {
    keyRefs.push(objects.length);
    objects.push(encodeBplistString(reservePlistKey(key, keys)));
    valueRefs.push(objects.length);
    objects.push(typeof value === "string" ? encodeBplistString(value) : encodePlistInteger(value));
  }

  // Object IDs stay fixed. When the reference width grows, rewrite every
  // reference-bearing object and copy scalar encodings byte for byte.
  for (let i = 0; i < count; i++) {
    if (i === rootId) continue;
    const object = objects[i]!;
    const type = object[0]! & 0xf0;
    if (type >= 0xa0 && type <= 0xd0) {
      const refs = readBplistReferences(object, refWidth, count, type === 0xd0);
      if (newRefWidth !== refWidth) objects[i] = encodeBplistReferences(type, refs, newRefWidth);
    }
  }
  objects[rootId] = encodeBplistReferences(0xd0, [...keyRefs, ...valueRefs], newRefWidth);

  let tableStart = BPLIST_HEADER.length;
  const newOffsets = objects.map((object) => {
    const offset = tableStart;
    tableStart += object.length;
    return offset;
  });
  const newOffsetWidth = plistUIntWidth(tableStart);
  const table = Buffer.alloc(newOffsets.length * newOffsetWidth);
  newOffsets.forEach((offset, i) => writePlistUInt(table, offset, i * newOffsetWidth, newOffsetWidth));
  const newTrailer = Buffer.from(trailer);
  newTrailer[6] = newOffsetWidth;
  newTrailer[7] = newRefWidth;
  newTrailer.writeBigUInt64BE(BigInt(objects.length), 8);
  newTrailer.writeBigUInt64BE(BigInt(rootId), 16);
  newTrailer.writeBigUInt64BE(BigInt(tableStart), 24);
  return { buffer: Buffer.concat([BPLIST_HEADER, ...objects, table, newTrailer]), stats };
}

export function protectApplePlistBuffer(rawBuffer: Buffer, options: PlistOptions = {}): PlistShieldStats & {
  readonly buffer: Buffer;
  readonly triggersBudgetAbort: boolean;
  readonly protectionSkipped?: string;
} {
  if (rawBuffer.subarray(0, 6).toString("ascii") === "bplist") {
    const { buffer, stats, protectionSkipped } = protectBinaryPlist(rawBuffer, options);
    return {
      buffer,
      triggersBudgetAbort: false,
      ...stats,
      ...(protectionSkipped ? { protectionSkipped } : {}),
    };
  }
  const utf16BE = rawBuffer[0] === 0xfe && rawBuffer[1] === 0xff ||
    rawBuffer[0] === 0 && rawBuffer[1] === 0x3c;
  const utf16LE = rawBuffer[0] === 0xff && rawBuffer[1] === 0xfe ||
    rawBuffer[0] === 0x3c && rawBuffer[1] === 0;
  const encoding = utf16BE || utf16LE ? "utf16le" : "utf8";
  if (encoding === "utf16le" && rawBuffer.length % 2 !== 0) {
    throw new Error("Invalid XML Apple property list: truncated UTF-16 code unit");
  }
  const xml = (utf16BE ? Buffer.from(rawBuffer).swap16() : rawBuffer).toString(encoding);
  const { xmlPlist, triggersInternalSubsetBudgetAbort, ...stats } = protectAppleXmlPlist(xml, options);
  const encoded = Buffer.from(encoding === "utf16le" ? `\uFEFF${xmlPlist}` : xmlPlist, encoding);
  return { buffer: utf16BE ? encoded.swap16() : encoded, triggersBudgetAbort: triggersInternalSubsetBudgetAbort, ...stats };
}
