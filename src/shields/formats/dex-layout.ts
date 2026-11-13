/**
 * DEX layout parse / rebuild used by opt-in sidecarEntangle string-pool notes.
 *
 * The rewriter keeps existing string indices stable by appending an unreferenced
 * string that sorts last (UTF-16 code-unit order), copies instruction bodies
 * bit-exact, and only patches file-offset fields (u32 and class_data uleb
 * code_off). Header checksum (Adler32) and signature (SHA-1) are recomputed.
 *
 * Fail closed on an unsupported endian, header, or map type — never invent a
 * synthetic DEX. Defensive only; no crack / RE advice.
 */
import { createHash } from "node:crypto";

export const DEX_HEADER_SIZE = 0x70;
export const DEX_ENDIAN_LE = 0x1234_5678;
export const DEX_SIDECAR_STRING_KEY = "bla.sidecar.v1=" as const;

export const DEX_MAP_TYPE = Object.freeze({
  HEADER_ITEM: 0x0000,
  STRING_ID_ITEM: 0x0001,
  TYPE_ID_ITEM: 0x0002,
  PROTO_ID_ITEM: 0x0003,
  FIELD_ID_ITEM: 0x0004,
  METHOD_ID_ITEM: 0x0005,
  CLASS_DEF_ITEM: 0x0006,
  CALL_SITE_ID_ITEM: 0x0007,
  METHOD_HANDLE_ITEM: 0x0008,
  MAP_LIST: 0x1000,
  TYPE_LIST: 0x1001,
  ANNOTATION_SET_REF_LIST: 0x1002,
  ANNOTATION_SET_ITEM: 0x1003,
  CLASS_DATA_ITEM: 0x2000,
  CODE_ITEM: 0x2001,
  STRING_DATA_ITEM: 0x2002,
  DEBUG_INFO_ITEM: 0x2003,
  ANNOTATION_ITEM: 0x2004,
  ENCODED_ARRAY_ITEM: 0x2005,
  ANNOTATIONS_DIRECTORY_ITEM: 0x2006,
});

const ALIGN4_TYPES = new Set<number>([
  DEX_MAP_TYPE.TYPE_LIST,
  DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST,
  DEX_MAP_TYPE.ANNOTATION_SET_ITEM,
  DEX_MAP_TYPE.CODE_ITEM,
  DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM,
  DEX_MAP_TYPE.MAP_LIST,
]);

export interface DexMapItem {
  readonly type: number;
  readonly size: number;
  readonly offset: number;
}

export interface DexProtoId {
  readonly shortyIdx: number;
  readonly returnTypeIdx: number;
  readonly parametersOff: number;
}

export interface DexFieldId {
  readonly classIdx: number;
  readonly typeIdx: number;
  readonly nameIdx: number;
}

export interface DexMethodId {
  readonly classIdx: number;
  readonly protoIdx: number;
  readonly nameIdx: number;
}

export interface DexClassDef {
  readonly classIdx: number;
  readonly accessFlags: number;
  readonly superclassIdx: number;
  readonly interfacesOff: number;
  readonly sourceFileIdx: number;
  readonly annotationsOff: number;
  readonly classDataOff: number;
  readonly staticValuesOff: number;
}

export interface DexMethodHandle {
  readonly methodHandleType: number;
  readonly fieldOrMethodId: number;
}

export interface DexEncodedField {
  readonly idxDiff: number;
  readonly accessFlags: number;
}

export interface DexEncodedMethod {
  readonly idxDiff: number;
  readonly accessFlags: number;
  readonly codeOff: number;
}

export interface DexClassData {
  readonly offset: number;
  readonly staticFields: readonly DexEncodedField[];
  readonly instanceFields: readonly DexEncodedField[];
  readonly directMethods: readonly DexEncodedMethod[];
  readonly virtualMethods: readonly DexEncodedMethod[];
}

export interface DexCodeItem {
  readonly offset: number;
  readonly debugInfoOff: number;
  readonly raw: Buffer;
}

export interface DexPointerItem {
  readonly type: number;
  readonly offset: number;
  readonly raw: Buffer;
}

export interface DexStringItem {
  readonly dataOff: number;
  readonly utf16Size: number;
  readonly text: string;
  readonly raw: Buffer;
}

export interface DexLayout {
  readonly magic: string;
  readonly headerSize: number;
  readonly endian: number;
  readonly linkSize: number;
  readonly linkOff: number;
  readonly mapOff: number;
  readonly stringIdsOff: number;
  readonly typeIdsOff: number;
  readonly protoIdsOff: number;
  readonly fieldIdsOff: number;
  readonly methodIdsOff: number;
  readonly classDefsOff: number;
  readonly callSiteIdsOff: number;
  readonly methodHandlesOff: number;
  readonly dataOff: number;
  readonly dataSize: number;
  readonly fileSize: number;
  readonly strings: readonly DexStringItem[];
  readonly typeIds: readonly number[];
  readonly protoIds: readonly DexProtoId[];
  readonly fieldIds: readonly DexFieldId[];
  readonly methodIds: readonly DexMethodId[];
  readonly classDefs: readonly DexClassDef[];
  readonly callSiteIds: readonly number[];
  readonly methodHandles: readonly DexMethodHandle[];
  readonly classData: readonly DexClassData[];
  readonly codeItems: readonly DexCodeItem[];
  readonly pointerItems: readonly DexPointerItem[];
  readonly map: readonly DexMapItem[];
  readonly trailer: Buffer;
}

class DexParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DexParseError";
  }
}

function fail(message: string): never {
  throw new DexParseError(message);
}

function align4(n: number): number {
  return (n + 3) & ~3;
}

function requireRange(buf: Buffer, offset: number, size: number, what: string): void {
  if (offset < 0 || size < 0 || offset + size > buf.length) {
    fail(`${what} is out of range`);
  }
}

export function encodeUleb128(value: number): Buffer {
  const bytes: number[] = [];
  let v = value >>> 0;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (v !== 0);
  return Buffer.from(bytes);
}

function readUleb128(buf: Buffer, offset: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let i = offset;
  while (i < buf.length) {
    const b = buf[i++]!;
    value |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value: value >>> 0, next: i };
    shift += 7;
    if (shift > 35) fail("uleb128 overflow");
  }
  fail("truncated uleb128");
}

function readSleb128(buf: Buffer, offset: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let i = offset;
  let b = 0;
  do {
    if (i >= buf.length) fail("truncated sleb128");
    b = buf[i++]!;
    value |= (b & 0x7f) << shift;
    shift += 7;
    if (shift > 35) fail("sleb128 overflow");
  } while ((b & 0x80) !== 0);
  if (shift < 32 && (b & 0x40) !== 0) {
    value |= ~0 << shift;
  }
  return { value: value | 0, next: i };
}

/** Modified UTF-8 used by DEX string_data_item (U+0000 as C0 80; supplementary as CESU-8). */
export function encodeMutf8(text: string): Buffer {
  const bytes: number[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0) {
      bytes.push(0xc0, 0x80);
    } else if (cp <= 0x7f) {
      bytes.push(cp);
    } else if (cp <= 0x7ff) {
      bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp <= 0xffff) {
      bytes.push(
        0xe0 | (cp >> 12),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    } else {
      const u = cp - 0x10000;
      const hi = 0xd800 + (u >> 10);
      const lo = 0xdc00 + (u & 0x3ff);
      for (const unit of [hi, lo]) {
        bytes.push(
          0xe0 | (unit >> 12),
          0x80 | ((unit >> 6) & 0x3f),
          0x80 | (unit & 0x3f),
        );
      }
    }
  }
  return Buffer.from(bytes);
}

export function decodeMutf8(bytes: Buffer): string {
  const units: number[] = [];
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i++]!;
    if (a === 0) break;
    if (a < 0x80) {
      units.push(a);
    } else if ((a & 0xe0) === 0xc0) {
      if (i >= bytes.length) fail("truncated MUTF-8");
      const b = bytes[i++]!;
      units.push(((a & 0x1f) << 6) | (b & 0x3f));
    } else if ((a & 0xf0) === 0xe0) {
      if (i + 1 >= bytes.length) fail("truncated MUTF-8");
      const b = bytes[i++]!;
      const c = bytes[i++]!;
      units.push(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
    } else {
      fail("invalid MUTF-8 lead byte");
    }
  }
  return String.fromCharCode(...units);
}

export function utf16SizeOf(text: string): number {
  let size = 0;
  for (const ch of text) {
    size += ch.codePointAt(0)! > 0xffff ? 2 : 1;
  }
  return size;
}

export function encodeDexStringData(text: string): Buffer {
  const mutf = encodeMutf8(text);
  return Buffer.concat([encodeUleb128(utf16SizeOf(text)), mutf, Buffer.from([0])]);
}

export function compareDexUtf16(a: string, b: string): number {
  const na = a.length;
  const nb = b.length;
  const n = Math.min(na, nb);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return na - nb;
}

/**
 * Build a string that sorts after every existing pool entry so inserting it
 * at the end leaves all existing string indices unchanged.
 */
export function chooseSortLastDexString(
  existing: readonly string[],
  body: string,
): string {
  let prefix = "\uFFFF";
  const candidate = (): string => prefix + body;
  const sortsLast = (text: string): boolean =>
    existing.every((s) => compareDexUtf16(s, text) < 0);
  let guard = 0;
  while (!sortsLast(candidate())) {
    prefix += "\uFFFF";
    guard += 1;
    if (guard > 16) fail("unable to choose a sort-last DEX string");
  }
  if (existing.includes(candidate())) {
    prefix += "\uFFFF";
  }
  return candidate();
}

export function stripDexSidecarPrefix(text: string): string | null {
  let i = 0;
  while (i < text.length && text.charCodeAt(i) === 0xffff) i += 1;
  if (i === text.length) return null;
  const rest = text.slice(i);
  if (!rest.startsWith(DEX_SIDECAR_STRING_KEY)) return null;
  return rest.slice(DEX_SIDECAR_STRING_KEY.length);
}

export function computeAdler32(bytes: Buffer): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]!) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

export function recomputeDexChecksums(file: Buffer): Buffer {
  const out = Buffer.from(file);
  const sha1 = createHash("sha1").update(out.subarray(32)).digest();
  sha1.copy(out, 12);
  out.writeUInt32LE(computeAdler32(out.subarray(12)), 8);
  return out;
}

export function dexChecksumsValid(file: Buffer): boolean {
  if (file.length < DEX_HEADER_SIZE) return false;
  if (file.readUInt32LE(32) !== file.length) return false;
  const sha1 = createHash("sha1").update(file.subarray(32)).digest();
  if (!sha1.equals(file.subarray(12, 32))) return false;
  return file.readUInt32LE(8) === computeAdler32(file.subarray(12));
}

function readStringData(buf: Buffer, offset: number): DexStringItem {
  const utf16 = readUleb128(buf, offset);
  let end = utf16.next;
  while (end < buf.length && buf[end] !== 0) end += 1;
  if (end >= buf.length) fail("unterminated string_data");
  const mutf = buf.subarray(utf16.next, end);
  const text = decodeMutf8(mutf);
  const raw = Buffer.from(buf.subarray(offset, end + 1));
  return { dataOff: offset, utf16Size: utf16.value, text, raw };
}

function skipEncodedValue(buf: Buffer, offset: number): number {
  requireRange(buf, offset, 1, "encoded_value");
  const header = buf[offset]!;
  const type = header & 0x1f;
  const arg = (header >> 5) & 7;
  let i = offset + 1;
  const consume = (n: number): void => {
    requireRange(buf, i, n, "encoded_value payload");
    i += n;
  };
  switch (type) {
    case 0x00:
      consume(1);
      return i;
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x06:
    case 0x10:
    case 0x11:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x18:
    case 0x19:
    case 0x1a:
    case 0x1b:
      consume(arg + 1);
      return i;
    case 0x1c:
      return skipEncodedArray(buf, i);
    case 0x1d:
      return skipEncodedAnnotation(buf, i);
    case 0x1e:
    case 0x1f:
      return i;
    default:
      fail(`unsupported encoded_value type 0x${type.toString(16)}`);
  }
}

function skipEncodedArray(buf: Buffer, offset: number): number {
  const size = readUleb128(buf, offset);
  let i = size.next;
  for (let n = 0; n < size.value; n++) i = skipEncodedValue(buf, i);
  return i;
}

function skipEncodedAnnotation(buf: Buffer, offset: number): number {
  const typ = readUleb128(buf, offset);
  const size = readUleb128(buf, typ.next);
  let i = size.next;
  for (let n = 0; n < size.value; n++) {
    const name = readUleb128(buf, i);
    i = skipEncodedValue(buf, name.next);
  }
  return i;
}

function sizeOfTypeList(buf: Buffer, offset: number): number {
  requireRange(buf, offset, 4, "type_list");
  const size = buf.readUInt32LE(offset);
  const bytes = 4 + size * 2;
  requireRange(buf, offset, bytes, "type_list entries");
  return align4(bytes);
}

function sizeOfAnnotationSet(buf: Buffer, offset: number): number {
  requireRange(buf, offset, 4, "annotation_set");
  const size = buf.readUInt32LE(offset);
  const bytes = 4 + size * 4;
  requireRange(buf, offset, bytes, "annotation_set entries");
  return bytes;
}

function sizeOfAnnotationSetRefList(buf: Buffer, offset: number): number {
  return sizeOfAnnotationSet(buf, offset);
}

function sizeOfAnnotationsDirectory(buf: Buffer, offset: number): number {
  requireRange(buf, offset, 16, "annotations_directory");
  const fields = buf.readUInt32LE(offset + 4);
  const methods = buf.readUInt32LE(offset + 8);
  const params = buf.readUInt32LE(offset + 12);
  const bytes = 16 + (fields + methods + params) * 8;
  requireRange(buf, offset, bytes, "annotations_directory entries");
  return bytes;
}

function sizeOfAnnotationItem(buf: Buffer, offset: number): number {
  requireRange(buf, offset, 1, "annotation_item");
  return skipEncodedAnnotation(buf, offset + 1) - offset;
}

function sizeOfEncodedArrayItem(buf: Buffer, offset: number): number {
  return skipEncodedArray(buf, offset) - offset;
}

function sizeOfDebugInfo(buf: Buffer, offset: number): number {
  const line = readUleb128(buf, offset);
  const params = readUleb128(buf, line.next);
  let i = params.next;
  for (let n = 0; n < params.value; n++) i = readUleb128(buf, i).next;
  for (;;) {
    requireRange(buf, i, 1, "debug_info opcode");
    const op = buf[i++]!;
    if (op === 0x00) return i - offset;
    if (op === 0x01) i = readUleb128(buf, i).next;
    else if (op === 0x02) i = readSleb128(buf, i).next;
    else if (op === 0x03) {
      i = readUleb128(buf, i).next;
      i = readUleb128(buf, i).next;
      i = readUleb128(buf, i).next;
    } else if (op === 0x04) {
      i = readUleb128(buf, i).next;
      i = readUleb128(buf, i).next;
      i = readUleb128(buf, i).next;
      i = readUleb128(buf, i).next;
    } else if (op === 0x05 || op === 0x06) i = readUleb128(buf, i).next;
    else if (op === 0x09) i = readUleb128(buf, i).next;
    else if (op === 0x07 || op === 0x08 || op >= 0x0a) continue;
    else fail(`unsupported debug_info opcode 0x${op.toString(16)}`);
  }
}

function sizeOfCodeItem(buf: Buffer, offset: number): number {
  requireRange(buf, offset, 16, "code_item");
  const triesSize = buf.readUInt16LE(offset + 6);
  const insnsSize = buf.readUInt32LE(offset + 12);
  let i = offset + 16 + insnsSize * 2;
  requireRange(buf, offset, i - offset, "code_item insns");
  if (triesSize > 0 && insnsSize % 2 === 1) {
    requireRange(buf, i, 2, "code_item insn padding");
    i += 2;
  }
  if (triesSize > 0) {
    requireRange(buf, i, triesSize * 8, "code_item tries");
    i += triesSize * 8;
    const count = readUleb128(buf, i);
    i = count.next;
    for (let n = 0; n < count.value; n++) {
      const signed = readSleb128(buf, i);
      i = signed.next;
      const typed = Math.abs(signed.value);
      for (let t = 0; t < typed; t++) {
        i = readUleb128(buf, i).next;
        i = readUleb128(buf, i).next;
      }
      if (signed.value <= 0) i = readUleb128(buf, i).next;
    }
  }
  return i - offset;
}

function parseClassData(buf: Buffer, offset: number): DexClassData {
  const staticSize = readUleb128(buf, offset);
  const instanceSize = readUleb128(buf, staticSize.next);
  const directSize = readUleb128(buf, instanceSize.next);
  const virtualSize = readUleb128(buf, directSize.next);
  let i = virtualSize.next;
  const readFields = (count: number): DexEncodedField[] => {
    const out: DexEncodedField[] = [];
    for (let n = 0; n < count; n++) {
      const idx = readUleb128(buf, i);
      const acc = readUleb128(buf, idx.next);
      i = acc.next;
      out.push({ idxDiff: idx.value, accessFlags: acc.value });
    }
    return out;
  };
  const readMethods = (count: number): DexEncodedMethod[] => {
    const out: DexEncodedMethod[] = [];
    for (let n = 0; n < count; n++) {
      const idx = readUleb128(buf, i);
      const acc = readUleb128(buf, idx.next);
      const code = readUleb128(buf, acc.next);
      i = code.next;
      out.push({ idxDiff: idx.value, accessFlags: acc.value, codeOff: code.value });
    }
    return out;
  };
  return {
    offset,
    staticFields: readFields(staticSize.value),
    instanceFields: readFields(instanceSize.value),
    directMethods: readMethods(directSize.value),
    virtualMethods: readMethods(virtualSize.value),
  };
}

function encodeClassData(item: DexClassData, remapOff: (off: number) => number): Buffer {
  const parts: Buffer[] = [
    encodeUleb128(item.staticFields.length),
    encodeUleb128(item.instanceFields.length),
    encodeUleb128(item.directMethods.length),
    encodeUleb128(item.virtualMethods.length),
  ];
  for (const field of [...item.staticFields, ...item.instanceFields]) {
    parts.push(encodeUleb128(field.idxDiff), encodeUleb128(field.accessFlags));
  }
  for (const method of [...item.directMethods, ...item.virtualMethods]) {
    parts.push(
      encodeUleb128(method.idxDiff),
      encodeUleb128(method.accessFlags),
      encodeUleb128(method.codeOff === 0 ? 0 : remapOff(method.codeOff)),
    );
  }
  return Buffer.concat(parts);
}

function patchU32Offsets(raw: Buffer, positions: readonly number[], remapOff: (off: number) => number): Buffer {
  const out = Buffer.from(raw);
  for (const pos of positions) {
    const current = out.readUInt32LE(pos);
    if (current !== 0) out.writeUInt32LE(remapOff(current), pos);
  }
  return out;
}

function pointerPositions(type: number, raw: Buffer): number[] {
  if (type === DEX_MAP_TYPE.ANNOTATION_SET_ITEM || type === DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST) {
    const size = raw.readUInt32LE(0);
    const pos: number[] = [];
    for (let i = 0; i < size; i++) pos.push(4 + i * 4);
    return pos;
  }
  if (type === DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM) {
    const pos: number[] = [0];
    const fields = raw.readUInt32LE(4);
    const methods = raw.readUInt32LE(8);
    const params = raw.readUInt32LE(12);
    const count = fields + methods + params;
    for (let i = 0; i < count; i++) pos.push(16 + i * 8 + 4);
    return pos;
  }
  return [];
}

function parseMap(buf: Buffer, mapOff: number): DexMapItem[] {
  requireRange(buf, mapOff, 4, "map_list");
  const count = buf.readUInt32LE(mapOff);
  requireRange(buf, mapOff, 4 + count * 12, "map_list entries");
  const items: DexMapItem[] = [];
  for (let i = 0; i < count; i++) {
    const at = mapOff + 4 + i * 12;
    items.push({
      type: buf.readUInt16LE(at),
      size: buf.readUInt32LE(at + 4),
      offset: buf.readUInt32LE(at + 8),
    });
  }
  return items;
}

const SUPPORTED_MAP_TYPES = new Set<number>(Object.values(DEX_MAP_TYPE));

function itemSize(type: number, buf: Buffer, offset: number): number {
  switch (type) {
    case DEX_MAP_TYPE.TYPE_LIST:
      return sizeOfTypeList(buf, offset);
    case DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST:
      return sizeOfAnnotationSetRefList(buf, offset);
    case DEX_MAP_TYPE.ANNOTATION_SET_ITEM:
      return sizeOfAnnotationSet(buf, offset);
    case DEX_MAP_TYPE.CODE_ITEM:
      return sizeOfCodeItem(buf, offset);
    case DEX_MAP_TYPE.DEBUG_INFO_ITEM:
      return sizeOfDebugInfo(buf, offset);
    case DEX_MAP_TYPE.ANNOTATION_ITEM:
      return sizeOfAnnotationItem(buf, offset);
    case DEX_MAP_TYPE.ENCODED_ARRAY_ITEM:
      return sizeOfEncodedArrayItem(buf, offset);
    case DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM:
      return sizeOfAnnotationsDirectory(buf, offset);
    default:
      fail(`cannot size map type 0x${type.toString(16)}`);
  }
}

function readIdTable<T>(
  buf: Buffer,
  off: number,
  size: number,
  stride: number,
  read: (at: number) => T,
  what: string,
): T[] {
  if (size === 0) return [];
  requireRange(buf, off, size * stride, what);
  const out: T[] = [];
  for (let i = 0; i < size; i++) out.push(read(off + i * stride));
  return out;
}

/**
 * Parse a little-endian DEX 035–039 container. Returns null when the file is
 * not a structurally valid DEX we can safely rewrite (header-only stubs,
 * big-endian, unsupported map types, truncated sections).
 */
export function parseDexLayout(bytes: Uint8Array): DexLayout | null {
  try {
    const buf = Buffer.from(bytes);
    if (buf.length < DEX_HEADER_SIZE) return null;
    if (buf[0] !== 0x64 || buf[1] !== 0x65 || buf[2] !== 0x78 || buf[3] !== 0x0a) {
      return null;
    }
    if (buf[7] !== 0x00) return null;
    const version = buf.subarray(4, 7).toString("ascii");
    if (!/^03[5-9]$/.test(version)) return null;
    const fileSize = buf.readUInt32LE(32);
    const headerSize = buf.readUInt32LE(36);
    const endian = buf.readUInt32LE(40);
    if (headerSize !== DEX_HEADER_SIZE || endian !== DEX_ENDIAN_LE) return null;
    if (fileSize < DEX_HEADER_SIZE || fileSize > buf.length) return null;

    const linkSize = buf.readUInt32LE(44);
    const linkOff = buf.readUInt32LE(48);
    if (linkSize !== 0 || linkOff !== 0) return null;
    const mapOff = buf.readUInt32LE(52);
    const stringIdsSize = buf.readUInt32LE(56);
    const stringIdsOff = buf.readUInt32LE(60);
    const typeIdsSize = buf.readUInt32LE(64);
    const typeIdsOff = buf.readUInt32LE(68);
    const protoIdsSize = buf.readUInt32LE(72);
    const protoIdsOff = buf.readUInt32LE(76);
    const fieldIdsSize = buf.readUInt32LE(80);
    const fieldIdsOff = buf.readUInt32LE(84);
    const methodIdsSize = buf.readUInt32LE(88);
    const methodIdsOff = buf.readUInt32LE(92);
    const classDefsSize = buf.readUInt32LE(96);
    const classDefsOff = buf.readUInt32LE(100);
    const dataSize = buf.readUInt32LE(104);
    const dataOff = buf.readUInt32LE(108);
    if (dataOff + dataSize > fileSize) return null;

    const map = parseMap(buf, mapOff);
    for (const item of map) {
      if (!SUPPORTED_MAP_TYPES.has(item.type)) return null;
    }

    const stringOffs = readIdTable(
      buf,
      stringIdsOff,
      stringIdsSize,
      4,
      (at) => buf.readUInt32LE(at),
      "string_ids",
    );
    const strings = stringOffs.map((off) => readStringData(buf, off));
    // Do not reject an unsorted pool: some emitted fixtures (and a few
    // toolchains) skip the official sort. Rebuilding preserves existing
    // order so string indices — and therefore bytecode — stay stable.

    const typeIds = readIdTable(
      buf,
      typeIdsOff,
      typeIdsSize,
      4,
      (at) => buf.readUInt32LE(at),
      "type_ids",
    );
    const protoIds = readIdTable(
      buf,
      protoIdsOff,
      protoIdsSize,
      12,
      (at) => ({
        shortyIdx: buf.readUInt32LE(at),
        returnTypeIdx: buf.readUInt32LE(at + 4),
        parametersOff: buf.readUInt32LE(at + 8),
      }),
      "proto_ids",
    );
    const fieldIds = readIdTable(
      buf,
      fieldIdsOff,
      fieldIdsSize,
      8,
      (at) => ({
        classIdx: buf.readUInt16LE(at),
        typeIdx: buf.readUInt16LE(at + 2),
        nameIdx: buf.readUInt32LE(at + 4),
      }),
      "field_ids",
    );
    const methodIds = readIdTable(
      buf,
      methodIdsOff,
      methodIdsSize,
      8,
      (at) => ({
        classIdx: buf.readUInt16LE(at),
        protoIdx: buf.readUInt16LE(at + 2),
        nameIdx: buf.readUInt32LE(at + 4),
      }),
      "method_ids",
    );
    const classDefs = readIdTable(
      buf,
      classDefsOff,
      classDefsSize,
      32,
      (at) => ({
        classIdx: buf.readUInt32LE(at),
        accessFlags: buf.readUInt32LE(at + 4),
        superclassIdx: buf.readUInt32LE(at + 8),
        interfacesOff: buf.readUInt32LE(at + 12),
        sourceFileIdx: buf.readUInt32LE(at + 16),
        annotationsOff: buf.readUInt32LE(at + 20),
        classDataOff: buf.readUInt32LE(at + 24),
        staticValuesOff: buf.readUInt32LE(at + 28),
      }),
      "class_defs",
    );

    const callSiteMap = map.find((m) => m.type === DEX_MAP_TYPE.CALL_SITE_ID_ITEM);
    const methodHandleMap = map.find((m) => m.type === DEX_MAP_TYPE.METHOD_HANDLE_ITEM);
    const callSiteIds = callSiteMap
      ? readIdTable(
          buf,
          callSiteMap.offset,
          callSiteMap.size,
          4,
          (at) => buf.readUInt32LE(at),
          "call_site_ids",
        )
      : [];
    const methodHandles = methodHandleMap
      ? readIdTable(
          buf,
          methodHandleMap.offset,
          methodHandleMap.size,
          8,
          (at) => ({
            methodHandleType: buf.readUInt16LE(at),
            fieldOrMethodId: buf.readUInt16LE(at + 4),
          }),
          "method_handles",
        )
      : [];

    const classData: DexClassData[] = [];
    const seenClassData = new Set<number>();
    for (const def of classDefs) {
      if (def.classDataOff === 0 || seenClassData.has(def.classDataOff)) continue;
      seenClassData.add(def.classDataOff);
      classData.push(parseClassData(buf, def.classDataOff));
    }

    const codeItems: DexCodeItem[] = [];
    const seenCode = new Set<number>();
    const addCode = (off: number): void => {
      if (off === 0 || seenCode.has(off)) return;
      seenCode.add(off);
      const size = sizeOfCodeItem(buf, off);
      const raw = Buffer.from(buf.subarray(off, off + size));
      codeItems.push({ offset: off, debugInfoOff: raw.readUInt32LE(8), raw });
    };
    for (const item of classData) {
      for (const method of [...item.directMethods, ...item.virtualMethods]) {
        addCode(method.codeOff);
      }
    }

    const pointerItems: DexPointerItem[] = [];
    const seenPointer = new Set<string>();
    const addPointer = (type: number, off: number): void => {
      if (off === 0) return;
      const key = `${type}:${off}`;
      if (seenPointer.has(key)) return;
      seenPointer.add(key);
      const size = itemSize(type, buf, off);
      pointerItems.push({ type, offset: off, raw: Buffer.from(buf.subarray(off, off + size)) });
    };

    for (const proto of protoIds) addPointer(DEX_MAP_TYPE.TYPE_LIST, proto.parametersOff);
    for (const def of classDefs) {
      addPointer(DEX_MAP_TYPE.TYPE_LIST, def.interfacesOff);
      addPointer(DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM, def.annotationsOff);
      addPointer(DEX_MAP_TYPE.ENCODED_ARRAY_ITEM, def.staticValuesOff);
    }
    for (const off of callSiteIds) addPointer(DEX_MAP_TYPE.ENCODED_ARRAY_ITEM, off);
    for (const code of codeItems) addPointer(DEX_MAP_TYPE.DEBUG_INFO_ITEM, code.debugInfoOff);

    // Follow annotation directories / sets after the first wave (newly added
    // directory blobs are already in pointerItems).
    const directoryItems = pointerItems.filter(
      (p) => p.type === DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM,
    );
    for (const dir of directoryItems) {
      const classAnn = dir.raw.readUInt32LE(0);
      addPointer(DEX_MAP_TYPE.ANNOTATION_SET_ITEM, classAnn);
      const fields = dir.raw.readUInt32LE(4);
      const methods = dir.raw.readUInt32LE(8);
      const params = dir.raw.readUInt32LE(12);
      let at = 16;
      for (let n = 0; n < fields + methods; n++) {
        addPointer(DEX_MAP_TYPE.ANNOTATION_SET_ITEM, dir.raw.readUInt32LE(at + 4));
        at += 8;
      }
      for (let n = 0; n < params; n++) {
        addPointer(DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST, dir.raw.readUInt32LE(at + 4));
        at += 8;
      }
    }
    const refLists = pointerItems.filter((p) => p.type === DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST);
    for (const list of refLists) {
      const size = list.raw.readUInt32LE(0);
      for (let n = 0; n < size; n++) {
        addPointer(DEX_MAP_TYPE.ANNOTATION_SET_ITEM, list.raw.readUInt32LE(4 + n * 4));
      }
    }
    const sets = pointerItems.filter((p) => p.type === DEX_MAP_TYPE.ANNOTATION_SET_ITEM);
    for (const set of sets) {
      const size = set.raw.readUInt32LE(0);
      for (let n = 0; n < size; n++) {
        addPointer(DEX_MAP_TYPE.ANNOTATION_ITEM, set.raw.readUInt32LE(4 + n * 4));
      }
    }

    // Include unreferenced-but-mapped items of known data types (except
    // string_data / class_data / code, which we already recovered by pointer).
    const packedTypes = new Set<number>([
      DEX_MAP_TYPE.TYPE_LIST,
      DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST,
      DEX_MAP_TYPE.ANNOTATION_SET_ITEM,
      DEX_MAP_TYPE.DEBUG_INFO_ITEM,
      DEX_MAP_TYPE.ANNOTATION_ITEM,
      DEX_MAP_TYPE.ENCODED_ARRAY_ITEM,
      DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM,
    ]);
    for (const item of map) {
      if (!packedTypes.has(item.type) || item.size === 0) continue;
      let cursor = item.offset;
      for (let n = 0; n < item.size; n++) {
        if (ALIGN4_TYPES.has(item.type)) cursor = align4(cursor);
        addPointer(item.type, cursor);
        cursor += itemSize(item.type, buf, cursor);
      }
    }

    const officialEnd = dataOff + dataSize;
    const trailer = Buffer.from(buf.subarray(officialEnd, fileSize));

    return {
      magic: buf.subarray(0, 8).toString("latin1"),
      headerSize,
      endian,
      linkSize,
      linkOff,
      mapOff,
      stringIdsOff,
      typeIdsOff,
      protoIdsOff,
      fieldIdsOff,
      methodIdsOff,
      classDefsOff,
      callSiteIdsOff: callSiteMap?.offset ?? 0,
      methodHandlesOff: methodHandleMap?.offset ?? 0,
      dataOff,
      dataSize,
      fileSize,
      strings,
      typeIds,
      protoIds,
      fieldIds,
      methodIds,
      classDefs,
      callSiteIds,
      methodHandles,
      classData,
      codeItems,
      pointerItems,
      map,
      trailer,
    };
  } catch (error) {
    if (process.env.BLA_DEBUG_DEX === "1") {
      console.error("parseDexLayout", error);
    }
    return null;
  }
}

export interface RebuildDexOptions {
  /** Additional pool strings (already sort-ordered by the caller when appending). */
  readonly appendStrings?: readonly string[];
  /** Drop pool strings matching this predicate (used to strip a prior note). */
  readonly dropString?: (text: string) => boolean;
}

/**
 * Rebuild a DEX from a parsed layout. Existing string indices stay stable when
 * strings are only appended and already sort last. Instruction bodies are
 * copied bit-exact; only file-offset fields are rewritten.
 */
export function rebuildDex(layout: DexLayout, options: RebuildDexOptions = {}): Buffer {
  const kept = options.dropString
    ? layout.strings.filter((s) => !options.dropString!(s.text))
    : [...layout.strings];
  if (kept.length !== layout.strings.length) {
    // Dropping a string that is not the last would require remapping every
    // string index. Only allow dropping a suffix of sort-last sidecar notes.
    for (let i = 0; i < kept.length; i++) {
      if (kept[i]!.text !== layout.strings[i]!.text) {
        throw new Error("DEX sidecar strip may only drop trailing sort-last strings");
      }
    }
  }
  const appended = (options.appendStrings ?? []).map((text) => {
    const raw = encodeDexStringData(text);
    return {
      dataOff: -1,
      utf16Size: utf16SizeOf(text),
      text,
      raw,
    } satisfies DexStringItem;
  });
  const strings: DexStringItem[] = [...kept, ...appended];
  for (const extra of appended) {
    if (kept.some((s) => compareDexUtf16(s.text, extra.text) >= 0)) {
      throw new Error("appended DEX sidecar string must sort after every existing pool entry");
    }
  }

  const headerSize = DEX_HEADER_SIZE;
  const stringIdsSize = strings.length * 4;
  const typeIdsSize = layout.typeIds.length * 4;
  const protoIdsSize = layout.protoIds.length * 12;
  const fieldIdsSize = layout.fieldIds.length * 8;
  const methodIdsSize = layout.methodIds.length * 8;
  const classDefsSize = layout.classDefs.length * 32;
  const callSiteIdsSize = layout.callSiteIds.length * 4;
  const methodHandlesSize = layout.methodHandles.length * 8;
  const idsEnd =
    headerSize +
    stringIdsSize +
    typeIdsSize +
    protoIdsSize +
    fieldIdsSize +
    methodIdsSize +
    classDefsSize +
    callSiteIdsSize +
    methodHandlesSize;

  type Planned = { key: string; align: boolean; bytes: (remap: (off: number) => number) => Buffer };
  const planned: Planned[] = [];

  for (const s of strings) {
    planned.push({
      key: s.dataOff >= 0 ? `string:${s.dataOff}` : `string-new:${s.text}`,
      align: false,
      bytes: () => s.raw,
    });
  }
  for (const item of layout.pointerItems) {
    planned.push({
      key: `ptr:${item.type}:${item.offset}`,
      align: ALIGN4_TYPES.has(item.type),
      bytes: (remap) => patchU32Offsets(item.raw, pointerPositions(item.type, item.raw), remap),
    });
  }
  for (const item of layout.codeItems) {
    planned.push({
      key: `code:${item.offset}`,
      align: true,
      bytes: (remap) => {
        const raw = Buffer.from(item.raw);
        raw.writeUInt32LE(item.debugInfoOff === 0 ? 0 : remap(item.debugInfoOff), 8);
        return raw;
      },
    });
  }
  for (const item of layout.classData) {
    planned.push({
      key: `classdata:${item.offset}`,
      align: false,
      bytes: (remap) => encodeClassData(item, remap),
    });
  }

  // Preserve original relative order of existing data items, then appended strings.
  const originalOrder = new Map<string, number>();
  let order = 0;
  for (const s of kept) originalOrder.set(`string:${s.dataOff}`, order++);
  const dataItems = [
    ...layout.pointerItems.map((p) => ({ key: `ptr:${p.type}:${p.offset}`, offset: p.offset })),
    ...layout.codeItems.map((p) => ({ key: `code:${p.offset}`, offset: p.offset })),
    ...layout.classData.map((p) => ({ key: `classdata:${p.offset}`, offset: p.offset })),
  ].sort((a, b) => a.offset - b.offset);
  for (const item of dataItems) originalOrder.set(item.key, order++);
  for (const s of appended) originalOrder.set(`string-new:${s.text}`, order++);

  planned.sort((a, b) => (originalOrder.get(a.key) ?? 1e9) - (originalOrder.get(b.key) ?? 1e9));

  // First pass: measure with a dummy remap that returns the old offsets so
  // class_data uleb widths are not needed for measurement of others... we must
  // measure class_data with the final offsets. Two-phase: allocate offsets
  // assuming encodeClassData length, iterating to a fixed point.
  const assign = (remap: (off: number) => number): { offsets: Map<string, number>; mapOff: number; fileSize: number; dataOff: number } => {
    const offsets = new Map<string, number>();
    let cursor = idsEnd;
    for (const item of planned) {
      if (item.align) cursor = align4(cursor);
      offsets.set(item.key, cursor);
      cursor += item.bytes(remap).length;
    }
    cursor = align4(cursor);
    const mapOff = cursor;
    const mapCount = countMapEntries(layout, strings.length);
    const mapBytes = 4 + mapCount * 12;
    const fileSize = mapOff + mapBytes + layout.trailer.length;
    return { offsets, mapOff, fileSize, dataOff: idsEnd };
  };

  const oldKeyByOff = new Map<number, string>();
  for (const s of kept) oldKeyByOff.set(s.dataOff, `string:${s.dataOff}`);
  for (const p of layout.pointerItems) oldKeyByOff.set(p.offset, `ptr:${p.type}:${p.offset}`);
  for (const p of layout.codeItems) oldKeyByOff.set(p.offset, `code:${p.offset}`);
  for (const p of layout.classData) oldKeyByOff.set(p.offset, `classdata:${p.offset}`);

  let remap: (off: number) => number = (off) => off;
  let assigned = assign(remap);
  for (let iter = 0; iter < 8; iter++) {
    const offsets = assigned.offsets;
    remap = (off: number): number => {
      if (off === 0) return 0;
      const key = oldKeyByOff.get(off);
      const next = key !== undefined ? offsets.get(key) : undefined;
      if (next === undefined) {
        throw new Error(`DEX rebuild lost offset ${off}`);
      }
      return next;
    };
    const nextAssigned = assign(remap);
    let same = nextAssigned.mapOff === assigned.mapOff && nextAssigned.fileSize === assigned.fileSize;
    if (same) {
      for (const [k, v] of nextAssigned.offsets) {
        if (assigned.offsets.get(k) !== v) {
          same = false;
          break;
        }
      }
    }
    assigned = nextAssigned;
    if (same) break;
  }

  const { offsets, mapOff, dataOff } = assigned;
  const dataChunks: { offset: number; bytes: Buffer }[] = [];
  let cursor = dataOff;
  for (const item of planned) {
    if (item.align) {
      const pad = align4(cursor) - cursor;
      if (pad > 0) {
        dataChunks.push({ offset: cursor, bytes: Buffer.alloc(pad, 0) });
        cursor += pad;
      }
    }
    const at = offsets.get(item.key)!;
    if (at !== cursor) {
      // Should not happen after the align loop above matches assign().
      if (at > cursor) {
        dataChunks.push({ offset: cursor, bytes: Buffer.alloc(at - cursor, 0) });
        cursor = at;
      }
    }
    const bytes = item.bytes(remap);
    dataChunks.push({ offset: at, bytes });
    cursor = at + bytes.length;
  }
  const padToMap = align4(cursor) - cursor;
  if (padToMap > 0) {
    dataChunks.push({ offset: cursor, bytes: Buffer.alloc(padToMap, 0) });
    cursor += padToMap;
  }

  const stringIdsOff = headerSize;
  const typeIdsOff = stringIdsOff + stringIdsSize;
  const protoIdsOff = typeIdsOff + typeIdsSize;
  const fieldIdsOff = protoIdsOff + protoIdsSize;
  const methodIdsOff = fieldIdsOff + fieldIdsSize;
  const classDefsOff = methodIdsOff + methodIdsSize;
  const callSiteIdsOff = classDefsOff + classDefsSize;
  const methodHandlesOff = callSiteIdsOff + callSiteIdsSize;

  const mapEntries: DexMapItem[] = [
    { type: DEX_MAP_TYPE.HEADER_ITEM, size: 1, offset: 0 },
    { type: DEX_MAP_TYPE.STRING_ID_ITEM, size: strings.length, offset: stringIdsOff },
  ];
  if (layout.typeIds.length > 0) {
    mapEntries.push({ type: DEX_MAP_TYPE.TYPE_ID_ITEM, size: layout.typeIds.length, offset: typeIdsOff });
  }
  if (layout.protoIds.length > 0) {
    mapEntries.push({ type: DEX_MAP_TYPE.PROTO_ID_ITEM, size: layout.protoIds.length, offset: protoIdsOff });
  }
  if (layout.fieldIds.length > 0) {
    mapEntries.push({ type: DEX_MAP_TYPE.FIELD_ID_ITEM, size: layout.fieldIds.length, offset: fieldIdsOff });
  }
  if (layout.methodIds.length > 0) {
    mapEntries.push({ type: DEX_MAP_TYPE.METHOD_ID_ITEM, size: layout.methodIds.length, offset: methodIdsOff });
  }
  if (layout.classDefs.length > 0) {
    mapEntries.push({ type: DEX_MAP_TYPE.CLASS_DEF_ITEM, size: layout.classDefs.length, offset: classDefsOff });
  }
  if (layout.callSiteIds.length > 0) {
    mapEntries.push({
      type: DEX_MAP_TYPE.CALL_SITE_ID_ITEM,
      size: layout.callSiteIds.length,
      offset: callSiteIdsOff,
    });
  }
  if (layout.methodHandles.length > 0) {
    mapEntries.push({
      type: DEX_MAP_TYPE.METHOD_HANDLE_ITEM,
      size: layout.methodHandles.length,
      offset: methodHandlesOff,
    });
  }

  const firstOff = (keys: string[]): number => {
    let min = Number.POSITIVE_INFINITY;
    for (const key of keys) {
      const off = offsets.get(key);
      if (off !== undefined && off < min) min = off;
    }
    return min;
  };
  const pushDataMap = (type: number, keys: string[]): void => {
    if (keys.length === 0) return;
    mapEntries.push({ type, size: keys.length, offset: firstOff(keys) });
  };
  pushDataMap(
    DEX_MAP_TYPE.TYPE_LIST,
    layout.pointerItems.filter((p) => p.type === DEX_MAP_TYPE.TYPE_LIST).map((p) => `ptr:${p.type}:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST,
    layout.pointerItems
      .filter((p) => p.type === DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST)
      .map((p) => `ptr:${p.type}:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.ANNOTATION_SET_ITEM,
    layout.pointerItems
      .filter((p) => p.type === DEX_MAP_TYPE.ANNOTATION_SET_ITEM)
      .map((p) => `ptr:${p.type}:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.CLASS_DATA_ITEM,
    layout.classData.map((p) => `classdata:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.CODE_ITEM,
    layout.codeItems.map((p) => `code:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.STRING_DATA_ITEM,
    strings.map((s) => (s.dataOff >= 0 ? `string:${s.dataOff}` : `string-new:${s.text}`)),
  );
  pushDataMap(
    DEX_MAP_TYPE.DEBUG_INFO_ITEM,
    layout.pointerItems
      .filter((p) => p.type === DEX_MAP_TYPE.DEBUG_INFO_ITEM)
      .map((p) => `ptr:${p.type}:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.ANNOTATION_ITEM,
    layout.pointerItems
      .filter((p) => p.type === DEX_MAP_TYPE.ANNOTATION_ITEM)
      .map((p) => `ptr:${p.type}:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.ENCODED_ARRAY_ITEM,
    layout.pointerItems
      .filter((p) => p.type === DEX_MAP_TYPE.ENCODED_ARRAY_ITEM)
      .map((p) => `ptr:${p.type}:${p.offset}`),
  );
  pushDataMap(
    DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM,
    layout.pointerItems
      .filter((p) => p.type === DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM)
      .map((p) => `ptr:${p.type}:${p.offset}`),
  );
  mapEntries.push({ type: DEX_MAP_TYPE.MAP_LIST, size: 1, offset: mapOff });
  mapEntries.sort((a, b) => a.type - b.type);

  if (mapEntries.length !== countMapEntries(layout, strings.length)) {
    throw new Error(
      `DEX map entry count drifted (${mapEntries.length} != ${countMapEntries(layout, strings.length)})`,
    );
  }

  const mapBuf = Buffer.alloc(4 + mapEntries.length * 12);
  mapBuf.writeUInt32LE(mapEntries.length, 0);
  for (let i = 0; i < mapEntries.length; i++) {
    const e = mapEntries[i]!;
    const at = 4 + i * 12;
    mapBuf.writeUInt16LE(e.type, at);
    mapBuf.writeUInt16LE(0, at + 2);
    mapBuf.writeUInt32LE(e.size, at + 4);
    mapBuf.writeUInt32LE(e.offset, at + 8);
  }

  const structuredEnd = mapOff + mapBuf.length;
  const fileSize = structuredEnd + layout.trailer.length;
  const out = Buffer.alloc(fileSize, 0);
  out.write(layout.magic, 0, "latin1");
  out.writeUInt32LE(fileSize, 32);
  out.writeUInt32LE(headerSize, 36);
  out.writeUInt32LE(DEX_ENDIAN_LE, 40);
  out.writeUInt32LE(0, 44);
  out.writeUInt32LE(0, 48);
  out.writeUInt32LE(mapOff, 52);
  out.writeUInt32LE(strings.length, 56);
  out.writeUInt32LE(stringIdsOff, 60);
  out.writeUInt32LE(layout.typeIds.length, 64);
  out.writeUInt32LE(layout.typeIds.length > 0 ? typeIdsOff : 0, 68);
  out.writeUInt32LE(layout.protoIds.length, 72);
  out.writeUInt32LE(layout.protoIds.length > 0 ? protoIdsOff : 0, 76);
  out.writeUInt32LE(layout.fieldIds.length, 80);
  out.writeUInt32LE(layout.fieldIds.length > 0 ? fieldIdsOff : 0, 84);
  out.writeUInt32LE(layout.methodIds.length, 88);
  out.writeUInt32LE(layout.methodIds.length > 0 ? methodIdsOff : 0, 92);
  out.writeUInt32LE(layout.classDefs.length, 96);
  out.writeUInt32LE(layout.classDefs.length > 0 ? classDefsOff : 0, 100);
  out.writeUInt32LE(structuredEnd - dataOff, 104);
  out.writeUInt32LE(dataOff, 108);

  let at = stringIdsOff;
  for (const s of strings) {
    const key = s.dataOff >= 0 ? `string:${s.dataOff}` : `string-new:${s.text}`;
    out.writeUInt32LE(offsets.get(key)!, at);
    at += 4;
  }
  for (const idx of layout.typeIds) {
    out.writeUInt32LE(idx, at);
    at += 4;
  }
  for (const proto of layout.protoIds) {
    out.writeUInt32LE(proto.shortyIdx, at);
    out.writeUInt32LE(proto.returnTypeIdx, at + 4);
    out.writeUInt32LE(proto.parametersOff === 0 ? 0 : remap(proto.parametersOff), at + 8);
    at += 12;
  }
  for (const field of layout.fieldIds) {
    out.writeUInt16LE(field.classIdx, at);
    out.writeUInt16LE(field.typeIdx, at + 2);
    out.writeUInt32LE(field.nameIdx, at + 4);
    at += 8;
  }
  for (const method of layout.methodIds) {
    out.writeUInt16LE(method.classIdx, at);
    out.writeUInt16LE(method.protoIdx, at + 2);
    out.writeUInt32LE(method.nameIdx, at + 4);
    at += 8;
  }
  for (const def of layout.classDefs) {
    out.writeUInt32LE(def.classIdx, at);
    out.writeUInt32LE(def.accessFlags, at + 4);
    out.writeUInt32LE(def.superclassIdx, at + 8);
    out.writeUInt32LE(def.interfacesOff === 0 ? 0 : remap(def.interfacesOff), at + 12);
    out.writeUInt32LE(def.sourceFileIdx, at + 16);
    out.writeUInt32LE(def.annotationsOff === 0 ? 0 : remap(def.annotationsOff), at + 20);
    out.writeUInt32LE(def.classDataOff === 0 ? 0 : remap(def.classDataOff), at + 24);
    out.writeUInt32LE(def.staticValuesOff === 0 ? 0 : remap(def.staticValuesOff), at + 28);
    at += 32;
  }
  for (const off of layout.callSiteIds) {
    out.writeUInt32LE(off === 0 ? 0 : remap(off), at);
    at += 4;
  }
  for (const handle of layout.methodHandles) {
    out.writeUInt16LE(handle.methodHandleType, at);
    out.writeUInt16LE(0, at + 2);
    out.writeUInt16LE(handle.fieldOrMethodId, at + 4);
    out.writeUInt16LE(0, at + 6);
    at += 8;
  }

  for (const chunk of dataChunks) {
    chunk.bytes.copy(out, chunk.offset);
  }
  mapBuf.copy(out, mapOff);
  if (layout.trailer.length > 0) {
    layout.trailer.copy(out, structuredEnd);
  }
  return recomputeDexChecksums(out);
}

function countMapEntries(layout: DexLayout, stringCount: number): number {
  let n = 2; // header + string_ids
  if (layout.typeIds.length > 0) n++;
  if (layout.protoIds.length > 0) n++;
  if (layout.fieldIds.length > 0) n++;
  if (layout.methodIds.length > 0) n++;
  if (layout.classDefs.length > 0) n++;
  if (layout.callSiteIds.length > 0) n++;
  if (layout.methodHandles.length > 0) n++;
  n++; // map_list
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.TYPE_LIST)) n++;
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.ANNOTATION_SET_REF_LIST)) n++;
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.ANNOTATION_SET_ITEM)) n++;
  if (layout.classData.length > 0) n++;
  if (layout.codeItems.length > 0) n++;
  if (stringCount > 0) n++;
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.DEBUG_INFO_ITEM)) n++;
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.ANNOTATION_ITEM)) n++;
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.ENCODED_ARRAY_ITEM)) n++;
  if (layout.pointerItems.some((p) => p.type === DEX_MAP_TYPE.ANNOTATIONS_DIRECTORY_ITEM)) n++;
  return n;
}


/**
 * Insert `text` as a new unreferenced string that sorts last. Existing string
 * indices and instruction bytes stay unchanged. Returns null when the buffer
 * is not a rewritable DEX.
 */
export function insertDexString(bytes: Uint8Array, text: string): Buffer | null {
  const layout = parseDexLayout(bytes);
  if (!layout) return null;
  const body = text;
  const chosen = chooseSortLastDexString(layout.strings.map((s) => s.text), body);
  return rebuildDex(layout, { appendStrings: [chosen] });
}

/**
 * Drop trailing sidecar-note strings (identified by `stripDexSidecarPrefix`).
 * Idempotent: returns a copy when none are present. Returns null if unparseable.
 */
export function dropDexSidecarStrings(bytes: Uint8Array): Buffer | null {
  const layout = parseDexLayout(bytes);
  if (!layout) return null;
  if (!layout.strings.some((s) => stripDexSidecarPrefix(s.text) !== null)) {
    return Buffer.from(bytes);
  }
  return rebuildDex(layout, {
    dropString: (text) => stripDexSidecarPrefix(text) !== null,
  });
}

export function readDexStringPool(bytes: Uint8Array): readonly string[] | null {
  const layout = parseDexLayout(bytes);
  if (!layout) return null;
  return layout.strings.map((s) => s.text);
}
