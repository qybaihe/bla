/**
 * Structural .pyc decoy weave — unused decoy TYPE_CODE entries are spliced
 * into customer/module `co_consts` pools.
 *
 * REA `inspect_python_pyc` inventories them as real functions; CPython never
 * executes them (no MAKE_FUNCTION / call references them).
 *
 * Safety rules (engineering red line):
 * - The customer's objects are never decoded and re-encoded. The marshal
 *   stream is parsed into a tree of byte spans and every original object is
 *   written back byte-for-byte: a `str` keeps its type code (`u`/`t` are UTF-8,
 *   `a`/`A`/`z`/`Z` are one byte per character — re-typing one as the other
 *   turns text into mojibake), its interning, and its FLAG_REF sharing.
 * - The only edits are additions: decoy code objects after the last element
 *   of a `co_consts` tuple, and — when that tuple is shared with other code
 *   objects or used as a constant value — a new tuple for this code object
 *   that references the original elements, so the shared object itself never
 *   gains an element.
 * - Reference indices are reassigned while writing, in the order CPython's
 *   reader assigns them, so every TYPE_REF still designates the same object.
 * - Original co_code / arg counts / flags / names tables preserved.
 * - Weave bytecode only for CPython releases whose opcodes are verified.
 */
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export type PythonPycCodeLayout = "py37" | "py38" | "py311";

const FLAG_REF = 0x80;
const TYPE_NULL = 0x30;
const TYPE_NONE = 0x4e;
const TYPE_FALSE = 0x46;
const TYPE_TRUE = 0x54;
const TYPE_STOPITER = 0x53;
const TYPE_ELLIPSIS = 0x2e;
const TYPE_INT = 0x69;
const TYPE_INT64 = 0x49;
const TYPE_FLOAT_TEXT = 0x66;
const TYPE_FLOAT = 0x67;
const TYPE_COMPLEX_TEXT = 0x78;
const TYPE_COMPLEX = 0x79;
const TYPE_LONG = 0x6c;
const TYPE_BYTES = 0x73;
const TYPE_INTERNED = 0x74;
const TYPE_REF = 0x72;
const TYPE_TUPLE = 0x28;
const TYPE_LIST = 0x5b;
const TYPE_DICT = 0x7b;
const TYPE_CODE = 0x63;
const TYPE_UNICODE = 0x75;
const TYPE_SET = 0x3c;
const TYPE_FROZENSET = 0x3e;
const TYPE_ASCII = 0x61;
const TYPE_ASCII_INTERNED = 0x41;
const TYPE_SMALL_TUPLE = 0x29;
const TYPE_SHORT_ASCII = 0x7a;
const TYPE_SHORT_ASCII_INTERNED = 0x5a;
const TYPE_SLICE = 0x3a; // marshal version 5 (CPython 3.14 constant slices)

/** Deeper nesting than any compiler output; keeps hostile input off the JS stack limit. */
const MAX_MARSHAL_DEPTH = 400;
// Stable CPython 3.11 and 3.12 magic numbers share RESUME, LOAD_CONST and
// RETURN_VALUE. Marshal CODE layout compatibility alone says nothing about opcodes.
const WEAVABLE_MAGIC = new Set([3495, 3531]);

const MAGIC_LAYOUT: ReadonlyMap<number, PythonPycCodeLayout> = new Map([
  // CPython marshal CODE layout families (see Include/internal/pycore_magic_number.h).
  ...range(3390, 3394, "py37"),
  ...range(3400, 3401, "py37"),
  ...range(3410, 3439, "py38"), // 3.8–3.10 (posonly + nlocals/varnames)
  ...range(3450, 3495, "py311"), // 3.11 (localsplus; nlocals dropped)
  ...range(3500, 3531, "py311"), // 3.12
  ...range(3550, 3571, "py311"), // 3.13
  ...range(3600, 3627, "py311"), // 3.14 (Ubuntu 26+ runners)
  ...range(3650, 3699, "py311"), // 3.15 headroom
]);

function range(
  start: number,
  end: number,
  layout: PythonPycCodeLayout,
): Array<[number, PythonPycCodeLayout]> {
  const out: Array<[number, PythonPycCodeLayout]> = [];
  for (let m = start; m <= end; m++) out.push([m, layout]);
  return out;
}

export function layoutForPycMagic(magic: number): PythonPycCodeLayout | null {
  return MAGIC_LAYOUT.get(magic) ?? null;
}

const MUNDANE_STEMS = [
  "reconcile_invoice_batch",
  "hydrate_session_cache",
  "flush_telemetry_buffer",
  "normalize_locale_bundle",
  "schedule_backoff_retry",
  "compact_wal_segment",
  "project_catalog_facet",
  "bind_worker_pool_slot",
  "materialize_report_cursor",
  "encode_transport_frame",
  "observe_metric_histogram",
  "adapt_gateway_policy",
  "reduce_pipeline_shard",
  "capture_audit_sample",
  "prime_connection_pool",
  "transform_lookup_vector",
] as const;

const SCARE_STEMS = [
  "verify_enclave_attestation",
  "derive_hardware_kdf_schedule",
  "authenticate_tpm_quote_digest",
  "negotiate_vsock_channel_cipher",
  "synchronize_hsm_key_slot",
  "unseal_protected_memory_page",
] as const;

export interface PythonPycWeaveResult {
  readonly buffer: Buffer;
  readonly decoyCodeObjectsInjected: number;
  readonly customerDefsWoven: number;
  readonly layout: PythonPycCodeLayout;
}

/** A byte range of the input that is copied to the output unchanged. */
type RawRange = readonly [from: number, to: number];

/** One object of the marshal stream and where it sits in the input. */
interface MarshalNode {
  /** Type code without FLAG_REF. */
  readonly type: number;
  /** Offset of the type byte. */
  readonly start: number;
  /** Offset just past the object. */
  end: number;
  /** Everything after the type byte, in stream order. */
  readonly parts: Array<MarshalNode | RawRange>;
  /** The reader enters this object in its reference table. */
  readonly registers: boolean;
  /** How many TYPE_REF objects in the stream designate this object. */
  refCount: number;
  /** TYPE_REF: the object it designates. */
  target: MarshalNode | null;
  /** TYPE_CODE: where the fields the weave needs sit within `parts`. */
  code: { readonly consts: number; readonly filename: number; readonly name: number } | null;
  /** Still being read — a reference to it now would be a cycle. */
  open: boolean;

  // Weave edits, applied when the object is written back.
  /** Write with FLAG_REF so that new references can designate it. */
  promote: boolean;
  /** Tuple: elements written after the original ones. */
  appended: readonly OutputItem[] | null;
  /** Code object: written in place of its `co_consts` field. */
  constsOverride: OutputItem | null;
}

/** Something written to the output stream. */
type OutputItem =
  | { readonly kind: "node"; readonly node: MarshalNode }
  | { readonly kind: "ref"; readonly target: MarshalNode }
  /** Bytes that contain no FLAG_REF object and no TYPE_REF. */
  | { readonly kind: "raw"; readonly bytes: Buffer }
  | { readonly kind: "sequence"; readonly items: readonly OutputItem[] }
  /**
   * A new tuple. With `identity` it is written with FLAG_REF and answers every
   * reference to that original object from here on.
   */
  | {
      readonly kind: "tuple";
      readonly items: readonly OutputItem[];
      readonly identity: MarshalNode | null;
    };

function isSingletonType(type: number): boolean {
  return (
    type === TYPE_NONE ||
    type === TYPE_TRUE ||
    type === TYPE_FALSE ||
    type === TYPE_ELLIPSIS ||
    type === TYPE_STOPITER
  );
}

function isTupleType(type: number): boolean {
  return type === TYPE_TUPLE || type === TYPE_SMALL_TUPLE;
}

function isStringType(type: number): boolean {
  return (
    type === TYPE_UNICODE ||
    type === TYPE_INTERNED ||
    type === TYPE_ASCII ||
    type === TYPE_ASCII_INTERNED ||
    type === TYPE_SHORT_ASCII ||
    type === TYPE_SHORT_ASCII_INTERNED
  );
}

function isRawRange(part: MarshalNode | RawRange): part is RawRange {
  return Array.isArray(part);
}

function childrenOf(node: MarshalNode): MarshalNode[] {
  const out: MarshalNode[] = [];
  for (const part of node.parts) {
    if (!isRawRange(part)) out.push(part);
  }
  return out;
}

/** Follow a TYPE_REF to the object it designates. */
function resolve(node: MarshalNode): MarshalNode {
  return node.type === TYPE_REF ? node.target! : node;
}

/**
 * Parses a marshal stream into {@link MarshalNode}s without interpreting any
 * payload. Reference-table bookkeeping mirrors CPython's `r_object`: an object
 * with FLAG_REF takes the next index when its type byte is read (containers
 * and code objects reserve theirs before their children), and the singletons
 * and TYPE_REF itself never take one.
 */
class MarshalParser {
  offset = 0;
  private readonly refs: MarshalNode[] = [];
  private depth = 0;

  constructor(
    private readonly buf: Buffer,
    private readonly layout: PythonPycCodeLayout,
  ) {}

  private need(count: number): void {
    if (count < 0 || this.offset + count > this.buf.length) {
      throw new Error("truncated marshal data");
    }
  }

  private u8(): number {
    this.need(1);
    return this.buf[this.offset++]!;
  }

  private u32(): number {
    this.need(4);
    const value = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  private i32(): number {
    this.need(4);
    const value = this.buf.readInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  /** Consume `count` payload bytes as one raw part. */
  private raw(node: MarshalNode, from: number, count: number): void {
    this.need(count);
    this.offset += count;
    node.parts.push([from, this.offset]);
  }

  private child(node: MarshalNode): MarshalNode {
    const child = this.parse();
    node.parts.push(child);
    return child;
  }

  parse(): MarshalNode {
    if (++this.depth > MAX_MARSHAL_DEPTH) throw new Error("marshal data nested too deeply");
    const start = this.offset;
    const byte = this.u8();
    const type = byte & ~FLAG_REF;
    const node: MarshalNode = {
      type,
      start,
      end: start,
      parts: [],
      registers:
        (byte & FLAG_REF) !== 0 && type !== TYPE_REF && type !== TYPE_NULL && !isSingletonType(type),
      refCount: 0,
      target: null,
      code: null,
      open: true,
      promote: false,
      appended: null,
      constsOverride: null,
    };
    if (node.registers) this.refs.push(node);
    this.readBody(node);
    node.end = this.offset;
    node.open = false;
    this.depth -= 1;
    return node;
  }

  private readBody(node: MarshalNode): void {
    const bodyStart = this.offset;
    switch (node.type) {
      case TYPE_NONE:
      case TYPE_TRUE:
      case TYPE_FALSE:
      case TYPE_ELLIPSIS:
      case TYPE_STOPITER:
        return;
      case TYPE_INT:
        return this.raw(node, bodyStart, 4);
      case TYPE_INT64:
      case TYPE_FLOAT:
        return this.raw(node, bodyStart, 8);
      case TYPE_COMPLEX:
        return this.raw(node, bodyStart, 16);
      case TYPE_FLOAT_TEXT: {
        const length = this.u8();
        return this.raw(node, bodyStart, length);
      }
      case TYPE_COMPLEX_TEXT: {
        const real = this.u8();
        this.need(real);
        this.offset += real;
        const imaginary = this.u8();
        return this.raw(node, bodyStart, imaginary);
      }
      case TYPE_LONG: {
        const digits = Math.abs(this.i32());
        return this.raw(node, bodyStart, digits * 2);
      }
      case TYPE_BYTES:
      case TYPE_INTERNED:
      case TYPE_UNICODE:
      case TYPE_ASCII:
      case TYPE_ASCII_INTERNED: {
        const length = this.u32();
        return this.raw(node, bodyStart, length);
      }
      case TYPE_SHORT_ASCII:
      case TYPE_SHORT_ASCII_INTERNED: {
        const length = this.u8();
        return this.raw(node, bodyStart, length);
      }
      case TYPE_SMALL_TUPLE:
      case TYPE_TUPLE:
      case TYPE_LIST:
      case TYPE_SET:
      case TYPE_FROZENSET: {
        const count = node.type === TYPE_SMALL_TUPLE ? this.u8() : this.i32();
        // Every element takes at least one byte.
        if (count < 0 || count > this.buf.length - this.offset) {
          throw new Error("bad marshal sequence size");
        }
        node.parts.push([bodyStart, this.offset]);
        for (let i = 0; i < count; i++) this.element(node);
        return;
      }
      case TYPE_DICT: {
        for (;;) {
          this.need(1);
          if ((this.buf[this.offset]! & ~FLAG_REF) === TYPE_NULL) {
            return this.raw(node, this.offset, 1);
          }
          this.element(node);
          this.element(node);
        }
      }
      case TYPE_SLICE:
        this.element(node);
        this.element(node);
        this.element(node);
        return;
      case TYPE_CODE:
        return this.readCode(node, bodyStart);
      case TYPE_REF: {
        const index = this.u32();
        const target = this.refs[index];
        if (target === undefined || target.open) {
          throw new Error(`invalid marshal reference ${index}`);
        }
        target.refCount += 1;
        node.target = target;
        node.parts.push([bodyStart, this.offset]);
        return;
      }
      default:
        throw new Error(`unsupported marshal type 0x${node.type.toString(16)}`);
    }
  }

  /** A container element: any object except the NULL terminator. */
  private element(node: MarshalNode): MarshalNode {
    const child = this.child(node);
    if (child.type === TYPE_NULL) throw new Error("NULL object in marshal data");
    return child;
  }

  private readCode(node: MarshalNode, bodyStart: number): void {
    const expect = (matches: (type: number) => boolean): MarshalNode => {
      const value = resolve(this.element(node));
      if (!matches(value.type)) throw new Error("unexpected marshal code field type");
      return value;
    };
    const isBytes = (type: number): boolean => type === TYPE_BYTES;
    // argcount, [posonlyargcount], kwonlyargcount, [nlocals], stacksize, flags
    const headerInts =
      this.layout === "py37" ? 5 : this.layout === "py38" ? 6 : 5;
    this.raw(node, bodyStart, headerInts * 4);
    const countAt = (index: number): number => this.buf.readInt32LE(bodyStart + index * 4);
    for (let i = 0; i < headerInts; i++) {
      if (countAt(i) < 0) throw new Error("negative marshal code field");
    }
    const argCount = countAt(0);
    const posOnly = this.layout === "py37" ? 0 : countAt(1);
    const kwOnly = countAt(this.layout === "py37" ? 1 : 2);
    const flags = countAt(headerInts - 1);
    if (posOnly > argCount) throw new Error("inconsistent positional argument counts");
    const requiredLocals = argCount + kwOnly + Number(!!(flags & 4)) + Number(!!(flags & 8));
    const code = expect(isBytes); // co_code
    const codeLength = this.buf.readUInt32LE(code.start + 1);
    if (codeLength === 0 || codeLength % 2 !== 0) throw new Error("invalid co_code length");
    const consts = node.parts.length;
    expect(isTupleType); // co_consts
    expect(isTupleType); // co_names
    if (this.layout === "py311") {
      const names = expect(isTupleType); // co_localsplusnames
      const kinds = expect(isBytes); // co_localspluskinds
      if (childrenOf(names).length !== this.buf.readUInt32LE(kinds.start + 1)) {
        throw new Error("inconsistent co_localsplusnames and co_localspluskinds");
      }
      let locals = 0;
      for (const kind of this.buf.subarray(kinds.start + 5, kinds.end)) {
        if (kind & 0x20) locals++;
      }
      if (locals < requiredLocals) throw new Error("too few local slots for code arguments");
    } else {
      const names = expect(isTupleType); // co_varnames
      if (childrenOf(names).length !== countAt(headerInts - 3) ||
          childrenOf(names).length < requiredLocals) {
        throw new Error("inconsistent co_varnames and argument counts");
      }
      expect(isTupleType); // co_freevars
      expect(isTupleType); // co_cellvars
    }
    const filename = node.parts.length;
    expect(isStringType);
    const name = node.parts.length;
    expect(isStringType);
    if (this.layout === "py311") expect(isStringType); // co_qualname
    this.raw(node, this.offset, 4); // co_firstlineno
    expect(isBytes); // co_linetable / co_lnotab
    if (this.layout === "py311") expect(isBytes); // co_exceptiontable
    node.code = { consts, filename, name };
  }
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}
function i32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeInt32LE(n, 0);
  return b;
}

/**
 * Writes nodes and additions back out. Reference indices are handed out in
 * output order, so adding or removing FLAG_REF objects renumbers every later
 * TYPE_REF consistently.
 */
class MarshalWriter {
  private readonly chunks: Buffer[] = [];
  private readonly refIndex = new Map<MarshalNode, number>();
  private nextRef = 0;

  constructor(private readonly input: Buffer) {}

  finish(): Buffer {
    return Buffer.concat(this.chunks);
  }

  private tupleHeader(count: number, flag: number, small: boolean): void {
    if (small && count <= 255) {
      this.chunks.push(Buffer.from([TYPE_SMALL_TUPLE | flag, count]));
    } else {
      this.chunks.push(Buffer.from([TYPE_TUPLE | flag]), u32(count));
    }
  }

  private writeRef(target: MarshalNode, typeByte: number): void {
    const index = this.refIndex.get(target);
    if (index === undefined) throw new Error("marshal reference to an object not yet written");
    this.chunks.push(Buffer.from([typeByte]), u32(index));
  }

  writeNode(node: MarshalNode): void {
    const inputByte = this.input[node.start]!;
    if (node.type === TYPE_REF) {
      this.writeRef(node.target!, inputByte);
      return;
    }
    const registers = node.registers || node.promote;
    if (registers) this.refIndex.set(node, this.nextRef++);
    const flag = registers ? FLAG_REF : inputByte & FLAG_REF;

    if (node.appended) {
      const elements = childrenOf(node);
      this.tupleHeader(
        elements.length + node.appended.length,
        flag,
        node.type === TYPE_SMALL_TUPLE,
      );
      for (const element of elements) this.writeNode(element);
      for (const item of node.appended) this.write(item);
      return;
    }

    this.chunks.push(Buffer.from([node.type | flag]));
    for (let index = 0; index < node.parts.length; index++) {
      const part = node.parts[index]!;
      if (isRawRange(part)) {
        this.chunks.push(this.input.subarray(part[0], part[1]));
      } else if (node.constsOverride && node.code && index === node.code.consts) {
        this.write(node.constsOverride);
      } else {
        this.writeNode(part);
      }
    }
  }

  write(item: OutputItem): void {
    switch (item.kind) {
      case "node":
        return this.writeNode(item.node);
      case "ref":
        return this.writeRef(item.target, TYPE_REF);
      case "raw":
        this.chunks.push(item.bytes);
        return;
      case "sequence":
        for (const part of item.items) this.write(part);
        return;
      case "tuple":
        if (item.identity) this.refIndex.set(item.identity, this.nextRef++);
        this.tupleHeader(item.items.length, item.identity ? FLAG_REF : 0, true);
        for (const part of item.items) this.write(part);
        return;
    }
  }
}

/** Payload bytes of a string object (after its length prefix). */
function stringPayload(buf: Buffer, node: MarshalNode): Buffer {
  const short = node.type === TYPE_SHORT_ASCII || node.type === TYPE_SHORT_ASCII_INTERNED;
  return buf.subarray(node.start + (short ? 2 : 5), node.end);
}

function shortAscii(text: string): Buffer {
  const bytes = Buffer.from(text, "ascii");
  return Buffer.concat([Buffer.from([TYPE_SHORT_ASCII, bytes.length]), bytes]);
}

/**
 * A decoy code object: `return None`, no FLAG_REF anywhere inside, so adding it
 * leaves the reference table of the surrounding stream untouched.
 */
function buildDecoyCode(
  layout: PythonPycCodeLayout,
  name: string,
  filename: OutputItem,
): OutputItem {
  const emptyTuple = Buffer.from([TYPE_SMALL_TUPLE, 0]);
  const emptyBytes = Buffer.concat([Buffer.from([TYPE_BYTES]), u32(0)]);
  const head: Buffer[] = [Buffer.from([TYPE_CODE]), u32(0)]; // argcount
  if (layout !== "py37") head.push(u32(0)); // posonlyargcount
  head.push(u32(0)); // kwonlyargcount
  if (layout !== "py311") head.push(u32(0)); // nlocals
  head.push(i32(1), i32(0x40)); // stacksize, flags (CO_NOFREE)
  // CPython 3.11/3.12: RESUME 0; LOAD_CONST 0; RETURN_VALUE.
  head.push(Buffer.from([TYPE_BYTES]), u32(6), Buffer.from([0x97, 0, 0x64, 0, 0x53, 0]));
  head.push(Buffer.from([TYPE_SMALL_TUPLE, 1, TYPE_NONE])); // co_consts
  head.push(emptyTuple); // co_names
  if (layout === "py311") {
    head.push(emptyTuple, emptyBytes); // co_localsplusnames, co_localspluskinds
  } else {
    head.push(emptyTuple, emptyTuple, emptyTuple); // co_varnames, co_freevars, co_cellvars
  }
  const tail: Buffer[] = [shortAscii(name)]; // co_name
  if (layout === "py311") tail.push(shortAscii(name)); // co_qualname
  tail.push(i32(1), emptyBytes); // co_firstlineno, co_linetable
  if (layout === "py311") tail.push(emptyBytes); // co_exceptiontable
  return {
    kind: "sequence",
    items: [
      { kind: "raw", bytes: Buffer.concat(head) },
      filename,
      { kind: "raw", bytes: Buffer.concat(tail) },
    ],
  };
}

function decoyCountForIntensity(intensity: ProtectionIntensity): number {
  switch (intensity) {
    case "stealth":
      return 2;
    case "balanced":
      return 6;
    case "maximum":
      return 12;
    case "bankrupt":
      return 20;
    default:
      return 6;
  }
}

function pickDecoyName(prng: SeededPrng, index: number): string {
  const scare = index % 3 === 0;
  const pool = scare ? SCARE_STEMS : MUNDANE_STEMS;
  const stem = pool[prng.nextInt(0, pool.length - 1)]!;
  return `${stem}_${prng.nextInt(1000, 9999)}`;
}

interface WeavePlan {
  readonly code: MarshalNode;
  /** The object in the code's `co_consts` field (a tuple, or a reference to one). */
  readonly constsField: MarshalNode;
  /** The tuple object itself. */
  readonly tuple: MarshalNode;
  readonly decoys: readonly OutputItem[];
}

/** How a new tuple refers to an element of an existing one. */
function referenceTo(element: MarshalNode): OutputItem {
  if (isSingletonType(element.type)) {
    return { kind: "raw", bytes: Buffer.from([element.type]) };
  }
  if (element.type === TYPE_REF) return { kind: "ref", target: element.target! };
  element.promote = true;
  return { kind: "ref", target: element };
}

/**
 * Decide the decoys for every code object (children first, then the object
 * itself — the order the PRNG has always been drawn in) and record them as
 * edits on the tree.
 */
function planWeave(
  root: MarshalNode,
  buf: Buffer,
  layout: PythonPycCodeLayout,
  prng: SeededPrng,
  moduleDecoys: number,
): { injected: number; woven: number } {
  const stats = { injected: 0, woven: 0 };
  const plans: WeavePlan[] = [];
  const planned = new Set<MarshalNode>();

  const visit = (code: MarshalNode, isRoot: boolean): void => {
    if (planned.has(code)) return;
    planned.add(code);
    const fields = code.code!;
    const constsField = code.parts[fields.consts] as MarshalNode;
    const tuple = resolve(constsField);
    if (!isTupleType(tuple.type)) throw new Error("co_consts not tuple");
    const filenameField = code.parts[fields.filename] as MarshalNode;
    const filename = resolve(filenameField);
    const name = resolve(code.parts[fields.name] as MarshalNode);
    if (!isStringType(filename.type)) throw new Error("co_filename not str");
    if (!isStringType(name.type)) throw new Error("co_name not str");

    for (const element of childrenOf(tuple)) {
      const nested = resolve(element);
      if (nested.type === TYPE_CODE) visit(nested, false);
    }

    const isModule = stringPayload(buf, name).equals(Buffer.from("<module>", "ascii"));
    const decoysToAdd = isRoot ? moduleDecoys : !isModule ? 1 : 0;
    if (decoysToAdd === 0) return;
    if (!isRoot) stats.woven += 1;

    // The decoys reuse the customer's own filename object. They are written
    // inside co_consts, i.e. before the code object's own filename field, so a
    // reference is only possible when the string was defined before that point;
    // otherwise they carry a copy of its bytes (same type code, no FLAG_REF).
    let decoyFilename: OutputItem;
    if (stringPayload(buf, filename).length === 0) {
      decoyFilename = { kind: "raw", bytes: shortAscii("shielded.py") };
    } else if (filename.registers && filename.start < constsField.end) {
      decoyFilename = { kind: "ref", target: filename };
    } else {
      const copy = Buffer.from(buf.subarray(filename.start, filename.end));
      copy[0] = filename.type;
      decoyFilename = { kind: "raw", bytes: copy };
    }

    const decoys: OutputItem[] = [];
    for (let i = 0; i < decoysToAdd; i++) {
      const decoyName = pickDecoyName(prng, stats.injected + i);
      decoys.push(buildDecoyCode(layout, decoyName, decoyFilename));
      stats.injected += 1;
    }
    plans.push({ code, constsField, tuple, decoys });
  };
  visit(root, true);

  // References to each tuple that disappear because the referring code object
  // gets a tuple of its own.
  const replacedRefs = new Map<MarshalNode, number>();
  for (const plan of plans) {
    if (plan.constsField !== plan.tuple) {
      replacedRefs.set(plan.tuple, (replacedRefs.get(plan.tuple) ?? 0) + 1);
    }
  }

  for (const { code, constsField, tuple, decoys } of plans) {
    const elements = childrenOf(tuple);
    if (constsField === tuple && tuple.refCount === 0) {
      // Nothing else can see this tuple: grow it in place.
      tuple.appended = decoys;
      continue;
    }
    if (constsField !== tuple) {
      // co_consts is a reference to a tuple defined elsewhere. Leave that
      // object alone; this code object gets its own tuple of the same elements.
      code.constsOverride = {
        kind: "tuple",
        identity: null,
        items: [...elements.map(referenceTo), ...decoys],
      };
      continue;
    }
    // co_consts defines a tuple that other objects reference. The elements are
    // written here as before, inside this code object's own tuple; if any
    // reference to the original tuple remains, an equal tuple of the very same
    // elements follows and takes over its place in the reference table.
    const remaining = tuple.refCount - (replacedRefs.get(tuple) ?? 0);
    const items: OutputItem[] = elements.map((node) => ({ kind: "node", node }));
    items.push(...decoys);
    if (remaining > 0) {
      items.push({ kind: "tuple", identity: tuple, items: elements.map(referenceTo) });
    }
    code.constsOverride = { kind: "tuple", identity: null, items };
  }
  return stats;
}

function countCodeObjects(node: MarshalNode): number {
  let count = node.type === TYPE_CODE ? 1 : 0;
  for (const child of childrenOf(node)) count += countCodeObjects(child);
  return count;
}

/** Validate the PEP 552 header and the complete root object, allowing trailers. */
export function validatePythonPycRoot(bytes: Buffer): void {
  if (bytes.length < 16 || bytes[2] !== 0x0d || bytes[3] !== 0x0a ||
      (bytes.readUInt32LE(4) & ~3) !== 0) {
    throw new Error("Invalid CPython .pyc header (magic marker or PEP 552 flags)");
  }
  const layout = layoutForPycMagic(bytes.readUInt16LE(0));
  if (!layout) throw new Error("Unsupported CPython .pyc magic; cannot validate the root code object");
  try {
    const root = new MarshalParser(bytes.subarray(16), layout).parse();
    if (root.type !== TYPE_CODE) throw new Error("root marshal object is not code");
  } catch (error) {
    throw new Error("Invalid or truncated CPython .pyc root code object", { cause: error });
  }
}

/**
 * Weave unused decoy CODE objects into a CPython .pyc buffer.
 * Returns null when magic/layout is unknown or the marshal stream cannot be
 * rewritten faithfully.
 */
export function weavePythonPycBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): PythonPycWeaveResult | null {
  if (bytes.length < 17 || bytes[2] !== 0x0d || bytes[3] !== 0x0a) return null;
  const magic = bytes.readUInt16LE(0);
  if (!WEAVABLE_MAGIC.has(magic)) return null;
  const layout = layoutForPycMagic(magic);
  if (!layout) return null;

  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-pyc-weave-v1");
  const moduleDecoys = decoyCountForIntensity(intensity);

  try {
    const header = bytes.subarray(0, 16);
    const payload = bytes.subarray(16);
    const parser = new MarshalParser(payload, layout);
    const root = parser.parse();
    if (root.type !== TYPE_CODE) return null;
    const trailing = payload.subarray(parser.offset);

    const stats = planWeave(root, payload, layout, prng, moduleDecoys);
    const writer = new MarshalWriter(payload);
    writer.writeNode(root);
    const wovenRoot = writer.finish();

    // The output must read back as one code object holding exactly the
    // original code objects plus the decoys.
    const check = new MarshalParser(wovenRoot, layout);
    const wovenTree = check.parse();
    if (
      check.offset !== wovenRoot.length ||
      wovenTree.type !== TYPE_CODE ||
      countCodeObjects(wovenTree) !== countCodeObjects(root) + stats.injected
    ) {
      return null;
    }

    return {
      buffer: Buffer.concat([header, wovenRoot, trailing]),
      decoyCodeObjectsInjected: stats.injected,
      customerDefsWoven: stats.woven,
      layout,
    };
  } catch {
    return null;
  }
}
