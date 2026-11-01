/**
 * Structural .pyc decoy weave — remmarshal code objects so unused decoy
 * TYPE_CODE entries sit in customer/module `co_consts` pools.
 *
 * REA `inspect_python_pyc` inventories them as real functions; CPython never
 * executes them (no MAKE_FUNCTION / call references them).
 *
 * Safety rules (engineering red line):
 * - Decode with a FLAG_REF intern table, then re-emit WITHOUT FLAG_REF so
 *   shared consts/filename refs expand to concrete copies (behavior-identical).
 * - Original co_code / arg counts / flags / names tables preserved.
 * - On unsupported marshal forms, abort and let caller keep trailer-only honey.
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

type MarshalValue =
  | { readonly kind: "none" }
  | { readonly kind: "bool"; readonly value: boolean }
  | { readonly kind: "ellipsis" }
  | { readonly kind: "stopiter" }
  | { readonly kind: "int"; readonly value: number }
  | { readonly kind: "int64"; readonly bytes: Buffer }
  | { readonly kind: "float"; readonly bytes: Buffer }
  | { readonly kind: "complex"; readonly bytes: Buffer }
  | { readonly kind: "float_text"; readonly text: string }
  | { readonly kind: "complex_text"; readonly real: string; readonly imag: string }
  | { readonly kind: "long"; readonly digits: Buffer; readonly negative: boolean }
  | { readonly kind: "bytes"; readonly data: Buffer }
  | { readonly kind: "str"; readonly data: string }
  | { readonly kind: "tuple"; readonly items: MarshalValue[] }
  | { readonly kind: "list"; readonly items: MarshalValue[] }
  | { readonly kind: "set"; readonly items: MarshalValue[]; readonly frozen: boolean }
  | { readonly kind: "dict"; readonly items: Array<[MarshalValue, MarshalValue]> }
  | { readonly kind: "code"; readonly code: CodeValue };

interface CodeValue {
  argcount: number;
  posonlyargcount: number | null;
  kwonlyargcount: number;
  nlocals: number | null;
  stacksize: number;
  flags: number;
  bytecode: Buffer;
  consts: MarshalValue[];
  names: MarshalValue[];
  localsplusnames: MarshalValue[] | null;
  localspluskinds: Buffer | null;
  varnames: MarshalValue[] | null;
  freevars: MarshalValue[] | null;
  cellvars: MarshalValue[] | null;
  filename: string;
  name: string;
  qualname: string | null;
  firstlineno: number;
  linetable: Buffer;
  exceptiontable: Buffer | null;
}

class Reader {
  offset = 0;
  readonly refs: MarshalValue[] = [];
  constructor(
    readonly buf: Buffer,
    readonly layout: PythonPycCodeLayout,
  ) {}

  u8(): number {
    if (this.offset >= this.buf.length) throw new Error("truncated u8");
    return this.buf[this.offset++]!;
  }
  i32(): number {
    if (this.offset + 4 > this.buf.length) throw new Error("truncated i32");
    const v = this.buf.readInt32LE(this.offset);
    this.offset += 4;
    return v;
  }
  u32(): number {
    if (this.offset + 4 > this.buf.length) throw new Error("truncated u32");
    const v = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return v;
  }
  slice(n: number): Buffer {
    if (n < 0 || this.offset + n > this.buf.length) throw new Error("truncated slice");
    const s = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return Buffer.from(s);
  }

  read(): MarshalValue {
    const raw = this.u8();
    const flagged = (raw & FLAG_REF) !== 0;
    const type = raw & ~FLAG_REF;
    if (type === TYPE_REF) {
      const idx = this.u32();
      const hit = this.refs[idx];
      if (hit === undefined || hit === null) {
        throw new Error(`bad TYPE_REF ${idx} (have ${this.refs.length})`);
      }
      return hit;
    }
    // CPython reserves FLAG_REF slots for containers BEFORE reading children so
    // nested TYPE_REF indices stay stable (see Python/marshal.c r_object).
    // Match CPython: tuples/lists/dicts/sets R_REF before children;
    // CODE and non-empty frozenset use r_ref_reserve before body (marshal.c).
    const earlyContainer =
      type === TYPE_TUPLE ||
      type === TYPE_SMALL_TUPLE ||
      type === TYPE_LIST ||
      type === TYPE_DICT ||
      type === TYPE_SET ||
      type === TYPE_FROZENSET ||
      type === TYPE_CODE;
    let slot = -1;
    if (flagged && earlyContainer) {
      slot = this.refs.length;
      this.refs.push(null as unknown as MarshalValue);
    }
    const value = this.readType(type);
    if (flagged) {
      if (slot >= 0) this.refs[slot] = value;
      else this.refs.push(value);
    }
    return value;
  }

  private readType(type: number): MarshalValue {
    switch (type) {
      case TYPE_NULL:
        throw new Error("unexpected NULL");
      case TYPE_NONE:
        return { kind: "none" };
      case TYPE_FALSE:
        return { kind: "bool", value: false };
      case TYPE_TRUE:
        return { kind: "bool", value: true };
      case TYPE_STOPITER:
        return { kind: "stopiter" };
      case TYPE_ELLIPSIS:
        return { kind: "ellipsis" };
      case TYPE_INT:
        return { kind: "int", value: this.i32() };
      case TYPE_INT64:
        return { kind: "int64", bytes: this.slice(8) };
      case TYPE_FLOAT:
        return { kind: "float", bytes: this.slice(8) };
      case TYPE_COMPLEX:
        return { kind: "complex", bytes: this.slice(16) };
      case TYPE_FLOAT_TEXT: {
        const n = this.u8();
        return { kind: "float_text", text: this.slice(n).toString("ascii") };
      }
      case TYPE_COMPLEX_TEXT: {
        const n1 = this.u8();
        const real = this.slice(n1).toString("ascii");
        const n2 = this.u8();
        const imag = this.slice(n2).toString("ascii");
        return { kind: "complex_text", real, imag };
      }
      case TYPE_LONG: {
        const n = this.i32();
        const abs = Math.abs(n);
        return {
          kind: "long",
          digits: this.slice(abs * 2),
          negative: n < 0,
        };
      }
      case TYPE_BYTES: {
        const n = this.u32();
        return { kind: "bytes", data: this.slice(n) };
      }
      case TYPE_INTERNED:
      case TYPE_UNICODE:
      case TYPE_ASCII:
      case TYPE_ASCII_INTERNED: {
        const n = this.u32();
        return { kind: "str", data: this.slice(n).toString("utf8") };
      }
      case TYPE_SHORT_ASCII:
      case TYPE_SHORT_ASCII_INTERNED: {
        const n = this.u8();
        return { kind: "str", data: this.slice(n).toString("utf8") };
      }
      case TYPE_SMALL_TUPLE: {
        const n = this.u8();
        const items: MarshalValue[] = [];
        for (let i = 0; i < n; i++) items.push(this.read());
        return { kind: "tuple", items };
      }
      case TYPE_TUPLE: {
        const n = this.u32();
        const items: MarshalValue[] = [];
        for (let i = 0; i < n; i++) items.push(this.read());
        return { kind: "tuple", items };
      }
      case TYPE_LIST: {
        const n = this.u32();
        const items: MarshalValue[] = [];
        for (let i = 0; i < n; i++) items.push(this.read());
        return { kind: "list", items };
      }
      case TYPE_SET:
      case TYPE_FROZENSET: {
        const n = this.u32();
        const items: MarshalValue[] = [];
        for (let i = 0; i < n; i++) items.push(this.read());
        return { kind: "set", items, frozen: type === TYPE_FROZENSET };
      }
      case TYPE_DICT: {
        const items: Array<[MarshalValue, MarshalValue]> = [];
        while (true) {
          const raw = this.buf[this.offset];
          if (raw === undefined) throw new Error("dict truncated");
          if ((raw & ~FLAG_REF) === TYPE_NULL) {
            this.u8();
            break;
          }
          const k = this.read();
          const v = this.read();
          items.push([k, v]);
        }
        return { kind: "dict", items };
      }
      case TYPE_CODE:
        return { kind: "code", code: this.readCode() };
      default:
        throw new Error(`unsupported marshal type 0x${type.toString(16)}`);
    }
  }

  private readCode(): CodeValue {
    const argcount = this.u32();
    const posonlyargcount = this.layout === "py37" ? null : this.u32();
    const kwonlyargcount = this.u32();
    const nlocals = this.layout === "py311" ? null : this.u32();
    const stacksize = this.i32();
    const flags = this.i32();
    const bytecodeVal = this.read();
    if (bytecodeVal.kind !== "bytes") throw new Error("co_code not bytes");
    const constsVal = this.read();
    if (constsVal.kind !== "tuple") throw new Error("co_consts not tuple");
    const namesVal = this.read();
    if (namesVal.kind !== "tuple") throw new Error("co_names not tuple");

    let localsplusnames: MarshalValue[] | null = null;
    let localspluskinds: Buffer | null = null;
    let varnames: MarshalValue[] | null = null;
    let freevars: MarshalValue[] | null = null;
    let cellvars: MarshalValue[] | null = null;
    if (this.layout === "py311") {
      const lp = this.read();
      if (lp.kind !== "tuple") throw new Error("localsplusnames not tuple");
      localsplusnames = lp.items;
      const lk = this.read();
      if (lk.kind !== "bytes") throw new Error("localspluskinds not bytes");
      localspluskinds = lk.data;
    } else {
      const vn = this.read();
      const fv = this.read();
      const cv = this.read();
      if (vn.kind !== "tuple" || fv.kind !== "tuple" || cv.kind !== "tuple") {
        throw new Error("var/free/cell names not tuples");
      }
      varnames = vn.items;
      freevars = fv.items;
      cellvars = cv.items;
    }

    const filenameVal = this.read();
    if (filenameVal.kind !== "str") throw new Error("co_filename not str");
    const nameVal = this.read();
    if (nameVal.kind !== "str") throw new Error("co_name not str");
    let qualname: string | null = null;
    if (this.layout === "py311") {
      const q = this.read();
      if (q.kind !== "str") throw new Error("co_qualname not str");
      qualname = q.data;
    }
    const firstlineno = this.i32();
    const lt = this.read();
    if (lt.kind !== "bytes") throw new Error("co_linetable not bytes");
    let exceptiontable: Buffer | null = null;
    if (this.layout === "py311") {
      const et = this.read();
      if (et.kind !== "bytes") throw new Error("co_exceptiontable not bytes");
      exceptiontable = et.data;
    }

    return {
      argcount,
      posonlyargcount,
      kwonlyargcount,
      nlocals,
      stacksize,
      flags,
      bytecode: bytecodeVal.data,
      consts: constsVal.items,
      names: namesVal.items,
      localsplusnames,
      localspluskinds,
      varnames,
      freevars,
      cellvars,
      filename: filenameVal.data,
      name: nameVal.data,
      qualname,
      firstlineno,
      linetable: lt.data,
      exceptiontable,
    };
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

function encode(value: MarshalValue, layout: PythonPycCodeLayout): Buffer {
  switch (value.kind) {
    case "none":
      return Buffer.from([TYPE_NONE]);
    case "bool":
      return Buffer.from([value.value ? TYPE_TRUE : TYPE_FALSE]);
    case "stopiter":
      return Buffer.from([TYPE_STOPITER]);
    case "ellipsis":
      return Buffer.from([TYPE_ELLIPSIS]);
    case "int":
      return Buffer.concat([Buffer.from([TYPE_INT]), i32(value.value)]);
    case "int64":
      return Buffer.concat([Buffer.from([TYPE_INT64]), value.bytes]);
    case "float":
      return Buffer.concat([Buffer.from([TYPE_FLOAT]), value.bytes]);
    case "complex":
      return Buffer.concat([Buffer.from([TYPE_COMPLEX]), value.bytes]);
    case "float_text": {
      const t = Buffer.from(value.text, "ascii");
      return Buffer.concat([Buffer.from([TYPE_FLOAT_TEXT, t.length]), t]);
    }
    case "complex_text": {
      const r = Buffer.from(value.real, "ascii");
      const im = Buffer.from(value.imag, "ascii");
      return Buffer.concat([
        Buffer.from([TYPE_COMPLEX_TEXT, r.length]),
        r,
        Buffer.from([im.length]),
        im,
      ]);
    }
    case "long": {
      const n = value.digits.length / 2;
      return Buffer.concat([
        Buffer.from([TYPE_LONG]),
        i32(value.negative ? -n : n),
        value.digits,
      ]);
    }
    case "bytes":
      return Buffer.concat([
        Buffer.from([TYPE_BYTES]),
        u32(value.data.length),
        value.data,
      ]);
    case "str": {
      const b = Buffer.from(value.data, "utf8");
      if (b.length <= 255) {
        return Buffer.concat([Buffer.from([TYPE_SHORT_ASCII, b.length]), b]);
      }
      return Buffer.concat([Buffer.from([TYPE_ASCII]), u32(b.length), b]);
    }
    case "tuple": {
      const parts = value.items.map((it) => encode(it, layout));
      if (value.items.length <= 255) {
        return Buffer.concat([
          Buffer.from([TYPE_SMALL_TUPLE, value.items.length]),
          ...parts,
        ]);
      }
      return Buffer.concat([Buffer.from([TYPE_TUPLE]), u32(value.items.length), ...parts]);
    }
    case "list": {
      const parts = value.items.map((it) => encode(it, layout));
      return Buffer.concat([Buffer.from([TYPE_LIST]), u32(value.items.length), ...parts]);
    }
    case "set": {
      const parts = value.items.map((it) => encode(it, layout));
      return Buffer.concat([
        Buffer.from([value.frozen ? TYPE_FROZENSET : TYPE_SET]),
        u32(value.items.length),
        ...parts,
      ]);
    }
    case "dict": {
      const parts: Buffer[] = [Buffer.from([TYPE_DICT])];
      for (const [k, v] of value.items) {
        parts.push(encode(k, layout), encode(v, layout));
      }
      parts.push(Buffer.from([TYPE_NULL]));
      return Buffer.concat(parts);
    }
    case "code":
      return encodeCode(value.code, layout);
    default: {
      const _exhaustive: never = value;
      return _exhaustive;
    }
  }
}

function encodeCode(code: CodeValue, layout: PythonPycCodeLayout): Buffer {
  const parts: Buffer[] = [Buffer.from([TYPE_CODE]), u32(code.argcount)];
  if (layout !== "py37") parts.push(u32(code.posonlyargcount ?? 0));
  parts.push(u32(code.kwonlyargcount));
  if (layout !== "py311") parts.push(u32(code.nlocals ?? 0));
  parts.push(i32(code.stacksize), i32(code.flags));
  parts.push(encode({ kind: "bytes", data: code.bytecode }, layout));
  parts.push(encode({ kind: "tuple", items: code.consts }, layout));
  parts.push(encode({ kind: "tuple", items: code.names }, layout));
  if (layout === "py311") {
    parts.push(encode({ kind: "tuple", items: code.localsplusnames ?? [] }, layout));
    parts.push(
      encode({ kind: "bytes", data: code.localspluskinds ?? Buffer.alloc(0) }, layout),
    );
  } else {
    parts.push(encode({ kind: "tuple", items: code.varnames ?? [] }, layout));
    parts.push(encode({ kind: "tuple", items: code.freevars ?? [] }, layout));
    parts.push(encode({ kind: "tuple", items: code.cellvars ?? [] }, layout));
  }
  parts.push(encode({ kind: "str", data: code.filename }, layout));
  parts.push(encode({ kind: "str", data: code.name }, layout));
  if (layout === "py311") {
    parts.push(encode({ kind: "str", data: code.qualname ?? code.name }, layout));
  }
  parts.push(i32(code.firstlineno));
  parts.push(encode({ kind: "bytes", data: code.linetable }, layout));
  if (layout === "py311") {
    parts.push(
      encode({ kind: "bytes", data: code.exceptiontable ?? Buffer.alloc(0) }, layout),
    );
  }
  return Buffer.concat(parts);
}

function buildDecoyCode(layout: PythonPycCodeLayout, name: string, filename: string): CodeValue {
  return {
    argcount: 0,
    posonlyargcount: layout === "py37" ? null : 0,
    kwonlyargcount: 0,
    nlocals: layout === "py311" ? null : 0,
    stacksize: 1,
    flags: 0x40, // CO_NOFREE
    bytecode: Buffer.from([0x64, 0x00, 0x53, 0x00]), // LOAD_CONST 0; RETURN_VALUE
    consts: [{ kind: "none" }],
    names: [],
    localsplusnames: layout === "py311" ? [] : null,
    localspluskinds: layout === "py311" ? Buffer.alloc(0) : null,
    varnames: layout === "py311" ? null : [],
    freevars: layout === "py311" ? null : [],
    cellvars: layout === "py311" ? null : [],
    filename,
    name,
    qualname: layout === "py311" ? name : null,
    firstlineno: 1,
    linetable: Buffer.alloc(0),
    exceptiontable: layout === "py311" ? Buffer.alloc(0) : null,
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

function injectDecoys(
  code: CodeValue,
  layout: PythonPycCodeLayout,
  prng: SeededPrng,
  moduleDecoys: number,
  stats: { injected: number; woven: number },
  isRoot: boolean,
): void {
  // CPython interns identical co_consts tuples via FLAG_REF/TYPE_REF; our Reader
  // returns the same array reference. Copy before mutating so sibling code objects
  // that shared a const tuple do not inherit each other's decoys.
  code.consts = code.consts.slice();

  // Snapshot nested codes before we push decoys into this consts list.
  const nestedCodes: CodeValue[] = [];
  for (const item of code.consts) {
    if (item.kind === "code") nestedCodes.push(item.code);
  }
  for (const child of nestedCodes) {
    injectDecoys(child, layout, prng, 0, stats, false);
  }

  const decoysToAdd = isRoot ? moduleDecoys : code.name !== "<module>" ? 1 : 0;
  if (!isRoot && code.name !== "<module>" && decoysToAdd > 0) {
    stats.woven += 1;
  }
  for (let i = 0; i < decoysToAdd; i++) {
    const nm = pickDecoyName(prng, stats.injected + i);
    const decoy = buildDecoyCode(layout, nm, code.filename || "shielded.py");
    code.consts.push({ kind: "code", code: decoy });
    stats.injected += 1;
  }
}

/**
 * Weave unused decoy CODE objects into a CPython .pyc buffer.
 * Returns null when magic/layout is unknown or marshal round-trip fails.
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
  const layout = layoutForPycMagic(magic);
  if (!layout) return null;

  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-pyc-weave-v1");
  const moduleDecoys = decoyCountForIntensity(intensity);

  try {
    const header = bytes.subarray(0, 16);
    const reader = new Reader(bytes.subarray(16), layout);
    const root = reader.read();
    if (root.kind !== "code") return null;
    const trailing = bytes.subarray(16 + reader.offset);

    const stats = { injected: 0, woven: 0 };
    injectDecoys(root.code, layout, prng, moduleDecoys, stats, true);
    const wovenRoot = encode(root, layout);

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
