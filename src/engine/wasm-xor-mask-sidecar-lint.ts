/**
 * WASM XOR-mask sidecar lint (red-blue round-6 residual).
 *
 * Detects entitlement packs stored as `masked_blob || plaintext_mask` in a
 * WASM data section (or initialized linear memory). Hosts can XOR-unmask
 * salt/rounds/expected-words/cipher with **no** key and **no** export call —
 * bankrupt export rename does not help. Round-6 red recovered the prize by
 * combining this static unpack with an invertible ARX expected-state compare.
 *
 * Bankrupt harden/protect refuses error findings unless
 * `allowWasmXorMaskSidecar` / `--allow-wasm-xor-mask-sidecar` /
 * `allow_wasm_xor_mask_sidecar`.
 *
 * DEFENSIVE ONLY — prefer key-dependent unmask, omit plaintext masks from the
 * binary, and one-way commitments instead of reversible expected words.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { walkBounded } from "../core/walk.js";

export const WASM_XOR_MASK_SIDECAR_SCHEMA = "bla-wasm-xor-mask-sidecar-lint/v1" as const;

export type WasmXorMaskSidecarFindingId =
  | "wasm-xor-mask-sidecar"
  | "wasm-xor-mask-entitlement-pack";

export type WasmXorMaskSidecarSeverity = "warning" | "error";

export interface WasmXorMaskSidecarFinding {
  readonly id: WasmXorMaskSidecarFindingId;
  readonly severity: WasmXorMaskSidecarSeverity;
  readonly summary: string;
  readonly evidence: string;
  readonly offset: number;
  readonly blobLen: number;
  readonly maskLen: number;
}

export interface WasmXorMaskSidecarReport {
  readonly schema: typeof WASM_XOR_MASK_SIDECAR_SCHEMA;
  readonly path: string;
  readonly sha256Prefix: string;
  readonly findings: readonly WasmXorMaskSidecarFinding[];
  readonly looksExposed: boolean;
  /** True when bankrupt harden/protect should refuse (error findings). */
  readonly shouldRefuseBankrupt: boolean;
  readonly oneLineAdvice: string;
}

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);

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
const MAX_WASM_FILES = 32;
const MAX_SCAN_BYTES = 32 * 1024 * 1024;
const MASK_LEN = 32;
const MIN_BLOB = 40;
const MAX_BLOB = 120;

function finding(
  id: WasmXorMaskSidecarFindingId,
  severity: WasmXorMaskSidecarSeverity,
  summary: string,
  evidence: string,
  offset: number,
  blobLen: number,
  maskLen: number,
): WasmXorMaskSidecarFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 200),
    offset,
    blobLen,
    maskLen,
  };
}

function emptyReport(pathLabel: string, sha256Prefix: string, advice: string): WasmXorMaskSidecarReport {
  return {
    schema: WASM_XOR_MASK_SIDECAR_SCHEMA,
    path: pathLabel,
    sha256Prefix,
    findings: [],
    looksExposed: false,
    shouldRefuseBankrupt: false,
    oneLineAdvice: advice,
  };
}

function readUleb(buf: Buffer, off: number): [number, number] {
  let r = 0;
  let s = 0;
  let b = 0;
  let o = off;
  do {
    if (o >= buf.length) throw new Error("uleb truncated");
    b = buf[o++]!;
    r |= (b & 0x7f) << s;
    s += 7;
  } while (b & 0x80);
  return [r >>> 0, o];
}

function readI32Leb(buf: Buffer, off: number): [number, number] {
  let r = 0;
  let s = 0;
  let b = 0;
  let o = off;
  do {
    if (o >= buf.length) throw new Error("ileb truncated");
    b = buf[o++]!;
    r |= (b & 0x7f) << s;
    s += 7;
  } while (b & 0x80);
  if (s < 32 && (b & 0x40)) r |= (~0 << s);
  return [r | 0, o];
}

function uleb(v: number): number[] {
  const out: number[] = [];
  v >>>= 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return out;
}

function iconst(v: number): number[] {
  v |= 0;
  const out = [0x41];
  while (true) {
    let b = v & 0x7f;
    v >>= 7;
    if ((v === 0 && (b & 0x40) === 0) || (v === -1 && (b & 0x40) !== 0)) {
      out.push(b);
      break;
    }
    out.push(b | 0x80);
  }
  return out;
}

function section(id: number, body: number[]): number[] {
  return [id, ...uleb(body.length), ...body];
}

/** Extract active data-segment payloads (mem0) from a WASM binary. */
export function extractWasmDataPayloads(buffer: Buffer): Array<{ memOff: number; payload: Buffer }> {
  const out: Array<{ memOff: number; payload: Buffer }> = [];
  if (buffer.length < 8 || !buffer.subarray(0, 4).equals(WASM_MAGIC)) return out;
  let off = 8;
  while (off < buffer.length) {
    const id = buffer[off++]!;
    let size = 0;
    try {
      [size, off] = readUleb(buffer, off);
    } catch {
      break;
    }
    const start = off;
    const end = off + size;
    if (end > buffer.length) break;
    if (id === 11) {
      let p = start;
      try {
        let count = 0;
        [count, p] = readUleb(buffer, p);
        for (let i = 0; i < count; i++) {
          if (p >= end) break;
          const flags = buffer[p++]!;
          let memOff = 0;
          if (flags === 0 || flags === 2) {
            if (flags === 2) {
              // memory index
              let _memIdx = 0;
              [_memIdx, p] = readUleb(buffer, p);
            }
            if (buffer[p] === 0x41) {
              p++;
              [memOff, p] = readI32Leb(buffer, p);
              if (buffer[p] === 0x0b) p++;
            } else {
              while (p < end && buffer[p] !== 0x0b) p++;
              if (p < end) p++;
            }
          } else {
            // passive / declarative — skip body length only
            let dlen = 0;
            [dlen, p] = readUleb(buffer, p);
            p += dlen;
            continue;
          }
          let dlen = 0;
          [dlen, p] = readUleb(buffer, p);
          if (p + dlen > end) break;
          out.push({ memOff, payload: Buffer.from(buffer.subarray(p, p + dlen)) });
          p += dlen;
        }
      } catch {
        // ignore malformed data section
      }
    }
    off = end;
  }
  return out;
}

function maskEntropyOk(mask: Buffer): boolean {
  if (mask.length !== MASK_LEN) return false;
  if (mask.every((b) => b === 0)) return false;
  const first = mask[0]!;
  if (mask.every((b) => b === first)) return false;
  const seen = new Set(mask);
  return seen.size >= 8;
}

/**
 * True when `payload[base .. base+N) XOR payload[base+N .. base+N+32)` looks like
 * the round-3..6 entitlement pack: salt_i32le || rounds_u8 || pad3 || 4×i32 || clen_u16le || cipher.
 */
export function looksLikeXorMaskedEntitlementPack(
  payload: Buffer,
  base = 0,
): { ok: true; blobLen: number; rounds: number; clen: number; salt: number } | { ok: false } {
  for (let N = MIN_BLOB; N <= Math.min(MAX_BLOB, payload.length - base - MASK_LEN); N++) {
    const mask = payload.subarray(base + N, base + N + MASK_LEN);
    if (!maskEntropyOk(mask)) continue;
    const plain = Buffer.alloc(N);
    for (let i = 0; i < N; i++) plain[i] = payload[base + i]! ^ mask[i % MASK_LEN]!;
    if (plain[5] || plain[6] || plain[7]) continue;
    const rounds = plain[4]!;
    if (rounds < 8 || rounds > 200) continue;
    const clen = plain.readUInt16LE(24);
    if (clen < 8 || clen > 200) continue;
    if (26 + clen !== N) continue;
    const words = [8, 12, 16, 20].map((o) => plain.readInt32LE(o));
    const nonzero = words.filter((w) => w !== 0).length;
    if (nonzero < 2) continue;
    const salt = plain.readInt32LE(0);
    // cipher should look binary-ish
    let nonPrint = 0;
    for (let i = 26; i < N; i++) {
      const b = plain[i]!;
      if (b < 0x20 || b > 0x7e) nonPrint++;
    }
    if (nonPrint < Math.max(2, Math.floor(clen * 0.25))) continue;
    return { ok: true, blobLen: N, rounds, clen, salt };
  }
  return { ok: false };
}

export function lintWasmXorMaskSidecarBuffer(
  buffer: Buffer,
  options: { readonly path?: string } = {},
): WasmXorMaskSidecarReport {
  const pathLabel = options.path ?? "<memory>";
  const sha256Prefix = createHash("sha256").update(buffer).digest("hex").slice(0, 12);
  if (buffer.length < 8 || !buffer.subarray(0, 4).equals(WASM_MAGIC)) {
    return emptyReport(pathLabel, sha256Prefix, "Not a WASM module — XOR-mask sidecar lint skipped.");
  }
  if (buffer.length > MAX_SCAN_BYTES) {
    return emptyReport(pathLabel, sha256Prefix, "WASM too large for XOR-mask sidecar lint.");
  }

  const findings: WasmXorMaskSidecarFinding[] = [];
  const payloads = extractWasmDataPayloads(buffer);
  for (const { memOff, payload } of payloads) {
    // Scan a few bases inside the payload (data@0 is the common case).
    const bases = [0];
    if (payload.length > 256) bases.push(64, 128, 256);
    for (const base of bases) {
      if (base >= payload.length) continue;
      const hit = looksLikeXorMaskedEntitlementPack(payload, base);
      if (!hit.ok) continue;
      findings.push(
        finding(
          "wasm-xor-mask-entitlement-pack",
          "error",
          "WASM data section looks like XOR-masked entitlement pack with adjacent plaintext 32-byte mask — static unmask recovers salt/rounds/expected-words/cipher without a key.",
          `memOff=${memOff}+${base} blobLen=${hit.blobLen} rounds=${hit.rounds} clen=${hit.clen} salt=${hit.salt}`,
          memOff + base,
          hit.blobLen,
          MASK_LEN,
        ),
      );
      break;
    }
  }

  const looksExposed = findings.length > 0;
  const shouldRefuseBankrupt = findings.some((f) => f.severity === "error");
  const oneLineAdvice = shouldRefuseBankrupt
    ? "ERROR: Prefer key-dependent unmask / omit plaintext XOR masks from WASM data; use one-way commitments instead of reversible expected words. Harden refuses unless allowWasmXorMaskSidecar / --allow-wasm-xor-mask-sidecar / allow_wasm_xor_mask_sidecar."
    : "No XOR-mask-beside-blob entitlement pack detected in WASM data sections (heuristic).";

  return {
    schema: WASM_XOR_MASK_SIDECAR_SCHEMA,
    path: pathLabel,
    sha256Prefix,
    findings,
    looksExposed,
    shouldRefuseBankrupt,
    oneLineAdvice,
  };
}

export function lintWasmXorMaskSidecarFile(filePath: string): WasmXorMaskSidecarReport {
  const abs = resolve(filePath);
  if (!existsSync(abs) || !statSync(abs).isFile()) {
    return emptyReport(abs, "000000000000", `File not found: ${abs}`);
  }
  const buf = readFileSync(abs);
  return lintWasmXorMaskSidecarBuffer(buf, { path: abs });
}

export function intensityEnforcesWasmXorMaskSidecarRefusal(
  intensity: string | undefined,
): boolean {
  return intensity === "bankrupt" || intensity === "maximum";
}

export function wasmXorMaskSidecarRefuseMessage(
  report: WasmXorMaskSidecarReport,
  pathLabel?: string,
): string {
  const p = pathLabel ?? report.path;
  const ids = report.findings.map((f) => f.id).join(",");
  return `BLA refused bankrupt/maximum protect of ${p}: WASM XOR-mask sidecar entitlement pack (${ids || "exposed"}). Pass allowWasmXorMaskSidecar / --allow-wasm-xor-mask-sidecar / allow_wasm_xor_mask_sidecar to override. Prefer key-dependent unmask and one-way commitments (red/blue round-6).`;
}

function walkWasmFiles(root: string): string[] {
  return walkBounded(root, {
    maxDepth: MAX_WALK_DEPTH,
    maxFiles: MAX_WASM_FILES,
    skipDirs: SKIP_DIR_NAMES,
    maxFileBytes: MAX_SCAN_BYTES,
    accept: (_full, name) => /\.wasm$/i.test(name),
  });
}

export function discoverAndLintWasmXorMaskSidecars(directory: string): WasmXorMaskSidecarReport[] {
  const abs = resolve(directory);
  const files: string[] = [];
  if (existsSync(abs) && statSync(abs).isFile() && /\.wasm$/i.test(abs)) files.push(abs);
  else if (existsSync(abs) && statSync(abs).isDirectory()) files.push(...walkWasmFiles(abs));
  return files.map((f) => lintWasmXorMaskSidecarFile(f));
}

/**
 * Minimal WASM footgun fixture: data section = masked entitlement pack || 32-byte mask.
 * Used by unit / harden-gate tests (not a customer sample).
 */
export function buildTestWasmWithXorMaskSidecar(
  options: {
    readonly salt?: number;
    readonly rounds?: number;
    readonly words?: readonly [number, number, number, number];
    readonly cipher?: Buffer;
    readonly mask?: Buffer;
    /** Round-7 style: store masked blob only (key-dependent unmask) — must NOT refuse. */
    readonly omitMaskSidecar?: boolean;
  } = {},
): Buffer {
  const salt = options.salt ?? 0x12345678;
  const rounds = options.rounds ?? 40;
  const words = options.words ?? [0x11111111, 0x22222222, 0x33333333, 0x44444444];
  const cipher = options.cipher ?? randomBytes(31);
  const mask = options.mask ?? randomBytes(32);
  if (mask.length !== 32) throw new Error("mask must be 32 bytes");
  const N = 26 + cipher.length;
  const plain = Buffer.alloc(N);
  plain.writeInt32LE(salt | 0, 0);
  plain[4] = rounds & 0xff;
  plain.writeInt32LE(words[0]!, 8);
  plain.writeInt32LE(words[1]!, 12);
  plain.writeInt32LE(words[2]!, 16);
  plain.writeInt32LE(words[3]!, 20);
  plain.writeUInt16LE(cipher.length, 24);
  cipher.copy(plain, 26);
  const masked = Buffer.alloc(N);
  for (let i = 0; i < N; i++) masked[i] = plain[i]! ^ mask[i % 32]!;
  const dataPayload = options.omitMaskSidecar ? masked : Buffer.concat([masked, mask]);

  const typeSec = section(1, [1, 0x60, 0, 0]);
  const funcSec = section(3, [1, 0]);
  const memSec = section(5, [1, 0, 1]);
  const exportSec = section(7, [1, ...uleb(3), 0x6e, 0x6f, 0x70, 0x00, 0]); // "nop"
  const codeSec = section(10, [1, 2, 0, 0x0b]); // empty function
  const dataSec = section(11, [
    1,
    0x00,
    ...iconst(0),
    0x0b,
    ...uleb(dataPayload.length),
    ...dataPayload,
  ]);
  const bytes = Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...typeSec,
    ...funcSec,
    ...memSec,
    ...exportSec,
    ...codeSec,
    ...dataSec,
  ]);
  if (!WebAssembly.validate(bytes)) throw new Error("test wasm invalid");
  return bytes;
}
