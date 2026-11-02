/**
 * WASM + seal.json XOR known-plaintext lint (red-blue round-7 residual).
 *
 * Detects entitlement packs XOR-masked with a repeating 32-byte mask where the
 * embedded 32-byte commitment equals the public `seal.json` `revision` digest.
 * An attacker XORs `masked[8..40)` with `revision` to recover the full mask,
 * unmasks salt/rounds/cipher, then (with a weak algebraic key-dependent mask
 * KDF) recovers the key — no adjacent plaintext mask sidecar required.
 *
 * Bankrupt harden/protect refuses error findings unless
 * `allowWasmSealXorKnownPlaintext` / `--allow-wasm-seal-xor-known-plaintext` /
 * `allow_wasm_seal_xor_known_plaintext`.
 *
 * DEFENSIVE ONLY — do not embed publicly known seal digests under XOR masks;
 * derive masks with a one-way KDF (e.g. SHA-256(key||i)); keep commitments
 * out of the masked plaintext prefix (or bind revision differently).
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { extractWasmDataPayloads } from "./wasm-xor-mask-sidecar-lint.js";

export const WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA =
  "bla-wasm-seal-xor-known-plaintext-lint/v1" as const;

export type WasmSealXorKnownPlaintextFindingId =
  | "wasm-seal-xor-known-plaintext"
  | "wasm-seal-revision-mask-oracle";

export type WasmSealXorKnownPlaintextSeverity = "warning" | "error";

export interface WasmSealXorKnownPlaintextFinding {
  readonly id: WasmSealXorKnownPlaintextFindingId;
  readonly severity: WasmSealXorKnownPlaintextSeverity;
  readonly summary: string;
  readonly evidence: string;
  readonly offset: number;
  readonly rounds: number;
  readonly clen: number;
}

export interface WasmSealXorKnownPlaintextReport {
  readonly schema: typeof WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA;
  readonly path: string;
  readonly sealPath: string | null;
  readonly sha256Prefix: string;
  readonly revisionPrefix: string | null;
  readonly findings: readonly WasmSealXorKnownPlaintextFinding[];
  readonly looksExposed: boolean;
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
const COMMIT_OFF = 8;
const CLEN_OFF = 40;
const HEADER = 42;

function finding(
  id: WasmSealXorKnownPlaintextFindingId,
  severity: WasmSealXorKnownPlaintextSeverity,
  summary: string,
  evidence: string,
  offset: number,
  rounds: number,
  clen: number,
): WasmSealXorKnownPlaintextFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 240),
    offset,
    rounds,
    clen,
  };
}

function emptyReport(
  pathLabel: string,
  sealPath: string | null,
  sha256Prefix: string,
  advice: string,
  revisionPrefix: string | null = null,
): WasmSealXorKnownPlaintextReport {
  return {
    schema: WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA,
    path: pathLabel,
    sealPath,
    sha256Prefix,
    revisionPrefix,
    findings: [],
    looksExposed: false,
    shouldRefuseBankrupt: false,
    oneLineAdvice: advice,
  };
}

function parseRevision(sealRaw: string): Buffer | null {
  let obj: unknown;
  try {
    obj = JSON.parse(sealRaw);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  const rev = (obj as { revision?: unknown }).revision;
  if (typeof rev !== "string" || !/^[0-9a-fA-F]{64}$/.test(rev)) return null;
  return Buffer.from(rev, "hex");
}

/** Recover repeating mask from commit known-plaintext at base+8; validate pack. */
export function looksLikeSealRevisionKnownPlaintextPack(
  payload: Buffer,
  commit: Buffer,
  base = 0,
): { ok: true; rounds: number; clen: number; salt: number } | { ok: false } {
  if (commit.length !== 32) return { ok: false };
  if (payload.length < base + HEADER + 8) return { ok: false };
  const mask = Buffer.alloc(MASK_LEN);
  for (let i = COMMIT_OFF; i < COMMIT_OFF + 32; i++) {
    mask[i % MASK_LEN] = payload[base + i]! ^ commit[i - COMMIT_OFF]!;
  }
  // Consistency: unmask must reproduce commit
  for (let i = COMMIT_OFF; i < COMMIT_OFF + 32; i++) {
    if ((payload[base + i]! ^ mask[i % MASK_LEN]!) !== commit[i - COMMIT_OFF]!) return { ok: false };
  }
  const plainHdr = Buffer.alloc(HEADER);
  for (let i = 0; i < HEADER; i++) plainHdr[i] = payload[base + i]! ^ mask[i % MASK_LEN]!;
  if (plainHdr[5] || plainHdr[6] || plainHdr[7]) return { ok: false };
  const rounds = plainHdr[4]!;
  if (rounds < 8 || rounds > 200) return { ok: false };
  const clen = plainHdr.readUInt16LE(CLEN_OFF);
  if (clen < 8 || clen > 200) return { ok: false };
  if (payload.length < base + HEADER + clen) return { ok: false };
  // cipher entropy
  let nonPrint = 0;
  for (let i = 0; i < clen; i++) {
    const b = payload[base + HEADER + i]! ^ mask[(HEADER + i) % MASK_LEN]!;
    if (b < 0x20 || b > 0x7e) nonPrint++;
  }
  if (nonPrint < Math.max(2, Math.floor(clen * 0.2))) return { ok: false };
  const salt = plainHdr.readInt32LE(0);
  // mask should not be trivial
  if (mask.every((b) => b === mask[0])) return { ok: false };
  if (new Set(mask).size < 8) return { ok: false };
  return { ok: true, rounds, clen, salt };
}

export function resolveSiblingSealPath(wasmPath: string, explicit?: string): string | null {
  if (explicit) {
    const abs = resolve(explicit);
    return existsSync(abs) && statSync(abs).isFile() ? abs : null;
  }
  const dir = dirname(resolve(wasmPath));
  const candidates = ["seal.json", "bla-seal.json", ".bla-seal.json"];
  for (const name of candidates) {
    const p = join(dir, name);
    if (existsSync(p) && statSync(p).isFile()) return p;
  }
  return null;
}

export function lintWasmSealXorKnownPlaintextBuffer(
  buffer: Buffer,
  options: {
    readonly path?: string;
    readonly sealPath?: string | null;
    readonly sealRaw?: string | null;
  } = {},
): WasmSealXorKnownPlaintextReport {
  const pathLabel = options.path ?? "<memory>";
  const sha256Prefix = createHash("sha256").update(buffer).digest("hex").slice(0, 12);
  const sealPath = options.sealPath ?? null;
  let sealRaw = options.sealRaw ?? null;
  if (!sealRaw && sealPath && existsSync(sealPath)) {
    try {
      sealRaw = readFileSync(sealPath, "utf8");
    } catch {
      sealRaw = null;
    }
  }
  if (!sealRaw) {
    return emptyReport(
      pathLabel,
      sealPath,
      sha256Prefix,
      "No seal.json revision available — seal XOR known-plaintext lint skipped.",
    );
  }
  const commit = parseRevision(sealRaw);
  if (!commit) {
    return emptyReport(
      pathLabel,
      sealPath,
      sha256Prefix,
      "seal.json has no 64-hex revision — seal XOR known-plaintext lint skipped.",
    );
  }
  const revisionPrefix = commit.toString("hex").slice(0, 12);
  if (buffer.length < 8 || !buffer.subarray(0, 4).equals(WASM_MAGIC)) {
    return emptyReport(
      pathLabel,
      sealPath,
      sha256Prefix,
      "Not a WASM module — seal XOR known-plaintext lint skipped.",
      revisionPrefix,
    );
  }
  if (buffer.length > MAX_SCAN_BYTES) {
    return emptyReport(
      pathLabel,
      sealPath,
      sha256Prefix,
      "WASM too large for seal XOR known-plaintext lint.",
      revisionPrefix,
    );
  }

  const findings: WasmSealXorKnownPlaintextFinding[] = [];
  const payloads = extractWasmDataPayloads(buffer);
  for (const { memOff, payload } of payloads) {
    const bases = [0];
    if (payload.length > 256) bases.push(64, 128, 256);
    for (const base of bases) {
      if (base + HEADER >= payload.length) continue;
      const hit = looksLikeSealRevisionKnownPlaintextPack(payload, commit, base);
      if (!hit.ok) continue;
      findings.push(
        finding(
          "wasm-seal-revision-mask-oracle",
          "error",
          "WASM data XOR-masked entitlement pack embeds seal.revision as known plaintext — recovering the repeating mask needs no key; combined with a weak key-dependent mask KDF this yields key+FLAG (red/blue round-7).",
          `memOff=${memOff}+${base} rounds=${hit.rounds} clen=${hit.clen} salt=${hit.salt} seal=${sealPath ?? "<inline>"}`,
          memOff + base,
          hit.rounds,
          hit.clen,
        ),
      );
      break;
    }
  }

  const looksExposed = findings.length > 0;
  const shouldRefuseBankrupt = findings.some((f) => f.severity === "error");
  const oneLineAdvice = shouldRefuseBankrupt
    ? "ERROR: Do not place public seal.revision bytes under a repeating XOR mask in WASM data; use a one-way mask KDF (SHA-256) and keep public digests out of the masked plaintext prefix. Harden refuses unless allowWasmSealXorKnownPlaintext / --allow-wasm-seal-xor-known-plaintext / allow_wasm_seal_xor_known_plaintext."
    : "No seal.revision-as-XOR-known-plaintext entitlement pack detected (heuristic).";

  return {
    schema: WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA,
    path: pathLabel,
    sealPath,
    sha256Prefix,
    revisionPrefix,
    findings,
    looksExposed,
    shouldRefuseBankrupt,
    oneLineAdvice,
  };
}

export function lintWasmSealXorKnownPlaintextFile(
  wasmPath: string,
  sealPathExplicit?: string,
): WasmSealXorKnownPlaintextReport {
  const abs = resolve(wasmPath);
  if (!existsSync(abs) || !statSync(abs).isFile()) {
    return emptyReport(abs, null, "000000000000", `File not found: ${abs}`);
  }
  const sealPath = resolveSiblingSealPath(abs, sealPathExplicit);
  const buf = readFileSync(abs);
  return lintWasmSealXorKnownPlaintextBuffer(buf, { path: abs, sealPath });
}

export function intensityEnforcesWasmSealXorKnownPlaintextRefusal(
  intensity: string | undefined,
): boolean {
  return intensity === "bankrupt" || intensity === "maximum";
}

export function wasmSealXorKnownPlaintextRefuseMessage(
  report: WasmSealXorKnownPlaintextReport,
  pathLabel?: string,
): string {
  const p = pathLabel ?? report.path;
  const ids = report.findings.map((f) => f.id).join(",");
  return `BLA refused bankrupt/maximum protect of ${p}: WASM seal.revision XOR known-plaintext entitlement pack (${ids || "exposed"}). Pass allowWasmSealXorKnownPlaintext / --allow-wasm-seal-xor-known-plaintext / allow_wasm_seal_xor_known_plaintext to override. Prefer one-way mask KDFs and keep public digests out of masked plaintext (red/blue round-7).`;
}

function walkWasmFiles(root: string, out: string[], depth: number): void {
  if (out.length >= MAX_WASM_FILES || depth > MAX_WALK_DEPTH) return;
  let entries: string[] = [];
  try {
    entries = readdirSync(root);
  } catch {
    return;
  }
  for (const name of entries) {
    if (out.length >= MAX_WASM_FILES) break;
    if (SKIP_DIR_NAMES.has(name)) continue;
    const full = join(root, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walkWasmFiles(full, out, depth + 1);
    else if (st.isFile() && /\.wasm$/i.test(name) && st.size <= MAX_SCAN_BYTES) out.push(full);
  }
}

export function discoverAndLintWasmSealXorKnownPlaintext(
  directory: string,
): WasmSealXorKnownPlaintextReport[] {
  const abs = resolve(directory);
  const files: string[] = [];
  if (existsSync(abs) && statSync(abs).isFile() && /\.wasm$/i.test(abs)) files.push(abs);
  else if (existsSync(abs) && statSync(abs).isDirectory()) walkWasmFiles(abs, files, 0);
  return files.map((f) => lintWasmSealXorKnownPlaintextFile(f));
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

/**
 * Minimal R7 footgun fixture: masked pack with commit===seal.revision under repeating XOR mask.
 */
export function buildTestWasmWithSealXorKnownPlaintext(
  options: {
    readonly salt?: number;
    readonly rounds?: number;
    readonly commit?: Buffer;
    readonly cipher?: Buffer;
    readonly mask?: Buffer;
    /** When true, commit in pack differs from provided sealCommit — must NOT refuse. */
    readonly mismatchCommit?: boolean;
  } = {},
): { wasm: Buffer; seal: Record<string, unknown>; commit: Buffer } {
  const salt = options.salt ?? 0x12345678;
  const rounds = options.rounds ?? 40;
  const commit = options.commit ?? randomBytes(32);
  const packCommit = options.mismatchCommit ? randomBytes(32) : commit;
  const cipher = options.cipher ?? randomBytes(33);
  const mask = options.mask ?? randomBytes(32);
  if (mask.length !== 32) throw new Error("mask must be 32 bytes");
  const N = HEADER + cipher.length;
  const plain = Buffer.alloc(N);
  plain.writeInt32LE(salt | 0, 0);
  plain[4] = rounds & 0xff;
  packCommit.copy(plain, COMMIT_OFF);
  plain.writeUInt16LE(cipher.length, CLEN_OFF);
  cipher.copy(plain, HEADER);
  const masked = Buffer.alloc(N);
  for (let i = 0; i < N; i++) masked[i] = plain[i]! ^ mask[i % 32]!;

  const typeSec = section(1, [1, 0x60, 0, 0]);
  const funcSec = section(3, [1, 0]);
  const memSec = section(5, [1, 0, 1]);
  const exportSec = section(7, [1, ...uleb(3), 0x6e, 0x6f, 0x70, 0x00, 0]);
  const codeSec = section(10, [1, 2, 0, 0x0b]);
  const dataSec = section(11, [1, 0x00, ...iconst(0), 0x0b, ...uleb(masked.length), ...masked]);
  const wasm = Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...typeSec,
    ...funcSec,
    ...memSec,
    ...exportSec,
    ...codeSec,
    ...dataSec,
  ]);
  if (!WebAssembly.validate(wasm)) throw new Error("test wasm invalid");
  const seal = {
    schema: "bla-test-seal/v1",
    algorithm: "sha256",
    revision: commit.toString("hex"),
    certificateSha256: createHash("sha256").update("FLAG{test}").digest("hex"),
  };
  return { wasm, seal, commit };
}
