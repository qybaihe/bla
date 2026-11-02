/**
 * Clear WASM param/cipher carrier lint (red-blue round-3 residual).
 *
 * Detects ASCII magics such as R3PARM / R3CIPH / R2SEAL embedded in a WASM
 * binary (typically the data section) followed by clear salt/rounds/ciphertext
 * bytes. Full encryption of WASM data is a follow-up; this gate surfaces the
 * footgun and lets bankrupt harden refuse unless explicitly allowed.
 *
 * Heuristic and defensive only — no crack / inversion advice. Tuned to avoid
 * flagging ordinary WASM text (requires tagged magic + null pad + binary blob).
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";

export const WASM_PARAM_CARRIER_SCHEMA = "bla-wasm-param-carrier-lint/v1" as const;

export type WasmParamCarrierFindingId =
  | "clear-wasm-param-magic"
  | "clear-wasm-cipher-carrier"
  | "clear-wasm-seal-magic";

export type WasmParamCarrierSeverity = "warning" | "error";

export interface WasmParamCarrierFinding {
  readonly id: WasmParamCarrierFindingId;
  readonly severity: WasmParamCarrierSeverity;
  readonly summary: string;
  readonly evidence: string;
  readonly offset: number;
  readonly magic: string;
}

export interface WasmParamCarrierReport {
  readonly schema: typeof WASM_PARAM_CARRIER_SCHEMA;
  readonly path: string;
  readonly sha256Prefix: string;
  readonly findings: readonly WasmParamCarrierFinding[];
  readonly looksExposed: boolean;
  /** True when bankrupt harden/protect should refuse (error findings). */
  readonly shouldRefuseBankrupt: boolean;
  readonly oneLineAdvice: string;
}

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);

/** Tagged footgun magics observed in red-blue rounds (and close cousins). */
const TAGGED_MAGIC =
  /(?:R[0-9]|BLA|V[0-9]|K[0-9])?(?:PARM|CIPH|SEAL|SALT)/g;

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

function isPrintableAscii(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e;
}

function looksBinaryBlob(buf: Buffer, start: number, len: number): boolean {
  if (start < 0 || start >= buf.length || len <= 0) return false;
  const end = Math.min(buf.length, start + len);
  let nonPrint = 0;
  for (let i = start; i < end; i++) {
    const b = buf[i]!;
    if (b === 0 || !isPrintableAscii(b)) nonPrint++;
  }
  return nonPrint >= Math.max(2, Math.floor((end - start) * 0.4));
}

function classifyMagic(magic: string): WasmParamCarrierFindingId {
  if (/CIPH$/i.test(magic)) return "clear-wasm-cipher-carrier";
  if (/SEAL$/i.test(magic)) return "clear-wasm-seal-magic";
  return "clear-wasm-param-magic";
}

function finding(
  id: WasmParamCarrierFindingId,
  severity: WasmParamCarrierSeverity,
  summary: string,
  evidence: string,
  offset: number,
  magic: string,
): WasmParamCarrierFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 160),
    offset,
    magic,
  };
}

/**
 * Scan a WASM (or WASM-shaped) buffer for clear param/cipher ASCII carriers.
 */
export function lintWasmParamCarrierBuffer(
  buffer: Buffer,
  options: { readonly path?: string } = {},
): WasmParamCarrierReport {
  const pathLabel = options.path ?? "<memory>";
  const sha256Prefix = createHash("sha256").update(buffer).digest("hex").slice(0, 12);
  const findings: WasmParamCarrierFinding[] = [];

  if (buffer.length < 8) {
    return emptyReport(pathLabel, sha256Prefix, "Buffer too small for WASM param-carrier lint.");
  }

  // Prefer real WASM; still scan if magic missing so mislabeled .bin carriers are caught.
  const hasWasmMagic = buffer.subarray(0, 4).equals(WASM_MAGIC);
  const scan = buffer.length > MAX_SCAN_BYTES ? buffer.subarray(0, MAX_SCAN_BYTES) : buffer;
  // latin1 preserves byte↔char 1:1 for ASCII magic search.
  const text = scan.toString("latin1");

  TAGGED_MAGIC.lastIndex = 0;
  let match: RegExpExecArray | null;
  const seenOffsets = new Set<number>();
  while ((match = TAGGED_MAGIC.exec(text)) !== null) {
    const magic = match[0]!;
    // Require at least 5 chars (e.g. R3PARM) — bare "SEAL"/"PARM" alone is too noisy.
    if (magic.length < 5) continue;
    // Must look like a tagged token: starts with letter, rest alnum.
    if (!/^[A-Z][A-Z0-9]{4,7}$/.test(magic)) continue;
    const offset = match.index;
    if (seenOffsets.has(offset)) continue;

    // Null pad within 0..2 bytes after magic (R3PARM\0\0 layout).
    const after = offset + magic.length;
    if (after >= scan.length) continue;
    // Require a null pad immediately after the magic (R3PARM\0\0 layout).
    const pad0 = scan[after]!;
    if (pad0 !== 0) continue;
    const pad1 = after + 1 < scan.length ? scan[after + 1]! : 0xff;
    const blobStart = after + (pad1 === 0 ? 2 : 1);
    // CIPH/SEAL carriers often pack ASCII-looking ciphertext; require only that
    // some payload bytes follow. PARM/SALT still need a binary-ish blob so we
    // do not flag English prose.
    const idHint = classifyMagic(magic);
    if (idHint === "clear-wasm-cipher-carrier" || idHint === "clear-wasm-seal-magic") {
      if (blobStart >= scan.length || scan.length - blobStart < 4) continue;
    } else if (!looksBinaryBlob(scan, blobStart, 12)) {
      continue;
    }

    seenOffsets.add(offset);
    const id = classifyMagic(magic);
    const preview = scan
      .subarray(offset, Math.min(scan.length, offset + magic.length + 16))
      .toString("hex");
    findings.push(
      finding(
        id,
        "error",
        hasWasmMagic
          ? `WASM binary embeds clear ${magic} param/cipher carrier magic with adjacent binary blob — relocate, encrypt, or bind under self-seal.`
          : `Buffer embeds clear ${magic} param/cipher carrier magic with adjacent binary blob (not a standard WASM header).`,
        `offset=${offset} magic=${magic} next=${preview}`,
        offset,
        magic,
      ),
    );
  }

  // Deduplicate by id+offset (keep first).
  const deduped: WasmParamCarrierFinding[] = [];
  const keySet = new Set<string>();
  for (const f of findings) {
    const key = `${f.id}@${f.offset}`;
    if (keySet.has(key)) continue;
    keySet.add(key);
    deduped.push(f);
  }

  const shouldRefuseBankrupt = deduped.some((f) => f.severity === "error");
  return {
    schema: WASM_PARAM_CARRIER_SCHEMA,
    path: pathLabel,
    sha256Prefix,
    findings: deduped,
    looksExposed: deduped.length > 0,
    shouldRefuseBankrupt,
    oneLineAdvice:
      deduped.length === 0
        ? "No clear WASM param/cipher ASCII carrier magic detected (heuristic)."
        : "ERROR: Clear WASM param/cipher carrier magic (e.g. R3PARM/R3CIPH/R2SEAL). Encrypt or relocate runtime params; bankrupt harden refuses unless allowWasmClearParamCarriers / --allow-wasm-clear-params / allow_wasm_clear_params. Defensive guidance only — full data-section encryption remains a follow-up.",
  };
}

function emptyReport(
  pathLabel: string,
  sha256Prefix: string,
  advice: string,
): WasmParamCarrierReport {
  return {
    schema: WASM_PARAM_CARRIER_SCHEMA,
    path: pathLabel,
    sha256Prefix,
    findings: [],
    looksExposed: false,
    shouldRefuseBankrupt: false,
    oneLineAdvice: advice,
  };
}

export function lintWasmParamCarrierFile(filePath: string): WasmParamCarrierReport {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    throw new Error(`wasm-param-carrier target not found: ${abs}`);
  }
  const buf = readFileSync(abs);
  return lintWasmParamCarrierBuffer(buf, { path: abs });
}

function walkWasmCandidates(dir: string, depth: number, out: string[]): void {
  if (out.length >= MAX_WASM_FILES || depth > MAX_WALK_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= MAX_WASM_FILES) return;
    if (entry.isDirectory()) {
      if (SKIP_DIR_NAMES.has(entry.name) || entry.name.startsWith(".")) continue;
      walkWasmCandidates(join(dir, entry.name), depth + 1, out);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!/\.wasm$/i.test(entry.name)) continue;
    out.push(join(dir, entry.name));
  }
}

export function discoverAndLintWasmParamCarriers(
  directory: string,
): readonly WasmParamCarrierReport[] {
  const abs = resolve(directory);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintWasmParamCarrierFile(abs)];
  }
  const candidates: string[] = [];
  walkWasmCandidates(abs, 0, candidates);
  return candidates.map((p) => lintWasmParamCarrierFile(p));
}

export function wasmParamCarrierRefuseMessage(
  report: WasmParamCarrierReport,
  filePath: string,
): string {
  const magics = [...new Set(report.findings.map((f) => f.magic))].join(", ");
  return (
    `Refusing bankrupt harden/protect: clear WASM param/cipher carrier at ${filePath}` +
    (magics ? ` [${magics}]` : "") +
    `. Encrypt or relocate salt/rounds/ciphertext out of plaintext WASM data. ` +
    `To override (lab fixture only), pass allowWasmClearParamCarriers / --allow-wasm-clear-params / allow_wasm_clear_params:true. ` +
    `Full WASM data-section encryption is not applied by this gate.`
  );
}

export function intensityEnforcesWasmParamRefusal(intensity: string): boolean {
  return intensity === "bankrupt";
}

/** Build a minimal valid empty WASM module with an appended data-like blob (tests). */
export function buildTestWasmWithParamCarrier(options: {
  readonly magic?: string;
  readonly salt?: number;
  readonly rounds?: number;
  readonly cipher?: Buffer;
}): Buffer {
  // Minimal module: magic + version + empty.
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const magic = options.magic ?? "R3PARM";
  const salt = options.salt ?? 0xd63be8f0;
  const rounds = options.rounds ?? 28;
  const cipher = options.cipher ?? Buffer.from("FLAG{test-cipher-padding!!}");
  const parm = Buffer.from(magic, "ascii");
  const ciphMagic = Buffer.from("R3CIPH", "ascii");
  const blob = Buffer.alloc(parm.length + 2 + 4 + 1 + ciphMagic.length + 2 + 2 + cipher.length);
  let o = 0;
  parm.copy(blob, o); o += parm.length;
  blob[o++] = 0;
  blob[o++] = 0;
  blob.writeInt32LE(salt | 0, o); o += 4;
  blob[o++] = rounds & 0xff;
  ciphMagic.copy(blob, o); o += ciphMagic.length;
  blob[o++] = 0;
  blob[o++] = 0;
  blob.writeUInt16LE(cipher.length, o); o += 2;
  cipher.copy(blob, o);
  return Buffer.concat([header, blob]);
}
