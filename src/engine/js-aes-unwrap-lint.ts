/**
 * JS AES wrap-key / sealed-blob unwrap lint (red-blue round-4 residual).
 *
 * Detects the footgun where entitlement params live in an AES-sealed WASM
 * (or similar) blob, but JS still holds hex/base64 wrap-key material and
 * calls Node `createDecipheriv` / `createCipheriv` against a fixed magic
 * header (e.g. `d17ea004`). Runtime instrumentation recovers the wrap key
 * in one wrong-key run — this is NOT white-box AES.
 *
 * Bankrupt harden/protect refuses error findings unless
 * `allowJsAesUnwrap` / `--allow-js-aes-unwrap` / `allow_js_aes_unwrap`.
 *
 * DEFENSIVE ONLY — no crack / key-recovery advice. Gate + honest leftover:
 * moving unwrap into WASM / true white-box remains a follow-up.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";

export const JS_AES_UNWRAP_SCHEMA = "bla-js-aes-unwrap-lint/v1" as const;

export type JsAesUnwrapFindingId =
  | "js-aes-wrap-key-material"
  | "js-aes-create-cipheriv"
  | "js-aes-fixed-sealed-hdr"
  | "js-aes-sealed-blob-unwrap";

export type JsAesUnwrapSeverity = "warning" | "error";

export interface JsAesUnwrapFinding {
  readonly id: JsAesUnwrapFindingId;
  readonly severity: JsAesUnwrapSeverity;
  readonly summary: string;
  readonly evidence: string;
}

export interface JsAesUnwrapReport {
  readonly schema: typeof JS_AES_UNWRAP_SCHEMA;
  readonly path: string;
  readonly sha256Prefix: string;
  readonly findings: readonly JsAesUnwrapFinding[];
  readonly looksExposed: boolean;
  /** True when bankrupt harden/protect should refuse (combo error). */
  readonly shouldRefuseBankrupt: boolean;
  readonly hasWrapKeyMaterial: boolean;
  readonly hasCreateCipherIv: boolean;
  readonly hasFixedSealedHdr: boolean;
  readonly oneLineAdvice: string;
}

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
const MAX_JS_FILES = 48;
const MAX_SCAN_CHARS = 800_000;

const CREATE_CIPHER_IV =
  /\bcreate(?:Decipher|Cipher)iv\b|\.create(?:Decipher|Cipher)iv\s*\(/;

/** Hex/base64 wrap-key material shapes (R4 WRAP_KEY_HEX + Buffer.from(..., "hex")). */
const WRAP_KEY_NAME =
  /\b(?:WRAP_KEY|AES_KEY|SEAL_KEY|UNWRAP_KEY|BLOB_KEY)(?:_HEX|_B64|_BASE64|_BYTES)?\b/;

const BUFFER_FROM_HEX_B64 =
  /Buffer\.from\s*\(\s*[^,)]+?\s*,\s*['"](?:hex|base64)['"]\s*\)/;

/** AES-256 key as a 64-hex string literal (or AES-128 32-hex). */
const HEX_KEY_LITERAL = /['"][0-9a-fA-F]{32}(?:[0-9a-fA-F]{32})?['"]/;

const AES_ALGO =
  /['"]aes-(?:128|192|256)-(?:ctr|cbc|gcm)['"]/i;

/** Fixed 4-byte sealed hdr beacons (R4 D17EA004 and generic Buffer.from("........","hex")). */
const FIXED_HDR_HEX =
  /Buffer\.from\s*\(\s*['"][0-9a-fA-F]{8}['"]\s*,\s*['"]hex['"]\s*\)/;

const NAMED_HDR =
  /\b(?:SEALED_HDR|SEAL_HDR|WRAP_HDR|MAGIC_HDR|BLOB_HDR|PARAM_HDR)\b/;

const R4_BEACON = /['"]d17ea004['"]/i;

const JS_EXT = /\.(?:[cm]?js|tsx?|mts|cts)$/i;

function finding(
  id: JsAesUnwrapFindingId,
  severity: JsAesUnwrapSeverity,
  summary: string,
  evidence: string,
): JsAesUnwrapFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 160),
  };
}

function detectSignals(text: string): {
  hasCreateCipherIv: boolean;
  hasWrapKeyMaterial: boolean;
  hasFixedSealedHdr: boolean;
  evidence: {
    cipher?: string;
    key?: string;
    hdr?: string;
  };
} {
  const cipherMatch = text.match(CREATE_CIPHER_IV);
  const hasCreateCipherIv = Boolean(cipherMatch);
  const algoMatch = text.match(AES_ALGO);

  let keyEvidence: string | undefined;
  let hasWrapKeyMaterial = false;
  if (WRAP_KEY_NAME.test(text)) {
    hasWrapKeyMaterial = true;
    keyEvidence = "named WRAP_KEY/AES_KEY-style constant";
  } else if (BUFFER_FROM_HEX_B64.test(text) && (hasCreateCipherIv || algoMatch)) {
    hasWrapKeyMaterial = true;
    keyEvidence = "Buffer.from(..., hex|base64) near cipheriv";
  } else if (HEX_KEY_LITERAL.test(text) && hasCreateCipherIv) {
    hasWrapKeyMaterial = true;
    keyEvidence = "32/64-hex string literal near cipheriv";
  }

  let hdrEvidence: string | undefined;
  let hasFixedSealedHdr = false;
  if (R4_BEACON.test(text)) {
    hasFixedSealedHdr = true;
    hdrEvidence = "d17ea004 beacon";
  } else if (NAMED_HDR.test(text)) {
    hasFixedSealedHdr = true;
    hdrEvidence = "SEALED_HDR/WRAP_HDR-style name";
  } else if (FIXED_HDR_HEX.test(text) && (hasCreateCipherIv || hasWrapKeyMaterial)) {
    hasFixedSealedHdr = true;
    hdrEvidence = "Buffer.from(8-hex, \"hex\") sealed hdr";
  }

  return {
    hasCreateCipherIv,
    hasWrapKeyMaterial,
    hasFixedSealedHdr,
    evidence: {
      ...(cipherMatch ? { cipher: cipherMatch[0] } : {}),
      ...(algoMatch ? { cipher: `${cipherMatch?.[0] ?? "cipheriv"}+${algoMatch[0]}` } : {}),
      ...(keyEvidence ? { key: keyEvidence } : {}),
      ...(hdrEvidence ? { hdr: hdrEvidence } : {}),
    },
  };
}

/**
 * Lint a JS/TS (or HTML-inline-script) UTF-8 body for AES wrap-key unwrap footguns.
 */
export function lintJsAesUnwrapSource(
  source: string,
  options: { readonly path?: string } = {},
): JsAesUnwrapReport {
  const pathLabel = options.path ?? "<memory>";
  const text = source.length > MAX_SCAN_CHARS ? source.slice(0, MAX_SCAN_CHARS) : source;
  const sha256Prefix = createHash("sha256").update(text, "utf8").digest("hex").slice(0, 12);
  const signals = detectSignals(text);
  const findings: JsAesUnwrapFinding[] = [];

  if (signals.hasWrapKeyMaterial) {
    findings.push(
      finding(
        "js-aes-wrap-key-material",
        signals.hasCreateCipherIv ? "error" : "warning",
        "JS appears to hold AES wrap-key material (hex/base64 Buffer.from or WRAP_KEY* constant) — recoverable under Node crypto instrumentation.",
        signals.evidence.key ?? "wrap-key",
      ),
    );
  }
  if (signals.hasCreateCipherIv) {
    findings.push(
      finding(
        "js-aes-create-cipheriv",
        signals.hasWrapKeyMaterial ? "error" : "warning",
        "JS calls createDecipheriv/createCipheriv — wrap keys passed here are RE-reachable at runtime (not white-box).",
        signals.evidence.cipher ?? "create*iv",
      ),
    );
  }
  if (signals.hasFixedSealedHdr) {
    findings.push(
      finding(
        "js-aes-fixed-sealed-hdr",
        signals.hasCreateCipherIv && signals.hasWrapKeyMaterial ? "error" : "warning",
        "Fixed sealed-blob header/magic in JS (stable beacon for AES-wrapped WASM/param blobs).",
        signals.evidence.hdr ?? "sealed-hdr",
      ),
    );
  }

  const combo =
    signals.hasCreateCipherIv &&
    signals.hasWrapKeyMaterial &&
    signals.hasFixedSealedHdr;
  if (combo) {
    findings.push(
      finding(
        "js-aes-sealed-blob-unwrap",
        "error",
        "JS AES sealed-blob unwrap footgun: wrap-key material + create*iv + fixed hdr — bankrupt harden refuses. Prefer unwrap inside WASM / avoid shipping recoverable wrap keys; this gate does not implement white-box AES.",
        [
          signals.evidence.key,
          signals.evidence.cipher,
          signals.evidence.hdr,
        ]
          .filter(Boolean)
          .join("; "),
      ),
    );
  }

  // Dedup by id (keep highest severity).
  const byId = new Map<JsAesUnwrapFindingId, JsAesUnwrapFinding>();
  for (const f of findings) {
    const prev = byId.get(f.id);
    if (!prev || (prev.severity === "warning" && f.severity === "error")) {
      byId.set(f.id, f);
    }
  }
  const deduped = [...byId.values()];
  const shouldRefuseBankrupt = combo;

  return {
    schema: JS_AES_UNWRAP_SCHEMA,
    path: pathLabel,
    sha256Prefix,
    findings: deduped,
    looksExposed: deduped.length > 0,
    shouldRefuseBankrupt,
    hasWrapKeyMaterial: signals.hasWrapKeyMaterial,
    hasCreateCipherIv: signals.hasCreateCipherIv,
    hasFixedSealedHdr: signals.hasFixedSealedHdr,
    oneLineAdvice:
      deduped.length === 0
        ? "No JS AES wrap-key + create*iv + fixed-hdr sealed-blob unwrap footgun detected (heuristic)."
        : shouldRefuseBankrupt
          ? "ERROR: JS holds recoverable AES wrap key + createDecipheriv/createCipheriv + fixed sealed hdr. Move unwrap out of JS or stop shipping key material; bankrupt refuses unless allowJsAesUnwrap / --allow-js-aes-unwrap / allow_js_aes_unwrap. Not white-box AES — defensive gate only."
          : "WARNING: Partial JS AES unwrap signals — avoid hex wrap keys and fixed hdr beacons next to create*iv for entitlement params.",
  };
}

export function lintJsAesUnwrapFile(filePath: string): JsAesUnwrapReport {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    throw new Error(`js-aes-unwrap target not found: ${abs}`);
  }
  return lintJsAesUnwrapSource(readFileSync(abs, "utf8"), { path: abs });
}

function walkJsCandidates(dir: string, depth: number, out: string[]): void {
  if (out.length >= MAX_JS_FILES || depth > MAX_WALK_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= MAX_JS_FILES) return;
    if (entry.isDirectory()) {
      if (SKIP_DIR_NAMES.has(entry.name) || entry.name.startsWith(".")) continue;
      walkJsCandidates(join(dir, entry.name), depth + 1, out);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!JS_EXT.test(entry.name) && !/\.html?$/i.test(entry.name)) continue;
    out.push(join(dir, entry.name));
  }
}

/**
 * Discover JS/TS/HTML under a directory and lint each for AES unwrap footguns.
 */
export function discoverAndLintJsAesUnwrap(
  directory: string,
): readonly JsAesUnwrapReport[] {
  const abs = resolve(directory);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintJsAesUnwrapFile(abs)];
  }
  const candidates: string[] = [];
  walkJsCandidates(abs, 0, candidates);
  return candidates.map((p) => lintJsAesUnwrapFile(p));
}

export function jsAesUnwrapRefuseMessage(
  report: JsAesUnwrapReport,
  filePath: string,
): string {
  return (
    `Refusing bankrupt harden/protect: JS AES sealed-blob unwrap footgun at ${filePath}` +
    ` (wrap-key material + create*iv + fixed hdr). ` +
    `Do not ship recoverable AES wrap keys in JS for entitlement params; prefer in-WASM unwrap. ` +
    `This gate does not provide white-box AES. ` +
    `To override (lab fixture only), pass allowJsAesUnwrap / --allow-js-aes-unwrap / allow_js_aes_unwrap:true.`
  );
}

export function intensityEnforcesJsAesUnwrapRefusal(intensity: string): boolean {
  return intensity === "bankrupt";
}

/** Minimal R4-shaped footgun source for tests. */
export function buildTestJsAesUnwrapFootgun(options: {
  readonly wrapKeyHex?: string;
  readonly hdrHex?: string;
  readonly omitKey?: boolean;
  readonly omitCipher?: boolean;
  readonly omitHdr?: boolean;
} = {}): string {
  const key = options.wrapKeyHex ?? "a".repeat(64);
  const hdr = options.hdrHex ?? "d17ea004";
  const parts: string[] = [
    'const crypto = require("crypto");',
    'const fs = require("fs");',
  ];
  if (!options.omitKey) {
    parts.push(`const WRAP_KEY_HEX = "${key}";`);
  }
  if (!options.omitHdr) {
    parts.push(`const SEALED_HDR = Buffer.from("${hdr}", "hex");`);
  }
  parts.push(`function unwrapSealed(buf) {`);
  if (!options.omitHdr) {
    parts.push(`  if (!buf.subarray(0, 4).equals(SEALED_HDR)) return null;`);
  }
  parts.push(`  const nonce = buf.subarray(4, 16);`);
  parts.push(`  const enc = buf.subarray(16);`);
  if (!options.omitKey) {
    parts.push(`  const key = Buffer.from(WRAP_KEY_HEX, "hex");`);
  } else {
    parts.push(`  const key = Buffer.alloc(32);`);
  }
  parts.push(`  const iv = Buffer.concat([nonce, Buffer.alloc(4)]);`);
  if (!options.omitCipher) {
    parts.push(`  const dec = crypto.createDecipheriv("aes-256-ctr", key, iv);`);
    parts.push(`  return Buffer.concat([dec.update(enc), dec.final()]);`);
  } else {
    parts.push(`  return key;`);
  }
  parts.push(`}`);
  parts.push(`module.exports = { unwrapSealed };`);
  return parts.join("\n") + "\n";
}
