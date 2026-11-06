/**
 * Opt-in self-seal / self-integrity helper (issue #40.5 + Direction-3).
 *
 * Generates a Node-oriented JS preamble that binds a runtime digest to:
 *   1. SHA-256 of the current module bytes (when fs + __filename / import.meta are available)
 *   2. SHA-256 of optional sibling module paths (customer-supplied)
 *   3. An optional environment fingerprint (inspector / NODE_OPTIONS / toString native check)
 *
 * The digest is exposed as a named binding so the AST shield can entangle it with
 * the opaque-predicate seed. Tampering with sibling modules or attaching an
 * inspector changes the digest → seed parity flips → opaque happy-path guards fail.
 *
 * When build-time `expectedSiblingSha256` hashes are embedded (harden/protect fills
 * these from siblings already on disk), runtime **hard-fails** on mismatch. Opaque
 * seed entanglement alone does not gate entitlement control flow that never reads
 * the seed (red/blue round-4 finding).
 *
 * Direction-3: when `interleavedSites >= 2` (default whenever siblings are present),
 * emit multiple independent measure helpers that each hard-fail on the same sibling
 * hashes. Pair with `buildInterleavedCoverageMatrix` so packaging gates can refuse
 * single-point topologies. Hash-only — no guessing.
 *
 * Entry self-coverage (CrackMe v8 red team 2026-11-05): in hard-fail mode each
 * site also hard-fails when the checker host's **own** bytes diverge. A file
 * cannot embed its own SHA-256, so the emitted literal starts as
 * {@link SELF_DIGEST_PLACEHOLDER} and {@link finalizeSelfSealSelfDigest} (run on
 * the final bytes at write time) replaces it with
 * `SHA-256(file with every digest occurrence → "0"×64)`. Runtime recomputes the
 * same canonical form. Until finalized the literal is not 64-hex and the self
 * check soft-skips (never bricks an un-finalized build).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice. Browser builds soft-skip (digest=0).
 */

import { createHash } from "node:crypto";
import type { SeededPrng } from "../../core/prng.js";
import {
  buildInterleavedCoverageMatrix,
  type CoverageMatrix,
} from "../../engine/integrity-coverage.js";

export const SELF_SEAL_SCHEMA = "bla-self-seal/v1" as const;

/**
 * Build-time placeholder for the entry self-digest literal (exactly 64 chars,
 * deliberately non-hex so runtime soft-skips if a write path never finalized).
 * Never ships: {@link finalizeSelfSealSelfDigest} replaces every occurrence.
 */
export const SELF_DIGEST_PLACEHOLDER =
  "~self-digest-pending-finalize~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" as const;

const SELF_DIGEST_ZERO = "0".repeat(64);
const HEX64_LOWER = /^[0-9a-f]{64}$/;

function replaceAllBytes(buf: Buffer, needle: Buffer, replacement: Buffer): Buffer {
  if (needle.length !== replacement.length) {
    throw new Error("replaceAllBytes requires equal-length needle/replacement");
  }
  const out = Buffer.from(buf);
  let at = out.indexOf(needle);
  while (at !== -1) {
    replacement.copy(out, at);
    at = out.indexOf(needle, at + needle.length);
  }
  return out;
}

/** Canonical self-digest: SHA-256 of bytes with every `digestLiteral` → "0"×64. */
export function canonicalSelfDigest(bytes: Buffer, digestLiteral: string): string {
  const canon = replaceAllBytes(
    bytes,
    Buffer.from(digestLiteral, "latin1"),
    Buffer.from(SELF_DIGEST_ZERO, "latin1"),
  );
  return createHash("sha256").update(canon).digest("hex");
}

export interface SelfDigestFinalizeResult<T extends string | Buffer> {
  readonly content: T;
  /** True when at least one placeholder was replaced. */
  readonly applied: boolean;
  readonly digest?: string;
  readonly occurrences: number;
}

/**
 * Replace {@link SELF_DIGEST_PLACEHOLDER} with the canonical self-digest of the
 * **final** artifact bytes. Idempotent no-op when the placeholder is absent.
 * Must run after every other transform (string encryption, source-map
 * directives…) — any later byte change trips the runtime self check.
 */
export function finalizeSelfSealSelfDigest<T extends string | Buffer>(
  content: T,
): SelfDigestFinalizeResult<T> {
  let asBuf: Buffer =
    typeof content === "string" ? Buffer.from(content as string, "utf8") : Buffer.from(content as Buffer);
  const needle = Buffer.from(SELF_DIGEST_PLACEHOLDER, "latin1");
  let occurrences = 0;
  for (let at = asBuf.indexOf(needle); at !== -1; at = asBuf.indexOf(needle, at + needle.length)) {
    occurrences += 1;
  }
  if (occurrences === 0) {
    // Support re-finalizing an already-finalized self-seal buffer after a post-pass
    // (such as sidecarEntangle prepending a preamble in hardenProject).
    const text = asBuf.toString("latin1");
    const existingMatch = text.match(/var\s+selfExpected\s*=\s*["']([0-9a-f]{64})["']/);
    if (existingMatch && existingMatch[1]) {
      const oldHexBuf = Buffer.from(existingMatch[1], "latin1");
      asBuf = replaceAllBytes(asBuf, oldHexBuf, needle);
      for (let at = asBuf.indexOf(needle); at !== -1; at = asBuf.indexOf(needle, at + needle.length)) {
        occurrences += 1;
      }
    }
  }
  if (occurrences === 0) return { content, applied: false, occurrences };
  const zero = Buffer.from(SELF_DIGEST_ZERO, "latin1");
  const canon = replaceAllBytes(asBuf, needle, zero);
  const digest = createHash("sha256").update(canon).digest("hex");
  const finalBuf = replaceAllBytes(asBuf, needle, Buffer.from(digest, "latin1"));
  const out = (typeof content === "string" ? finalBuf.toString("utf8") : finalBuf) as T;
  return { content: out, applied: true, digest, occurrences };
}

/**
 * Offline check: does any 64-hex literal in `bytes` verify as the canonical
 * self-digest? Used by harden to keep the coverage matrix honest (only claim
 * entry self-coverage when the runtime check can actually hard-fail).
 */
export function verifySelfSealSelfDigest(bytes: Buffer): { readonly verified: boolean; readonly digest?: string } {
  const text = bytes.toString("latin1");
  const seen = new Set<string>();
  const re = /["'`]([0-9a-f]{64})["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const lit = m[1]!;
    if (seen.has(lit)) continue;
    seen.add(lit);
    if (canonicalSelfDigest(bytes, lit) === lit) return { verified: true, digest: lit };
  }
  return { verified: false };
}

export interface SelfSealOptions {
  /** Extra sibling module paths to hash at runtime (relative or absolute). */
  readonly siblingPaths?: readonly string[];
  /** When true (default), fold inspector / NODE_OPTIONS / Function#toString checks into the digest. */
  readonly envFingerprint?: boolean;
  /** Override the emitted binding name (tests). */
  readonly bindingName?: string;
  /**
   * Optional build-time SHA-256 hex of sibling file bytes (keyed by the same
   * path strings listed in siblingPaths). When present, runtime hard-fails if
   * a sibling's bytes diverge — opaque-seed entanglement alone does not gate
   * entitlement control flow (red/blue round-4).
   */
  readonly expectedSiblingSha256?: Readonly<Record<string, string>>;
  /**
   * When true (default if expectedSiblingSha256 is non-empty), throw on sibling
   * hash mismatch instead of only poisoning the digest.
   */
  readonly hardFailOnSiblingMismatch?: boolean;
  /**
   * Number of colocated interleaved check sites (Direction-3). Default: 2 when
   * siblingPaths is non-empty, else 1 (legacy single preamble).
   */
  readonly interleavedSites?: number;
  /** Stable relative path of this checker host (for coverage matrix keys). */
  readonly checkerHostPath?: string;
  /** All protected file nodes (for coverage matrix); defaults to siblingPaths + host. */
  readonly coverageFileNodes?: readonly string[];
  /**
   * Emit the canonical self-digest check on the checker host's own bytes.
   * Default: true whenever siblings are present (hard-fail when
   * hardFailOnSiblingMismatch, else poison digest).
   */
  readonly selfDigestCheck?: boolean;
}

export interface SelfSealSnippet {
  readonly schema: typeof SELF_SEAL_SCHEMA;
  readonly code: string;
  readonly bindingName: string;
  /** Pure helper used by tests — not embedded in customer output. */
  readonly expectedDigestHelperName: string;
  readonly siblingCount: number;
  readonly envFingerprint: boolean;
  /** How many sibling expected hashes were embedded for hard-fail. */
  readonly expectedSiblingHashCount: number;
  readonly hardFailOnSiblingMismatch: boolean;
  /** Colocated interleaved site count actually emitted. */
  readonly interleavedSites: number;
  /** Coverage matrix for packaging gates / bla_lint_integrity_coverage. */
  readonly coverageMatrix: CoverageMatrix;
  /** True when sites embed {@link SELF_DIGEST_PLACEHOLDER} (finalize at write time). */
  readonly selfDigestCheck: boolean;
}

function emitMeasureFunction(
  helperName: string,
  siblingsLiteral: string,
  expectedLiteral: string,
  hardFailOnSiblingMismatch: boolean,
  envFingerprint: boolean,
  selfDigestCheck: boolean,
): string[] {
  const lines: string[] = [];
  lines.push(`function ${helperName}() {`);
  lines.push(`  var digest = 0;`);
  lines.push(`  try {`);
  lines.push(`    var _c = require("node:crypto");`);
  lines.push(`    var _fs = require("node:fs");`);
  lines.push(`    var _path = require("node:path");`);
  lines.push(`    var h = _c.createHash("sha256");`);
  lines.push(
    `    var selfPath = (typeof __filename === "string" ? __filename : null);`,
  );
  lines.push(
    `    if (!selfPath && typeof __dirname === "string") selfPath = _path.join(__dirname, "index.js");`,
  );
  lines.push(`    var selfBuf = null;`);
  lines.push(
    `    if (selfPath) { try { selfBuf = _fs.readFileSync(selfPath); h.update(selfBuf); } catch (_e) { selfBuf = null; } }`,
  );
  if (selfDigestCheck) {
    // Canonical self-digest: zero every occurrence of the embedded literal, hash,
    // compare. Literal is finalized at write time; non-hex → soft-skip.
    lines.push(`    var selfExpected = ${JSON.stringify(SELF_DIGEST_PLACEHOLDER)};`);
    lines.push(`    if (selfBuf && /^[0-9a-f]{64}$/.test(selfExpected)) {`);
    lines.push(`      var _lit = Buffer.from(selfExpected, "latin1");`);
    lines.push(`      var _zero = Buffer.alloc(64, 0x30);`);
    lines.push(`      var _canon = Buffer.from(selfBuf);`);
    lines.push(`      for (var _at = _canon.indexOf(_lit); _at !== -1; _at = _canon.indexOf(_lit, _at + 64)) _zero.copy(_canon, _at);`);
    lines.push(
      `      if (_c.createHash("sha256").update(_canon).digest("hex") !== selfExpected) {`,
    );
    if (hardFailOnSiblingMismatch) {
      lines.push(`        throw new Error("integrity check failed");`);
    } else {
      lines.push(`        digest = 0xffffffff;`);
    }
    lines.push(`      }`);
    lines.push(`    }`);
  }
  lines.push(`    var siblings = ${siblingsLiteral};`);
  lines.push(`    var expected = ${expectedLiteral};`);
  lines.push(`    for (var i = 0; i < siblings.length; i++) {`);
  lines.push(`      try {`);
  lines.push(`        var spKey = siblings[i];`);
  lines.push(`        var sp = spKey;`);
  lines.push(
    `        if (!_path.isAbsolute(sp) && typeof __dirname === "string") sp = _path.join(__dirname, sp);`,
  );
  lines.push(`        var sibBuf = _fs.readFileSync(sp);`);
  lines.push(
    `        var sibHex = _c.createHash("sha256").update(sibBuf).digest("hex");`,
  );
  lines.push(`        if (expected[spKey] && expected[spKey] !== sibHex) {`);
  if (hardFailOnSiblingMismatch) {
    lines.push(`          throw new Error("integrity check failed");`);
  } else {
    lines.push(`          digest = 0xffffffff;`);
  }
  lines.push(`        }`);
  lines.push(`        h.update(sp);`);
  lines.push(`        h.update(sibBuf);`);
  lines.push(`      } catch (_e2) {`);
  lines.push(
    `        if (_e2 && _e2.message === "integrity check failed") throw _e2;`,
  );
  if (hardFailOnSiblingMismatch) {
    // A missing sibling is a failed integrity invariant, not a benign state:
    // otherwise deleting the anchor file silently downgrades the hard-fail check.
    lines.push(
      `        if (expected[String(siblings[i])]) throw new Error("integrity check failed");`,
    );
  }
  lines.push(`        h.update("missing:" + String(siblings[i]));`);
  lines.push(`      }`);
  lines.push(`    }`);
  if (envFingerprint) {
    lines.push(`    var envNote = "";`);
    lines.push(`    try {`);
    lines.push(`      envNote += String(process.env.NODE_OPTIONS || "");`);
    lines.push(`      envNote += (process.execArgv || []).join(",");`);
    lines.push(
      `      envNote += (/\\[native code\\]/.test(Function.prototype.toString.call(Function.prototype.toString)) ? "N" : "T");`,
    );
    lines.push(`    } catch (_e3) { envNote += "E"; }`);
    lines.push(`    h.update(envNote);`);
  }
  lines.push(`    var hex = h.digest("hex");`);
  lines.push(`    digest = parseInt(hex.slice(0, 8), 16) >>> 0;`);
  lines.push(`  } catch (_e4) {`);
  lines.push(
    `    if (_e4 && _e4.message === "integrity check failed") throw _e4;`,
  );
  lines.push(`    digest = 0;`);
  lines.push(`  }`);
  lines.push(`  return digest >>> 0;`);
  lines.push(`}`);
  return lines;
}

/**
 * Build a deterministic, greppable-marker-free self-seal preamble.
 * Identifiers come from the project PRNG so hardened artifacts stay mixed-vocab.
 */
export function generateSelfSealSnippet(
  prng: SeededPrng,
  options: SelfSealOptions = {},
): SelfSealSnippet {
  const bindingName =
    options.bindingName ??
    prng.identifier({ style: "camel", hint: "integrityDigest", entropy: 4 });
  const envFingerprint = options.envFingerprint !== false;
  const siblings = (options.siblingPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  const expectedSiblingSha256 = options.expectedSiblingSha256 ?? {};
  const expectedEntries = Object.entries(expectedSiblingSha256).filter(
    ([k, v]) =>
      typeof k === "string" &&
      k.length > 0 &&
      typeof v === "string" &&
      /^[0-9a-f]{64}$/i.test(v),
  );
  const hardFailOnSiblingMismatch =
    options.hardFailOnSiblingMismatch !== undefined
      ? options.hardFailOnSiblingMismatch
      : expectedEntries.length > 0;

  const interleavedSites =
    options.interleavedSites !== undefined
      ? Math.max(1, Math.floor(options.interleavedSites))
      : siblings.length > 0
        ? 2
        : 1;

  const selfDigestCheck =
    options.selfDigestCheck !== undefined ? options.selfDigestCheck : siblings.length > 0;

  const siblingsLiteral = JSON.stringify(siblings);
  const expectedLiteral = JSON.stringify(
    Object.fromEntries(expectedEntries.map(([k, v]) => [k, v.toLowerCase()])),
  );

  const helperNames: string[] = [];
  const lines: string[] = [];
  for (let site = 0; site < interleavedSites; site++) {
    const helperName = prng.identifier({
      style: "camel",
      hint: site === 0 ? "measureIntegrity" : `measureIntegrity${site}`,
      entropy: 4,
    });
    helperNames.push(helperName);
    lines.push(
      ...emitMeasureFunction(
        helperName,
        siblingsLiteral,
        expectedLiteral,
        hardFailOnSiblingMismatch,
        envFingerprint,
        selfDigestCheck,
      ),
    );
  }

  // Invoke every site; fold digests so NOP-ing one still leaves others running
  // (each already hard-fails independently on sibling mismatch before return).
  if (interleavedSites === 1) {
    lines.push(`var ${bindingName} = ${helperNames[0]}();`);
  } else {
    const parts = helperNames.map((h) => `${h}()`).join(" ^ ");
    lines.push(`var ${bindingName} = (${parts}) >>> 0;`);
  }

  const host = options.checkerHostPath ?? "entry.js";
  const fileNodes =
    options.coverageFileNodes && options.coverageFileNodes.length > 0
      ? options.coverageFileNodes
      : [...siblings, host];
  const expectedForMatrix: Record<string, string> = {
    ...Object.fromEntries(
      expectedEntries.map(([k, v]) => [k, v.toLowerCase()]),
    ),
  };
  // Host / colocated-site hashes are filled by finalizeCoverageMatrixHashes after
  // the checker file is written — never invent placeholder digests.

  const coverageMatrix = buildInterleavedCoverageMatrix({
    fileNodes,
    checkerHosts: [host],
    expectedSha256: expectedForMatrix,
    colocatedSites: interleavedSites,
  });

  return {
    schema: SELF_SEAL_SCHEMA,
    code: lines.join("\n"),
    bindingName,
    expectedDigestHelperName: helperNames[0]!,
    siblingCount: siblings.length,
    envFingerprint,
    expectedSiblingHashCount: expectedEntries.length,
    hardFailOnSiblingMismatch,
    interleavedSites,
    coverageMatrix,
    selfDigestCheck,
  };
}

/**
 * Offline helper for tests / tooling: SHA-256 first-8-hex → u32 of concatenated
 * path‖bytes pairs (mirrors the runtime happy path without env fingerprint).
 */
export function measureSelfSealDigestOffline(
  parts: readonly { readonly pathLabel: string; readonly bytes: Buffer }[],
): number {
  const h = createHash("sha256");
  for (const part of parts) {
    h.update(part.pathLabel);
    h.update(part.bytes);
  }
  return parseInt(h.digest("hex").slice(0, 8), 16) >>> 0;
}
