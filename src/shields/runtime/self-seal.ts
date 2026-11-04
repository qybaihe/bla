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
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice. Browser builds soft-skip (digest=0).
 */

import { createHash } from "node:crypto";
import type { SeededPrng } from "../../core/prng.js";
import {
  buildInterleavedCoverageMatrix,
  type CoverageMatrix,
} from "../../engine/integrity-coverage.js";

export const SELF_SEAL_SCHEMA = "bla-self-seal/v1" as const;

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
}

function emitMeasureFunction(
  helperName: string,
  siblingsLiteral: string,
  expectedLiteral: string,
  hardFailOnSiblingMismatch: boolean,
  envFingerprint: boolean,
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
  lines.push(
    `    if (selfPath) { try { h.update(_fs.readFileSync(selfPath)); } catch (_e) {} }`,
  );
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
