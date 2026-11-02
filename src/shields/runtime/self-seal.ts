/**
 * Opt-in self-seal / self-integrity helper (issue #40.5).
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
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice. Browser builds soft-skip (digest=0).
 */

import { createHash } from "node:crypto";
import type { SeededPrng } from "../../core/prng.js";

export const SELF_SEAL_SCHEMA = "bla-self-seal/v1" as const;

export interface SelfSealOptions {
  /** Extra sibling module paths to hash at runtime (relative or absolute). */
  readonly siblingPaths?: readonly string[];
  /** When true (default), fold inspector / NODE_OPTIONS / Function#toString checks into the digest. */
  readonly envFingerprint?: boolean;
  /** Override the emitted binding name (tests). */
  readonly bindingName?: string;
}

export interface SelfSealSnippet {
  readonly schema: typeof SELF_SEAL_SCHEMA;
  readonly code: string;
  readonly bindingName: string;
  /** Pure helper used by tests — not embedded in customer output. */
  readonly expectedDigestHelperName: string;
  readonly siblingCount: number;
  readonly envFingerprint: boolean;
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
  const helperName = prng.identifier({
    style: "camel",
    hint: "measureIntegrity",
    entropy: 4,
  });
  const envFingerprint = options.envFingerprint !== false;
  const siblings = (options.siblingPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );

  // Embed sibling list as a JSON array literal — paths are customer-controlled.
  const siblingsLiteral = JSON.stringify(siblings);

  const lines: string[] = [];
  lines.push(`function ${helperName}() {`);
  lines.push(`  var digest = 0;`);
  lines.push(`  try {`);
  lines.push(`    var _c = require("node:crypto");`);
  lines.push(`    var _fs = require("node:fs");`);
  lines.push(`    var _path = require("node:path");`);
  lines.push(`    var h = _c.createHash("sha256");`);
  lines.push(`    var selfPath = (typeof __filename === "string" ? __filename : null);`);
  lines.push(`    if (!selfPath && typeof __dirname === "string") selfPath = _path.join(__dirname, "index.js");`);
  lines.push(`    if (selfPath) { try { h.update(_fs.readFileSync(selfPath)); } catch (_e) {} }`);
  lines.push(`    var siblings = ${siblingsLiteral};`);
  lines.push(`    for (var i = 0; i < siblings.length; i++) {`);
  lines.push(`      try {`);
  lines.push(`        var sp = siblings[i];`);
  lines.push(`        if (!_path.isAbsolute(sp) && typeof __dirname === "string") sp = _path.join(__dirname, sp);`);
  lines.push(`        h.update(sp);`);
  lines.push(`        h.update(_fs.readFileSync(sp));`);
  lines.push(`      } catch (_e2) { h.update("missing:" + String(siblings[i])); }`);
  lines.push(`    }`);
  if (envFingerprint) {
    lines.push(`    var envNote = "";`);
    lines.push(`    try {`);
    lines.push(`      envNote += String(process.env.NODE_OPTIONS || "");`);
    lines.push(`      envNote += (process.execArgv || []).join(",");`);
    lines.push(`      envNote += (/\\[native code\\]/.test(Function.prototype.toString.call(Function.prototype.toString)) ? "N" : "T");`);
    lines.push(`    } catch (_e3) { envNote += "E"; }`);
    lines.push(`    h.update(envNote);`);
  }
  lines.push(`    var hex = h.digest("hex");`);
  lines.push(`    digest = parseInt(hex.slice(0, 8), 16) >>> 0;`);
  lines.push(`  } catch (_e4) { digest = 0; }`);
  lines.push(`  return digest >>> 0;`);
  lines.push(`}`);
  lines.push(`var ${bindingName} = ${helperName}();`);

  return {
    schema: SELF_SEAL_SCHEMA,
    code: lines.join("\n"),
    bindingName,
    expectedDigestHelperName: helperName,
    siblingCount: siblings.length,
    envFingerprint,
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
