/**
 * Sidecar / entry entanglement planner (issue #40 / Direction-3).
 *
 * Elevates the former planned-stub into a coverage-matrix planner that assigns
 * interleaved SHA-256 check edges across entry + sidecar paths. JS + Python
 * strip⇒fail rewrite is available via `bindSidecarEntanglement` /
 * `generateSidecarJsPreamble` / `generateSidecarPythonPreamble` when
 * `sidecarEntangle` is set (see `docs/design/sidecar-entry-entanglement.md`).
 * WASM custom-section notes remain TBD.
 *
 * DEFENSIVE ONLY. Hash-only — no guessing.
 */

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, isAbsolute } from "node:path";
import {
  INTEGRITY_COVERAGE_SCHEMA,
  buildInterleavedCoverageMatrix,
  evaluateCoverageMatrix,
  finalizeCoverageMatrixHashes,
  type CoverageEvaluation,
  type CoverageMatrix,
} from "../../engine/integrity-coverage.js";
import { findPythonPrologueInsertionOffset } from "../formats/python.js";

export const SIDECAR_ENTANGLE_SCHEMA = "bla-sidecar-entangle/v1" as const;

export interface SidecarEntanglePlanOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** When true, plan folds the binding into self-seal / opaque seed rather than a hard throw. */
  readonly softFold?: boolean;
  /**
   * Optional on-disk bytes (or absolute paths to read) keyed by the same relative
   * paths listed in entry/sidecars — used to finalize expectedSha256.
   */
  readonly fileBytes?: Readonly<Record<string, Buffer | string>>;
  /** Absolute directory used to resolve relative paths when reading hashes. */
  readonly baseDir?: string;
}

export interface SidecarEntanglePlan {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly digestAlgorithm: "sha256";
  readonly seedTag: string;
  readonly softFold: boolean;
  /** Offline binding id (hash of paths + seedTag) — not the runtime content digest. */
  readonly planId: string;
  readonly entryHookKind: "js-preamble" | "python-preamble" | "wasm-custom-section" | "unspecified";
  /** `ready` when coverage matrix satisfies refuse predicates; else `incomplete`. */
  readonly status: "ready" | "incomplete" | "bound";
  readonly note: string;
  readonly coverageMatrix: CoverageMatrix;
  readonly coverageEvaluation: CoverageEvaluation;
}

function guessHookKind(entryPath: string): SidecarEntanglePlan["entryHookKind"] {
  const lower = entryPath.toLowerCase();
  if (/\.(mjs|cjs|js|ts|tsx|jsx)$/.test(lower)) return "js-preamble";
  if (/\.py$/.test(lower)) return "python-preamble";
  if (/\.wasm$/.test(lower)) return "wasm-custom-section";
  return "unspecified";
}

function isJsChecker(path: string): boolean {
  return /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(path);
}

function isPythonChecker(path: string): boolean {
  return /\.py$/i.test(path);
}

/** Entry formats that can host an interleaved strip⇒fail checker preamble. */
function isCheckerHost(path: string): boolean {
  return isJsChecker(path) || isPythonChecker(path);
}

/**
 * Plan interleaved sidecar↔entry entanglement as a coverage matrix.
 * Reads optional on-disk bytes to finalize hashes when `baseDir` + paths exist.
 */
export function planSidecarEntanglement(
  options: SidecarEntanglePlanOptions,
): SidecarEntanglePlan {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const planId = createHash("sha256")
    .update(options.entryPath)
    .update("\0")
    .update(sidecars.join("\0"))
    .update("\0")
    .update(seedTag)
    .digest("hex")
    .slice(0, 16);

  const fileNodes = [...new Set([options.entryPath, ...sidecars])].sort();
  const checkerHosts = fileNodes.filter(isCheckerHost);
  // Prefer entry as a checker host even if list empty.
  const hosts =
    checkerHosts.length > 0
      ? checkerHosts
      : isCheckerHost(options.entryPath)
        ? [options.entryPath]
        : [];

  let expected: Record<string, string> = {};
  const supplied = options.fileBytes ?? {};
  for (const [k, v] of Object.entries(supplied)) {
    expected[k] = createHash("sha256")
      .update(typeof v === "string" ? Buffer.from(v) : v)
      .digest("hex");
  }

  // Optionally read from disk when baseDir is provided.
  if (options.baseDir) {
    for (const rel of fileNodes) {
      if (expected[rel]) continue;
      const abs = isAbsolute(rel) ? rel : join(options.baseDir, rel);
      try {
        if (existsSync(abs)) {
          expected[rel] = createHash("sha256")
            .update(readFileSync(abs))
            .digest("hex");
        }
      } catch {
        /* leave missing — evaluate will refuse */
      }
    }
  }

  let matrix = buildInterleavedCoverageMatrix({
    fileNodes,
    checkerHosts: hosts.length > 0 ? hosts : [options.entryPath],
    expectedSha256: expected,
    colocatedSites: 2,
  });
  matrix = finalizeCoverageMatrixHashes(matrix, {
    ...Object.fromEntries(
      Object.entries(supplied).map(([k, v]) => [
        k,
        typeof v === "string" ? Buffer.from(v) : v,
      ]),
    ),
  });
  // Re-apply disk hashes into finalize if we computed expected above.
  if (Object.keys(expected).length > 0) {
    matrix = {
      schema: INTEGRITY_COVERAGE_SCHEMA,
      nodes: matrix.nodes,
      edges: matrix.edges,
      expectedSha256: { ...matrix.expectedSha256, ...expected },
    };
    matrix = finalizeCoverageMatrixHashes(matrix, {});
  }

  const coverageEvaluation = evaluateCoverageMatrix(matrix);
  const status = coverageEvaluation.ok ? "ready" : "incomplete";

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    digestAlgorithm: "sha256",
    seedTag,
    softFold: options.softFold === true,
    planId,
    entryHookKind: guessHookKind(options.entryPath),
    status,
    note: coverageEvaluation.ok
      ? "Interleaved coverage matrix ready — wire checkers via self-seal / protect."
      : `Coverage incomplete: ${coverageEvaluation.reasons.join(", ")}. ${coverageEvaluation.oneLineAdvice}`,
    coverageMatrix: matrix,
    coverageEvaluation,
  };
}

/** A labelled entry- or sidecar-file measurement for offline binding. */
export interface SidecarBindingPart {
  readonly pathLabel: string;
  readonly bytes: Uint8Array;
}

export interface SidecarBindingDigest {
  /** Full SHA-256 hex over entry‖sidecars‖seedTag (mode-dependent). */
  readonly hex: string;
  /** First 8 hex chars folded to an unsigned 32-bit int (matches self-seal fold shape). */
  readonly u32: number;
}

/**
 * Binding modes:
 * - "sidecars" (default): hash entry path label + each sidecar path‖bytes + seedTag.
 *   Safe to prepend a preamble to the entry without invalidating the digest
 *   (strip⇒fail targets sidecar removal/tamper; entry body integrity is self-seal).
 * - "full": also fold entry.bytes (protect-time snapshot). Use only when the
 *   entry will not be rewritten after the digest is sealed.
 */
export type SidecarBindingMode = "sidecars" | "full";

/**
 * Compute the offline binding digest for an entry and its sidecars.
 *
 * DEFENSIVE ONLY — integrity binding, not an encryption primitive.
 */
export function computeSidecarBindingDigest(
  entry: SidecarBindingPart,
  sidecars: readonly SidecarBindingPart[],
  seedTag = "bla-sidecar-v1",
  mode: SidecarBindingMode = "sidecars",
): SidecarBindingDigest {
  const h = createHash("sha256");
  h.update(entry.pathLabel);
  h.update("\0");
  if (mode === "full") {
    h.update(entry.bytes);
    h.update("\0");
  }
  for (const s of sidecars) {
    h.update(s.pathLabel);
    h.update("\0");
    h.update(s.bytes);
    h.update("\0");
  }
  h.update(seedTag);
  const hex = h.digest("hex");
  return { hex, u32: parseInt(hex.slice(0, 8), 16) >>> 0 };
}

export interface SidecarJsInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). Required for hard fail. */
  readonly expectedHex: string;
  /** Binding name for the measured digest (tests / soft-fold). */
  readonly bindingName?: string;
  /**
   * When true, emit a soft fold that only flips the measured u32 on mismatch
   * (caller entangles with opaque seed). When false (default), throw on mismatch.
   */
  readonly softFold?: boolean;
}

export interface SidecarJsInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
}

/**
 * Emit a Node JS preamble that re-measures sidecar siblings and compares
 * against the protect-time SHA-256 hex. Strip / alter ⇒ throw (hard) or
 * expose a flipped digest (softFold) for opaque-seed entanglement.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarJsPreamble(
  options: SidecarJsInjectOptions,
): SidecarJsInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const bindingName = options.bindingName ?? "__blaSidecarDigest";
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const sidecarsLiteral = JSON.stringify(sidecars);
  const entryLiteral = JSON.stringify(options.entryPath);
  const seedLiteral = JSON.stringify(seedTag);

  const lines: string[] = [];
  lines.push(`(function(){`);
  lines.push(`  var __expected = ${JSON.stringify(expectedHex)};`);
  lines.push(`  var ${bindingName} = 0;`);
  lines.push(`  try {`);
  lines.push(`    var _c = require("node:crypto");`);
  lines.push(`    var _fs = require("node:fs");`);
  lines.push(`    var _path = require("node:path");`);
  lines.push(`    var h = _c.createHash("sha256");`);
  lines.push(`    var entryLabel = ${entryLiteral};`);
  lines.push(`    h.update(entryLabel);`);
  lines.push(`    h.update(String.fromCharCode(0));`);
  lines.push(`    var sidecars = ${sidecarsLiteral};`);
  lines.push(`    for (var i = 0; i < sidecars.length; i++) {`);
  lines.push(`      var sp = sidecars[i];`);
  lines.push(`      var spAbs = sp;`);
  lines.push(
    `      if (!_path.isAbsolute(spAbs) && typeof __dirname === "string") spAbs = _path.join(__dirname, sp);`,
  );
  lines.push(`      h.update(sp);`);
  lines.push(`      h.update(String.fromCharCode(0));`);
  lines.push(
    `      try { h.update(_fs.readFileSync(spAbs)); } catch (_e1) { h.update("missing:" + String(sp)); }`,
  );
  lines.push(`      h.update(String.fromCharCode(0));`);
  lines.push(`    }`);
  lines.push(`    h.update(${seedLiteral});`);
  lines.push(`    var hex = h.digest("hex");`);
  lines.push(`    ${bindingName} = parseInt(hex.slice(0, 8), 16) >>> 0;`);
  if (softFold) {
    lines.push(
      `    if (hex !== __expected) { ${bindingName} = (${bindingName} ^ 0xffffffff) >>> 0; }`,
    );
  } else {
    lines.push(
      `    if (hex !== __expected) { throw new Error("integrity binding mismatch"); }`,
    );
  }
  lines.push(`  } catch (_e2) {`);
  if (softFold) {
    lines.push(`    ${bindingName} = 0;`);
  } else {
    lines.push(
      `    if (_e2 && _e2.message === "integrity binding mismatch") throw _e2;`,
    );
    lines.push(`    throw new Error("integrity binding mismatch");`);
  }
  lines.push(`  }`);
  lines.push(`  return ${bindingName};`);
  lines.push(`})();`);

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
  };
}

export interface SidecarJsBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarJsInjectResult;
  /** Entry source with the strip⇒fail preamble prepended. */
  readonly code: string;
}

/**
 * Plan + bind for a JS entry: compute the offline digest from in-memory
 * sidecar bytes and return a `bound` plan plus the rewritten entry source.
 *
 * Uses sidecars-mode digest so the prepended preamble does not invalidate H.
 */
export function bindSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
    /** Original entry source to prepend into. Defaults to utf8 of entryBytes. */
    readonly entrySource?: string;
  },
): SidecarJsBindResult {
  const plan = planSidecarEntanglement(options);
  if (options.sidecarBytes.length !== plan.sidecarPaths.length) {
    throw new Error("sidecarBytes length must match sidecarPaths length");
  }
  const digest = computeSidecarBindingDigest(
    { pathLabel: options.entryPath, bytes: options.entryBytes },
    plan.sidecarPaths.map((pathLabel, i) => ({
      pathLabel,
      bytes: options.sidecarBytes[i]!,
    })),
    plan.seedTag,
    "sidecars",
  );
  const inject = generateSidecarJsPreamble({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const entrySource =
    options.entrySource ?? new TextDecoder().decode(options.entryBytes);
  const shebangMatch = entrySource.match(/^#![^\n]*\r?\n/);
  const shebang = shebangMatch ? shebangMatch[0] : "";
  const afterShebang = shebang ? entrySource.slice(shebang.length) : entrySource;
  const strictMatch = afterShebang.match(/^["']use strict["'];?\r?\n/);
  const strict = strictMatch ? strictMatch[0] : "";
  const body = strict ? afterShebang.slice(strict.length) : afterShebang;
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    status: "bound",
    note: "Bound — JS preamble ready; prepend to entry and ship sidecars alongside. Strip/alter fails closed.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    code: `${shebang}${strict}${inject.preamble}\n${body}`,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + entry source, produce the
 * strip⇒fail-bound entry. Returns null when there are no sidecars to bind.
 */
export function entangleJsEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entrySource: string;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarJsBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindSidecarEntanglement({
    entryPath: options.entryPath,
    sidecarPaths: options.sidecars.map((s) => s.pathLabel),
    seedTag: options.seedTag,
    softFold: options.softFold,
    entryBytes: new TextEncoder().encode(options.entrySource),
    sidecarBytes: options.sidecars.map((s) => s.bytes),
    entrySource: options.entrySource,
    fileBytes: Object.fromEntries(
      options.sidecars.map((s) => [s.pathLabel, Buffer.from(s.bytes)]),
    ),
  });
}

export interface SidecarPythonInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). Required for hard fail. */
  readonly expectedHex: string;
  /** Binding name for the measured digest (tests / soft-fold). */
  readonly bindingName?: string;
  /**
   * When true, emit a soft fold that only flips the measured u32 on mismatch
   * (caller entangles with opaque seed). When false (default), throw on mismatch.
   */
  readonly softFold?: boolean;
}

export interface SidecarPythonInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
}

/**
 * Emit a CPython preamble that re-measures sidecar siblings and compares
 * against the protect-time SHA-256 hex. Strip / alter ⇒ raise (hard) or
 * expose a flipped digest (softFold) for opaque-seed entanglement.
 *
 * Uses the same byte layout as `generateSidecarJsPreamble` /
 * `computeSidecarBindingDigest` (UTF-8 path labels + NUL separators).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarPythonPreamble(
  options: SidecarPythonInjectOptions,
): SidecarPythonInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const bindingName = options.bindingName ?? "__bla_sidecar_digest";
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const sidecarsLiteral = JSON.stringify(sidecars);
  const entryLiteral = JSON.stringify(options.entryPath);
  const seedLiteral = JSON.stringify(seedTag);
  const expectedLiteral = JSON.stringify(expectedHex);

  const lines: string[] = [];
  lines.push(`import hashlib as __bla_hashlib`);
  lines.push(`import pathlib as __bla_pathlib`);
  lines.push(`${bindingName} = 0`);
  lines.push(`try:`);
  lines.push(`    __bla_expected = ${expectedLiteral}`);
  lines.push(`    __bla_h = __bla_hashlib.sha256()`);
  lines.push(`    __bla_entry_label = ${entryLiteral}`);
  lines.push(`    __bla_h.update(__bla_entry_label.encode("utf-8"))`);
  lines.push(`    __bla_h.update(b"\\x00")`);
  lines.push(`    __bla_sidecars = ${sidecarsLiteral}`);
  lines.push(`    __bla_base = __bla_pathlib.Path(__file__).resolve().parent`);
  lines.push(`    for __bla_sp in __bla_sidecars:`);
  lines.push(`        __bla_h.update(__bla_sp.encode("utf-8"))`);
  lines.push(`        __bla_h.update(b"\\x00")`);
  lines.push(`        __bla_sp_path = __bla_pathlib.Path(__bla_sp)`);
  lines.push(`        if not __bla_sp_path.is_absolute():`);
  lines.push(`            __bla_sp_path = __bla_base / __bla_sp`);
  lines.push(`        try:`);
  lines.push(`            __bla_h.update(__bla_sp_path.read_bytes())`);
  lines.push(`        except Exception:`);
  lines.push(`            __bla_h.update(("missing:" + str(__bla_sp)).encode("utf-8"))`);
  lines.push(`        __bla_h.update(b"\\x00")`);
  lines.push(`    __bla_h.update(${seedLiteral}.encode("utf-8"))`);
  lines.push(`    __bla_hex = __bla_h.hexdigest()`);
  lines.push(`    ${bindingName} = int(__bla_hex[:8], 16) & 0xffffffff`);
  if (softFold) {
    lines.push(`    if __bla_hex != __bla_expected:`);
    lines.push(`        ${bindingName} = (${bindingName} ^ 0xffffffff) & 0xffffffff`);
  } else {
    lines.push(`    if __bla_hex != __bla_expected:`);
    lines.push(`        raise RuntimeError("integrity binding mismatch")`);
  }
  lines.push(`except Exception as __bla_e2:`);
  if (softFold) {
    lines.push(`    ${bindingName} = 0`);
  } else {
    lines.push(
      `    if isinstance(__bla_e2, RuntimeError) and str(__bla_e2) == "integrity binding mismatch":`,
    );
    lines.push(`        raise`);
    lines.push(`    raise RuntimeError("integrity binding mismatch") from None`);
  }

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
  };
}

export interface SidecarPythonBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarPythonInjectResult;
  /** Entry source with the strip⇒fail preamble inserted after shebang/docstring/futures. */
  readonly code: string;
}

/**
 * Plan + bind for a Python entry: compute the offline digest from in-memory
 * sidecar bytes and return a `bound` plan plus the rewritten entry source.
 *
 * Uses sidecars-mode digest so the inserted preamble does not invalidate H.
 * Inserts after shebang / PEP 263 / module docstring / `from __future__`
 * via `findPythonPrologueInsertionOffset` so real module semantics stay intact.
 */
export function bindPythonSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
    /** Original entry source to insert into. Defaults to utf8 of entryBytes. */
    readonly entrySource?: string;
  },
): SidecarPythonBindResult {
  const plan = planSidecarEntanglement(options);
  if (options.sidecarBytes.length !== plan.sidecarPaths.length) {
    throw new Error("sidecarBytes length must match sidecarPaths length");
  }
  const digest = computeSidecarBindingDigest(
    { pathLabel: options.entryPath, bytes: options.entryBytes },
    plan.sidecarPaths.map((pathLabel, i) => ({
      pathLabel,
      bytes: options.sidecarBytes[i]!,
    })),
    plan.seedTag,
    "sidecars",
  );
  const inject = generateSidecarPythonPreamble({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const entrySource =
    options.entrySource ?? new TextDecoder().decode(options.entryBytes);
  const eol = entrySource.includes("\r\n") ? "\r\n" : "\n";
  const analysis = findPythonPrologueInsertionOffset(entrySource);
  const headRaw = entrySource.slice(0, analysis.insertOffset);
  const tailRaw = entrySource.slice(analysis.insertOffset);
  // Normalize bordering newlines the same way protectPythonSource does so we
  // never glue the preamble onto a trailing partial line or swallow blank lines.
  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "");
  const preamble = inject.preamble.replace(/\r?\n/g, eol).replace(/(?:\r?\n)+$/, "");
  const parts: string[] = [];
  if (head.length > 0) parts.push(head);
  parts.push(preamble);
  if (tail.length > 0) parts.push(tail);
  const code = parts.join(eol) + (entrySource.endsWith("\n") || entrySource.endsWith("\r\n") ? eol : "");
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "python-preamble",
    status: "bound",
    note: "Bound — Python preamble ready; insert after futures and ship sidecars alongside. Strip/alter fails closed.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    code,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + Python entry source, produce
 * the strip⇒fail-bound entry. Returns null when there are no sidecars to bind.
 */
export function entanglePythonEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entrySource: string;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarPythonBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindPythonSidecarEntanglement({
    entryPath: options.entryPath,
    sidecarPaths: options.sidecars.map((s) => s.pathLabel),
    seedTag: options.seedTag,
    softFold: options.softFold,
    entryBytes: new TextEncoder().encode(options.entrySource),
    sidecarBytes: options.sidecars.map((s) => s.bytes),
    entrySource: options.entrySource,
    fileBytes: Object.fromEntries(
      options.sidecars.map((s) => [s.pathLabel, Buffer.from(s.bytes)]),
    ),
  });
}
