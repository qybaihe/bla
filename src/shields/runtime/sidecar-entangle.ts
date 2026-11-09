/**
 * Sidecar / entry entanglement planner (issue #40 / Direction-3).
 *
 * Elevates the former planned-stub into a coverage-matrix planner that assigns
 * interleaved SHA-256 check edges across entry + sidecar paths. JS + Python
 * strip⇒fail rewrite is available via `bindSidecarEntanglement` /
 * `generateSidecarJsPreamble` / `generateSidecarPythonPreamble` when
 * `sidecarEntangle` is set; WASM uses a `bla.sidecar.v1` custom-section note
 * plus host-side `verifyWasmSidecarCustomSection`; Bun standalone plants a
 * sibling `.bla-sidecar.v1.json` companion note (byte-exact binary preserved)
 * verified by `verifyBunSidecarCompanionNote`; Electron ASAR plants an in-archive
 * `.bla/sidecar.v1.json` note verified by `verifyAsarSidecarArchiveNote` (see
 * `docs/design/sidecar-entry-entanglement.md`).
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
import {
  appendWasmCustomSection,
  createWasmCustomSection,
  inspectWasmBinary,
  readWasmCustomSectionContent,
  stripWasmCustomSectionByName,
} from "../formats/wasm.js";
import { unpackAsarBuffer } from "../formats/asar.js";

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
  readonly entryHookKind: "js-preamble" | "python-preamble" | "wasm-custom-section" | "bun-companion-note" | "asar-archive-note" | "unspecified";
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
  if (/\.asar$/.test(lower)) return "asar-archive-note";
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

/** Stable WASM custom-section name for sidecar binding notes (bla.* convention). */
export const WASM_SIDECAR_SECTION_NAME = "bla.sidecar.v1" as const;

export interface WasmSidecarNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly section: typeof WASM_SIDECAR_SECTION_NAME;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarWasmInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). */
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarWasmInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly sectionName: typeof WASM_SIDECAR_SECTION_NAME;
  /** UTF-8 JSON note embedded as the custom-section content. */
  readonly noteJson: string;
  readonly note: WasmSidecarNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  /** Raw custom-section bytes ready to append (id 0 + LEB size + name + content). */
  readonly sectionBytes: Buffer;
}

/**
 * Build a `bla.sidecar.v1` custom-section note that embeds the protect-time
 * sidecar binding digest + path labels. Does not alter WASM exports or
 * function bodies — strip/alter detection is via host-side
 * `verifyWasmSidecarCustomSection` (WASM cannot re-read the host FS alone).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarWasmCustomSection(
  options: SidecarWasmInjectOptions,
): SidecarWasmInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: WasmSidecarNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    section: WASM_SIDECAR_SECTION_NAME,
    digest: expectedHex,
    seedTag,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    softFold,
    mode: "sidecars",
  };
  const noteJson = JSON.stringify(note);
  const sectionBytes = createWasmCustomSection(
    WASM_SIDECAR_SECTION_NAME,
    Buffer.from(noteJson, "utf8"),
  );
  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    sectionName: WASM_SIDECAR_SECTION_NAME,
    noteJson,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
    sectionBytes,
  };
}

export interface SidecarWasmBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarWasmInjectResult;
  /** WASM binary with the bla.sidecar.v1 custom section appended/replaced. */
  readonly bytes: Buffer;
}

/**
 * Plan + bind for a WASM entry: compute the offline digest from in-memory
 * sidecar bytes and return a `bound` plan plus the rewritten WASM binary
 * with a `bla.sidecar.v1` custom-section note. Uses sidecars-mode digest so
 * appending the note does not invalidate H. Export surface unchanged.
 */
export function bindWasmSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarWasmBindResult {
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
  const inject = generateSidecarWasmCustomSection({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const entryBuf = Buffer.from(options.entryBytes);
  const inspection = inspectWasmBinary(entryBuf);
  if (!inspection.validMagic) {
    throw new Error("entryBytes is not a valid WASM binary (bad magic)");
  }
  const bytes = appendWasmCustomSection(
    entryBuf,
    WASM_SIDECAR_SECTION_NAME,
    Buffer.from(inject.noteJson, "utf8"),
  );
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "wasm-custom-section",
    status: "bound",
    note: "Bound — WASM bla.sidecar.v1 custom-section note planted; ship sidecars alongside and verify via verifyWasmSidecarCustomSection. Strip/alter fails closed.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    bytes,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + WASM entry bytes, produce
 * the strip⇒fail-bound entry. Returns null when there are no sidecars to bind.
 */
export function entangleWasmEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarWasmBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindWasmSidecarEntanglement({
    entryPath: options.entryPath,
    sidecarPaths: options.sidecars.map((s) => s.pathLabel),
    seedTag: options.seedTag,
    softFold: options.softFold,
    entryBytes: options.entryBytes,
    sidecarBytes: options.sidecars.map((s) => s.bytes),
    fileBytes: Object.fromEntries(
      options.sidecars.map((s) => [s.pathLabel, Buffer.from(s.bytes)]),
    ),
  });
}

export interface WasmSidecarVerifyOptions {
  /** WASM bytes that should carry bla.sidecar.v1. */
  readonly wasmBytes: Uint8Array;
  /**
   * Absolute directory used to resolve relative sidecar paths from the note.
   * Required when note.sidecarPaths are relative.
   */
  readonly baseDir?: string;
  /**
   * Optional in-memory sidecar bytes keyed by pathLabel (overrides disk read).
   */
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface WasmSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: WasmSidecarNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

/**
 * Host-side strip⇒fail check: parse `bla.sidecar.v1`, re-hash sibling sidecar
 * bytes with the same layout as `computeSidecarBindingDigest` (sidecars mode),
 * and compare to the embedded digest. Missing section / missing sibling /
 * altered sibling ⇒ ok:false (or soft-fold flipped u32 when note.softFold).
 *
 * DEFENSIVE ONLY — for tests, JS loaders, and future self-seal hooks.
 */
export function verifyWasmSidecarCustomSection(
  options: WasmSidecarVerifyOptions,
): WasmSidecarVerifyResult {
  const wasmBuf = Buffer.from(options.wasmBytes);
  const content = readWasmCustomSectionContent(wasmBuf, WASM_SIDECAR_SECTION_NAME);
  if (!content) {
    return {
      ok: false,
      reason: "bla.sidecar.v1 custom section missing or unreadable",
    };
  }
  let note: WasmSidecarNote;
  try {
    const parsed = JSON.parse(content.toString("utf8")) as WasmSidecarNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.section !== WASM_SIDECAR_SECTION_NAME ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return { ok: false, reason: "bla.sidecar.v1 note malformed" };
    }
    note = {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      section: WASM_SIDECAR_SECTION_NAME,
      digest: parsed.digest.toLowerCase(),
      seedTag: typeof parsed.seedTag === "string" ? parsed.seedTag : "bla-sidecar-v1",
      entryPath: typeof parsed.entryPath === "string" ? parsed.entryPath : "",
      sidecarPaths: Array.isArray(parsed.sidecarPaths)
        ? parsed.sidecarPaths.filter((p): p is string => typeof p === "string" && p.length > 0)
        : [],
      softFold: parsed.softFold === true,
      mode: "sidecars",
    };
  } catch {
    return { ok: false, reason: "bla.sidecar.v1 note is not valid JSON" };
  }

  const sidecarParts: SidecarBindingPart[] = [];
  for (const label of note.sidecarPaths) {
    const override = options.sidecarBytes?.[label];
    if (override) {
      sidecarParts.push({ pathLabel: label, bytes: override });
      continue;
    }
    if (!options.baseDir) {
      return {
        ok: false,
        reason: `sidecar ${label} not supplied and no baseDir to read`,
        note,
        expectedHex: note.digest,
        softFold: note.softFold,
      };
    }
    const abs = isAbsolute(label) ? label : join(options.baseDir, label);
    try {
      if (!existsSync(abs)) {
        sidecarParts.push({
          pathLabel: label,
          bytes: new TextEncoder().encode(`missing:${label}`),
        });
        continue;
      }
      sidecarParts.push({ pathLabel: label, bytes: readFileSync(abs) });
    } catch {
      sidecarParts.push({
        pathLabel: label,
        bytes: new TextEncoder().encode(`missing:${label}`),
      });
    }
  }

  const measured = computeSidecarBindingDigest(
    {
      pathLabel: note.entryPath,
      bytes: new Uint8Array(0),
    },
    sidecarParts,
    note.seedTag,
    "sidecars",
  );

  if (measured.hex === note.digest) {
    return {
      ok: true,
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: measured.u32,
      softFold: note.softFold,
    };
  }

  if (note.softFold) {
    return {
      ok: false,
      reason: "integrity binding mismatch (soft-fold)",
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: (measured.u32 ^ 0xffffffff) >>> 0,
      softFold: true,
    };
  }

  return {
    ok: false,
    reason: "integrity binding mismatch",
    note,
    expectedHex: note.digest,
    measuredHex: measured.hex,
    measuredU32: measured.u32,
    softFold: false,
  };
}


/** Sibling companion note next to a Bun standalone / native EOF-preserved binary. */
export const BUN_SIDECAR_COMPANION_SUFFIX = ".bla-sidecar.v1.json" as const;
export const BUN_SIDECAR_COMPANION_KIND = "bun-companion-note" as const;

export interface BunSidecarCompanionNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof BUN_SIDECAR_COMPANION_KIND;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarBunInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). */
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarBunInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof BUN_SIDECAR_COMPANION_KIND;
  /** UTF-8 JSON companion note (written next to the binary; binary stays byte-exact). */
  readonly noteJson: string;
  readonly note: BunSidecarCompanionNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  /** Suggested filename suffix relative to the entry basename (`<entry>.bla-sidecar.v1.json`). */
  readonly companionSuffix: typeof BUN_SIDECAR_COMPANION_SUFFIX;
}

/**
 * Build a Bun companion note that embeds the protect-time sidecar binding
 * digest + path labels. The Bun / EOF-preserved binary itself is NEVER
 * rewritten (runtime red line — Bun locates the appended graph relative to
 * EOF). Strip/alter detection is via host-side `verifyBunSidecarCompanionNote`.
 *
 * Typical sidecar is `<binary>.bunfs-snapshot` planted by protectNativeBinary.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarBunCompanionNote(
  options: SidecarBunInjectOptions,
): SidecarBunInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: BunSidecarCompanionNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: BUN_SIDECAR_COMPANION_KIND,
    digest: expectedHex,
    seedTag,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    softFold,
    mode: "sidecars",
  };
  const noteJson = `${JSON.stringify(note, null, 2)}\n`;
  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: BUN_SIDECAR_COMPANION_KIND,
    noteJson,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
    companionSuffix: BUN_SIDECAR_COMPANION_SUFFIX,
  };
}

export interface SidecarBunBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarBunInjectResult;
  /** Companion note JSON bytes to write next to the entry (entry bytes untouched). */
  readonly noteBytes: Buffer;
}

/**
 * Plan + bind for a Bun / EOF-preserved native entry: compute the offline
 * digest from in-memory sidecar bytes (typically `.bunfs-snapshot`) and return
 * a `bound` plan plus companion-note bytes. Uses sidecars-mode digest; the
 * entry binary is never mutated.
 */
export function bindBunSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarBunBindResult {
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
  const inject = generateSidecarBunCompanionNote({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "bun-companion-note",
    status: "bound",
    note: "Bound — Bun companion `.bla-sidecar.v1.json` ready; ship next to the byte-exact binary with `.bunfs-snapshot` sidecars. Strip/alter fails closed via verifyBunSidecarCompanionNote.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    noteBytes: Buffer.from(inject.noteJson, "utf8"),
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + Bun entry bytes, produce
 * the companion note. Returns null when there are no sidecars to bind.
 * Does NOT rewrite entry bytes.
 */
export function entangleBunEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarBunBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindBunSidecarEntanglement({
    entryPath: options.entryPath,
    sidecarPaths: options.sidecars.map((s) => s.pathLabel),
    seedTag: options.seedTag,
    softFold: options.softFold,
    entryBytes: options.entryBytes,
    sidecarBytes: options.sidecars.map((s) => s.bytes),
    fileBytes: Object.fromEntries(
      options.sidecars.map((s) => [s.pathLabel, Buffer.from(s.bytes)]),
    ),
  });
}

export interface BunSidecarVerifyOptions {
  /** Companion note JSON bytes (or parsed UTF-8 string). */
  readonly noteBytes: Uint8Array | string;
  /**
   * Absolute directory used to resolve relative sidecar paths from the note.
   * Required when note.sidecarPaths are relative and not supplied in-memory.
   */
  readonly baseDir?: string;
  /** Optional in-memory sidecar bytes keyed by pathLabel (overrides disk read). */
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface BunSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: BunSidecarCompanionNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

/**
 * Host-side strip⇒fail check for Bun companions: parse `.bla-sidecar.v1.json`,
 * re-hash sibling sidecar bytes with the same layout as
 * `computeSidecarBindingDigest` (sidecars mode), and compare to the embedded
 * digest. Missing note / missing sibling / altered sibling ⇒ ok:false.
 *
 * DEFENSIVE ONLY — for tests, loaders, and harden post-pass verification.
 */
export function verifyBunSidecarCompanionNote(
  options: BunSidecarVerifyOptions,
): BunSidecarVerifyResult {
  let note: BunSidecarCompanionNote;
  try {
    const raw =
      typeof options.noteBytes === "string"
        ? options.noteBytes
        : Buffer.from(options.noteBytes).toString("utf8");
    const parsed = JSON.parse(raw) as BunSidecarCompanionNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.kind !== BUN_SIDECAR_COMPANION_KIND ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return { ok: false, reason: "bun companion note malformed" };
    }
    note = {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      kind: BUN_SIDECAR_COMPANION_KIND,
      digest: parsed.digest.toLowerCase(),
      seedTag: typeof parsed.seedTag === "string" ? parsed.seedTag : "bla-sidecar-v1",
      entryPath: typeof parsed.entryPath === "string" ? parsed.entryPath : "",
      sidecarPaths: Array.isArray(parsed.sidecarPaths)
        ? parsed.sidecarPaths.filter((p): p is string => typeof p === "string" && p.length > 0)
        : [],
      softFold: parsed.softFold === true,
      mode: "sidecars",
    };
  } catch {
    return { ok: false, reason: "bun companion note is not valid JSON" };
  }

  const sidecarParts: SidecarBindingPart[] = [];
  for (const label of note.sidecarPaths) {
    const override = options.sidecarBytes?.[label];
    if (override) {
      sidecarParts.push({ pathLabel: label, bytes: override });
      continue;
    }
    if (!options.baseDir) {
      return {
        ok: false,
        reason: `sidecar ${label} not supplied and no baseDir to read`,
        note,
        expectedHex: note.digest,
        softFold: note.softFold,
      };
    }
    const abs = isAbsolute(label) ? label : join(options.baseDir, label);
    try {
      if (!existsSync(abs)) {
        sidecarParts.push({
          pathLabel: label,
          bytes: new TextEncoder().encode(`missing:${label}`),
        });
        continue;
      }
      sidecarParts.push({ pathLabel: label, bytes: readFileSync(abs) });
    } catch {
      sidecarParts.push({
        pathLabel: label,
        bytes: new TextEncoder().encode(`missing:${label}`),
      });
    }
  }

  const measured = computeSidecarBindingDigest(
    {
      pathLabel: note.entryPath,
      bytes: new Uint8Array(0),
    },
    sidecarParts,
    note.seedTag,
    "sidecars",
  );

  if (measured.hex === note.digest) {
    return {
      ok: true,
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: measured.u32,
      softFold: note.softFold,
    };
  }

  if (note.softFold) {
    return {
      ok: false,
      reason: "integrity binding mismatch (soft-fold)",
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: (measured.u32 ^ 0xffffffff) >>> 0,
      softFold: true,
    };
  }

  return {
    ok: false,
    reason: "integrity binding mismatch",
    note,
    expectedHex: note.digest,
    measuredHex: measured.hex,
    measuredU32: measured.u32,
    softFold: false,
  };
}



/** In-archive companion note path inside an Electron `.asar` (Pickle member). */
export const ASAR_SIDECAR_ARCHIVE_NOTE_PATH = ".bla/sidecar.v1.json" as const;
export const ASAR_SIDECAR_ARCHIVE_NOTE_KIND = "asar-archive-note" as const;

export interface AsarSidecarArchiveNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof ASAR_SIDECAR_ARCHIVE_NOTE_KIND;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarAsarInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). */
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarAsarInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof ASAR_SIDECAR_ARCHIVE_NOTE_KIND;
  /** UTF-8 JSON archive note (written as `.bla/sidecar.v1.json` member). */
  readonly noteJson: string;
  readonly note: AsarSidecarArchiveNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  /** Canonical in-archive member path for the note. */
  readonly archiveNotePath: typeof ASAR_SIDECAR_ARCHIVE_NOTE_PATH;
}

/**
 * Build an ASAR archive-note that embeds the protect-time sidecar binding
 * digest + path labels. The note is planted as the Pickle member
 * `.bla/sidecar.v1.json` (not a sibling on disk). Strip/alter detection is via
 * host-side `verifyAsarSidecarArchiveNote` (and optional future main JS preamble).
 *
 * Typical sidecars are in-archive decoys such as `enclave/hardware-tee-bridge.js`.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarAsarArchiveNote(
  options: SidecarAsarInjectOptions,
): SidecarAsarInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: AsarSidecarArchiveNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: ASAR_SIDECAR_ARCHIVE_NOTE_KIND,
    digest: expectedHex,
    seedTag,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    softFold,
    mode: "sidecars",
  };
  const noteJson = `${JSON.stringify(note, null, 2)}\n`;
  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: ASAR_SIDECAR_ARCHIVE_NOTE_KIND,
    noteJson,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
    archiveNotePath: ASAR_SIDECAR_ARCHIVE_NOTE_PATH,
  };
}

export interface SidecarAsarBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarAsarInjectResult;
  /** Archive-note JSON bytes to plant as `.bla/sidecar.v1.json` (entry asar rebuilt). */
  readonly noteBytes: Buffer;
}

/**
 * Plan + bind for an Electron ASAR entry: compute the offline digest from
 * in-memory in-archive sidecar member bytes and return a `bound` plan plus
 * archive-note bytes. Uses sidecars-mode digest; the asar is repacked with the
 * note member (real app modules otherwise untouched by this helper).
 */
export function bindAsarSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarAsarBindResult {
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
  const inject = generateSidecarAsarArchiveNote({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "asar-archive-note",
    status: "bound",
    note: "Bound — ASAR archive note `.bla/sidecar.v1.json` ready; plant as Pickle member with decoy sidecars. Strip/alter fails closed via verifyAsarSidecarArchiveNote.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    noteBytes: Buffer.from(inject.noteJson, "utf8"),
  };
}

/**
 * Convenience: given final in-archive sidecar member bytes + ASAR entry label,
 * produce the archive note. Returns null when there are no sidecars to bind.
 * Does NOT rewrite other members — caller plants `noteBytes` and repacks.
 */
export function entangleAsarEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarAsarBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindAsarSidecarEntanglement({
    entryPath: options.entryPath,
    sidecarPaths: options.sidecars.map((s) => s.pathLabel),
    seedTag: options.seedTag,
    softFold: options.softFold,
    entryBytes: options.entryBytes,
    sidecarBytes: options.sidecars.map((s) => s.bytes),
    fileBytes: Object.fromEntries(
      options.sidecars.map((s) => [s.pathLabel, Buffer.from(s.bytes)]),
    ),
  });
}

export interface AsarSidecarVerifyOptions {
  /** Archive note JSON bytes (or parsed UTF-8 string), or full ASAR buffer to unpack. */
  readonly noteBytes?: Uint8Array | string;
  /** Full ASAR bytes — when set, note is read from `.bla/sidecar.v1.json` member. */
  readonly asarBytes?: Uint8Array;
  /**
   * In-memory archive members keyed by relative path (overrides asar unpack /
   * disk). Used for unit tests and protect-time checks.
   */
  readonly memberBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface AsarSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: AsarSidecarArchiveNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

function parseAsarSidecarArchiveNote(
  raw: string,
): { ok: true; note: AsarSidecarArchiveNote } | { ok: false; reason: string } {
  try {
    const parsed = JSON.parse(raw) as AsarSidecarArchiveNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.kind !== ASAR_SIDECAR_ARCHIVE_NOTE_KIND ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return { ok: false, reason: "asar archive note malformed" };
    }
    return {
      ok: true,
      note: {
        schema: SIDECAR_ENTANGLE_SCHEMA,
        kind: ASAR_SIDECAR_ARCHIVE_NOTE_KIND,
        digest: parsed.digest.toLowerCase(),
        seedTag: typeof parsed.seedTag === "string" ? parsed.seedTag : "bla-sidecar-v1",
        entryPath: typeof parsed.entryPath === "string" ? parsed.entryPath : "",
        sidecarPaths: Array.isArray(parsed.sidecarPaths)
          ? parsed.sidecarPaths.filter((p): p is string => typeof p === "string" && p.length > 0)
          : [],
        softFold: parsed.softFold === true,
        mode: "sidecars",
      },
    };
  } catch {
    return { ok: false, reason: "asar archive note is not valid JSON" };
  }
}

/**
 * Host-side strip⇒fail check for ASAR archive notes: parse
 * `.bla/sidecar.v1.json`, re-hash listed in-archive member bytes with the same
 * layout as `computeSidecarBindingDigest` (sidecars mode), and compare to the
 * embedded digest. Missing note / missing member / altered member ⇒ ok:false.
 *
 * DEFENSIVE ONLY — for tests, loaders, and harden post-pass verification.
 */
export function verifyAsarSidecarArchiveNote(
  options: AsarSidecarVerifyOptions,
): AsarSidecarVerifyResult {
  let noteRaw: string | undefined;
  const members: Record<string, Uint8Array> = {
    ...(options.memberBytes ?? {}),
  };

  if (options.asarBytes) {
    try {
      const unpacked = unpackAsarBuffer(Buffer.from(options.asarBytes));
      for (const vf of unpacked) {
        if (!(vf.relativePath in members)) {
          members[vf.relativePath] = vf.content;
        }
      }
    } catch {
      return { ok: false, reason: "asar archive could not be unpacked" };
    }
  }

  if (options.noteBytes !== undefined) {
    noteRaw =
      typeof options.noteBytes === "string"
        ? options.noteBytes
        : Buffer.from(options.noteBytes).toString("utf8");
  } else if (members[ASAR_SIDECAR_ARCHIVE_NOTE_PATH]) {
    noteRaw = Buffer.from(members[ASAR_SIDECAR_ARCHIVE_NOTE_PATH]!).toString("utf8");
  } else {
    return { ok: false, reason: "asar archive note not supplied" };
  }

  const parsed = parseAsarSidecarArchiveNote(noteRaw);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const note = parsed.note;

  const sidecarParts: SidecarBindingPart[] = [];
  for (const label of note.sidecarPaths) {
    const override = members[label];
    if (override) {
      sidecarParts.push({ pathLabel: label, bytes: override });
      continue;
    }
    sidecarParts.push({
      pathLabel: label,
      bytes: new TextEncoder().encode(`missing:${label}`),
    });
  }

  const measured = computeSidecarBindingDigest(
    {
      pathLabel: note.entryPath,
      bytes: new Uint8Array(0),
    },
    sidecarParts,
    note.seedTag,
    "sidecars",
  );

  if (measured.hex === note.digest) {
    return {
      ok: true,
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: measured.u32,
      softFold: note.softFold,
    };
  }

  if (note.softFold) {
    return {
      ok: false,
      reason: "integrity binding mismatch (soft-fold)",
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: (measured.u32 ^ 0xffffffff) >>> 0,
      softFold: true,
    };
  }

  return {
    ok: false,
    reason: "integrity binding mismatch",
    note,
    expectedHex: note.digest,
    measuredHex: measured.hex,
    measuredU32: measured.u32,
    softFold: false,
  };
}

/** Test/helper: strip the sidecar note section from a WASM binary. */
export function stripWasmSidecarCustomSection(bytes: Uint8Array): Buffer {
  return stripWasmCustomSectionByName(Buffer.from(bytes), WASM_SIDECAR_SECTION_NAME);
}
