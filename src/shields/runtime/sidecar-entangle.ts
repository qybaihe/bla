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
 * `.bla/sidecar.v1.json` note verified by `verifyAsarSidecarArchiveNote`, plus an
 * optional in-archive main JS preamble (`generateSidecarAsarMainJsPreamble`) that
 * re-measures members via Electron's fs-patched `readFileSync`; CPython `.pyc`
 * appends a TYPE_ASCII marshal trailer note (`__blaPycSidecarDigest=…`) verified
 * by `verifyPycSidecarMarshalNote` (importlib ignores post-root trailers — see
 * `docs/design/sidecar-entry-entanglement.md`); GGUF plants a STRING metadata
 * KV note (`bla.sidecar.v1`) verified by `verifyGgufSidecarMetadataNote`, with
 * alignment-safe rewrite so tensor bytes stay bit-exact.
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
import {
  encodeGgufStringKv,
  parseGgufLayout,
  readGgufStringKv,
  rebuildGguf,
} from "../formats/gguf-layout.js";
import {
  buildSafetensorsBuffer,
  validateSafetensorsBuffer,
} from "../formats/model.js";

export const SIDECAR_ENTANGLE_SCHEMA = "bla-sidecar-entangle/v1" as const;

export type SidecarJsCarrier = "module" | "script" | "commonjs";

/**
 * Validate `carrier` for JS sidecar entanglement. Both CommonJS/script and ES
 * module (`"module"`) carriers are supported: `"module"` emits an ESM-safe
 * preamble backed by `import { createRequire } from "node:module"` +
 * `import.meta.url`, while CommonJS/script emits the classic synchronous IIFE.
 */
export function assertSidecarJsCarrierSupported(carrier?: SidecarJsCarrier): void {
  if (
    carrier !== undefined &&
    carrier !== "module" &&
    carrier !== "script" &&
    carrier !== "commonjs"
  ) {
    throw new Error(`Unsupported sidecar JS carrier: ${String(carrier)}`);
  }
}

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
  /**
   * Module carrier of the entry being bound. `"module"` is refused: the
   * preamble cannot run under ESM scope (see `assertSidecarJsCarrierSupported`).
   */
  readonly carrier?: SidecarJsCarrier;
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
  readonly entryHookKind: "js-preamble" | "python-preamble" | "wasm-custom-section" | "bun-companion-note" | "asar-archive-note" | "pyc-marshal-note" | "gguf-metadata-note" | "safetensors-metadata-note" | "unspecified";
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
  if (/\.pyc$/.test(lower)) return "pyc-marshal-note";
  if (/\.wasm$/.test(lower)) return "wasm-custom-section";
  if (/\.asar$/.test(lower)) return "asar-archive-note";
  if (/\.gguf$/.test(lower)) return "gguf-metadata-note";
  if (/\.safetensors$/.test(lower)) return "safetensors-metadata-note";
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
  /** Runtime JS carrier (`"module"` emits an ESM-native `createRequire(import.meta.url)` preamble). */
  readonly carrier?: SidecarJsCarrier;
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
  const isEsm = options.carrier === "module";
  const reqHelperAlias = `__blaSidecarReq_${expectedHex.slice(0, 8)}`;

  const lines: string[] = [];
  if (isEsm) {
    lines.push(`import { createRequire as ${reqHelperAlias} } from "node:module";`);
  }
  lines.push(`(function(){`);
  lines.push(`  var __expected = ${JSON.stringify(expectedHex)};`);
  lines.push(`  var ${bindingName} = 0;`);
  lines.push(`  try {`);
  if (isEsm) {
    lines.push(`    var _req = ${reqHelperAlias}(import.meta.url);`);
    lines.push(`    var _c = _req("node:crypto");`);
    lines.push(`    var _fs = _req("node:fs");`);
    lines.push(`    var _path = _req("node:path");`);
    lines.push(
      `    var _baseDir = _path.dirname(_req("node:url").fileURLToPath(import.meta.url));`,
    );
  } else {
    lines.push(`    var _c = require("node:crypto");`);
    lines.push(`    var _fs = require("node:fs");`);
    lines.push(`    var _path = require("node:path");`);
    lines.push(
      `    var _baseDir = (typeof __dirname === "string" ? __dirname : null);`,
    );
  }
  lines.push(`    var h = _c.createHash("sha256");`);
  lines.push(`    var entryLabel = ${entryLiteral};`);
  lines.push(`    h.update(entryLabel);`);
  lines.push(`    h.update(String.fromCharCode(0));`);
  lines.push(`    var sidecars = ${sidecarsLiteral};`);
  lines.push(`    for (var i = 0; i < sidecars.length; i++) {`);
  lines.push(`      var sp = sidecars[i];`);
  lines.push(`      var spAbs = sp;`);
  lines.push(
    `      if (!_path.isAbsolute(spAbs) && typeof _baseDir === "string") spAbs = _path.join(_baseDir, sp);`,
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
  assertSidecarJsCarrierSupported(options.carrier);
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
    carrier: options.carrier,
  });
  const entrySource =
    options.entrySource ?? new TextDecoder().decode(options.entryBytes);
  const shebangMatch = entrySource.match(/^#![^\n]*\r?\n/);
  const shebang = shebangMatch ? shebangMatch[0] : "";
  const afterShebang = shebang ? entrySource.slice(shebang.length) : entrySource;
  const isEsm = options.carrier === "module";
  const strictMatch = !isEsm ? afterShebang.match(/^["']use strict["'];?\r?\n/) : null;
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
  readonly carrier?: SidecarJsCarrier;
}): SidecarJsBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindSidecarEntanglement({
    entryPath: options.entryPath,
    sidecarPaths: options.sidecars.map((s) => s.pathLabel),
    seedTag: options.seedTag,
    softFold: options.softFold,
    carrier: options.carrier,
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
 * host-side `verifyAsarSidecarArchiveNote` and optional in-archive main JS preamble.
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
    note: "Bound — ASAR archive note `.bla/sidecar.v1.json` ready; plant as Pickle member with decoy sidecars; optionally prepend generateSidecarAsarMainJsPreamble to the main JS member. Strip/alter fails closed.",
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


/** Marker substring embedded in ASAR main JS strip⇒fail preambles (detect / idempotency). */
export const ASAR_SIDECAR_MAIN_JS_MARKER = "__blaAsarSidecarDigest" as const;

/**
 * Resolve an asar-root-relative member path so it can be read via
 * `path.join(__dirname, …)` from a main module that may live in a subdirectory.
 */
export function asarMemberPathFromMain(
  mainRelativePath: string,
  memberRelativePath: string,
): string {
  const main = mainRelativePath.replaceAll("\\", "/").replace(/^\.\//, "");
  const member = memberRelativePath.replaceAll("\\", "/").replace(/^\.\//, "");
  const slash = main.lastIndexOf("/");
  const mainDir = slash === -1 ? "" : main.slice(0, slash);
  if (!mainDir) return member;
  const mainParts = mainDir.split("/").filter((p) => p.length > 0 && p !== ".");
  const memberParts = member.split("/").filter((p) => p.length > 0 && p !== ".");
  let i = 0;
  while (
    i < mainParts.length &&
    i < memberParts.length &&
    mainParts[i] === memberParts[i]
  ) {
    i++;
  }
  const ups = mainParts.length - i;
  const down = memberParts.slice(i);
  const rel = [...Array.from({ length: ups }, () => ".."), ...down].join("/");
  return rel.length > 0 ? rel : ".";
}

/**
 * Pick the Electron main JS member inside an ASAR: `package.json#main` when it
 * points at an in-archive `.js/.mjs/.cjs`, else common entry filenames, else the
 * first top-level JS member that is not a BLA decoy.
 */
export function selectAsarMainJsMember(
  members: readonly { readonly relativePath: string; readonly content?: Uint8Array }[],
): string | null {
  const normalized = members.map((m) => ({
    relativePath: m.relativePath.replaceAll("\\", "/"),
    content: m.content,
  }));
  const byPath = new Map(normalized.map((m) => [m.relativePath, m]));
  const pkg = byPath.get("package.json");
  if (pkg?.content) {
    try {
      const json = JSON.parse(Buffer.from(pkg.content).toString("utf8")) as {
        main?: unknown;
      };
      if (typeof json.main === "string" && json.main.length > 0) {
        const main = json.main.replaceAll("\\", "/").replace(/^\.\//, "");
        if (byPath.has(main) && /\.(mjs|cjs|js)$/i.test(main)) return main;
      }
    } catch {
      /* ignore malformed package.json */
    }
  }
  for (const candidate of [
    "main.js",
    "index.js",
    "app.js",
    "src/main.js",
    "src/index.js",
    "lib/main.js",
    "lib/index.js",
  ]) {
    if (byPath.has(candidate)) return candidate;
  }
  for (const m of normalized) {
    const p = m.relativePath;
    if (p.includes("/")) continue;
    if (!/\.(mjs|cjs|js)$/i.test(p)) continue;
    if (p.startsWith(".")) continue;
    return p;
  }
  return null;
}

export interface SidecarAsarMainJsInjectOptions {
  /** Entry path label used in the binding digest (usually the `.asar` basename). */
  readonly entryPath: string;
  /** In-archive relative path of the main JS member that will host the preamble. */
  readonly mainRelativePath: string;
  /** Asar-root-relative sidecar member paths (digest labels). */
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  readonly expectedHex: string;
  readonly softFold?: boolean;
  readonly bindingName?: string;
}

export interface SidecarAsarMainJsInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: typeof ASAR_SIDECAR_MAIN_JS_MARKER | string;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  readonly mainRelativePath: string;
  /** Asar-root path labels hashed into the digest. */
  readonly sidecarPathLabels: readonly string[];
  /** Paths used with `path.join(__dirname, …)` from the main member. */
  readonly sidecarReadPaths: readonly string[];
}

/**
 * Emit an Electron-ASAR main JS preamble that re-measures in-archive sidecar
 * members via fs-patched `readFileSync` (paths resolved from the main member's
 * `__dirname` back to the asar root) and compares against the protect-time
 * digest. Digest path *labels* stay asar-root-relative so they match
 * `generateSidecarAsarArchiveNote` / `verifyAsarSidecarArchiveNote`.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarAsarMainJsPreamble(
  options: SidecarAsarMainJsInjectOptions,
): SidecarAsarMainJsInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const bindingName = options.bindingName ?? ASAR_SIDECAR_MAIN_JS_MARKER;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const mainRelativePath = options.mainRelativePath.replaceAll("\\", "/").replace(/^\.\//, "");
  const readPaths = sidecars.map((sp) => asarMemberPathFromMain(mainRelativePath, sp));
  const labelsLiteral = JSON.stringify(sidecars);
  const readsLiteral = JSON.stringify(readPaths);
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
  lines.push(`    var sidecars = ${labelsLiteral};`);
  lines.push(`    var reads = ${readsLiteral};`);
  lines.push(`    for (var i = 0; i < sidecars.length; i++) {`);
  lines.push(`      var sp = sidecars[i];`);
  lines.push(`      var spAbs = reads[i];`);
  lines.push(
    `      if (!_path.isAbsolute(spAbs) && typeof __dirname === "string") spAbs = _path.join(__dirname, spAbs);`,
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
    mainRelativePath,
    sidecarPathLabels: sidecars,
    sidecarReadPaths: readPaths,
  };
}

/**
 * Prepend an ASAR main JS preamble after shebang / `"use strict"`, idempotent
 * when the marker is already present.
 */
export function prependAsarMainJsPreamble(
  entrySource: string,
  preamble: string,
): string {
  if (entrySource.includes(ASAR_SIDECAR_MAIN_JS_MARKER)) return entrySource;
  const shebangMatch = entrySource.match(/^#![^\n]*\r?\n/);
  const shebang = shebangMatch ? shebangMatch[0] : "";
  const afterShebang = shebang ? entrySource.slice(shebang.length) : entrySource;
  const strictMatch = afterShebang.match(/^["']use strict["'];?\r?\n/);
  const strict = strictMatch ? strictMatch[0] : "";
  const body = strict ? afterShebang.slice(strict.length) : afterShebang;
  return `${shebang}${strict}${preamble}\n${body}`;
}

/**
 * Plant (or refresh) the ASAR main JS strip⇒fail preamble on the selected main
 * member. Returns null when no suitable main JS member exists.
 */
export function entangleAsarMainJsWithSidecars(options: {
  readonly members: readonly {
    readonly relativePath: string;
    readonly content: Buffer;
    readonly executable?: boolean;
  }[];
  readonly entryPath: string;
  readonly expectedHex: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): {
  readonly mainRelativePath: string;
  readonly inject: SidecarAsarMainJsInjectResult;
  readonly members: {
    relativePath: string;
    content: Buffer;
    executable?: true;
  }[];
} | null {
  const mainRelativePath = selectAsarMainJsMember(options.members);
  if (!mainRelativePath) return null;
  const inject = generateSidecarAsarMainJsPreamble({
    entryPath: options.entryPath,
    mainRelativePath,
    sidecarPaths: options.sidecarPaths,
    seedTag: options.seedTag,
    expectedHex: options.expectedHex,
    softFold: options.softFold,
  });
  type MemberOut = {
    relativePath: string;
    content: Buffer;
    executable?: true;
  };
  const members: MemberOut[] = options.members.map((m): MemberOut => {
    const rel = m.relativePath.replaceAll("\\", "/");
    if (rel !== mainRelativePath) {
      return m.executable
        ? { relativePath: m.relativePath, content: m.content, executable: true }
        : { relativePath: m.relativePath, content: m.content };
    }
    const next = prependAsarMainJsPreamble(
      m.content.toString("utf8"),
      inject.preamble,
    );
    const content = Buffer.from(next, "utf8");
    return m.executable
      ? { relativePath: m.relativePath, content, executable: true }
      : { relativePath: m.relativePath, content };
  });
  return { mainRelativePath, inject, members };
}


/** Marker prefix inside the TYPE_ASCII marshal trailer for `.pyc` sidecar notes. */
export const PYC_SIDECAR_MARSHAL_MARKER = "__blaPycSidecarDigest=" as const;
export const PYC_SIDECAR_MARSHAL_KIND = "pyc-marshal-note" as const;

export interface PycSidecarMarshalNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof PYC_SIDECAR_MARSHAL_KIND;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarPycInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). */
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarPycInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof PYC_SIDECAR_MARSHAL_KIND;
  /** UTF-8 payload stored inside the TYPE_ASCII record (marker + JSON). */
  readonly payload: string;
  readonly note: PycSidecarMarshalNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  /** Full marshal TYPE_ASCII record ready to append after the root object. */
  readonly marshalRecord: Buffer;
}

/**
 * Build a CPython marshal TYPE_ASCII record that carries the sidecar binding
 * note. Appended AFTER the root marshal object so `importlib` / `marshal.load`
 * stop at the woven root and runtime behavior stays byte-equivalent for the
 * executed code object (same trailer convention as protectPythonPycBuffer honey).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarPycMarshalNote(
  options: SidecarPycInjectOptions,
): SidecarPycInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: PycSidecarMarshalNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: PYC_SIDECAR_MARSHAL_KIND,
    digest: expectedHex,
    seedTag,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    softFold,
    mode: "sidecars",
  };
  const payload = `${PYC_SIDECAR_MARSHAL_MARKER}${JSON.stringify(note)}`;
  const strBytes = Buffer.from(payload, "utf8");
  const header = Buffer.alloc(5);
  header[0] = 0x61; // TYPE_ASCII
  header.writeUInt32LE(strBytes.length, 1);
  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: PYC_SIDECAR_MARSHAL_KIND,
    payload,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
    marshalRecord: Buffer.concat([header, strBytes]),
  };
}

export interface SidecarPycBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarPycInjectResult;
  /** `.pyc` bytes with the marshal note trailer appended (root object untouched). */
  readonly bytes: Buffer;
}

/**
 * Plan + bind for a CPython `.pyc` entry: compute the offline digest from
 * in-memory sidecar bytes and return a `bound` plan plus the rewritten `.pyc`
 * with a TYPE_ASCII marshal trailer note. Uses sidecars-mode digest so
 * appending the trailer does not invalidate H. Executed code object unchanged.
 */
export function bindPycSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarPycBindResult {
  const plan = planSidecarEntanglement(options);
  if (options.sidecarBytes.length !== plan.sidecarPaths.length) {
    throw new Error("sidecarBytes length must match sidecarPaths length");
  }
  const entryBuf = Buffer.from(options.entryBytes);
  if (entryBuf.length < 16 || entryBuf[2] !== 0x0d || entryBuf[3] !== 0x0a) {
    throw new Error("entryBytes is not a valid CPython .pyc (bad magic marker)");
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
  // Strip any prior note trailer so re-bind is idempotent.
  const stripped = stripPycSidecarMarshalNote(entryBuf);
  const inject = generateSidecarPycMarshalNote({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const bytes = Buffer.concat([stripped, inject.marshalRecord]);
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "pyc-marshal-note",
    status: "bound",
    note: "Bound — .pyc TYPE_ASCII marshal trailer note planted; ship sidecars alongside and verify via verifyPycSidecarMarshalNote. Host verify fails closed on strip/alter; importlib ignores the trailer (no process-start fail until an import-time hook lands).",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    bytes,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + `.pyc` entry bytes, produce
 * the strip⇒fail-bound entry. Returns null when there are no sidecars to bind.
 */
export function entanglePycEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarPycBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindPycSidecarEntanglement({
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

export interface PycSidecarVerifyOptions {
  /** Full `.pyc` bytes (header + root marshal + optional trailers). */
  readonly entryBytes: Uint8Array;
  /**
   * Absolute directory used to resolve relative sidecar paths from the note.
   * Required when note.sidecarPaths are relative and not supplied in-memory.
   */
  readonly baseDir?: string;
  /** Optional in-memory sidecar bytes keyed by pathLabel (overrides disk read). */
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface PycSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: PycSidecarMarshalNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

/**
 * Locate the `__blaPycSidecarDigest=` TYPE_ASCII payload inside `.pyc` trailers.
 * Returns null when the marker is absent.
 */
export function extractPycSidecarMarshalNote(
  entryBytes: Uint8Array,
): PycSidecarMarshalNote | null {
  const buf = Buffer.from(entryBytes);
  const marker = Buffer.from(PYC_SIDECAR_MARSHAL_MARKER, "utf8");
  const at = buf.lastIndexOf(marker);
  if (at < 0) return null;
  // Prefer framed TYPE_ASCII: 0x61 + u32le len immediately before marker.
  let jsonText: string | null = null;
  if (at >= 5 && buf[at - 5] === 0x61) {
    const declared = buf.readUInt32LE(at - 4);
    const payloadStart = at;
    const payloadEnd = payloadStart + declared;
    if (payloadEnd <= buf.length) {
      const payload = buf.subarray(payloadStart, payloadEnd).toString("utf8");
      if (payload.startsWith(PYC_SIDECAR_MARSHAL_MARKER)) {
        jsonText = payload.slice(PYC_SIDECAR_MARSHAL_MARKER.length);
      }
    }
  }
  if (jsonText === null) {
    // Fallback: marker through end-of-buffer (or next NUL).
    const rest = buf.subarray(at + marker.length).toString("utf8");
    const nul = rest.indexOf("\0");
    jsonText = nul >= 0 ? rest.slice(0, nul) : rest;
  }
  try {
    const parsed = JSON.parse(jsonText) as PycSidecarMarshalNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.kind !== PYC_SIDECAR_MARSHAL_KIND ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return null;
    }
    return {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      kind: PYC_SIDECAR_MARSHAL_KIND,
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
    return null;
  }
}

/**
 * Remove a previously planted `.pyc` sidecar marshal note trailer (idempotent).
 * Leaves honey/chaff TYPE_ASCII trailers from protectPythonPycBuffer intact
 * when they do not carry the sidecar marker.
 */
export function stripPycSidecarMarshalNote(entryBytes: Uint8Array): Buffer {
  const buf = Buffer.from(entryBytes);
  const marker = Buffer.from(PYC_SIDECAR_MARSHAL_MARKER, "utf8");
  const at = buf.lastIndexOf(marker);
  if (at < 0) return buf;
  if (at >= 5 && buf[at - 5] === 0x61) {
    const declared = buf.readUInt32LE(at - 4);
    const recordStart = at - 5;
    const recordEnd = at + declared;
    if (recordEnd <= buf.length && at + declared === recordEnd) {
      // Drop this TYPE_ASCII record only.
      return Buffer.concat([buf.subarray(0, recordStart), buf.subarray(recordEnd)]);
    }
  }
  // Fallback: truncate from marker (may leave a dangling TYPE_ASCII header).
  return buf.subarray(0, Math.max(0, at - 5));
}

/**
 * Host-side strip⇒fail check for `.pyc` marshal notes: extract the trailer
 * note, re-hash sibling sidecar bytes with the same layout as
 * `computeSidecarBindingDigest` (sidecars mode), and compare to the embedded
 * digest. Missing note / missing sibling / altered sibling ⇒ ok:false.
 *
 * DEFENSIVE ONLY — for tests, loaders, and harden post-pass verification.
 */
export function verifyPycSidecarMarshalNote(
  options: PycSidecarVerifyOptions,
): PycSidecarVerifyResult {
  const note = extractPycSidecarMarshalNote(options.entryBytes);
  if (!note) {
    return { ok: false, reason: "pyc sidecar marshal note missing" };
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
        return {
          ok: false,
          reason: `sidecar ${label} missing on disk`,
          note,
          expectedHex: note.digest,
          softFold: note.softFold,
        };
      }
      sidecarParts.push({ pathLabel: label, bytes: readFileSync(abs) });
    } catch {
      return {
        ok: false,
        reason: `sidecar ${label} unreadable`,
        note,
        expectedHex: note.digest,
        softFold: note.softFold,
      };
    }
  }

  const measured = computeSidecarBindingDigest(
    {
      pathLabel: note.entryPath,
      bytes: options.entryBytes,
    },
    sidecarParts,
    note.seedTag,
    "sidecars",
  );
  if (measured.hex !== note.digest) {
    return {
      ok: false,
      reason: "pyc sidecar digest mismatch",
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: measured.u32,
      softFold: note.softFold,
    };
  }
  return {
    ok: true,
    note,
    expectedHex: note.digest,
    measuredHex: measured.hex,
    measuredU32: measured.u32,
    softFold: note.softFold,
  };
}



// ---------------------------------------------------------------------------
// GGUF STRING metadata note (alignment-safe)
// ---------------------------------------------------------------------------

/** Metadata KV key planted inside the GGUF header. */
export const GGUF_SIDECAR_METADATA_KEY = "bla.sidecar.v1" as const;
export const GGUF_SIDECAR_METADATA_KIND = "gguf-sidecar-metadata" as const;

export interface GgufSidecarMetadataNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof GGUF_SIDECAR_METADATA_KIND;
  readonly key: typeof GGUF_SIDECAR_METADATA_KEY;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarGgufInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** Offline expected digest (from computeSidecarBindingDigest). */
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarGgufInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof GGUF_SIDECAR_METADATA_KIND;
  readonly key: typeof GGUF_SIDECAR_METADATA_KEY;
  readonly noteJson: string;
  readonly note: GgufSidecarMetadataNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  /** Fully encoded STRING-typed GGUF KV record ready to append. */
  readonly kvRecord: Buffer;
}

/**
 * Build a GGUF STRING metadata KV (`bla.sidecar.v1`) that carries the sidecar
 * binding note. Tensor bytes, tensor infos, and relative tensor offsets stay
 * untouched when the entry is rewritten via `rebuildGguf` (alignment-safe).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarGgufMetadataNote(
  options: SidecarGgufInjectOptions,
): SidecarGgufInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: GgufSidecarMetadataNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: GGUF_SIDECAR_METADATA_KIND,
    key: GGUF_SIDECAR_METADATA_KEY,
    digest: expectedHex,
    seedTag,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    softFold,
    mode: "sidecars",
  };
  const noteJson = JSON.stringify(note);
  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: GGUF_SIDECAR_METADATA_KIND,
    key: GGUF_SIDECAR_METADATA_KEY,
    noteJson,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
    kvRecord: encodeGgufStringKv(GGUF_SIDECAR_METADATA_KEY, noteJson),
  };
}

export interface SidecarGgufBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarGgufInjectResult;
  /** GGUF bytes with the bla.sidecar.v1 STRING KV planted (tensors bit-exact). */
  readonly bytes: Buffer;
}

/**
 * Plan + bind for a GGUF entry: compute the offline digest from in-memory
 * sidecar bytes and return a `bound` plan plus the rewritten GGUF with a
 * `bla.sidecar.v1` STRING metadata note. Uses sidecars-mode digest so planting
 * the note does not invalidate H. Tensor bytes stay bit-exact via
 * alignment-safe rebuild.
 */
export function bindGgufSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarGgufBindResult {
  const plan = planSidecarEntanglement(options);
  if (options.sidecarBytes.length !== plan.sidecarPaths.length) {
    throw new Error("sidecarBytes length must match sidecarPaths length");
  }
  const entryBuf = Buffer.from(options.entryBytes);
  const layout = parseGgufLayout(entryBuf);
  if (!layout) {
    throw new Error("entryBytes is not a valid GGUF v2/v3 container");
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
  const inject = generateSidecarGgufMetadataNote({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  // Drop any prior note so re-bind is idempotent, then append the fresh one.
  const bytes = rebuildGguf(entryBuf, layout, {
    dropKeys: new Set([GGUF_SIDECAR_METADATA_KEY]),
    appendKvs: [inject.kvRecord],
  });
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "gguf-metadata-note",
    status: "bound",
    note: "Bound — GGUF bla.sidecar.v1 STRING metadata note planted; ship sidecars alongside and verify via verifyGgufSidecarMetadataNote. Host verify fails closed on strip/alter; GGUF loaders ignore unknown STRING KVs (no process-start fail until a load-time hook lands). Tensor bytes stay bit-exact.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    bytes,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + GGUF entry bytes, produce
 * the strip⇒fail-bound entry. Returns null when there are no sidecars to bind.
 */
export function entangleGgufEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarGgufBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindGgufSidecarEntanglement({
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

export interface GgufSidecarVerifyOptions {
  /** Full GGUF bytes (header + KVs + tensor infos + data). */
  readonly entryBytes: Uint8Array;
  /**
   * Absolute directory used to resolve relative sidecar paths from the note.
   * Required when note.sidecarPaths are relative and not supplied in-memory.
   */
  readonly baseDir?: string;
  /** Optional in-memory sidecar bytes keyed by pathLabel (overrides disk read). */
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface GgufSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: GgufSidecarMetadataNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

/**
 * Extract the `bla.sidecar.v1` STRING metadata note from a GGUF buffer.
 * Returns null when the key is absent or the value is not a well-formed note.
 */
export function extractGgufSidecarMetadataNote(
  entryBytes: Uint8Array,
): GgufSidecarMetadataNote | null {
  const layout = parseGgufLayout(entryBytes);
  if (!layout) return null;
  const jsonText = readGgufStringKv(entryBytes, layout, GGUF_SIDECAR_METADATA_KEY);
  if (jsonText === null) return null;
  try {
    const parsed = JSON.parse(jsonText) as GgufSidecarMetadataNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.kind !== GGUF_SIDECAR_METADATA_KIND ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return null;
    }
    return {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      kind: GGUF_SIDECAR_METADATA_KIND,
      key: GGUF_SIDECAR_METADATA_KEY,
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
    return null;
  }
}

/**
 * Remove a previously planted GGUF sidecar metadata note (idempotent).
 * Tensor bytes stay bit-exact via alignment-safe rebuild.
 */
export function stripGgufSidecarMetadataNote(entryBytes: Uint8Array): Buffer {
  const layout = parseGgufLayout(entryBytes);
  if (!layout) return Buffer.from(entryBytes);
  if (!layout.kvs.some((kv) => kv.key === GGUF_SIDECAR_METADATA_KEY)) {
    return Buffer.from(entryBytes);
  }
  return rebuildGguf(entryBytes, layout, {
    dropKeys: new Set([GGUF_SIDECAR_METADATA_KEY]),
  });
}

/**
 * Host-side strip⇒fail check for GGUF metadata notes: extract the STRING KV
 * note, re-hash sibling sidecar bytes with the same layout as
 * `computeSidecarBindingDigest` (sidecars mode), and compare to the embedded
 * digest. Missing note / missing sibling / altered sibling ⇒ ok:false.
 *
 * DEFENSIVE ONLY — for tests, loaders, and harden post-pass verification.
 * GGUF loaders ignore unknown STRING KVs, so strip does not break load until
 * a load-time hook lands (same honesty bar as .pyc marshal trailer).
 */
export function verifyGgufSidecarMetadataNote(
  options: GgufSidecarVerifyOptions,
): GgufSidecarVerifyResult {
  const note = extractGgufSidecarMetadataNote(options.entryBytes);
  if (!note) {
    return { ok: false, reason: "gguf sidecar metadata note missing" };
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
        return {
          ok: false,
          reason: `sidecar ${label} missing on disk`,
          note,
          expectedHex: note.digest,
          softFold: note.softFold,
        };
      }
      sidecarParts.push({ pathLabel: label, bytes: readFileSync(abs) });
    } catch {
      return {
        ok: false,
        reason: `sidecar ${label} unreadable`,
        note,
        expectedHex: note.digest,
        softFold: note.softFold,
      };
    }
  }

  const measured = computeSidecarBindingDigest(
    {
      pathLabel: note.entryPath,
      bytes: options.entryBytes,
    },
    sidecarParts,
    note.seedTag,
    "sidecars",
  );
  if (measured.hex !== note.digest) {
    return {
      ok: false,
      reason: "gguf sidecar digest mismatch",
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: measured.u32,
      softFold: note.softFold,
    };
  }
  return {
    ok: true,
    note,
    expectedHex: note.digest,
    measuredHex: measured.hex,
    measuredU32: measured.u32,
    softFold: note.softFold,
  };
}

/** Test/helper: strip the sidecar note section from a WASM binary. */
export function stripWasmSidecarCustomSection(bytes: Uint8Array): Buffer {
  return stripWasmCustomSectionByName(Buffer.from(bytes), WASM_SIDECAR_SECTION_NAME);
}

// ---------------------------------------------------------------------------
// Safetensors __metadata__ Sidecar Note (host-verify; tensor bytes bit-exact)
// ---------------------------------------------------------------------------

export const SAFETENSORS_SIDECAR_METADATA_KEY = "bla.sidecar.v1" as const;
export const SAFETENSORS_SIDECAR_METADATA_KIND = "bla-safetensors-sidecar-v1" as const;

export interface SafetensorsSidecarMetadataNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof SAFETENSORS_SIDECAR_METADATA_KIND;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag: string;
  readonly digestAlgorithm: "sha256";
  readonly digestMode: "sidecars";
  readonly digest: string;
  readonly u32: number;
  readonly softFold: boolean;
}

export interface SidecarSafetensorsInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarSafetensorsInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly metadataKey: typeof SAFETENSORS_SIDECAR_METADATA_KEY;
  readonly metadataValue: string;
  readonly note: SafetensorsSidecarMetadataNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
}

export function generateSidecarSafetensorsMetadataNote(
  options: SidecarSafetensorsInjectOptions,
): SidecarSafetensorsInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: SafetensorsSidecarMetadataNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: SAFETENSORS_SIDECAR_METADATA_KIND,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    seedTag,
    digestAlgorithm: "sha256",
    digestMode: "sidecars",
    digest: expectedHex,
    u32: expectedU32,
    softFold,
  };
  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    metadataKey: SAFETENSORS_SIDECAR_METADATA_KEY,
    metadataValue: JSON.stringify(note),
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
  };
}

export interface SidecarSafetensorsBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarSafetensorsInjectResult;
  readonly bytes: Buffer;
}

export function stripSafetensorsSidecarMetadataNote(bytes: Uint8Array): Buffer {
  const buf = Buffer.from(bytes);
  const { header, tensorData } = validateSafetensorsBuffer(buf);
  const nextHeader: Record<string, unknown> = { ...header };
  if (
    typeof nextHeader.__metadata__ === "object" &&
    nextHeader.__metadata__ !== null &&
    !Array.isArray(nextHeader.__metadata__)
  ) {
    const meta = { ...(nextHeader.__metadata__ as Record<string, string>) };
    delete meta[SAFETENSORS_SIDECAR_METADATA_KEY];
    if (Object.keys(meta).length === 0) {
      delete nextHeader.__metadata__;
    } else {
      nextHeader.__metadata__ = meta;
    }
  }
  return buildSafetensorsBuffer(nextHeader, tensorData);
}

export function bindSafetensorsSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarSafetensorsBindResult {
  const rawBuf = Buffer.from(options.entryBytes);
  const { header, tensorData } = validateSafetensorsBuffer(rawBuf);
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
  const inject = generateSidecarSafetensorsMetadataNote({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const nextHeader: Record<string, unknown> = { ...header };
  const nextMeta =
    typeof nextHeader.__metadata__ === "object" &&
    nextHeader.__metadata__ !== null &&
    !Array.isArray(nextHeader.__metadata__)
      ? { ...(nextHeader.__metadata__ as Record<string, string>) }
      : {};
  nextMeta[SAFETENSORS_SIDECAR_METADATA_KEY] = inject.metadataValue;
  nextHeader.__metadata__ = nextMeta;
  const outBytes = buildSafetensorsBuffer(nextHeader, tensorData);
  validateSafetensorsBuffer(outBytes);
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "safetensors-metadata-note",
    status: "bound",
    note: "Bound — Safetensors __metadata__ bla.sidecar.v1 note planted (tensor bytes bit-exact); verify via verifySafetensorsSidecarMetadataNote.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    bytes: outBytes,
  };
}

export function entangleSafetensorsEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarSafetensorsBindResult | null {
  if (options.sidecars.length === 0) return null;
  return bindSafetensorsSidecarEntanglement({
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

export function extractSafetensorsSidecarMetadataNote(
  entryBytes: Uint8Array,
): SafetensorsSidecarMetadataNote | null {
  try {
    const { header } = validateSafetensorsBuffer(Buffer.from(entryBytes));
    const meta = header.__metadata__;
    if (typeof meta !== "object" || meta === null || Array.isArray(meta)) return null;
    const raw = (meta as Record<string, unknown>)[SAFETENSORS_SIDECAR_METADATA_KEY];
    if (typeof raw !== "string" || raw.length === 0) return null;
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const rec = parsed as Record<string, unknown>;
    if (
      rec.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      rec.kind !== SAFETENSORS_SIDECAR_METADATA_KIND ||
      typeof rec.entryPath !== "string" ||
      !Array.isArray(rec.sidecarPaths) ||
      !rec.sidecarPaths.every((p) => typeof p === "string") ||
      typeof rec.seedTag !== "string" ||
      rec.digestAlgorithm !== "sha256" ||
      rec.digestMode !== "sidecars" ||
      typeof rec.digest !== "string" ||
      !/^[0-9a-f]{64}$/.test(rec.digest) ||
      typeof rec.u32 !== "number" ||
      typeof rec.softFold !== "boolean"
    ) {
      return null;
    }
    return {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      kind: SAFETENSORS_SIDECAR_METADATA_KIND,
      entryPath: rec.entryPath,
      sidecarPaths: rec.sidecarPaths as string[],
      seedTag: rec.seedTag,
      digestAlgorithm: "sha256",
      digestMode: "sidecars",
      digest: rec.digest,
      u32: rec.u32,
      softFold: rec.softFold,
    };
  } catch {
    return null;
  }
}

export interface SafetensorsSidecarVerifyOptions {
  readonly entryBytes: Uint8Array;
  readonly baseDir?: string;
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface SafetensorsSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: SafetensorsSidecarMetadataNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

export function verifySafetensorsSidecarMetadataNote(
  options: SafetensorsSidecarVerifyOptions,
): SafetensorsSidecarVerifyResult {
  const note = extractSafetensorsSidecarMetadataNote(options.entryBytes);
  if (!note) {
    return { ok: false, reason: "safetensors sidecar metadata note missing" };
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
        return {
          ok: false,
          reason: `sidecar ${label} missing on disk`,
          note,
          expectedHex: note.digest,
          softFold: note.softFold,
        };
      }
      sidecarParts.push({ pathLabel: label, bytes: readFileSync(abs) });
    } catch {
      return {
        ok: false,
        reason: `sidecar ${label} unreadable`,
        note,
        expectedHex: note.digest,
        softFold: note.softFold,
      };
    }
  }
  const measured = computeSidecarBindingDigest(
    { pathLabel: note.entryPath, bytes: options.entryBytes },
    sidecarParts,
    note.seedTag,
    "sidecars",
  );
  if (measured.hex !== note.digest) {
    return {
      ok: false,
      reason: "safetensors sidecar digest mismatch",
      note,
      expectedHex: note.digest,
      measuredHex: measured.hex,
      measuredU32: measured.u32,
      softFold: note.softFold,
    };
  }
  return {
    ok: true,
    note,
    expectedHex: note.digest,
    measuredHex: measured.hex,
    measuredU32: measured.u32,
    softFold: note.softFold,
  };
}
