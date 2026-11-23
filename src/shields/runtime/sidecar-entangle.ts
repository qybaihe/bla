/**
 * Sidecar / entry entanglement planner (issue #40 / Direction-3).
 *
 * Elevates the former planned-stub into a coverage-matrix planner that assigns
 * interleaved SHA-256 check edges across entry + sidecar paths. JS + Python
 * strip⇒fail rewrite is available via `bindSidecarEntanglement` /
 * `generateSidecarJsPreamble` / `generateSidecarPythonPreamble` when
 * `sidecarEntangle` is set; WASM uses a `bla.sidecar.v1` custom-section note
 * plus host-side `verifyWasmSidecarCustomSection` and an optional host JS
 * loader hook (`generateSidecarWasmLoaderSnippet`) that wraps
 * `WebAssembly.instantiate` / `compile` / `instantiateStreaming` so stripping
 * the custom section fails closed at load time when the host prepends it;
 * Bun standalone plants a
 * sibling `.bla-sidecar.v1.json` companion note (byte-exact binary preserved)
 * verified by `verifyBunSidecarCompanionNote`; Electron ASAR plants an in-archive
 * `.bla/sidecar.v1.json` note verified by `verifyAsarSidecarArchiveNote`, plus an
 * optional in-archive main JS preamble (`generateSidecarAsarMainJsPreamble`) that
 * re-measures members via Electron's fs-patched `readFileSync`; CPython `.pyc`
 * appends a TYPE_ASCII marshal trailer note (`__blaPycSidecarDigest=…`) verified
 * by `verifyPycSidecarMarshalNote` (importlib ignores post-root trailers) and an
 * optional same-directory Python import-time hook
 * (`generateSidecarPycLoaderSnippet` / `prependPycSidecarLoaderHook` /
 * `entanglePycLoaderWithSidecars`) auto-wired into a known safe loader
 * (`loader.py`, `__init__.py`, `__main__.py` — never the `.py` source of the
 * `.pyc` itself) so strip / sibling delete fail closed when that loader runs;
 * only then is `pyc-sidecar-entangle` recorded and
 * `pyc-sidecar-host-verify-only` cleared (see
 * `docs/design/sidecar-entry-entanglement.md`); GGUF plants a STRING metadata
 * KV note (`bla.sidecar.v1`) verified by `verifyGgufSidecarMetadataNote`, with
 * alignment-safe rewrite so tensor bytes stay bit-exact;
 * SQLite plants a reserved unused VIEW (`bla_sidecar_v1`) whose SQL
 * string literal / schema comment carries `bla.sidecar.v1` JSON, verified
 * by `verifySqliteSidecarSchemaComment` (SQLite ignores the unused view —
 * user tables, rows, query results, WAL/FK, and application_id/user_version
 * stay unchanged) and an optional same-directory Python load-time hook
 * (`generateSidecarSqliteLoaderSnippet` / `prependSqliteSidecarLoaderHook` /
 * `entangleSqliteLoaderWithSidecars`) auto-wired into a known safe loader
 * (`loader.py`, `__init__.py`, `__main__.py`) that already mentions the
 * database basename so strip / sibling delete fail closed when that loader
 * runs; only then is `sqlite-sidecar-entangle` recorded and
 * `sqlite-sidecar-host-verify-only` cleared (see
 * `docs/design/sidecar-entry-entanglement.md`).
 *
 * DEFENSIVE ONLY. Hash-only — no guessing.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, posix, relative } from "node:path";
import { isBuiltin } from "node:module";
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
import {
  DEX_SIDECAR_STRING_KEY,
  chooseSortLastDexString,
  dropDexSidecarStrings,
  parseDexLayout,
  rebuildDex,
  stripDexSidecarPrefix,
} from "../formats/dex-layout.js";
import {
  SQLITE_SIDECAR_NOTE_COLUMN,
  SQLITE_SIDECAR_VIEW_NAME,
  canRewriteSqliteSidecar,
  computeSqliteSidecarCodeIdentity,
  extractSqliteSidecarSchemaCommentJson,
  plantSqliteSidecarSchemaComment,
  stripSqliteSidecarSchemaComment as dropSqliteSidecarSchemaView,
} from "../formats/sqlite.js";
import type { Program } from "@babel/types";
import {
  parseNodeRuntimeJavaScript,
  readNodePackageType,
  resolveNodePackageModuleType,
} from "../javascript/node-runtime-carrier.js";
import { ESM_PREHOIST_CAPTURE_DATA_URL } from "./self-seal.js";

/** Insert after the shebang, leading comments, and all directive statements. */
function prependJsPreamble(source: string, preamble: string, filename?: string): string {
  const program = parseNodeRuntimeJavaScript(source, undefined, filename);
  const bodyStart = program.body[0]?.start ?? source.length;
  const directiveEnd = program.directives.at(-1)?.end;
  let prologue = source.slice(0, bodyStart);
  if (directiveEnd != null && source[directiveEnd - 1] !== ";") {
    // A newline alone would let a leading IIFE continue the directive as
    // a call expression. Terminate the literal before its trailing comments.
    prologue = source.slice(0, directiveEnd) + ";" + source.slice(directiveEnd, bodyStart);
  }
  const newline = prologue && !/[\r\n]$/.test(prologue) ? "\n" : "";
  return `${prologue}${newline}${preamble}\n${source.slice(bodyStart)}`;
}

export const SIDECAR_ENTANGLE_SCHEMA = "bla-sidecar-entangle/v1" as const;

/**
 * Derive a one-way public binding nonce from a project/master seed so sidecar
 * preambles, custom sections, and metadata notes never leak the raw master seed.
 * Idempotent when `rawSeed` is already a `scn1-<32hex>` public tag.
 */
export function derivePublicSidecarSeedTag(rawSeed: string): string {
  if (/^scn1-[0-9a-f]{32}$/.test(rawSeed)) return rawSeed;
  const hex = createHash("sha256")
    .update("bla-sidecar-public-nonce/v1\0")
    .update(rawSeed)
    .digest("hex")
    .slice(0, 32);
  return `scn1-${hex}`;
}

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
  readonly entryHookKind: "js-preamble" | "python-preamble" | "wasm-custom-section" | "bun-companion-note" | "asar-archive-note" | "pyc-marshal-note" | "gguf-metadata-note" | "safetensors-metadata-note" | "dex-string-pool-note" | "sqlite-schema-comment" | "unspecified";
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
  if (/\.dex$/.test(lower)) return "dex-string-pool-note";
  if (/\.(sqlite|sqlite3|db)$/.test(lower)) return "sqlite-schema-comment";
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
 * Fill `fileBytes` from the bytes a binder is about to bind so the coverage
 * plan reflects reality instead of reporting missing hashes for sidecars whose
 * bytes are already in hand.
 */
function withBoundFileBytes<
  T extends SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
>(options: T): T {
  const fileBytes: Record<string, Uint8Array | string> = {
    ...(options.fileBytes ?? {}),
    [options.entryPath]: options.entryBytes,
  };
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  for (let i = 0; i < sidecars.length; i += 1) {
    const bytes = options.sidecarBytes[i];
    if (bytes !== undefined) fileBytes[sidecars[i]!] = bytes;
  }
  return { ...options, fileBytes };
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

type SidecarPartsCollection =
  | { readonly ok: true; readonly parts: SidecarBindingPart[] }
  | { readonly ok: false; readonly reason: string };

/**
 * Shared sidecar-part resolution for the `verify*Sidecar*` host checks.
 *
 * - `missingPolicy: "marker"` hashes a `missing:<label>` stand-in so the
 *   digest comparison fails closed (wasm/bun/asar).
 * - `missingPolicy: "fail"` returns the first missing/unreadable label
 *   (pyc/gguf/safetensors).
 * - `requireBaseDir` (default true) fails when a label needs a disk read but
 *   no `baseDir` was supplied; ASAR members never read the disk.
 */
function collectSidecarVerifyParts(options: {
  readonly sidecarPaths: readonly string[];
  readonly overrides?: Readonly<Record<string, Uint8Array>>;
  readonly baseDir?: string;
  readonly requireBaseDir?: boolean;
  readonly missingPolicy: "marker" | "fail";
}): SidecarPartsCollection {
  const parts: SidecarBindingPart[] = [];
  for (const label of options.sidecarPaths) {
    const override = options.overrides?.[label];
    if (override) {
      parts.push({ pathLabel: label, bytes: override });
      continue;
    }
    if (!options.baseDir) {
      if (options.requireBaseDir !== false) {
        return {
          ok: false,
          reason: `sidecar ${label} not supplied and no baseDir to read`,
        };
      }
      parts.push({
        pathLabel: label,
        bytes: new TextEncoder().encode(`missing:${label}`),
      });
      continue;
    }
    const abs = isAbsolute(label) ? label : join(options.baseDir, label);
    try {
      if (!existsSync(abs)) {
        if (options.missingPolicy === "fail") {
          return { ok: false, reason: `sidecar ${label} missing on disk` };
        }
        parts.push({
          pathLabel: label,
          bytes: new TextEncoder().encode(`missing:${label}`),
        });
        continue;
      }
      parts.push({ pathLabel: label, bytes: readFileSync(abs) });
    } catch {
      if (options.missingPolicy === "fail") {
        return { ok: false, reason: `sidecar ${label} unreadable` };
      }
      parts.push({
        pathLabel: label,
        bytes: new TextEncoder().encode(`missing:${label}`),
      });
    }
  }
  return { ok: true, parts };
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
 * `bindingName` overrides are interpolated verbatim into `var <name> = …`
 * declarations, so a caller-supplied value must be a plain identifier: a
 * newline or an unbalanced quote would otherwise inject statements into the
 * preamble that ships inside the protected artifact, and a merely malformed
 * one (a space, a leading digit) would emit code that does not parse.
 */
function assertJsBindingName(bindingName: string): void {
  if (!/^[$A-Za-z_][$A-Za-z0-9_]*$/.test(bindingName)) {
    throw new Error("sidecar bindingName must be a valid JavaScript identifier");
  }
}

/** Python counterpart of {@link assertJsBindingName}; `$` is not a Python identifier character. */
function assertPythonBindingName(bindingName: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(bindingName)) {
    throw new Error("sidecar bindingName must be a valid Python identifier");
  }
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
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const tag = expectedHex.slice(0, 8);
  const bindingName = options.bindingName ?? `_verifySiblingDigest_${tag}`;
  // Interpolated verbatim into `var <name> = …` declarations — require a plain
  // identifier so an override cannot break or inject into the preamble.
  assertJsBindingName(bindingName);
  const expectedU32 = parseInt(tag, 16) >>> 0;
  const sidecarsLiteral = JSON.stringify(sidecars);
  const entryLiteral = JSON.stringify(options.entryPath);
  const seedLiteral = JSON.stringify(seedTag);
  const isEsm = options.carrier === "module";
  const reqHelperAlias = `_resolveModuleRequire_${tag}`;
  const capReadAlias = `_capRead_${tag}`;
  const capHashAlias = `_capHash_${tag}`;

  const lines: string[] = [];
  if (isEsm) {
    // Evaluate BEFORE any user sibling `import` (e.g. `./quota.mjs`), capturing
    // unpatched `node:fs` and `node:crypto` references so a tampered hoisted
    // sibling cannot spoof `fs.readFileSync` / `crypto.createHash`.
    lines.push(
      `import { r as ${capReadAlias}, h as ${capHashAlias} } from ${JSON.stringify(ESM_PREHOIST_CAPTURE_DATA_URL)};`,
    );
    lines.push(`import { createRequire as ${reqHelperAlias} } from "node:module";`);
  }
  lines.push(`(function(){`);
  lines.push(`  var __expected = ${JSON.stringify(expectedHex)};`);
  lines.push(`  var ${bindingName} = 0;`);
  lines.push(`  try {`);
  if (isEsm) {
    lines.push(`    var _req = ${reqHelperAlias}(import.meta.url);`);
    lines.push(`    var _path = _req("node:path");`);
    lines.push(
      `    var _baseDir = _path.dirname(_req("node:url").fileURLToPath(import.meta.url));`,
    );
    lines.push(`    var h = ${capHashAlias}("sha256");`);
  } else {
    lines.push(`    var _c = require("node:crypto");`);
    lines.push(`    var _fs = require("node:fs");`);
    lines.push(`    var _path = require("node:path");`);
    lines.push(
      `    var _baseDir = (typeof __dirname === "string" ? __dirname : null);`,
    );
    lines.push(`    var h = _c.createHash("sha256");`);
  }
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
    isEsm
      ? `      try { h.update(${capReadAlias}(spAbs)); } catch (_e1) { h.update("missing:" + String(sp)); }`
      : `      try { h.update(_fs.readFileSync(spAbs)); } catch (_e1) { h.update("missing:" + String(sp)); }`,
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    status: "bound",
    note: "Bound — JS preamble ready; prepend to entry and ship sidecars alongside. Strip/alter fails closed.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    code: prependJsPreamble(entrySource, inject.preamble, options.entryPath),
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
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const tag = expectedHex.slice(0, 8);
  const bindingName = options.bindingName ?? `_verify_sibling_digest_${tag}`;
  assertPythonBindingName(bindingName);
  const expectedU32 = parseInt(tag, 16) >>> 0;
  const sidecarsLiteral = JSON.stringify(sidecars);
  const entryLiteral = JSON.stringify(options.entryPath);
  const seedLiteral = JSON.stringify(seedTag);
  const expectedLiteral = JSON.stringify(expectedHex);

  const lines: string[] = [];
  lines.push(`import builtins as _sc_bi_${tag}`);
  lines.push(`import hashlib as _sc_hashlib_${tag}`);
  lines.push(`import pathlib as _sc_pathlib_${tag}`);
  lines.push(`${bindingName} = 0`);
  lines.push(`try:`);
  lines.push(`    _sc_expected_${tag} = ${expectedLiteral}`);
  // Prefer C-builtin/extension SHA-256 (`_hashlib` / `_sha256`) so dropping a
  // spoofed `hashlib.py` into PYTHONPATH or CWD cannot forge the digest.
  lines.push(`    _sc_sha256_${tag} = None`);
  lines.push(`    try:`);
  lines.push(`        _sc_sha256_${tag} = _sc_bi_${tag}.getattr(_sc_bi_${tag}.__import__("_hashlib"), "openssl_sha256", None)`);
  lines.push(`    except _sc_bi_${tag}.Exception:`);
  lines.push(`        _sc_sha256_${tag} = None`);
  lines.push(`    if _sc_sha256_${tag} is None:`);
  lines.push(`        try:`);
  lines.push(`            _sc_sha256_${tag} = _sc_bi_${tag}.getattr(_sc_bi_${tag}.__import__("_sha256"), "sha256", None)`);
  lines.push(`        except _sc_bi_${tag}.Exception:`);
  lines.push(`            _sc_sha256_${tag} = None`);
  lines.push(`    if _sc_sha256_${tag} is None:`);
  lines.push(`        _sc_sha256_${tag} = _sc_hashlib_${tag}.sha256`);
  lines.push(`    _sc_h_${tag} = _sc_sha256_${tag}()`);
  lines.push(`    _sc_entry_label_${tag} = ${entryLiteral}`);
  lines.push(`    _sc_h_${tag}.update(_sc_entry_label_${tag}.encode("utf-8"))`);
  lines.push(`    _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`    _sc_sidecars_${tag} = ${sidecarsLiteral}`);
  lines.push(`    _sc_base_${tag} = _sc_pathlib_${tag}.Path(__file__).resolve().parent`);
  lines.push(`    for _sc_sp_${tag} in _sc_sidecars_${tag}:`);
  lines.push(`        _sc_h_${tag}.update(_sc_sp_${tag}.encode("utf-8"))`);
  lines.push(`        _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        _sc_sp_path_${tag} = _sc_pathlib_${tag}.Path(_sc_sp_${tag})`);
  lines.push(`        if not _sc_sp_path_${tag}.is_absolute():`);
  lines.push(`            _sc_sp_path_${tag} = _sc_base_${tag} / _sc_sp_${tag}`);
  lines.push(`        try:`);
  lines.push(`            _sc_h_${tag}.update(_sc_sp_path_${tag}.read_bytes())`);
  lines.push(`        except _sc_bi_${tag}.Exception:`);
  // Inside a zipapp (.pyz) the siblings are archive members, not files: ask
  // the module's own loader for the same bytes before calling them missing.
  lines.push(`            try:`);
  lines.push(
    `                _sc_h_${tag}.update(__loader__.get_data(_sc_bi_${tag}.__import__("os").path.join(_sc_bi_${tag}.__import__("os").path.dirname(__file__), _sc_sp_${tag})))`,
  );
  lines.push(`            except _sc_bi_${tag}.Exception:`);
  lines.push(`                raise _sc_bi_${tag}.RuntimeError("integrity binding mismatch") from None`);
  lines.push(`        _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`    _sc_h_${tag}.update(${seedLiteral}.encode("utf-8"))`);
  lines.push(`    _sc_hex_${tag} = _sc_h_${tag}.hexdigest()`);
  lines.push(`    ${bindingName} = _sc_bi_${tag}.int(_sc_hex_${tag}[:8], 16) & 0xffffffff`);
  lines.push(`    if _sc_hex_${tag} != _sc_expected_${tag}:`);
  if (softFold) {
    lines.push(`        ${bindingName} = (${bindingName} ^ 0xffffffff) & 0xffffffff`);
  } else {
    lines.push(`        raise _sc_bi_${tag}.RuntimeError("integrity binding mismatch")`);
  }
  lines.push(`except _sc_bi_${tag}.Exception as _sc_err_${tag}:`);
  if (softFold) {
    lines.push(`    ${bindingName} = 0`);
  } else {
    lines.push(
      `    if _sc_bi_${tag}.isinstance(_sc_err_${tag}, _sc_bi_${tag}.RuntimeError) and _sc_bi_${tag}.str(_sc_err_${tag}) == "integrity binding mismatch":`,
    );
    lines.push(`        raise`);
    lines.push(`    raise _sc_bi_${tag}.RuntimeError("integrity binding mismatch") from None`);
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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
  /** When true, plant a custom-section note even with no sibling sidecars (load-time hook strip⇒fail). */
  readonly allowEmptySidecars?: boolean;
}): SidecarWasmBindResult | null {
  if (options.sidecars.length === 0 && options.allowEmptySidecars !== true) return null;
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

  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "marker",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const sidecarParts = collected.parts;

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

/**
 * SHA-256 hex of a WASM binary with every `bla.sidecar.v1` custom section
 * removed. Used by the optional JS loader hook to recognize the protected
 * module after an adversary strips the note (non-custom sections stay
 * identical, so the hook can still fail closed).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function computeWasmSidecarCodeIdentity(bytes: Uint8Array): string {
  const stripped = stripWasmSidecarCustomSection(bytes);
  return createHash("sha256").update(stripped).digest("hex");
}

/** Idempotence marker prepended with the optional WASM JS-loader hook. */
export const WASM_SIDECAR_LOADER_MARKER = "_installWasmSidecarLoaderHook" as const;

export interface SidecarWasmLoaderInjectOptions {
  /**
   * SHA-256 hex (or list) of the protected module with `bla.sidecar.v1`
   * stripped. Instantiated modules whose identity matches MUST present a
   * valid custom-section note; other modules pass through unchanged.
   */
  readonly codeIdentityHex: string | readonly string[];
  readonly carrier?: SidecarJsCarrier;
  readonly bindingName?: string;
  /**
   * Optional absolute directory used to resolve relative sidecar paths from
   * the note. When omitted, the hook uses the loader file's directory
   * (`__dirname` / `import.meta.url`).
   */
  readonly baseDir?: string;
  /**
   * @deprecated Export names do not identify a protected module. Runtime
   * enforcement uses the code identity and the binding section.
   */
  readonly protectedExportNames?: readonly string[];
}

export interface SidecarWasmLoaderInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly codeIdentityHexes: readonly string[];
  readonly sidecarCount: 0;
}

function normalizeWasmCodeIdentity(hex: string): string {
  const value = hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("codeIdentityHex must be a 64-char lowercase hex SHA-256 digest");
  }
  return value;
}

/**
 * Emit a self-contained host JS snippet that wraps `WebAssembly.instantiate`,
 * `WebAssembly.compile`, and `WebAssembly.instantiateStreaming` (when present)
 * so a protected module whose `bla.sidecar.v1` custom section is missing or
 * whose sibling sidecars were stripped/altered fails closed at load time.
 *
 * Unrelated WASM modules (identity mismatch) pass through. Export surface and
 * function bodies of the protected module are not rewritten. The hook is
 * host-opt-in: it runs only when the customer prepends or evals this snippet
 * in the loader that actually instantiates the module. `protectTarget` /
 * `hardenProject` auto-wire this hook into a same-directory Node.js
 * CommonJS or ESM loader that already uses `fs` and
 * `WebAssembly.instantiate` / `compile` / `instantiateStreaming` and
 * mentions the `.wasm` basename (ESM only when every static `import` /
 * `export-from` specifier is a Node builtin, so hoisting cannot run
 * user-module side effects or instantiate WASM before the hook);
 * only then is `wasm-sidecar-entangle` recorded and
 * `wasm-sidecar-host-verify-only` cleared. Browser `fetch`-only,
 * minified, and ambiguous loaders, and ESM files that statically import
 * user modules or `.wasm`, are left untouched.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarWasmLoaderSnippet(
  options: SidecarWasmLoaderInjectOptions,
): SidecarWasmLoaderInjectResult {
  const raw = options.codeIdentityHex;
  const list = (Array.isArray(raw) ? raw : [raw]).map((hex) =>
    normalizeWasmCodeIdentity(hex),
  );
  if (list.length === 0) {
    throw new Error("codeIdentityHex must contain at least one digest");
  }
  const tag = list[0]!.slice(0, 8);
  const bindingName = options.bindingName ?? `${WASM_SIDECAR_LOADER_MARKER}_${tag}`;
  assertJsBindingName(bindingName);
  const isEsm = options.carrier === "module";
  const reqHelperAlias = `_resolveWasmLoaderRequire_${tag}`;
  const idsLiteral = JSON.stringify(list);
  const sectionLiteral = JSON.stringify(WASM_SIDECAR_SECTION_NAME);
  const schemaLiteral = JSON.stringify(SIDECAR_ENTANGLE_SCHEMA);
  const markerLiteral = JSON.stringify(WASM_SIDECAR_LOADER_MARKER);
  const baseDirLiteral =
    typeof options.baseDir === "string" && options.baseDir.length > 0
      ? JSON.stringify(options.baseDir)
      : "null";
  const lines: string[] = [];
  if (isEsm) {
    lines.push(`import { createRequire as ${reqHelperAlias} } from "node:module";`);
  }
  lines.push(`(function(){`);
  lines.push(`  var ${WASM_SIDECAR_LOADER_MARKER} = true;`);
  lines.push(`  var ${bindingName} = { ok: false };`);
  lines.push(`  var __ids = ${idsLiteral};`);
  lines.push(`  var __idSet = Object.create(null);`);
  lines.push(`  for (var __i = 0; __i < __ids.length; __i++) __idSet[__ids[__i]] = true;`);
  lines.push(`  var __section = ${sectionLiteral};`);
  lines.push(`  var __schema = ${schemaLiteral};`);
  lines.push(`  var __marker = ${markerLiteral};`);
  lines.push(`  var __bakedBaseDir = ${baseDirLiteral};`);
  if (isEsm) {
    lines.push(`  var _req = ${reqHelperAlias}(import.meta.url);`);
    lines.push(`  var _c = _req("node:crypto");`);
    lines.push(`  var _fs = _req("node:fs");`);
    lines.push(`  var _path = _req("node:path");`);
    lines.push(
      `  var __loaderDir = _path.dirname(_req("node:url").fileURLToPath(import.meta.url));`,
    );
  } else {
    lines.push(`  var _c = require("node:crypto");`);
    lines.push(`  var _fs = require("node:fs");`);
    lines.push(`  var _path = require("node:path");`);
    lines.push(
      `  var __loaderDir = (typeof __dirname === "string" ? __dirname : ".");`,
    );
  }
  lines.push(`  function __uleb(bytes, offset) {`);
  lines.push(`    var value = 0, shift = 0, i = offset;`);
  lines.push(`    while (i < bytes.length) {`);
  lines.push(`      var b = bytes[i++];`);
  lines.push(`      value = (value | ((b & 0x7f) << shift)) >>> 0;`);
  lines.push(`      if ((b & 0x80) === 0) return { value: value, next: i };`);
  lines.push(`      shift += 7;`);
  lines.push(`      if (shift > 35) break;`);
  lines.push(`    }`);
  lines.push(`    return null;`);
  lines.push(`  }`);
  lines.push(`  function __asU8(src) {`);
  lines.push(`    if (_types.isArrayBuffer(src)) return new Uint8Array(src);`);
  lines.push(`    if (_types.isTypedArray(src)) return new Uint8Array(src.buffer, src.byteOffset, src.byteLength);`);
  lines.push(`    return null;`);
  lines.push(`  }`);
  lines.push(`  function __concat(chunks) {`);
  lines.push(`    var total = 0, i;`);
  lines.push(`    for (i = 0; i < chunks.length; i++) total += chunks[i].length;`);
  lines.push(`    var out = new Uint8Array(total), o = 0;`);
  lines.push(`    for (i = 0; i < chunks.length; i++) { out.set(chunks[i], o); o += chunks[i].length; }`);
  lines.push(`    return out;`);
  lines.push(`  }`);
  lines.push(`  function __strip(bytes) {`);
  lines.push(`    if (bytes.length < 8 || bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) return bytes;`);
  lines.push(`    var chunks = [bytes.subarray(0, 8)];`);
  lines.push(`    var offset = 8;`);
  lines.push(`    while (offset < bytes.length) {`);
  lines.push(`      var start = offset;`);
  lines.push(`      var sectionId = bytes[offset++];`);
  lines.push(`      var header = __uleb(bytes, offset);`);
  lines.push(`      if (!header) { chunks.push(bytes.subarray(start)); break; }`);
  lines.push(`      var sectionEnd = header.next + header.value;`);
  lines.push(`      if (sectionEnd > bytes.length) { chunks.push(bytes.subarray(start)); break; }`);
  lines.push(`      var drop = false;`);
  lines.push(`      if (sectionId === 0) {`);
  lines.push(`        var payload = bytes.subarray(header.next, sectionEnd);`);
  lines.push(`        var nameHdr = __uleb(payload, 0);`);
  lines.push(`        if (nameHdr && nameHdr.next + nameHdr.value <= payload.length) {`);
  lines.push(`          var name = new TextDecoder("utf-8").decode(payload.subarray(nameHdr.next, nameHdr.next + nameHdr.value));`);
  lines.push(`          if (name === __section) drop = true;`);
  lines.push(`        }`);
  lines.push(`      }`);
  lines.push(`      if (!drop) chunks.push(bytes.subarray(start, sectionEnd));`);
  lines.push(`      offset = sectionEnd;`);
  lines.push(`    }`);
  lines.push(`    return __concat(chunks);`);
  lines.push(`  }`);
  lines.push(`  function __readNote(bytes) {`);
  lines.push(`    if (bytes.length < 8 || bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) return null;`);
  lines.push(`    var offset = 8;`);
  lines.push(`    while (offset < bytes.length) {`);
  lines.push(`      var sectionId = bytes[offset++];`);
  lines.push(`      var header = __uleb(bytes, offset);`);
  lines.push(`      if (!header) break;`);
  lines.push(`      var sectionEnd = header.next + header.value;`);
  lines.push(`      if (sectionEnd > bytes.length) break;`);
  lines.push(`      if (sectionId === 0) {`);
  lines.push(`        var payload = bytes.subarray(header.next, sectionEnd);`);
  lines.push(`        var nameHdr = __uleb(payload, 0);`);
  lines.push(`        if (nameHdr && nameHdr.next + nameHdr.value <= payload.length) {`);
  lines.push(`          var name = new TextDecoder("utf-8").decode(payload.subarray(nameHdr.next, nameHdr.next + nameHdr.value));`);
  lines.push(`          if (name === __section) return new TextDecoder("utf-8").decode(payload.subarray(nameHdr.next + nameHdr.value));`);
  lines.push(`        }`);
  lines.push(`      }`);
  lines.push(`      offset = sectionEnd;`);
  lines.push(`    }`);
  lines.push(`    return null;`);
  lines.push(`  }`);
  lines.push(`  function __sha256Hex(bytes) {`);
  lines.push(`    return _c.createHash("sha256").update(Buffer.from(bytes)).digest("hex");`);
  lines.push(`  }`);
  lines.push(`  function __identity(bytes) {`);
  lines.push(`    return __sha256Hex(__strip(bytes));`);
  lines.push(`  }`);
  lines.push(`  function __resolveBase(noteBase) {`);
  lines.push(`    if (typeof __bakedBaseDir === "string" && __bakedBaseDir.length > 0) return __bakedBaseDir;`);
  lines.push(`    if (typeof noteBase === "string" && noteBase.length > 0) return noteBase;`);
  lines.push(`    return __loaderDir;`);
  lines.push(`  }`);
  lines.push(`  function __readSidecar(label, baseDir) {`);
  lines.push(`    var abs = label;`);
  lines.push(`    try { if (!_path.isAbsolute(abs) && typeof baseDir === "string") abs = _path.join(baseDir, label); } catch (_eJoin) {}`);
  lines.push(`    try { return _fs.readFileSync(abs); } catch (_eRead) { return Buffer.from("missing:" + String(label), "utf8"); }`);
  lines.push(`  }`);
  lines.push(`  function __verify(bytes) {`);
  lines.push(`    var raw = __readNote(bytes);`);
  lines.push(`    if (typeof raw !== "string") return { ok: false, reason: "bla.sidecar.v1 custom section missing or unreadable" };`);
  lines.push(`    var note;`);
  lines.push(`    try { note = JSON.parse(raw); } catch (_eJson) { return { ok: false, reason: "bla.sidecar.v1 note is not valid JSON" }; }`);
  lines.push(`    if (!note || note.schema !== __schema || note.section !== __section || typeof note.digest !== "string" || !/^[0-9a-f]{64}$/i.test(note.digest)) {`);
  lines.push(`      return { ok: false, reason: "bla.sidecar.v1 note malformed" };`);
  lines.push(`    }`);
  lines.push(`    var digest = String(note.digest).toLowerCase();`);
  lines.push(`    var seedTag = typeof note.seedTag === "string" ? note.seedTag : "bla-sidecar-v1";`);
  lines.push(`    var entryPath = typeof note.entryPath === "string" ? note.entryPath : "";`);
  lines.push(`    var sidecarPaths = Array.isArray(note.sidecarPaths) ? note.sidecarPaths.filter(function(p){ return typeof p === "string" && p.length > 0; }) : [];`);
  lines.push(`    var softFold = note.softFold === true;`);
  lines.push(`    var baseDir = __resolveBase();`);
  lines.push(`    var h = _c.createHash("sha256");`);
  lines.push(`    h.update(entryPath);`);
  lines.push(`    h.update(String.fromCharCode(0));`);
  lines.push(`    for (var i = 0; i < sidecarPaths.length; i++) {`);
  lines.push(`      var sp = sidecarPaths[i];`);
  lines.push(`      h.update(sp);`);
  lines.push(`      h.update(String.fromCharCode(0));`);
  lines.push(`      h.update(__readSidecar(sp, baseDir));`);
  lines.push(`      h.update(String.fromCharCode(0));`);
  lines.push(`    }`);
  lines.push(`    h.update(seedTag);`);
  lines.push(`    var hex = h.digest("hex");`);
  lines.push(`    if (hex === digest) return { ok: true, softFold: softFold };`);
  lines.push(`    return { ok: false, reason: softFold ? "integrity binding mismatch (soft-fold)" : "integrity binding mismatch", softFold: softFold };`);
  lines.push(`  }`);
  lines.push(`  function __enforce(src) {`);
  lines.push(`    var bytes = __asU8(src);`);
  lines.push(`    if (!bytes) return;`);
  lines.push(`    var id = __identity(bytes);`);
  lines.push(`    if (!__idSet[id]) {`);
  lines.push(`      if (__readNote(bytes) !== null) {`);
  lines.push(`        ${bindingName} = { ok: false, reason: "integrity binding mismatch" };`);
  lines.push(`        throw new Error("integrity binding mismatch");`);
  lines.push(`      }`);
  lines.push(`      return;`);
  lines.push(`    }`);
  lines.push(`    var result = __verify(bytes);`);
  lines.push(`    ${bindingName} = result;`);
  lines.push(`    if (result.ok) return;`);
  lines.push(`    if (result.softFold) return;`);
  lines.push(`    throw new Error(result.reason || "integrity binding mismatch");`);
  lines.push(`  }`);
  lines.push(`  var _types = ${isEsm ? "_req" : "require"}("node:util").types;`);
  // A construct trap leaves all native properties and call semantics on
  // Module intact, and Reflect.construct preserves a subclass's newTarget.
  lines.push(`  var _OrigModule = WebAssembly.Module;`);
  lines.push(`  WebAssembly.Module = new Proxy(_OrigModule, {`);
  lines.push(`    construct: function(target, args, newTarget) {`);
  lines.push(`      __enforce(args[0]);`);
  lines.push(`      return Reflect.construct(target, args, newTarget);`);
  lines.push(`    }`);
  lines.push(`  });`);
  lines.push(`  var _instantiate = WebAssembly.instantiate;`);
  lines.push(`  WebAssembly.instantiate = function(first, imports) {`);
  lines.push(`    var args = arguments;`);
  lines.push(`    if (first instanceof _OrigModule) return Reflect.apply(_instantiate, WebAssembly, args);`);
  lines.push(`    return Promise.resolve().then(function(){`);
  lines.push(`      __enforce(first);`);
  lines.push(`      return Reflect.apply(_instantiate, WebAssembly, args);`);
  lines.push(`    });`);
  lines.push(`  };`);
  lines.push(`  var _compile = WebAssembly.compile;`);
  lines.push(`  WebAssembly.compile = function(source) {`);
  lines.push(`    var args = arguments;`);
  lines.push(`    return Promise.resolve().then(function(){`);
  lines.push(`      __enforce(source);`);
  lines.push(`      return Reflect.apply(_compile, WebAssembly, args);`);
  lines.push(`    });`);
  lines.push(`  };`);
  // Read a duplicate before instantiation can run any WASM start function.
  // Pass the original Response (including status, headers, and body state)
  // to the native API, which owns validation and its error types.
  lines.push(`  function __checkedResponse(source) {`);
  lines.push(`    return Promise.resolve(source).then(function(response) {`);
  lines.push(`      if (typeof Response !== "function" || !(response instanceof Response) ||`);
  lines.push(`          !response.ok || response.bodyUsed || response.headers.get("Content-Type") !== "application/wasm") return response;`);
  lines.push(`      return Response.prototype.clone.call(response).arrayBuffer().then(function(bytes) {`);
  lines.push(`        __enforce(bytes);`);
  lines.push(`        return response;`);
  lines.push(`      });`);
  lines.push(`    });`);
  lines.push(`  }`);
  lines.push(`  if (typeof WebAssembly.instantiateStreaming === "function") {`);
  lines.push(`    var _is = WebAssembly.instantiateStreaming;`);
  lines.push(`    WebAssembly.instantiateStreaming = function(source, imports) {`);
  lines.push(`      var args = Array.from(arguments);`);
  lines.push(`      args[0] = __checkedResponse(source);`);
  lines.push(`      return Reflect.apply(_is, WebAssembly, args);`);
  lines.push(`    };`);
  lines.push(`  }`);
  lines.push(`  if (typeof WebAssembly.compileStreaming === "function") {`);
  lines.push(`    var _cs = WebAssembly.compileStreaming;`);
  lines.push(`    WebAssembly.compileStreaming = function(source) {`);
  lines.push(`      var args = Array.from(arguments);`);
  lines.push(`      args[0] = __checkedResponse(source);`);
  lines.push(`      return Reflect.apply(_cs, WebAssembly, args);`);
  lines.push(`    };`);
  lines.push(`  }`);
  lines.push(`  ${bindingName} = { ok: true, installed: true, marker: __marker };`);
  lines.push(`})();`);

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    codeIdentityHexes: list,
    sidecarCount: 0,
  };
}

/**
 * Prepend a WASM JS-loader hook after shebang / `"use strict"`, idempotent
 * when {@link WASM_SIDECAR_LOADER_MARKER} is already present.
 */
export function prependWasmSidecarLoaderHook(
  entrySource: string,
  preamble: string,
): string {
  if (entrySource.includes(WASM_SIDECAR_LOADER_MARKER)) return entrySource;
  return prependJsPreamble(entrySource, preamble);
}

/**
 * Convenience: build a JS-loader hook from a (possibly already bound) WASM
 * binary and prepend it onto an existing loader source. Returns the original
 * source unchanged when the marker is already present.
 */
export function entangleWasmLoaderWithSidecars(options: {
  readonly loaderSource: string;
  readonly wasmBytes: Uint8Array;
  readonly carrier?: SidecarJsCarrier;
  readonly baseDir?: string;
}): {
  readonly code: string;
  readonly inject: SidecarWasmLoaderInjectResult;
  readonly codeIdentityHex: string;
} {
  const codeIdentityHex = computeWasmSidecarCodeIdentity(options.wasmBytes);
  const inject = generateSidecarWasmLoaderSnippet({
    codeIdentityHex,
    carrier: options.carrier ??
      (parseNodeRuntimeJavaScript(options.loaderSource).sourceType === "module" ? "module" : "commonjs"),
    baseDir: options.baseDir,
  });
  return {
    code: prependWasmSidecarLoaderHook(options.loaderSource, inject.preamble),
    inject,
    codeIdentityHex,
  };
}

/** Candidate Node.js WASM loader extensions (CommonJS and ESM). */
const NODE_WASM_JS_LOADER_EXTENSIONS = [".cjs", ".js", ".mjs"] as const;

/** Skip tests, typings, and minified bundles — too risky to rewrite automatically. */
const UNSAFE_WASM_LOADER_NAME = /\.(?:test|spec|d)\.(?:cjs|mjs|js)$/i;

const WASM_INSTANTIATE_API_RE =
  /WebAssembly\s*\.\s*(instantiate(?:Streaming)?|compile(?:Streaming)?)\b/;

const NODE_FS_LOADER_RE =
  /\b(?:require|import)\s*\(\s*["'](?:node:)?fs(?:\/promises)?["']\s*\)|\bfrom\s+["'](?:node:)?fs(?:\/promises)?["']|createRequire\s*\(|\bfs\.readFile(?:Sync)?\b/;

/** Soft cap so we do not slurp huge bundled artifacts as loader candidates. */
const MAX_WASM_LOADER_CANDIDATE_BYTES = 2 * 1024 * 1024;

/** Dedicated loaders are small; large JS entries (apps / already-protected artifacts) are not auto-wired. */
const MAX_WASM_LOADER_AUTOWIRE_CHARS = 64 * 1024;

/**
 * Already-entangled JS entries (self-seal / sidecar preamble) are applications,
 * not dedicated WASM loaders — rewriting them again would invalidate baked
 * integrity digests (red line).
 */
const ALREADY_ENTANGLED_JS_RE =
  /bla-self-seal\/v1|integrity check failed|integrity binding mismatch/;

function escapeRegExpLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function isNodeWasmJsLoaderFilename(filename: string): boolean {
  const base = basename(filename);
  const lower = base.toLowerCase();
  if (UNSAFE_WASM_LOADER_NAME.test(base) || lower.endsWith(".min.js") || lower.endsWith(".min.mjs")) {
    return false;
  }
  return NODE_WASM_JS_LOADER_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * True when `source` mentions `wasmBasename` (or a path ending in it) inside a
 * quoted string or template literal.
 */
export function sourceMentionsWasmBasename(source: string, wasmBasename: string): boolean {
  const name = wasmBasename.replaceAll("\\", "/").split("/").pop() ?? "";
  if (!name || !name.toLowerCase().endsWith(".wasm")) return false;
  const pattern = new RegExp(
    `['"\`](?:[^'"\`\\\\]|\\\\.)*${escapeRegExpLiteral(name)}['"\`]`,
  );
  return pattern.test(source);
}

function isNodeBuiltinModuleSpecifier(specifier: string): boolean {
  if (typeof specifier !== "string" || specifier.length === 0) return false;
  try {
    return isBuiltin(specifier);
  } catch {
    return false;
  }
}

/**
 * Collect static `import` / `export ... from` module specifiers.
 * Returns `null` when the source looks like a module-edge we cannot
 * confidently parse (refuse auto-wire).
 *
 * DEFENSIVE ONLY. Conservative — prefer a false-negative over rewriting
 * a file whose import graph is unclear.
 */
export function listStaticEsmModuleSpecifiers(source: string): string[] | null {
  try {
    return collectStaticEsmModuleSpecifiers(parseNodeRuntimeJavaScript(source));
  } catch {
    return null;
  }
}

function collectStaticEsmModuleSpecifiers(program: Program): string[] {
  const specs: string[] = [];
  for (const statement of program.body) {
    if ((statement.type === "ImportDeclaration" ||
         statement.type === "ExportNamedDeclaration" ||
         statement.type === "ExportAllDeclaration") && statement.source) {
      specs.push(statement.source.value);
    }
  }
  return specs;
}

/** True when every static import / export-from specifier is a Node builtin. */
export function esmStaticImportsAreNodeBuiltinsOnly(source: string): boolean {
  const specs = listStaticEsmModuleSpecifiers(source);
  if (specs === null) return false;
  return specs.every((s) => isNodeBuiltinModuleSpecifier(s));
}

export type WasmJsLoaderCarrier = "commonjs" | "module";

/**
 * Infer the snippet carrier for a candidate loader, or `null` when the
 * file must not be auto-wired as either CJS or ESM (`.cjs` with ESM
 * syntax, or ESM that statically imports a user module / `.wasm`).
 *
 * DEFENSIVE ONLY.
 */
export function detectWasmJsLoaderCarrier(
  filename: string,
  source: string,
): WasmJsLoaderCarrier | null {
  const lower = basename(filename).toLowerCase();
  const explicitCarrier = lower.endsWith(".cjs")
    ? "commonjs"
    : lower.endsWith(".mjs") ? "module" :
      isAbsolute(filename) ? resolveNodePackageModuleType(filename) : undefined;
  try {
    const program = parseNodeRuntimeJavaScript(source, explicitCarrier);
    if (program.sourceType !== "module") return "commonjs";
    if (program.body.some((statement) => statement.type === "ReturnStatement")) return null;
    return collectStaticEsmModuleSpecifiers(program).every(isNodeBuiltinModuleSpecifier)
      ? "module"
      : null;
  } catch {
    return null;
  }
}

/**
 * Conservative auto-wire predicate: a Node.js CommonJS or ESM file that
 * already loads the named `.wasm` via `WebAssembly.instantiate` / `compile`
 * / `instantiateStreaming` and already uses `fs`. ESM is admitted only
 * when every static `import` / `export-from` specifier is a Node builtin
 * (`fs`, `node:path`, `node:url`, …), so hoisting cannot run user-module
 * side effects or instantiate WASM before the prepended hook. Browser
 * (`fetch`-only), minified, and test files return false.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function isSafeNodeWasmJsLoader(options: {
  readonly source: string;
  readonly filename: string;
  readonly wasmBasename: string;
}): boolean {
  if (!isNodeWasmJsLoaderFilename(options.filename)) return false;
  if (options.source.length > MAX_WASM_LOADER_AUTOWIRE_CHARS) return false;
  if (ALREADY_ENTANGLED_JS_RE.test(options.source)) return false;
  if (detectWasmJsLoaderCarrier(options.filename, options.source) === null) return false;
  if (!WASM_INSTANTIATE_API_RE.test(options.source)) return false;
  if (!NODE_FS_LOADER_RE.test(options.source)) return false;
  return sourceMentionsWasmBasename(options.source, options.wasmBasename);
}

function wasmLoaderPreference(loaderName: string, wasmBasename: string): number {
  const stem = (wasmBasename.replaceAll("\\", "/").split("/").pop() ?? "").replace(
    /\.wasm$/i,
    "",
  );
  const base = basename(loaderName).replace(/\.(?:cjs|mjs|js)$/i, "");
  if (stem.length > 0 && base.toLowerCase() === stem.toLowerCase()) return 0;
  if (/^loader$/i.test(base)) return 1;
  if (/^index$/i.test(base)) return 2;
  return 3;
}

/** `.cjs` wins a same-rank tie, then `.js`, then `.mjs`. */
function wasmLoaderExtRank(name: string): number {
  const lower = basename(name).toLowerCase();
  if (lower.endsWith(".cjs")) return 0;
  if (lower.endsWith(".js")) return 1;
  if (lower.endsWith(".mjs")) return 2;
  return 3;
}

export interface NodeWasmJsLoaderCandidate {
  readonly name: string;
  readonly source: string;
}

/**
 * Pick a single same-directory Node CJS or ESM WASM loader, or `null`
 * when none qualify or several unranked files all qualify (do not guess).
 * Preferred names: `<stem>.cjs` / `<stem>.js` / `<stem>.mjs`, then
 * `loader.*`, then `index.*` (`.cjs` wins a same-rank tie, then `.js`,
 * then `.mjs`).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function selectNodeWasmJsLoader(
  wasmBasename: string,
  candidates: readonly NodeWasmJsLoaderCandidate[],
): string | null {
  const qualifying = candidates.filter((c) =>
    isSafeNodeWasmJsLoader({
      source: c.source,
      filename: c.name,
      wasmBasename,
    }),
  );
  if (qualifying.length === 0) return null;
  const scored = qualifying.map((c) => ({
    c,
    score: wasmLoaderPreference(c.name, wasmBasename),
    ext: wasmLoaderExtRank(c.name),
  }));
  scored.sort(
    (a, b) =>
      a.score - b.score || a.ext - b.ext || a.c.name.localeCompare(b.c.name),
  );
  const best = scored[0]!;
  // Only known names: <stem>, loader, index. Never guess at unique app files
  // such as license.cjs / main.cjs / helper.cjs.
  if (best.score >= 3) return null;
  const ties = scored.filter((s) => s.score === best.score && s.ext === best.ext);
  if (ties.length > 1) return null;
  return best.c.name;
}

export interface DiscoveredNodeWasmJsLoader {
  readonly absPath: string;
  readonly name: string;
  readonly source: string;
}

function readWasmLoaderCandidateSource(absPath: string): string | null {
  try {
    const st = statSync(absPath);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_WASM_LOADER_CANDIDATE_BYTES) {
      return null;
    }
    return readFileSync(absPath, "utf8");
  } catch {
    return null;
  }
}

/**
 * List same-directory `.cjs` / `.js` / `.mjs` candidates (no recursion).
 * Unreadable or oversized files are skipped.
 */
export function listSameDirNodeWasmJsLoaderCandidates(
  directory: string,
): DiscoveredNodeWasmJsLoader[] {
  let names: string[] = [];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  const out: DiscoveredNodeWasmJsLoader[] = [];
  for (const name of names) {
    if (!isNodeWasmJsLoaderFilename(name)) continue;
    const absPath = join(directory, name);
    const source = readWasmLoaderCandidateSource(absPath);
    if (source === null) continue;
    out.push({ absPath, name, source });
  }
  return out;
}

/**
 * Discover the unique safe Node CJS or ESM loader for `wasmBasename` in
 * the first search directory that yields a selection. Later directories
 * are not consulted once one directory produces a hit (output dir wins
 * over source).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function discoverNodeWasmJsLoader(options: {
  readonly wasmBasename: string;
  readonly searchDirectories: readonly string[];
}): DiscoveredNodeWasmJsLoader | null {
  const seen = new Set<string>();
  for (const directory of options.searchDirectories) {
    if (typeof directory !== "string" || directory.length === 0) continue;
    const key = directory;
    if (seen.has(key)) continue;
    seen.add(key);
    const candidates = listSameDirNodeWasmJsLoaderCandidates(directory);
    const selected = selectNodeWasmJsLoader(options.wasmBasename, candidates);
    if (!selected) continue;
    const hit = candidates.find((c) => c.name === selected || c.absPath === selected);
    if (hit) return hit;
  }
  return null;
}

/**
 * True when a same-directory JS file already carries the WASM loader hook
 * bound to this module's code identity (used by defenseScore honesty).
 *
 * DEFENSIVE ONLY.
 */
export function isWasmSidecarLoaderHookWired(options: {
  readonly wasmBytes: Uint8Array;
  readonly wasmPath: string;
}): boolean {
  const identity = computeWasmSidecarCodeIdentity(options.wasmBytes);
  const directory = dirname(options.wasmPath);
  const candidates = listSameDirNodeWasmJsLoaderCandidates(directory);
  return candidates.some(
    (c) =>
      c.source.includes(WASM_SIDECAR_LOADER_MARKER) && c.source.includes(identity),
  );
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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

  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "marker",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const sidecarParts = collected.parts;

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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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

  const collectedParts = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: members,
    missingPolicy: "marker",
    requireBaseDir: false,
  });
  if (!collectedParts.ok) {
    return { ok: false, reason: collectedParts.reason };
  }
  const sidecarParts = collectedParts.parts;

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
  /** Runtime carrier resolved from the archive's package context. */
  readonly carrier?: SidecarJsCarrier;
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
  assertJsBindingName(bindingName);
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
  const isEsm = (options.carrier ?? (/\.mjs$/i.test(mainRelativePath) ? "module" : "commonjs")) === "module";
  const reqAlias = `_resolveAsarRequire_${expectedHex.slice(0, 8)}`;

  const lines: string[] = [];
  if (isEsm) lines.push(`import { createRequire as ${reqAlias} } from "node:module";`);
  lines.push(`(function(){`);
  lines.push(`  var __expected = ${JSON.stringify(expectedHex)};`);
  lines.push(`  var ${bindingName} = 0;`);
  lines.push(`  try {`);
  lines.push(`    var _req = ${isEsm ? `${reqAlias}(import.meta.url)` : "require"};`);
  lines.push(`    var _c = _req("node:crypto");`);
  lines.push(`    var _fs = _req("node:fs");`);
  lines.push(`    var _path = _req("node:path");`);
  lines.push(isEsm
    ? `    var baseDir = _path.dirname(_req("node:url").fileURLToPath(import.meta.url));`
    : `    var baseDir = (typeof __dirname === "string" ? __dirname : null);`);
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
    `      if (!_path.isAbsolute(spAbs) && typeof baseDir === "string") spAbs = _path.join(baseDir, spAbs);`,
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
  return prependJsPreamble(entrySource, preamble);
}

function resolveAsarMainJsCarrier(
  main: string,
  members: ReadonlyMap<string, Buffer>,
): "module" | "commonjs" {
  if (/\.mjs$/i.test(main)) return "module";
  if (/\.cjs$/i.test(main)) return "commonjs";
  for (let dir = posix.dirname(main); ; dir = posix.dirname(dir)) {
    const manifest = members.get(posix.join(dir, "package.json"));
    if (manifest !== undefined) {
      try {
        const type = readNodePackageType(manifest.toString("utf8"));
        if (type !== undefined) return type;
      } catch {
        // Leave an invalid package manifest to the runtime.
      }
      break;
    }
    if (dir === "." || dir === "/") break;
  }
  const source = members.get(main)?.toString("utf8") ?? "";
  return parseNodeRuntimeJavaScript(source).sourceType === "module" ? "module" : "commonjs";
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
  const membersByPath = new Map(options.members.map((member) => [
    member.relativePath.replaceAll("\\", "/"), member.content,
  ]));
  const inject = generateSidecarAsarMainJsPreamble({
    entryPath: options.entryPath,
    mainRelativePath,
    carrier: resolveAsarMainJsCarrier(mainRelativePath, membersByPath),
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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
  /** When true, plant a trailer even if there are no sibling artifacts (hook can still fail-closed on strip). */
  readonly allowEmptySidecars?: boolean;
}): SidecarPycBindResult | null {
  if (options.sidecars.length === 0 && options.allowEmptySidecars !== true) return null;
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

  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "fail",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const sidecarParts = collected.parts;

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



/**
 * SHA-256 hex of a `.pyc` with any `__blaPycSidecarDigest=` TYPE_ASCII trailer
 * removed. Used by the optional Python import-time hook to recognize the
 * protected module after an adversary strips the note (the root marshal object
 * stays identical, so the hook can still fail closed).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function computePycSidecarCodeIdentity(bytes: Uint8Array): string {
  const stripped = stripPycSidecarMarshalNote(bytes);
  return createHash("sha256").update(stripped).digest("hex");
}

/** Idempotence marker inserted with the optional `.pyc` import-time hook. */
export const PYC_SIDECAR_LOADER_MARKER = "_installPycSidecarLoaderHook" as const;

export interface SidecarPycLoaderInjectOptions {
  /**
   * SHA-256 hex (or list) of the protected `.pyc` with the sidecar marshal
   * note stripped. Files whose identity matches MUST present a valid
   * TYPE_ASCII trailer; other `.pyc` files pass through unchanged.
   */
  readonly codeIdentityHex: string | readonly string[];
  /**
   * Paths to the protected `.pyc`, relative to the loader file's directory
   * (`Path(__file__).resolve().parent`). Sidecar paths inside the note are
   * resolved against the `.pyc` file's own directory.
   */
  readonly pycRelPaths: readonly string[];
  readonly bindingName?: string;
}

export interface SidecarPycLoaderInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly codeIdentityHexes: readonly string[];
  readonly pycRelPaths: readonly string[];
}

function normalizePycCodeIdentity(hex: string): string {
  const value = hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("codeIdentityHex must be a 64-char lowercase hex SHA-256 digest");
  }
  return value;
}

/**
 * Emit a self-contained host Python snippet that, at import time of the
 * loader it is inserted into, reads the sibling `.pyc`, and when the
 * stripped-body identity matches, verifies the TYPE_ASCII marshal note and
 * sibling sidecar digest. Missing targets or siblings and mismatches fail closed.
 *
 * The hook does not rewrite the `.pyc` (marshal layout, `co_filename` /
 * `co_name`, PEP 552 hash header, and `co_consts` weaves stay untouched).
 * It is host-opt-in: `protectTarget` / `hardenProject` auto-wire it only
 * into a known same-directory (or parent-of-`__pycache__`) Python loader
 * (`loader.py`, `__init__.py`, `__main__.py`) that already mentions the
 * module or `.pyc` basename — never the `.py` source of the target `.pyc`,
 * and never a test / already-entangled / self-seal file. Only then is
 * `pyc-sidecar-entangle` recorded and `pyc-sidecar-host-verify-only` cleared.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarPycLoaderSnippet(
  options: SidecarPycLoaderInjectOptions,
): SidecarPycLoaderInjectResult {
  const raw = options.codeIdentityHex;
  const list = (Array.isArray(raw) ? raw : [raw]).map((hex) =>
    normalizePycCodeIdentity(hex),
  );
  if (list.length === 0) {
    throw new Error("codeIdentityHex must contain at least one digest");
  }
  const relPaths = (options.pycRelPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (relPaths.length === 0) {
    throw new Error("pycRelPaths must contain at least one path");
  }
  const tag = list[0]!.slice(0, 8);
  const bindingName = options.bindingName ?? `${PYC_SIDECAR_LOADER_MARKER}_${tag}`;
  assertPythonBindingName(bindingName);
  const idsLiteral = JSON.stringify(list);
  const pathsLiteral = JSON.stringify(relPaths);
  const markerLiteral = JSON.stringify(PYC_SIDECAR_MARSHAL_MARKER);
  const schemaLiteral = JSON.stringify(SIDECAR_ENTANGLE_SCHEMA);
  const kindLiteral = JSON.stringify(PYC_SIDECAR_MARSHAL_KIND);

  const lines: string[] = [];
  lines.push(`# ${PYC_SIDECAR_LOADER_MARKER}`);
  lines.push(`def ${bindingName}():`);
  lines.push(`    import hashlib as _sc_hashlib_${tag}`);
  lines.push(`    import json as _sc_json_${tag}`);
  lines.push(`    import pathlib as _sc_pathlib_${tag}`);
  lines.push(`    _sc_ids_${tag} = ${idsLiteral}`);
  lines.push(`    _sc_idset_${tag} = set(_sc_ids_${tag})`);
  lines.push(`    _sc_paths_${tag} = ${pathsLiteral}`);
  lines.push(`    _sc_marker_${tag} = ${markerLiteral}`);
  lines.push(`    _sc_schema_${tag} = ${schemaLiteral}`);
  lines.push(`    _sc_kind_${tag} = ${kindLiteral}`);
  lines.push(`    _sc_marker_b_${tag} = _sc_marker_${tag}.encode("utf-8")`);
  lines.push(`    _sc_base_${tag} = _sc_pathlib_${tag}.Path(__file__).resolve().parent`);
  lines.push(`    def _sc_strip_${tag}(_sc_buf_${tag}):`);
  lines.push(`        _sc_at_${tag} = _sc_buf_${tag}.rfind(_sc_marker_b_${tag})`);
  lines.push(`        if _sc_at_${tag} < 0:`);
  lines.push(`            return _sc_buf_${tag}`);
  lines.push(`        if _sc_at_${tag} >= 5 and _sc_buf_${tag}[_sc_at_${tag} - 5] == 0x61:`);
  lines.push(
    `            _sc_decl_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_at_${tag} - 4:_sc_at_${tag}], "little")`,
  );
  lines.push(`            _sc_start_${tag} = _sc_at_${tag} - 5`);
  lines.push(`            _sc_end_${tag} = _sc_at_${tag} + _sc_decl_${tag}`);
  lines.push(`            if _sc_end_${tag} <= len(_sc_buf_${tag}):`);
  lines.push(
    `                return _sc_buf_${tag}[:_sc_start_${tag}] + _sc_buf_${tag}[_sc_end_${tag}:]`,
  );
  lines.push(`        return _sc_buf_${tag}[: max(0, _sc_at_${tag} - 5)]`);
  lines.push(`    def _sc_extract_${tag}(_sc_buf_${tag}):`);
  lines.push(`        _sc_at_${tag} = _sc_buf_${tag}.rfind(_sc_marker_b_${tag})`);
  lines.push(`        if _sc_at_${tag} < 0:`);
  lines.push(`            return None`);
  lines.push(`        _sc_text_${tag} = None`);
  lines.push(`        if _sc_at_${tag} >= 5 and _sc_buf_${tag}[_sc_at_${tag} - 5] == 0x61:`);
  lines.push(
    `            _sc_decl_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_at_${tag} - 4:_sc_at_${tag}], "little")`,
  );
  lines.push(`            _sc_pay_end_${tag} = _sc_at_${tag} + _sc_decl_${tag}`);
  lines.push(`            if _sc_pay_end_${tag} <= len(_sc_buf_${tag}):`);
  lines.push(
    `                _sc_pay_${tag} = _sc_buf_${tag}[_sc_at_${tag}:_sc_pay_end_${tag}]`,
  );
  lines.push(`                if _sc_pay_${tag}.startswith(_sc_marker_b_${tag}):`);
  lines.push(
    `                    _sc_text_${tag} = _sc_pay_${tag}[len(_sc_marker_b_${tag}):].decode("utf-8")`,
  );
  lines.push(`        if _sc_text_${tag} is None:`);
  lines.push(
    `            _sc_rest_${tag} = _sc_buf_${tag}[_sc_at_${tag} + len(_sc_marker_b_${tag}):]`,
  );
  lines.push(`            _sc_nul_${tag} = _sc_rest_${tag}.find(b"\\x00")`);
  lines.push(
    `            _sc_slice_${tag} = _sc_rest_${tag} if _sc_nul_${tag} < 0 else _sc_rest_${tag}[:_sc_nul_${tag}]`,
  );
  lines.push(`            _sc_text_${tag} = _sc_slice_${tag}.decode("utf-8", "replace")`);
  lines.push(`        try:`);
  lines.push(`            _sc_obj_${tag} = _sc_json_${tag}.loads(_sc_text_${tag})`);
  lines.push(`        except Exception:`);
  lines.push(`            return None`);
  lines.push(
    `        if _sc_obj_${tag}.get("schema") != _sc_schema_${tag} or _sc_obj_${tag}.get("kind") != _sc_kind_${tag}:`,
  );
  lines.push(`            return None`);
  lines.push(`        _sc_dig_${tag} = _sc_obj_${tag}.get("digest")`);
  lines.push(
    `        if not isinstance(_sc_dig_${tag}, str) or len(_sc_dig_${tag}) != 64:`,
  );
  lines.push(`            return None`);
  lines.push(`        return _sc_obj_${tag}`);
  lines.push(`    def _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}):`);
  lines.push(`        _sc_h_${tag} = _sc_hashlib_${tag}.sha256()`);
  lines.push(`        _sc_h_${tag}.update(_sc_entry_${tag}.encode("utf-8"))`);
  lines.push(`        _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        for _sc_sp_${tag}, _sc_data_${tag} in _sc_parts_${tag}:`);
  lines.push(`            _sc_h_${tag}.update(_sc_sp_${tag}.encode("utf-8"))`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`            _sc_h_${tag}.update(_sc_data_${tag})`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        _sc_h_${tag}.update(_sc_seed_${tag}.encode("utf-8"))`);
  lines.push(`        return _sc_h_${tag}.hexdigest()`);
  lines.push(`    for _sc_rel_${tag} in _sc_paths_${tag}:`);
  lines.push(`        _sc_path_${tag} = _sc_pathlib_${tag}.Path(_sc_rel_${tag})`);
  lines.push(`        if not _sc_path_${tag}.is_absolute():`);
  lines.push(`            _sc_path_${tag} = _sc_base_${tag} / _sc_rel_${tag}`);
  lines.push(`        try:`);
  lines.push(`            _sc_raw_${tag} = _sc_path_${tag}.read_bytes()`);
  lines.push(`        except Exception:`);
  lines.push(`            continue`);
  lines.push(
    `        _sc_ident_${tag} = _sc_hashlib_${tag}.sha256(_sc_strip_${tag}(_sc_raw_${tag})).hexdigest()`,
  );
  lines.push(`        if _sc_ident_${tag} not in _sc_idset_${tag}:`);
  lines.push(`            continue`);
  lines.push(`        _sc_note_${tag} = _sc_extract_${tag}(_sc_raw_${tag})`);
  lines.push(`        if _sc_note_${tag} is None:`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        _sc_parts_${tag} = []`);
  lines.push(`        _sc_dir_${tag} = _sc_path_${tag}.parent`);
  lines.push(`        _sc_sp_list_${tag} = _sc_note_${tag}.get("sidecarPaths") or []`);
  lines.push(`        if not isinstance(_sc_sp_list_${tag}, list):`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        for _sc_sp_${tag} in _sc_sp_list_${tag}:`);
  lines.push(`            if not isinstance(_sc_sp_${tag}, str) or len(_sc_sp_${tag}) == 0:`);
  lines.push(`                continue`);
  lines.push(`            _sc_sib_${tag} = _sc_pathlib_${tag}.Path(_sc_sp_${tag})`);
  lines.push(`            if not _sc_sib_${tag}.is_absolute():`);
  lines.push(`                _sc_sib_${tag} = _sc_dir_${tag} / _sc_sp_${tag}`);
  lines.push(`            try:`);
  lines.push(`                _sc_parts_${tag}.append((_sc_sp_${tag}, _sc_sib_${tag}.read_bytes()))`);
  lines.push(`            except Exception:`);
  lines.push(`                raise RuntimeError("integrity binding mismatch") from None`);
  lines.push(`        _sc_seed_${tag} = _sc_note_${tag}.get("seedTag")`);
  lines.push(
    `        if not isinstance(_sc_seed_${tag}, str) or len(_sc_seed_${tag}) == 0:`,
  );
  lines.push(`            _sc_seed_${tag} = "bla-sidecar-v1"`);
  lines.push(`        _sc_entry_${tag} = _sc_note_${tag}.get("entryPath")`);
  lines.push(`        if not isinstance(_sc_entry_${tag}, str):`);
  lines.push(`            _sc_entry_${tag} = ""`);
  lines.push(
    `        if _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}) != str(_sc_note_${tag}.get("digest")).lower():`,
  );
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        return`);
  lines.push(`    raise RuntimeError("integrity binding mismatch")`);
  lines.push(`try:`);
  lines.push(`    ${bindingName}()`);
  lines.push(`finally:`);
  lines.push(`    del ${bindingName}`);

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    codeIdentityHexes: list,
    pycRelPaths: relPaths,
  };
}

/**
 * Insert a `.pyc` import-time hook after shebang / encoding / docstring /
 * `from __future__`, idempotent when {@link PYC_SIDECAR_LOADER_MARKER} is
 * already present. Preserves surrounding newlines the same way
 * `bindPythonSidecarEntanglement` does.
 */
export function prependPycSidecarLoaderHook(
  entrySource: string,
  preamble: string,
): string {
  if (entrySource.includes(PYC_SIDECAR_LOADER_MARKER)) return entrySource;
  const eol = entrySource.includes("\r\n") ? "\r\n" : "\n";
  const analysis = findPythonPrologueInsertionOffset(entrySource);
  const headRaw = entrySource.slice(0, analysis.insertOffset);
  const tailRaw = entrySource.slice(analysis.insertOffset);
  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "");
  const body = preamble.replace(/\r?\n/g, eol).replace(/(?:\r?\n)+$/, "");
  const parts: string[] = [];
  if (head.length > 0) parts.push(head);
  parts.push(body);
  if (tail.length > 0) parts.push(tail);
  return (
    parts.join(eol) +
    (entrySource.endsWith("\n") || entrySource.endsWith("\r\n") ? eol : "")
  );
}

/**
 * Convenience: prepend a loader hook bound to this `.pyc` file's stripped
 * identity. Idempotent when the marker is already present.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function entanglePycLoaderWithSidecars(options: {
  readonly loaderSource: string;
  readonly pycBytes: Uint8Array;
  readonly pycRelPath: string | readonly string[];
}): { readonly code: string; readonly identity: string } {
  const identity = computePycSidecarCodeIdentity(options.pycBytes);
  const paths = (
    Array.isArray(options.pycRelPath) ? options.pycRelPath : [options.pycRelPath]
  ).filter((p) => p.length > 0);
  const inject = generateSidecarPycLoaderSnippet({
    codeIdentityHex: identity,
    pycRelPaths: paths,
  });
  return {
    code: prependPycSidecarLoaderHook(options.loaderSource, inject.preamble),
    identity,
  };
}

const MAX_PYC_LOADER_CANDIDATE_BYTES = 2 * 1024 * 1024;
const MAX_PYC_LOADER_AUTOWIRE_CHARS = 64 * 1024;
const PYC_LOADER_EXTENSIONS = [".py"] as const;
const ALREADY_ENTANGLED_PY_RE =
  /bla-self-seal\/v1|_verify_sibling_digest_|integrity binding mismatch|_installPycSidecarLoaderHook|_installWasmSidecarLoaderHook|_installGgufSidecarLoaderHook|_installSafetensorsSidecarLoaderHook|_installSqliteSidecarLoaderHook/;

/** Module stem of a CPython cache filename (`sample.cpython-312.opt-1.pyc` → `sample`). */
export function pycModuleStemFromBasename(filename: string): string {
  const base = basename(filename);
  return base
    .replace(/\.opt-\d+(?=\.pyc$)/i, "")
    .replace(/\.cpython-\d+(?=\.pyc$)/i, "")
    .replace(/\.py[co]$/i, "");
}

function isUnsafePythonPycLoaderName(filename: string): boolean {
  const lower = basename(filename).toLowerCase();
  if (lower === "conftest.py" || lower === "test.py" || lower === "tests.py") {
    return true;
  }
  if (lower.startsWith("test_")) return true;
  if (lower.endsWith("_test.py") || lower.endsWith("_tests.py")) return true;
  return false;
}

/**
 * True when `filename` is a `.py` file that may be considered as a `.pyc`
 * import-time loader (not a test module).
 */
export function isPythonPycLoaderFilename(filename: string): boolean {
  const base = basename(filename);
  const lower = base.toLowerCase();
  if (isUnsafePythonPycLoaderName(base)) return false;
  return PYC_LOADER_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * True when `source` mentions `pycBasename` in a quoted string / template,
 * or statically imports the corresponding module stem (`import sample`,
 * `from .sample import …`, `from . import sample`, `importlib.import_module`).
 */
export function sourceMentionsPycModule(source: string, pycBasename: string): boolean {
  const name = (pycBasename.replaceAll("\\", "/").split("/").pop() ?? "");
  if (!name || !name.toLowerCase().endsWith(".pyc")) return false;
  const stem = pycModuleStemFromBasename(name);
  if (!stem) return false;
  const quoted = new RegExp(
    `['"\`](?:[^'"\`\\\\]|\\\\.)*${escapeRegExpLiteral(name)}['"\`]`,
  );
  if (quoted.test(source)) return true;
  const id = escapeRegExpLiteral(stem);
  const importRe = new RegExp(
    String.raw`(?:^|[\n;])\s*(?:import\s+${id}\b|from\s+\.*${id}\b|from\s+\.+\s+import\s+\(?\s*(?:[\w$.]+\s+as\s+)?(?:[\w$]+\s*,\s*)*${id}\b)`,
  );
  if (importRe.test(source)) return true;
  const importlibRe = new RegExp(
    String.raw`import_module\(\s*['"](?:\.*)?${id}['"]`,
  );
  return importlibRe.test(source);
}

/**
 * Conservative auto-wire predicate: a Python file with a known loader name
 * (`loader.py`, `__init__.py`, `__main__.py`) that already mentions the
 * target `.pyc` / module stem. The `.py` source counterpart of the `.pyc`
 * (`<stem>.py`) is never admitted — rewriting it would invalidate PEP 552
 * / timestamp headers and change that module's own import semantics.
 * Test, already-entangled, and oversized files return false.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function isSafePythonPycLoader(options: {
  readonly source: string;
  readonly filename: string;
  readonly pycBasename: string;
}): boolean {
  if (!isPythonPycLoaderFilename(options.filename)) return false;
  if (options.source.length > MAX_PYC_LOADER_AUTOWIRE_CHARS) return false;
  if (ALREADY_ENTANGLED_PY_RE.test(options.source)) return false;
  const stem = pycModuleStemFromBasename(options.pycBasename);
  const base = basename(options.filename).replace(/\.py$/i, "");
  if (stem.length > 0 && base.toLowerCase() === stem.toLowerCase()) return false;
  return sourceMentionsPycModule(options.source, options.pycBasename);
}

function pycLoaderPreference(loaderName: string): number {
  const base = basename(loaderName);
  if (/^loader\.py$/i.test(base)) return 0;
  if (/^__init__\.py$/i.test(base)) return 1;
  if (/^__main__\.py$/i.test(base)) return 2;
  return 3;
}

export interface PythonPycLoaderCandidate {
  readonly name: string;
  readonly source: string;
}

/**
 * Pick a single same-directory (or parent-of-`__pycache__`) Python loader,
 * or `null` when none qualify or several unranked files all qualify (do
 * not guess). Preferred names: `loader.py`, then `__init__.py`, then
 * `__main__.py`.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function selectPythonPycLoader(
  pycBasename: string,
  candidates: readonly PythonPycLoaderCandidate[],
): string | null {
  const qualifying = candidates.filter((c) =>
    isSafePythonPycLoader({
      source: c.source,
      filename: c.name,
      pycBasename,
    }),
  );
  if (qualifying.length === 0) return null;
  const scored = qualifying.map((c) => ({
    c,
    score: pycLoaderPreference(c.name),
  }));
  scored.sort((a, b) => a.score - b.score || a.c.name.localeCompare(b.c.name));
  const best = scored[0]!;
  // Only known names: loader, __init__, __main__. Never guess at unique
  // app files such as helper.py / main.py / app.py.
  if (best.score >= 3) return null;
  const ties = scored.filter((s) => s.score === best.score);
  if (ties.length > 1) return null;
  return best.c.name;
}

export interface DiscoveredPythonPycLoader {
  readonly absPath: string;
  readonly name: string;
  readonly source: string;
}

function readPycLoaderCandidateSource(absPath: string): string | null {
  try {
    const st = statSync(absPath);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_PYC_LOADER_CANDIDATE_BYTES) {
      return null;
    }
    return readFileSync(absPath, "utf8");
  } catch {
    return null;
  }
}

/** Directories to search for a Python loader next to a `.pyc`. */
export function listPycLoaderSearchDirectories(pycPath: string): string[] {
  const dir = dirname(pycPath);
  const out = [dir];
  if (basename(dir).toLowerCase() === "__pycache__") {
    out.push(dirname(dir));
  }
  return out;
}

/**
 * List same-directory `.py` candidates (no recursion). Unreadable or
 * oversized files are skipped.
 */
export function listSameDirPythonPycLoaderCandidates(
  directory: string,
): DiscoveredPythonPycLoader[] {
  let names: string[] = [];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  const out: DiscoveredPythonPycLoader[] = [];
  for (const name of names) {
    if (!isPythonPycLoaderFilename(name)) continue;
    const absPath = join(directory, name);
    const source = readPycLoaderCandidateSource(absPath);
    if (source === null) continue;
    out.push({ absPath, name, source });
  }
  return out;
}

/**
 * Discover the unique safe Python loader for `pycBasename` in the first
 * search directory that yields a selection. Later directories are not
 * consulted once one directory produces a hit (output dir wins over source).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function discoverPythonPycLoader(options: {
  readonly pycBasename: string;
  readonly searchDirectories: readonly string[];
}): DiscoveredPythonPycLoader | null {
  const seen = new Set<string>();
  for (const directory of options.searchDirectories) {
    if (typeof directory !== "string" || directory.length === 0) continue;
    if (seen.has(directory)) continue;
    seen.add(directory);
    const candidates = listSameDirPythonPycLoaderCandidates(directory);
    const selected = selectPythonPycLoader(options.pycBasename, candidates);
    if (!selected) continue;
    const hit = candidates.find((c) => c.name === selected || c.absPath === selected);
    if (hit) return hit;
  }
  return null;
}

/**
 * True when a same-directory (or parent-of-`__pycache__`) Python file already
 * carries the `.pyc` import-time hook bound to this module's code identity
 * (used by defenseScore honesty).
 *
 * DEFENSIVE ONLY.
 */
export function isPycSidecarLoaderHookWired(options: {
  readonly pycBytes: Uint8Array;
  readonly pycPath: string;
}): boolean {
  const identity = computePycSidecarCodeIdentity(options.pycBytes);
  const directories = listPycLoaderSearchDirectories(options.pycPath);
  return directories.some((directory) =>
    listSameDirPythonPycLoaderCandidates(directory).some(
      (c) =>
        c.source.includes(PYC_SIDECAR_LOADER_MARKER) && c.source.includes(identity),
    ),
  );
}

/** Relative path from a loader file's directory to the protected `.pyc`. */
export function relativePycPathFromLoader(loaderPath: string, pycPath: string): string {
  const rel = relative(dirname(loaderPath), pycPath).split("\\").join("/");
  return rel.length === 0 ? basename(pycPath) : rel;
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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
    note: "Bound — GGUF bla.sidecar.v1 STRING metadata note planted; ship sidecars alongside and verify via verifyGgufSidecarMetadataNote. Host verify fails closed on strip/alter; GGUF loaders ignore unknown STRING KVs unless a same-directory Python loader was auto-wired with the load-time hook. Tensor bytes stay bit-exact.",
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
  readonly allowEmptySidecars?: boolean;
}): SidecarGgufBindResult | null {
  if (options.sidecars.length === 0 && options.allowEmptySidecars !== true) return null;
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
 * GGUF loaders ignore unknown STRING KVs, so strip does not break load unless
 * a same-directory Python loader was auto-wired with the load-time hook
 * (same honesty bar as the .pyc import-time hook).
 */
export function verifyGgufSidecarMetadataNote(
  options: GgufSidecarVerifyOptions,
): GgufSidecarVerifyResult {
  const note = extractGgufSidecarMetadataNote(options.entryBytes);
  if (!note) {
    return { ok: false, reason: "gguf sidecar metadata note missing" };
  }

  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "fail",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const sidecarParts = collected.parts;

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


/**
 * SHA-256 of a GGUF container with the `bla.sidecar.v1` STRING KV stripped
 * (alignment-safe rebuild). Files that do not carry the note hash as-is, so
 * the identity is stable across planting for canonically padded inputs.
 *
 * DEFENSIVE ONLY.
 */
export function computeGgufSidecarCodeIdentity(bytes: Uint8Array): string {
  let stripped: Buffer;
  try {
    stripped = stripGgufSidecarMetadataNote(bytes);
  } catch {
    stripped = Buffer.from(bytes);
  }
  return createHash("sha256").update(stripped).digest("hex");
}

/** Idempotence marker inserted with the optional GGUF load-time hook. */
export const GGUF_SIDECAR_LOADER_MARKER = "_installGgufSidecarLoaderHook" as const;

export interface SidecarGgufLoaderInjectOptions {
  /**
   * SHA-256 hex (or list) of the protected GGUF with the sidecar metadata
   * note stripped. Files whose identity matches MUST present a valid
   * `bla.sidecar.v1` STRING KV; other GGUF files pass through unchanged.
   */
  readonly codeIdentityHex: string | readonly string[];
  /**
   * Paths to the protected `.gguf`, relative to the loader file's directory
   * (`Path(__file__).resolve().parent`). Sidecar paths inside the note are
   * resolved against the `.gguf` file's own directory.
   */
  readonly ggufRelPaths: readonly string[];
  readonly bindingName?: string;
}

export interface SidecarGgufLoaderInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly codeIdentityHexes: readonly string[];
  readonly ggufRelPaths: readonly string[];
}

function normalizeGgufCodeIdentity(hex: string): string {
  const value = hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("codeIdentityHex must be a 64-char lowercase hex SHA-256 digest");
  }
  return value;
}

/**
 * Emit a self-contained host Python snippet that, at import time of the
 * loader it is inserted into, reads the sibling `.gguf`, and when the
 * stripped-body identity matches, verifies the `bla.sidecar.v1` STRING
 * metadata note and sibling sidecar digest. Missing targets or siblings and
 * mismatches fail closed.
 *
 * The hook does not rewrite the `.gguf` (tensor infos, relative tensor
 * offsets, and tensor bytes stay untouched; the existing alignment-safe
 * metadata note is the only GGUF mutation, and it is planted separately).
 * It is host-opt-in: `protectTarget` / `hardenProject` auto-wire it only
 * into a known same-directory Python loader (`loader.py`, `__init__.py`,
 * `__main__.py`) that already mentions the `.gguf` basename — never a
 * test / already-entangled / self-seal file. Only then is
 * `gguf-sidecar-entangle` recorded and `gguf-sidecar-host-verify-only`
 * cleared.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarGgufLoaderSnippet(
  options: SidecarGgufLoaderInjectOptions,
): SidecarGgufLoaderInjectResult {
  const raw = options.codeIdentityHex;
  const list = (Array.isArray(raw) ? raw : [raw]).map((hex) =>
    normalizeGgufCodeIdentity(hex),
  );
  if (list.length === 0) {
    throw new Error("codeIdentityHex must contain at least one digest");
  }
  const relPaths = (options.ggufRelPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (relPaths.length === 0) {
    throw new Error("ggufRelPaths must contain at least one path");
  }
  const tag = list[0]!.slice(0, 8);
  const bindingName = options.bindingName ?? `${GGUF_SIDECAR_LOADER_MARKER}_${tag}`;
  assertPythonBindingName(bindingName);
  const idsLiteral = JSON.stringify(list);
  const pathsLiteral = JSON.stringify(relPaths);
  const keyLiteral = JSON.stringify(GGUF_SIDECAR_METADATA_KEY);
  const schemaLiteral = JSON.stringify(SIDECAR_ENTANGLE_SCHEMA);
  const kindLiteral = JSON.stringify(GGUF_SIDECAR_METADATA_KIND);

  const lines: string[] = [];
  lines.push(`# ${GGUF_SIDECAR_LOADER_MARKER}`);
  lines.push(`def ${bindingName}():`);
  lines.push(`    import hashlib as _sc_hashlib_${tag}`);
  lines.push(`    import json as _sc_json_${tag}`);
  lines.push(`    import pathlib as _sc_pathlib_${tag}`);
  lines.push(`    _sc_ids_${tag} = ${idsLiteral}`);
  lines.push(`    _sc_idset_${tag} = set(_sc_ids_${tag})`);
  lines.push(`    _sc_paths_${tag} = ${pathsLiteral}`);
  lines.push(`    _sc_key_${tag} = ${keyLiteral}`);
  lines.push(`    _sc_schema_${tag} = ${schemaLiteral}`);
  lines.push(`    _sc_kind_${tag} = ${kindLiteral}`);
  lines.push(`    _sc_base_${tag} = _sc_pathlib_${tag}.Path(__file__).resolve().parent`);
  lines.push(`    def _sc_skip_${tag}(_sc_buf_${tag}, _sc_off_${tag}, _sc_ty_${tag}, _sc_depth_${tag}):`);
  lines.push(`        if _sc_depth_${tag} > 64 or _sc_off_${tag} > len(_sc_buf_${tag}):`);
  lines.push(`            return None`);
  lines.push(`        if _sc_ty_${tag} in (0, 1, 7):`);
  lines.push(`            return _sc_off_${tag} + 1 if _sc_off_${tag} + 1 <= len(_sc_buf_${tag}) else None`);
  lines.push(`        if _sc_ty_${tag} in (2, 3):`);
  lines.push(`            return _sc_off_${tag} + 2 if _sc_off_${tag} + 2 <= len(_sc_buf_${tag}) else None`);
  lines.push(`        if _sc_ty_${tag} in (4, 5, 6):`);
  lines.push(`            return _sc_off_${tag} + 4 if _sc_off_${tag} + 4 <= len(_sc_buf_${tag}) else None`);
  lines.push(`        if _sc_ty_${tag} in (10, 11, 12):`);
  lines.push(`            return _sc_off_${tag} + 8 if _sc_off_${tag} + 8 <= len(_sc_buf_${tag}) else None`);
  lines.push(`        if _sc_ty_${tag} == 8:`);
  lines.push(`            if _sc_off_${tag} + 8 > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_ln_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_off_${tag}:_sc_off_${tag} + 8], "little")`);
  lines.push(`            _sc_end_${tag} = _sc_off_${tag} + 8 + _sc_ln_${tag}`);
  lines.push(`            return _sc_end_${tag} if _sc_end_${tag} <= len(_sc_buf_${tag}) else None`);
  lines.push(`        if _sc_ty_${tag} == 9:`);
  lines.push(`            if _sc_off_${tag} + 12 > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_elem_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_off_${tag}:_sc_off_${tag} + 4], "little")`);
  lines.push(`            _sc_cnt_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_off_${tag} + 4:_sc_off_${tag} + 12], "little")`);
  lines.push(`            if _sc_cnt_${tag} > len(_sc_buf_${tag}) - (_sc_off_${tag} + 12):`);
  lines.push(`                return None`);
  lines.push(`            _sc_cur_${tag} = _sc_off_${tag} + 12`);
  lines.push(`            for _sc_i_${tag} in range(_sc_cnt_${tag}):`);
  lines.push(`                _sc_nxt_${tag} = _sc_skip_${tag}(_sc_buf_${tag}, _sc_cur_${tag}, _sc_elem_${tag}, _sc_depth_${tag} + 1)`);
  lines.push(`                if _sc_nxt_${tag} is None:`);
  lines.push(`                    return None`);
  lines.push(`                _sc_cur_${tag} = _sc_nxt_${tag}`);
  lines.push(`            return _sc_cur_${tag}`);
  lines.push(`        return None`);
  lines.push(`    def _sc_parse_${tag}(_sc_buf_${tag}):`);
  lines.push(`        if len(_sc_buf_${tag}) < 24 or _sc_buf_${tag}[0:4] != b"GGUF":`);
  lines.push(`            return None`);
  lines.push(`        _sc_ver_${tag} = int.from_bytes(_sc_buf_${tag}[4:8], "little")`);
  lines.push(`        if _sc_ver_${tag} not in (2, 3):`);
  lines.push(`            return None`);
  lines.push(`        _sc_tc_${tag} = int.from_bytes(_sc_buf_${tag}[8:16], "little")`);
  lines.push(`        _sc_kc_${tag} = int.from_bytes(_sc_buf_${tag}[16:24], "little")`);
  lines.push(`        if _sc_kc_${tag} > 100000 or _sc_tc_${tag} > 1000000:`);
  lines.push(`            return None`);
  lines.push(`        _sc_off_${tag} = 24`);
  lines.push(`        _sc_kvs_${tag} = []`);
  lines.push(`        _sc_align_${tag} = 32`);
  lines.push(`        for _sc_i_${tag} in range(_sc_kc_${tag}):`);
  lines.push(`            _sc_start_${tag} = _sc_off_${tag}`);
  lines.push(`            if _sc_off_${tag} + 8 > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_klen_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_off_${tag}:_sc_off_${tag} + 8], "little")`);
  lines.push(`            _sc_kend_${tag} = _sc_off_${tag} + 8 + _sc_klen_${tag}`);
  lines.push(`            if _sc_kend_${tag} + 4 > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_key_${tag}2 = _sc_buf_${tag}[_sc_off_${tag} + 8:_sc_kend_${tag}].decode("utf-8", "replace")`);
  lines.push(`            _sc_vty_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_kend_${tag}:_sc_kend_${tag} + 4], "little")`);
  lines.push(`            _sc_nxt_${tag} = _sc_skip_${tag}(_sc_buf_${tag}, _sc_kend_${tag} + 4, _sc_vty_${tag}, 0)`);
  lines.push(`            if _sc_nxt_${tag} is None:`);
  lines.push(`                return None`);
  lines.push(`            if _sc_key_${tag}2 == "general.alignment" and _sc_vty_${tag} == 4:`);
  lines.push(`                _sc_a_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_kend_${tag} + 4:_sc_kend_${tag} + 8], "little")`);
  lines.push(`                if _sc_a_${tag} > 0 and _sc_a_${tag} % 8 == 0:`);
  lines.push(`                    if _sc_a_${tag} > 1048576:`);
  lines.push(`                        return None`);
  lines.push(`                    _sc_align_${tag} = _sc_a_${tag}`);
  lines.push(`            _sc_kvs_${tag}.append((_sc_key_${tag}2, _sc_start_${tag}, _sc_nxt_${tag}, _sc_vty_${tag}))`);
  lines.push(`            _sc_off_${tag} = _sc_nxt_${tag}`);
  lines.push(`        _sc_kvend_${tag} = _sc_off_${tag}`);
  lines.push(`        for _sc_t_${tag} in range(_sc_tc_${tag}):`);
  lines.push(`            if _sc_off_${tag} + 8 > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_nlen_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_off_${tag}:_sc_off_${tag} + 8], "little")`);
  lines.push(`            _sc_nend_${tag} = _sc_off_${tag} + 8 + _sc_nlen_${tag}`);
  lines.push(`            if _sc_nend_${tag} + 4 > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_off_${tag} = _sc_nend_${tag}`);
  lines.push(`            _sc_ndims_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_off_${tag}:_sc_off_${tag} + 4], "little")`);
  lines.push(`            if _sc_ndims_${tag} > 8:`);
  lines.push(`                return None`);
  lines.push(`            _sc_off_${tag} += 4`);
  lines.push(`            _sc_tail_${tag} = _sc_ndims_${tag} * 8 + 4 + 8`);
  lines.push(`            if _sc_off_${tag} + _sc_tail_${tag} > len(_sc_buf_${tag}):`);
  lines.push(`                return None`);
  lines.push(`            _sc_off_${tag} += _sc_tail_${tag}`);
  lines.push(`        _sc_tiend_${tag} = _sc_off_${tag}`);
  lines.push(`        _sc_has_${tag} = len(_sc_buf_${tag}) > _sc_tiend_${tag}`);
  lines.push(`        _sc_rem_${tag} = _sc_tiend_${tag} % _sc_align_${tag}`);
  lines.push(`        _sc_dstart_${tag} = _sc_tiend_${tag} if _sc_rem_${tag} == 0 else _sc_tiend_${tag} + (_sc_align_${tag} - _sc_rem_${tag})`);
  lines.push(`        return (_sc_ver_${tag}, _sc_tc_${tag}, _sc_kvs_${tag}, _sc_kvend_${tag}, _sc_tiend_${tag}, _sc_align_${tag}, _sc_dstart_${tag}, _sc_has_${tag})`);
  lines.push(`    def _sc_strip_${tag}(_sc_buf_${tag}):`);
  lines.push(`        _sc_lay_${tag} = _sc_parse_${tag}(_sc_buf_${tag})`);
  lines.push(`        if _sc_lay_${tag} is None:`);
  lines.push(`            return _sc_buf_${tag}`);
  lines.push(`        _sc_ver_${tag}, _sc_tc_${tag}, _sc_kvs_${tag}, _sc_kvend_${tag}, _sc_tiend_${tag}, _sc_align_${tag}, _sc_dstart_${tag}, _sc_has_${tag} = _sc_lay_${tag}`);
  lines.push(`        if not any(_sc_kv_${tag}[0] == _sc_key_${tag} for _sc_kv_${tag} in _sc_kvs_${tag}):`);
  lines.push(`            return _sc_buf_${tag}`);
  lines.push(`        _sc_kept_${tag} = [_sc_kv_${tag} for _sc_kv_${tag} in _sc_kvs_${tag} if _sc_kv_${tag}[0] != _sc_key_${tag}]`);
  lines.push(`        _sc_hdr_${tag} = bytearray(24)`);
  lines.push(`        _sc_hdr_${tag}[0:4] = b"GGUF"`);
  lines.push(`        _sc_hdr_${tag}[4:8] = int(_sc_ver_${tag}).to_bytes(4, "little")`);
  lines.push(`        _sc_hdr_${tag}[8:16] = int(_sc_tc_${tag}).to_bytes(8, "little")`);
  lines.push(`        _sc_hdr_${tag}[16:24] = int(len(_sc_kept_${tag})).to_bytes(8, "little")`);
  lines.push(`        _sc_parts_${tag} = [bytes(_sc_hdr_${tag})]`);
  lines.push(`        for _sc_kv_${tag} in _sc_kept_${tag}:`);
  lines.push(`            _sc_parts_${tag}.append(_sc_buf_${tag}[_sc_kv_${tag}[1]:_sc_kv_${tag}[2]])`);
  lines.push(`        _sc_parts_${tag}.append(_sc_buf_${tag}[_sc_kvend_${tag}:_sc_tiend_${tag}])`);
  lines.push(`        _sc_meta_${tag} = b"".join(_sc_parts_${tag})`);
  lines.push(`        if not _sc_has_${tag}:`);
  lines.push(`            return _sc_meta_${tag}`);
  lines.push(`        if _sc_dstart_${tag} > len(_sc_buf_${tag}):`);
  lines.push(`            return _sc_buf_${tag}`);
  lines.push(`        _sc_prem_${tag} = len(_sc_meta_${tag}) % _sc_align_${tag}`);
  lines.push(`        _sc_pad_${tag} = 0 if _sc_prem_${tag} == 0 else _sc_align_${tag} - _sc_prem_${tag}`);
  lines.push(`        return _sc_meta_${tag} + (b"\\x00" * _sc_pad_${tag}) + _sc_buf_${tag}[_sc_dstart_${tag}:]`);
  lines.push(`    def _sc_extract_${tag}(_sc_buf_${tag}):`);
  lines.push(`        _sc_lay_${tag} = _sc_parse_${tag}(_sc_buf_${tag})`);
  lines.push(`        if _sc_lay_${tag} is None:`);
  lines.push(`            return None`);
  lines.push(`        _sc_kvs_${tag} = _sc_lay_${tag}[2]`);
  lines.push(`        _sc_hit_${tag} = None`);
  lines.push(`        for _sc_kv_${tag} in _sc_kvs_${tag}:`);
  lines.push(`            if _sc_kv_${tag}[0] == _sc_key_${tag} and _sc_kv_${tag}[3] == 8:`);
  lines.push(`                _sc_hit_${tag} = _sc_kv_${tag}`);
  lines.push(`                break`);
  lines.push(`        if _sc_hit_${tag} is None:`);
  lines.push(`            return None`);
  lines.push(`        _sc_start_${tag} = _sc_hit_${tag}[1]`);
  lines.push(`        _sc_klen_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_start_${tag}:_sc_start_${tag} + 8], "little")`);
  lines.push(`        _sc_vstart_${tag} = _sc_start_${tag} + 8 + _sc_klen_${tag} + 4`);
  lines.push(`        if _sc_vstart_${tag} + 8 > len(_sc_buf_${tag}):`);
  lines.push(`            return None`);
  lines.push(`        _sc_vlen_${tag} = int.from_bytes(_sc_buf_${tag}[_sc_vstart_${tag}:_sc_vstart_${tag} + 8], "little")`);
  lines.push(`        if _sc_vstart_${tag} + 8 + _sc_vlen_${tag} > len(_sc_buf_${tag}):`);
  lines.push(`            return None`);
  lines.push(`        try:`);
  lines.push(`            _sc_obj_${tag} = _sc_json_${tag}.loads(_sc_buf_${tag}[_sc_vstart_${tag} + 8:_sc_vstart_${tag} + 8 + _sc_vlen_${tag}].decode("utf-8"))`);
  lines.push(`        except Exception:`);
  lines.push(`            return None`);
  lines.push(`        if _sc_obj_${tag}.get("schema") != _sc_schema_${tag} or _sc_obj_${tag}.get("kind") != _sc_kind_${tag}:`);
  lines.push(`            return None`);
  lines.push(`        _sc_dig_${tag} = _sc_obj_${tag}.get("digest")`);
  lines.push(`        if not isinstance(_sc_dig_${tag}, str) or len(_sc_dig_${tag}) != 64:`);
  lines.push(`            return None`);
  lines.push(`        return _sc_obj_${tag}`);
  lines.push(`    def _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}):`);
  lines.push(`        _sc_h_${tag} = _sc_hashlib_${tag}.sha256()`);
  lines.push(`        _sc_h_${tag}.update(_sc_entry_${tag}.encode("utf-8"))`);
  lines.push(`        _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        for _sc_sp_${tag}, _sc_data_${tag} in _sc_parts_${tag}:`);
  lines.push(`            _sc_h_${tag}.update(_sc_sp_${tag}.encode("utf-8"))`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`            _sc_h_${tag}.update(_sc_data_${tag})`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        _sc_h_${tag}.update(_sc_seed_${tag}.encode("utf-8"))`);
  lines.push(`        return _sc_h_${tag}.hexdigest()`);
  lines.push(`    for _sc_rel_${tag} in _sc_paths_${tag}:`);
  lines.push(`        _sc_path_${tag} = _sc_pathlib_${tag}.Path(_sc_rel_${tag})`);
  lines.push(`        if not _sc_path_${tag}.is_absolute():`);
  lines.push(`            _sc_path_${tag} = _sc_base_${tag} / _sc_rel_${tag}`);
  lines.push(`        try:`);
  lines.push(`            _sc_raw_${tag} = _sc_path_${tag}.read_bytes()`);
  lines.push(`        except Exception:`);
  lines.push(`            continue`);
  lines.push(`        _sc_ident_${tag} = _sc_hashlib_${tag}.sha256(_sc_strip_${tag}(_sc_raw_${tag})).hexdigest()`);
  lines.push(`        if _sc_ident_${tag} not in _sc_idset_${tag}:`);
  lines.push(`            continue`);
  lines.push(`        _sc_note_${tag} = _sc_extract_${tag}(_sc_raw_${tag})`);
  lines.push(`        if _sc_note_${tag} is None:`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        _sc_parts_${tag} = []`);
  lines.push(`        _sc_dir_${tag} = _sc_path_${tag}.parent`);
  lines.push(`        _sc_sp_list_${tag} = _sc_note_${tag}.get("sidecarPaths") or []`);
  lines.push(`        if not isinstance(_sc_sp_list_${tag}, list):`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        for _sc_sp_${tag} in _sc_sp_list_${tag}:`);
  lines.push(`            if not isinstance(_sc_sp_${tag}, str) or len(_sc_sp_${tag}) == 0:`);
  lines.push(`                continue`);
  lines.push(`            _sc_sib_${tag} = _sc_pathlib_${tag}.Path(_sc_sp_${tag})`);
  lines.push(`            if not _sc_sib_${tag}.is_absolute():`);
  lines.push(`                _sc_sib_${tag} = _sc_dir_${tag} / _sc_sp_${tag}`);
  lines.push(`            try:`);
  lines.push(`                _sc_parts_${tag}.append((_sc_sp_${tag}, _sc_sib_${tag}.read_bytes()))`);
  lines.push(`            except Exception:`);
  lines.push(`                raise RuntimeError("integrity binding mismatch") from None`);
  lines.push(`        _sc_seed_${tag} = _sc_note_${tag}.get("seedTag")`);
  lines.push(`        if not isinstance(_sc_seed_${tag}, str) or len(_sc_seed_${tag}) == 0:`);
  lines.push(`            _sc_seed_${tag} = "bla-sidecar-v1"`);
  lines.push(`        _sc_entry_${tag} = _sc_note_${tag}.get("entryPath")`);
  lines.push(`        if not isinstance(_sc_entry_${tag}, str):`);
  lines.push(`            _sc_entry_${tag} = ""`);
  lines.push(`        if _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}) != str(_sc_note_${tag}.get("digest")).lower():`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        return`);
  lines.push(`    raise RuntimeError("integrity binding mismatch")`);
  lines.push(`try:`);
  lines.push(`    ${bindingName}()`);
  lines.push(`finally:`);
  lines.push(`    del ${bindingName}`);

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    codeIdentityHexes: list,
    ggufRelPaths: relPaths,
  };
}

/**
 * Insert a GGUF load-time hook after shebang / encoding / docstring /
 * `from __future__`, idempotent when {@link GGUF_SIDECAR_LOADER_MARKER} is
 * already present. Preserves surrounding newlines the same way
 * `bindPythonSidecarEntanglement` does.
 */
export function prependGgufSidecarLoaderHook(
  entrySource: string,
  preamble: string,
): string {
  if (entrySource.includes(GGUF_SIDECAR_LOADER_MARKER)) return entrySource;
  const eol = entrySource.includes("\r\n") ? "\r\n" : "\n";
  const analysis = findPythonPrologueInsertionOffset(entrySource);
  const headRaw = entrySource.slice(0, analysis.insertOffset);
  const tailRaw = entrySource.slice(analysis.insertOffset);
  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "");
  const body = preamble.replace(/\r?\n/g, eol).replace(/(?:\r?\n)+$/, "");
  const parts: string[] = [];
  if (head.length > 0) parts.push(head);
  parts.push(body);
  if (tail.length > 0) parts.push(tail);
  return (
    parts.join(eol) +
    (entrySource.endsWith("\n") || entrySource.endsWith("\r\n") ? eol : "")
  );
}

/**
 * Convenience: prepend a loader hook bound to this GGUF file's stripped
 * identity. Idempotent when the marker is already present.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function entangleGgufLoaderWithSidecars(options: {
  readonly loaderSource: string;
  readonly ggufBytes: Uint8Array;
  readonly ggufRelPath: string | readonly string[];
}): { readonly code: string; readonly identity: string } {
  const identity = computeGgufSidecarCodeIdentity(options.ggufBytes);
  const paths = (
    Array.isArray(options.ggufRelPath) ? options.ggufRelPath : [options.ggufRelPath]
  ).filter((p) => p.length > 0);
  const inject = generateSidecarGgufLoaderSnippet({
    codeIdentityHex: identity,
    ggufRelPaths: paths,
  });
  return {
    code: prependGgufSidecarLoaderHook(options.loaderSource, inject.preamble),
    identity,
  };
}

const MAX_GGUF_LOADER_CANDIDATE_BYTES = 2 * 1024 * 1024;
const MAX_GGUF_LOADER_AUTOWIRE_CHARS = 64 * 1024;

/**
 * True when `source` mentions `ggufBasename` in a quoted string / template.
 */
export function sourceMentionsGgufFile(source: string, ggufBasename: string): boolean {
  const name = (ggufBasename.replaceAll("\\", "/").split("/").pop() ?? "");
  if (!name || !name.toLowerCase().endsWith(".gguf")) return false;
  const quoted = new RegExp(
    `['"\`](?:[^'"\`\\\\]|\\\\.)*${escapeRegExpLiteral(name)}['"\`]`,
  );
  return quoted.test(source);
}

/**
 * Conservative auto-wire predicate: a Python file with a known loader name
 * (`loader.py`, `__init__.py`, `__main__.py`) that already mentions the
 * target `.gguf` basename. Test, already-entangled, and oversized files
 * return false.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function isSafePythonGgufLoader(options: {
  readonly source: string;
  readonly filename: string;
  readonly ggufBasename: string;
}): boolean {
  if (!isPythonPycLoaderFilename(options.filename)) return false;
  if (options.source.length > MAX_GGUF_LOADER_AUTOWIRE_CHARS) return false;
  if (ALREADY_ENTANGLED_PY_RE.test(options.source)) return false;
  return sourceMentionsGgufFile(options.source, options.ggufBasename);
}

function ggufLoaderPreference(loaderName: string): number {
  const base = basename(loaderName);
  if (/^loader\.py$/i.test(base)) return 0;
  if (/^__init__\.py$/i.test(base)) return 1;
  if (/^__main__\.py$/i.test(base)) return 2;
  return 3;
}

export interface PythonGgufLoaderCandidate {
  readonly name: string;
  readonly source: string;
}

/**
 * Pick a single same-directory Python loader, or `null` when none qualify
 * or several unranked files all qualify (do not guess). Preferred names:
 * `loader.py`, then `__init__.py`, then `__main__.py`.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function selectPythonGgufLoader(
  ggufBasename: string,
  candidates: readonly PythonGgufLoaderCandidate[],
): string | null {
  const qualifying = candidates.filter((c) =>
    isSafePythonGgufLoader({
      source: c.source,
      filename: c.name,
      ggufBasename,
    }),
  );
  if (qualifying.length === 0) return null;
  const scored = qualifying.map((c) => ({
    c,
    score: ggufLoaderPreference(c.name),
  }));
  scored.sort((a, b) => a.score - b.score || a.c.name.localeCompare(b.c.name));
  const best = scored[0]!;
  if (best.score >= 3) return null;
  const ties = scored.filter((s) => s.score === best.score);
  if (ties.length > 1) return null;
  return best.c.name;
}

export interface DiscoveredPythonGgufLoader {
  readonly absPath: string;
  readonly name: string;
  readonly source: string;
}

function readGgufLoaderCandidateSource(absPath: string): string | null {
  try {
    const st = statSync(absPath);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_GGUF_LOADER_CANDIDATE_BYTES) {
      return null;
    }
    return readFileSync(absPath, "utf8");
  } catch {
    return null;
  }
}

/** Directories to search for a Python loader next to a `.gguf`. */
export function listGgufLoaderSearchDirectories(ggufPath: string): string[] {
  return [dirname(ggufPath)];
}

/**
 * List same-directory `.py` candidates (no recursion). Unreadable or
 * oversized files are skipped.
 */
export function listSameDirPythonGgufLoaderCandidates(
  directory: string,
): DiscoveredPythonGgufLoader[] {
  let names: string[] = [];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  const out: DiscoveredPythonGgufLoader[] = [];
  for (const name of names) {
    if (!isPythonPycLoaderFilename(name)) continue;
    const absPath = join(directory, name);
    const source = readGgufLoaderCandidateSource(absPath);
    if (source === null) continue;
    out.push({ absPath, name, source });
  }
  return out;
}

/**
 * Discover the unique safe Python loader for `ggufBasename` in the first
 * search directory that yields a selection. Later directories are not
 * consulted once one directory produces a hit (output dir wins over source).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function discoverPythonGgufLoader(options: {
  readonly ggufBasename: string;
  readonly searchDirectories: readonly string[];
}): DiscoveredPythonGgufLoader | null {
  const seen = new Set<string>();
  for (const directory of options.searchDirectories) {
    if (typeof directory !== "string" || directory.length === 0) continue;
    if (seen.has(directory)) continue;
    seen.add(directory);
    const candidates = listSameDirPythonGgufLoaderCandidates(directory);
    const selected = selectPythonGgufLoader(options.ggufBasename, candidates);
    if (!selected) continue;
    const hit = candidates.find((c) => c.name === selected || c.absPath === selected);
    if (hit) return hit;
  }
  return null;
}

/**
 * True when a same-directory Python file already carries the GGUF load-time
 * hook bound to this file's code identity (used by defenseScore honesty).
 *
 * DEFENSIVE ONLY.
 */
export function isGgufSidecarLoaderHookWired(options: {
  readonly ggufBytes: Uint8Array;
  readonly ggufPath: string;
}): boolean {
  const identity = computeGgufSidecarCodeIdentity(options.ggufBytes);
  const directories = listGgufLoaderSearchDirectories(options.ggufPath);
  return directories.some((directory) =>
    listSameDirPythonGgufLoaderCandidates(directory).some(
      (c) =>
        c.source.includes(GGUF_SIDECAR_LOADER_MARKER) && c.source.includes(identity),
    ),
  );
}

/** Relative path from a loader file's directory to the protected `.gguf`. */
export function relativeGgufPathFromLoader(loaderPath: string, ggufPath: string): string {
  const rel = relative(dirname(loaderPath), ggufPath).split("\\").join("/");
  return rel.length === 0 ? basename(ggufPath) : rel;
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
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
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
    note: "Bound — Safetensors __metadata__ bla.sidecar.v1 note planted (tensor bytes bit-exact); ship sidecars alongside and verify via verifySafetensorsSidecarMetadataNote. Host verify fails closed on strip/alter; Safetensors loaders ignore unknown __metadata__ keys unless a same-directory Python loader was auto-wired with the load-time hook.",
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
  readonly allowEmptySidecars?: boolean;
}): SidecarSafetensorsBindResult | null {
  if (options.sidecars.length === 0 && options.allowEmptySidecars !== true) return null;
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
  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "fail",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const sidecarParts = collected.parts;
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



/**
 * SHA-256 of a Safetensors container with the `bla.sidecar.v1`
 * `__metadata__` key stripped (header rebuilt with the same 8-byte
 * space-padded JSON layout `buildSafetensorsBuffer` uses). Files that
 * do not carry the note hash as the rebuilt header plus original
 * tensor bytes, so the identity is stable across planting for
 * `buildSafetensorsBuffer` inputs.
 *
 * DEFENSIVE ONLY.
 */
export function computeSafetensorsSidecarCodeIdentity(bytes: Uint8Array): string {
  let stripped: Buffer;
  try {
    stripped = stripSafetensorsSidecarMetadataNote(bytes);
  } catch {
    stripped = Buffer.from(bytes);
  }
  return createHash("sha256").update(stripped).digest("hex");
}

/** Idempotence marker inserted with the optional Safetensors load-time hook. */
export const SAFETENSORS_SIDECAR_LOADER_MARKER =
  "_installSafetensorsSidecarLoaderHook" as const;

export interface SidecarSafetensorsLoaderInjectOptions {
  /**
   * SHA-256 hex (or list) of the protected Safetensors file with the
   * sidecar `__metadata__` note stripped. Files whose identity matches
   * MUST present a valid `bla.sidecar.v1` `__metadata__` entry; other
   * Safetensors files pass through unchanged.
   */
  readonly codeIdentityHex: string | readonly string[];
  /**
   * Paths to the protected `.safetensors`, relative to the loader
   * file's directory (`Path(__file__).resolve().parent`). Sidecar paths
   * inside the note are resolved against the `.safetensors` file's own
   * directory.
   */
  readonly safetensorsRelPaths: readonly string[];
  readonly bindingName?: string;
}

export interface SidecarSafetensorsLoaderInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly codeIdentityHexes: readonly string[];
  readonly safetensorsRelPaths: readonly string[];
}

function normalizeSafetensorsCodeIdentity(hex: string): string {
  const value = hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("codeIdentityHex must be a 64-char lowercase hex SHA-256 digest");
  }
  return value;
}

/**
 * Emit a self-contained host Python snippet that, at import time of the
 * loader it is inserted into, reads the sibling `.safetensors`, and when
 * the stripped-body identity matches, verifies the `bla.sidecar.v1`
 * `__metadata__` note and sibling sidecar digest. Missing targets or siblings
 * and mismatches fail closed.
 *
 * The hook does not rewrite the `.safetensors` (header JSON tensor
 * descriptors, `data_offsets`, dtype, and tensor bytes stay untouched;
 * the existing `__metadata__` host-verify note is the only Safetensors
 * mutation, and it is planted separately). It is host-opt-in:
 * `protectTarget` / `hardenProject` auto-wire it only into a known
 * same-directory Python loader (`loader.py`, `__init__.py`,
 * `__main__.py`) that already mentions the `.safetensors` basename —
 * never a test / already-entangled / self-seal file. Only then is
 * `safetensors-sidecar-entangle` recorded and
 * `safetensors-sidecar-host-verify-only` cleared.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarSafetensorsLoaderSnippet(
  options: SidecarSafetensorsLoaderInjectOptions,
): SidecarSafetensorsLoaderInjectResult {
  const raw = options.codeIdentityHex;
  const list = (Array.isArray(raw) ? raw : [raw]).map((hex) =>
    normalizeSafetensorsCodeIdentity(hex),
  );
  if (list.length === 0) {
    throw new Error("codeIdentityHex must contain at least one digest");
  }
  const relPaths = (options.safetensorsRelPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (relPaths.length === 0) {
    throw new Error("safetensorsRelPaths must contain at least one path");
  }
  const tag = list[0]!.slice(0, 8);
  const bindingName =
    options.bindingName ?? `${SAFETENSORS_SIDECAR_LOADER_MARKER}_${tag}`;
  assertPythonBindingName(bindingName);
  const idsLiteral = JSON.stringify(list);
  const pathsLiteral = JSON.stringify(relPaths);
  const keyLiteral = JSON.stringify(SAFETENSORS_SIDECAR_METADATA_KEY);
  const schemaLiteral = JSON.stringify(SIDECAR_ENTANGLE_SCHEMA);
  const kindLiteral = JSON.stringify(SAFETENSORS_SIDECAR_METADATA_KIND);

  const lines: string[] = [];
  lines.push(`# ${SAFETENSORS_SIDECAR_LOADER_MARKER}`);
  lines.push(`def ${bindingName}():`);
  lines.push(`    import hashlib as _sc_hashlib_${tag}`);
  lines.push(`    import json as _sc_json_${tag}`);
  lines.push(`    import pathlib as _sc_pathlib_${tag}`);
  lines.push(`    _sc_ids_${tag} = ${idsLiteral}`);
  lines.push(`    _sc_idset_${tag} = set(_sc_ids_${tag})`);
  lines.push(`    _sc_paths_${tag} = ${pathsLiteral}`);
  lines.push(`    _sc_key_${tag} = ${keyLiteral}`);
  lines.push(`    _sc_schema_${tag} = ${schemaLiteral}`);
  lines.push(`    _sc_kind_${tag} = ${kindLiteral}`);
  lines.push(`    _sc_base_${tag} = _sc_pathlib_${tag}.Path(__file__).resolve().parent`);
  lines.push(`    def _sc_parse_${tag}(_sc_buf_${tag}):`);
  lines.push(`        if len(_sc_buf_${tag}) < 10:`);
  lines.push(`            return None`);
  lines.push(`        _sc_hlen_${tag} = int.from_bytes(_sc_buf_${tag}[0:8], "little")`);
  lines.push(`        if _sc_hlen_${tag} < 2 or _sc_hlen_${tag} > 100000000 or 8 + _sc_hlen_${tag} > len(_sc_buf_${tag}):`);
  lines.push(`            return None`);
  lines.push(`        _sc_end_${tag} = 8 + _sc_hlen_${tag}`);
  lines.push(`        if _sc_buf_${tag}[8:9] != b"{":`);
  lines.push(`            return None`);
  lines.push(`        try:`);
  lines.push(`            _sc_header_${tag} = _sc_json_${tag}.loads(_sc_buf_${tag}[8:_sc_end_${tag}].decode("utf-8"))`);
  lines.push(`        except Exception:`);
  lines.push(`            return None`);
  lines.push(`        if not isinstance(_sc_header_${tag}, dict):`);
  lines.push(`            return None`);
  lines.push(`        return (_sc_header_${tag}, _sc_buf_${tag}[_sc_end_${tag}:])`);
  lines.push(`    def _sc_build_${tag}(_sc_header_${tag}, _sc_data_${tag}):`);
  lines.push(`        _sc_raw_${tag} = _sc_json_${tag}.dumps(_sc_header_${tag}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`);
  lines.push(`        _sc_pad_${tag} = (8 - (len(_sc_raw_${tag}) % 8)) % 8`);
  lines.push(`        _sc_jsonb_${tag} = _sc_raw_${tag} + (b" " * _sc_pad_${tag})`);
  lines.push(`        return int(len(_sc_jsonb_${tag})).to_bytes(8, "little") + _sc_jsonb_${tag} + _sc_data_${tag}`);
  lines.push(`    def _sc_strip_${tag}(_sc_buf_${tag}):`);
  lines.push(`        _sc_parsed_${tag} = _sc_parse_${tag}(_sc_buf_${tag})`);
  lines.push(`        if _sc_parsed_${tag} is None:`);
  lines.push(`            return _sc_buf_${tag}`);
  lines.push(`        _sc_header_${tag}, _sc_data_${tag} = _sc_parsed_${tag}`);
  lines.push(`        _sc_meta_${tag} = _sc_header_${tag}.get("__metadata__")`);
  lines.push(`        if not isinstance(_sc_meta_${tag}, dict) or _sc_key_${tag} not in _sc_meta_${tag}:`);
  lines.push(`            return _sc_buf_${tag}`);
  lines.push(`        _sc_next_${tag} = dict(_sc_header_${tag})`);
  lines.push(`        _sc_nextmeta_${tag} = dict(_sc_meta_${tag})`);
  lines.push(`        _sc_nextmeta_${tag}.pop(_sc_key_${tag}, None)`);
  lines.push(`        if len(_sc_nextmeta_${tag}) == 0:`);
  lines.push(`            _sc_next_${tag}.pop("__metadata__", None)`);
  lines.push(`        else:`);
  lines.push(`            _sc_next_${tag}["__metadata__"] = _sc_nextmeta_${tag}`);
  lines.push(`        return _sc_build_${tag}(_sc_next_${tag}, _sc_data_${tag})`);
  lines.push(`    def _sc_extract_${tag}(_sc_buf_${tag}):`);
  lines.push(`        _sc_parsed_${tag} = _sc_parse_${tag}(_sc_buf_${tag})`);
  lines.push(`        if _sc_parsed_${tag} is None:`);
  lines.push(`            return None`);
  lines.push(`        _sc_meta_${tag} = _sc_parsed_${tag}[0].get("__metadata__")`);
  lines.push(`        if not isinstance(_sc_meta_${tag}, dict):`);
  lines.push(`            return None`);
  lines.push(`        _sc_rawnote_${tag} = _sc_meta_${tag}.get(_sc_key_${tag})`);
  lines.push(`        if not isinstance(_sc_rawnote_${tag}, str) or len(_sc_rawnote_${tag}) == 0:`);
  lines.push(`            return None`);
  lines.push(`        try:`);
  lines.push(`            _sc_obj_${tag} = _sc_json_${tag}.loads(_sc_rawnote_${tag})`);
  lines.push(`        except Exception:`);
  lines.push(`            return None`);
  lines.push(`        if _sc_obj_${tag}.get("schema") != _sc_schema_${tag} or _sc_obj_${tag}.get("kind") != _sc_kind_${tag}:`);
  lines.push(`            return None`);
  lines.push(`        _sc_dig_${tag} = _sc_obj_${tag}.get("digest")`);
  lines.push(`        if not isinstance(_sc_dig_${tag}, str) or len(_sc_dig_${tag}) != 64:`);
  lines.push(`            return None`);
  lines.push(`        return _sc_obj_${tag}`);
  lines.push(`    def _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}):`);
  lines.push(`        _sc_h_${tag} = _sc_hashlib_${tag}.sha256()`);
  lines.push(`        _sc_h_${tag}.update(_sc_entry_${tag}.encode("utf-8"))`);
  lines.push(`        _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        for _sc_sp_${tag}, _sc_data_${tag} in _sc_parts_${tag}:`);
  lines.push(`            _sc_h_${tag}.update(_sc_sp_${tag}.encode("utf-8"))`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`            _sc_h_${tag}.update(_sc_data_${tag})`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        _sc_h_${tag}.update(_sc_seed_${tag}.encode("utf-8"))`);
  lines.push(`        return _sc_h_${tag}.hexdigest()`);
  lines.push(`    for _sc_rel_${tag} in _sc_paths_${tag}:`);
  lines.push(`        _sc_path_${tag} = _sc_pathlib_${tag}.Path(_sc_rel_${tag})`);
  lines.push(`        if not _sc_path_${tag}.is_absolute():`);
  lines.push(`            _sc_path_${tag} = _sc_base_${tag} / _sc_rel_${tag}`);
  lines.push(`        try:`);
  lines.push(`            _sc_raw_${tag} = _sc_path_${tag}.read_bytes()`);
  lines.push(`        except Exception:`);
  lines.push(`            continue`);
  lines.push(`        _sc_ident_${tag} = _sc_hashlib_${tag}.sha256(_sc_strip_${tag}(_sc_raw_${tag})).hexdigest()`);
  lines.push(`        if _sc_ident_${tag} not in _sc_idset_${tag}:`);
  lines.push(`            continue`);
  lines.push(`        _sc_note_${tag} = _sc_extract_${tag}(_sc_raw_${tag})`);
  lines.push(`        if _sc_note_${tag} is None:`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        _sc_parts_${tag} = []`);
  lines.push(`        _sc_dir_${tag} = _sc_path_${tag}.parent`);
  lines.push(`        _sc_sp_list_${tag} = _sc_note_${tag}.get("sidecarPaths") or []`);
  lines.push(`        if not isinstance(_sc_sp_list_${tag}, list):`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        for _sc_sp_${tag} in _sc_sp_list_${tag}:`);
  lines.push(`            if not isinstance(_sc_sp_${tag}, str) or len(_sc_sp_${tag}) == 0:`);
  lines.push(`                continue`);
  lines.push(`            _sc_sib_${tag} = _sc_pathlib_${tag}.Path(_sc_sp_${tag})`);
  lines.push(`            if not _sc_sib_${tag}.is_absolute():`);
  lines.push(`                _sc_sib_${tag} = _sc_dir_${tag} / _sc_sp_${tag}`);
  lines.push(`            try:`);
  lines.push(`                _sc_parts_${tag}.append((_sc_sp_${tag}, _sc_sib_${tag}.read_bytes()))`);
  lines.push(`            except Exception:`);
  lines.push(`                raise RuntimeError("integrity binding mismatch") from None`);
  lines.push(`        _sc_seed_${tag} = _sc_note_${tag}.get("seedTag")`);
  lines.push(`        if not isinstance(_sc_seed_${tag}, str) or len(_sc_seed_${tag}) == 0:`);
  lines.push(`            _sc_seed_${tag} = "bla-sidecar-v1"`);
  lines.push(`        _sc_entry_${tag} = _sc_note_${tag}.get("entryPath")`);
  lines.push(`        if not isinstance(_sc_entry_${tag}, str):`);
  lines.push(`            _sc_entry_${tag} = ""`);
  lines.push(`        if _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}) != str(_sc_note_${tag}.get("digest")).lower():`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        return`);
  lines.push(`    raise RuntimeError("integrity binding mismatch")`);
  lines.push(`try:`);
  lines.push(`    ${bindingName}()`);
  lines.push(`finally:`);
  lines.push(`    del ${bindingName}`);

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    codeIdentityHexes: list,
    safetensorsRelPaths: relPaths,
  };
}

/**
 * Insert a Safetensors load-time hook after shebang / encoding / docstring /
 * `from __future__`, idempotent when {@link SAFETENSORS_SIDECAR_LOADER_MARKER}
 * is already present. Preserves surrounding newlines the same way
 * `bindPythonSidecarEntanglement` does.
 */
export function prependSafetensorsSidecarLoaderHook(
  entrySource: string,
  preamble: string,
): string {
  if (entrySource.includes(SAFETENSORS_SIDECAR_LOADER_MARKER)) return entrySource;
  const eol = entrySource.includes("\r\n") ? "\r\n" : "\n";
  const analysis = findPythonPrologueInsertionOffset(entrySource);
  const headRaw = entrySource.slice(0, analysis.insertOffset);
  const tailRaw = entrySource.slice(analysis.insertOffset);
  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "");
  const body = preamble.replace(/\r?\n/g, eol).replace(/(?:\r?\n)+$/, "");
  const parts: string[] = [];
  if (head.length > 0) parts.push(head);
  parts.push(body);
  if (tail.length > 0) parts.push(tail);
  return (
    parts.join(eol) +
    (entrySource.endsWith("\n") || entrySource.endsWith("\r\n") ? eol : "")
  );
}

/**
 * Convenience: prepend a loader hook bound to this Safetensors file's
 * stripped identity. Idempotent when the marker is already present.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function entangleSafetensorsLoaderWithSidecars(options: {
  readonly loaderSource: string;
  readonly safetensorsBytes: Uint8Array;
  readonly safetensorsRelPath: string | readonly string[];
}): { readonly code: string; readonly identity: string } {
  const identity = computeSafetensorsSidecarCodeIdentity(options.safetensorsBytes);
  const paths = (
    Array.isArray(options.safetensorsRelPath)
      ? options.safetensorsRelPath
      : [options.safetensorsRelPath]
  ).filter((p) => p.length > 0);
  const inject = generateSidecarSafetensorsLoaderSnippet({
    codeIdentityHex: identity,
    safetensorsRelPaths: paths,
  });
  return {
    code: prependSafetensorsSidecarLoaderHook(options.loaderSource, inject.preamble),
    identity,
  };
}

const MAX_SAFETENSORS_LOADER_CANDIDATE_BYTES = 2 * 1024 * 1024;
const MAX_SAFETENSORS_LOADER_AUTOWIRE_CHARS = 64 * 1024;

/**
 * True when `source` mentions `safetensorsBasename` in a quoted string /
 * template.
 */
export function sourceMentionsSafetensorsFile(
  source: string,
  safetensorsBasename: string,
): boolean {
  const name = (safetensorsBasename.replaceAll("\\", "/").split("/").pop() ?? "");
  if (!name || !name.toLowerCase().endsWith(".safetensors")) return false;
  const quoted = new RegExp(
    `['"\`](?:[^'"\`\\\\]|\\\\.)*${escapeRegExpLiteral(name)}['"\`]`,
  );
  return quoted.test(source);
}

/**
 * Conservative auto-wire predicate: a Python file with a known loader name
 * (`loader.py`, `__init__.py`, `__main__.py`) that already mentions the
 * target `.safetensors` basename. Test, already-entangled, and oversized
 * files return false.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function isSafePythonSafetensorsLoader(options: {
  readonly source: string;
  readonly filename: string;
  readonly safetensorsBasename: string;
}): boolean {
  if (!isPythonPycLoaderFilename(options.filename)) return false;
  if (options.source.length > MAX_SAFETENSORS_LOADER_AUTOWIRE_CHARS) return false;
  if (ALREADY_ENTANGLED_PY_RE.test(options.source)) return false;
  return sourceMentionsSafetensorsFile(options.source, options.safetensorsBasename);
}

function safetensorsLoaderPreference(loaderName: string): number {
  const base = basename(loaderName);
  if (/^loader\.py$/i.test(base)) return 0;
  if (/^__init__\.py$/i.test(base)) return 1;
  if (/^__main__\.py$/i.test(base)) return 2;
  return 3;
}

export interface PythonSafetensorsLoaderCandidate {
  readonly name: string;
  readonly source: string;
}

/**
 * Pick a single same-directory Python loader, or `null` when none qualify
 * or several unranked files all qualify (do not guess). Preferred names:
 * `loader.py`, then `__init__.py`, then `__main__.py`.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function selectPythonSafetensorsLoader(
  safetensorsBasename: string,
  candidates: readonly PythonSafetensorsLoaderCandidate[],
): string | null {
  const qualifying = candidates.filter((c) =>
    isSafePythonSafetensorsLoader({
      source: c.source,
      filename: c.name,
      safetensorsBasename,
    }),
  );
  if (qualifying.length === 0) return null;
  const scored = qualifying.map((c) => ({
    c,
    score: safetensorsLoaderPreference(c.name),
  }));
  scored.sort((a, b) => a.score - b.score || a.c.name.localeCompare(b.c.name));
  const best = scored[0]!;
  if (best.score >= 3) return null;
  const ties = scored.filter((s) => s.score === best.score);
  if (ties.length > 1) return null;
  return best.c.name;
}

export interface DiscoveredPythonSafetensorsLoader {
  readonly absPath: string;
  readonly name: string;
  readonly source: string;
}

function readSafetensorsLoaderCandidateSource(absPath: string): string | null {
  try {
    const st = statSync(absPath);
    if (st.isFile() === false || st.size <= 0 || st.size > MAX_SAFETENSORS_LOADER_CANDIDATE_BYTES) {
      return null;
    }
    return readFileSync(absPath, "utf8");
  } catch {
    return null;
  }
}

/** Directories to search for a Python loader next to a `.safetensors`. */
export function listSafetensorsLoaderSearchDirectories(safetensorsPath: string): string[] {
  return [dirname(safetensorsPath)];
}

/**
 * List same-directory `.py` candidates (no recursion). Unreadable or
 * oversized files are skipped.
 */
export function listSameDirPythonSafetensorsLoaderCandidates(
  directory: string,
): DiscoveredPythonSafetensorsLoader[] {
  let names: string[] = [];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  const out: DiscoveredPythonSafetensorsLoader[] = [];
  for (const name of names) {
    if (!isPythonPycLoaderFilename(name)) continue;
    const absPath = join(directory, name);
    const source = readSafetensorsLoaderCandidateSource(absPath);
    if (source === null) continue;
    out.push({ absPath, name, source });
  }
  return out;
}

/**
 * Discover the unique safe Python loader for `safetensorsBasename` in the
 * first search directory that yields a selection. Later directories are
 * not consulted once one directory produces a hit (output dir wins over
 * source).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function discoverPythonSafetensorsLoader(options: {
  readonly safetensorsBasename: string;
  readonly searchDirectories: readonly string[];
}): DiscoveredPythonSafetensorsLoader | null {
  const seen = new Set<string>();
  for (const directory of options.searchDirectories) {
    if (typeof directory !== "string" || directory.length === 0) continue;
    if (seen.has(directory)) continue;
    seen.add(directory);
    const candidates = listSameDirPythonSafetensorsLoaderCandidates(directory);
    const selected = selectPythonSafetensorsLoader(
      options.safetensorsBasename,
      candidates,
    );
    if (!selected) continue;
    const hit = candidates.find((c) => c.name === selected || c.absPath === selected);
    if (hit) return hit;
  }
  return null;
}

/**
 * True when a same-directory Python file already carries the Safetensors
 * load-time hook bound to this file's code identity (used by defenseScore
 * honesty).
 *
 * DEFENSIVE ONLY.
 */
export function isSafetensorsSidecarLoaderHookWired(options: {
  readonly safetensorsBytes: Uint8Array;
  readonly safetensorsPath: string;
}): boolean {
  const identity = computeSafetensorsSidecarCodeIdentity(options.safetensorsBytes);
  const directories = listSafetensorsLoaderSearchDirectories(options.safetensorsPath);
  return directories.some((directory) =>
    listSameDirPythonSafetensorsLoaderCandidates(directory).some(
      (c) =>
        c.source.includes(SAFETENSORS_SIDECAR_LOADER_MARKER) &&
        c.source.includes(identity),
    ),
  );
}

/** Relative path from a loader file's directory to the protected `.safetensors`. */
export function relativeSafetensorsPathFromLoader(
  loaderPath: string,
  safetensorsPath: string,
): string {
  const rel = relative(dirname(loaderPath), safetensorsPath).split("\\").join("/");
  return rel.length === 0 ? basename(safetensorsPath) : rel;
}


// ---------------------------------------------------------------------------
// DEX string-pool sidecar note (host-verify; existing string indices + insn
// bytes stay unchanged; official DEX remains loader-valid)
// ---------------------------------------------------------------------------

export const DEX_SIDECAR_METADATA_KEY = "bla.sidecar.v1" as const;
export const DEX_SIDECAR_METADATA_KIND = "dex-string-pool-note" as const;

export interface DexSidecarMetadataNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof DEX_SIDECAR_METADATA_KIND;
  readonly key: typeof DEX_SIDECAR_METADATA_KEY;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarDexInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarDexInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof DEX_SIDECAR_METADATA_KIND;
  readonly key: typeof DEX_SIDECAR_METADATA_KEY;
  readonly noteJson: string;
  readonly note: DexSidecarMetadataNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
  /** Pool string body (before sort-last U+FFFF prefix). */
  readonly stringBody: string;
}

/**
 * Build a DEX string-pool note (`bla.sidecar.v1=<json>`) that carries the
 * sidecar binding digest. The note is planted as an unreferenced, sort-last
 * string so existing string indices and instruction bytes stay unchanged.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarDexStringPoolNote(
  options: SidecarDexInjectOptions,
): SidecarDexInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: DexSidecarMetadataNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: DEX_SIDECAR_METADATA_KIND,
    key: DEX_SIDECAR_METADATA_KEY,
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
    kind: DEX_SIDECAR_METADATA_KIND,
    key: DEX_SIDECAR_METADATA_KEY,
    noteJson,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
    stringBody: `${DEX_SIDECAR_STRING_KEY}${noteJson}`,
  };
}

export interface SidecarDexBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarDexInjectResult;
  readonly bytes: Buffer;
}

/**
 * Plan + bind for a DEX entry: compute the offline digest from in-memory
 * sidecar bytes and return a bound plan plus the rewritten DEX with an
 * unreferenced sort-last string-pool note. Uses sidecars-mode digest so
 * planting the note does not invalidate H. Existing string indices and
 * instruction bytes stay unchanged.
 */
export function bindDexSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarDexBindResult {
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
  if (options.sidecarBytes.length !== plan.sidecarPaths.length) {
    throw new Error("sidecarBytes length must match sidecarPaths length");
  }
  const stripped = dropDexSidecarStrings(options.entryBytes);
  if (!stripped) {
    throw new Error("entryBytes is not a structurally rewritable DEX container");
  }
  const layout = parseDexLayout(stripped);
  if (!layout) {
    throw new Error("entryBytes is not a structurally rewritable DEX container");
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
  const inject = generateSidecarDexStringPoolNote({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const chosen = chooseSortLastDexString(
    layout.strings.map((s) => s.text),
    inject.stringBody,
  );
  const bytes = rebuildDex(layout, { appendStrings: [chosen] });
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "dex-string-pool-note",
    status: "bound",
    note: "Bound — DEX bla.sidecar.v1 string-pool note planted; ship sidecars alongside and verify via verifyDexSidecarStringPoolNote. Host verify fails closed on strip/alter; ART/Dalvik ignore the unreferenced string (no process-start fail until a load-time hook lands). Existing string indices and instruction bytes stay unchanged.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    bytes,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + DEX entry bytes, produce
 * the strip⇒fail-bound entry. Returns null when there are no sidecars to bind
 * or when the DEX is not structurally rewritable (header-only stubs).
 */
export function entangleDexEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
}): SidecarDexBindResult | null {
  if (options.sidecars.length === 0) return null;
  if (!parseDexLayout(options.entryBytes)) {
    return null;
  }
  return bindDexSidecarEntanglement({
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

export interface DexSidecarVerifyOptions {
  readonly entryBytes: Uint8Array;
  readonly baseDir?: string;
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface DexSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: DexSidecarMetadataNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

function parseDexSidecarNoteJson(jsonText: string): DexSidecarMetadataNote | null {
  try {
    const parsed = JSON.parse(jsonText) as DexSidecarMetadataNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.kind !== DEX_SIDECAR_METADATA_KIND ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return null;
    }
    return {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      kind: DEX_SIDECAR_METADATA_KIND,
      key: DEX_SIDECAR_METADATA_KEY,
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
 * Extract the `bla.sidecar.v1=` string-pool note from a DEX buffer.
 * Returns null when the note is absent or not well-formed.
 */
export function extractDexSidecarStringPoolNote(
  entryBytes: Uint8Array,
): DexSidecarMetadataNote | null {
  const layout = parseDexLayout(entryBytes);
  if (!layout) return null;
  for (let i = layout.strings.length - 1; i >= 0; i--) {
    const body = stripDexSidecarPrefix(layout.strings[i]!.text);
    if (body === null) continue;
    const note = parseDexSidecarNoteJson(body);
    if (note) return note;
  }
  return null;
}

/**
 * Remove a previously planted DEX sidecar string-pool note (idempotent).
 * Existing string indices and instruction bytes stay unchanged.
 */
export function stripDexSidecarStringPoolNote(entryBytes: Uint8Array): Buffer {
  return dropDexSidecarStrings(entryBytes) ?? Buffer.from(entryBytes);
}

/**
 * Host-side strip⇒fail check for DEX string-pool notes: extract the note,
 * re-hash sibling sidecar bytes with the same layout as
 * `computeSidecarBindingDigest` (sidecars mode), and compare to the embedded
 * digest. Missing note / missing sibling / altered sibling ⇒ ok:false.
 *
 * DEFENSIVE ONLY. ART/Dalvik ignore the unreferenced pool string, so strip
 * does not break load until a load-time hook lands (same honesty bar as
 * GGUF / Safetensors / .pyc host-verify notes).
 */
export function verifyDexSidecarStringPoolNote(
  options: DexSidecarVerifyOptions,
): DexSidecarVerifyResult {
  const note = extractDexSidecarStringPoolNote(options.entryBytes);
  if (!note) {
    return { ok: false, reason: "dex sidecar string-pool note missing" };
  }
  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "fail",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const measured = computeSidecarBindingDigest(
    { pathLabel: note.entryPath, bytes: options.entryBytes },
    collected.parts,
    note.seedTag,
    "sidecars",
  );
  if (measured.hex !== note.digest) {
    return {
      ok: false,
      reason: "dex sidecar digest mismatch",
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

export const SQLITE_SIDECAR_METADATA_KEY = SQLITE_SIDECAR_NOTE_COLUMN;
export const SQLITE_SIDECAR_METADATA_KIND = "sqlite-schema-comment" as const;
export { SQLITE_SIDECAR_VIEW_NAME, computeSqliteSidecarCodeIdentity };

export interface SqliteSidecarMetadataNote {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof SQLITE_SIDECAR_METADATA_KIND;
  readonly key: typeof SQLITE_SIDECAR_METADATA_KEY;
  readonly digest: string;
  readonly seedTag: string;
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly softFold: boolean;
  readonly mode: "sidecars";
}

export interface SidecarSqliteInjectOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  readonly expectedHex: string;
  readonly softFold?: boolean;
}

export interface SidecarSqliteInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly kind: typeof SQLITE_SIDECAR_METADATA_KIND;
  readonly key: typeof SQLITE_SIDECAR_METADATA_KEY;
  readonly noteJson: string;
  readonly note: SqliteSidecarMetadataNote;
  readonly expectedHex: string;
  readonly expectedU32: number;
  readonly softFold: boolean;
  readonly sidecarCount: number;
}

/**
 * Build a SQLite schema-comment / reserved-VIEW metadata note
 * (`bla.sidecar.v1` JSON) that carries the sidecar binding digest.
 * The note is planted as an unused `bla_sidecar_v1` VIEW (`SELECT … WHERE 0`)
 * so user tables, rows, query results, WAL/FK behavior, and
 * application_id / user_version stay unchanged.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarSqliteSchemaComment(
  options: SidecarSqliteInjectOptions,
): SidecarSqliteInjectResult {
  const sidecars = (options.sidecarPaths ?? []).filter((p) => p.length > 0);
  const seedTag = options.seedTag ?? "bla-sidecar-v1";
  const softFold = options.softFold === true;
  const expectedHex = options.expectedHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    throw new Error("expectedHex must be a 64-char lowercase hex SHA-256 digest");
  }
  const expectedU32 = parseInt(expectedHex.slice(0, 8), 16) >>> 0;
  const note: SqliteSidecarMetadataNote = {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    kind: SQLITE_SIDECAR_METADATA_KIND,
    key: SQLITE_SIDECAR_METADATA_KEY,
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
    kind: SQLITE_SIDECAR_METADATA_KIND,
    key: SQLITE_SIDECAR_METADATA_KEY,
    noteJson,
    note,
    expectedHex,
    expectedU32,
    softFold,
    sidecarCount: sidecars.length,
  };
}

export interface SidecarSqliteBindResult {
  readonly plan: SidecarEntanglePlan;
  readonly digest: SidecarBindingDigest;
  readonly inject: SidecarSqliteInjectResult;
  readonly bytes: Buffer;
}

/**
 * Plan + bind for a SQLite entry: compute the offline digest from in-memory
 * sidecar bytes and return a bound plan plus the rewritten DB with a
 * reserved unused VIEW schema-comment note. Uses sidecars-mode digest so
 * planting the note does not invalidate H. User tables, rows, query results,
 * WAL/FK, and application_id / user_version stay unchanged.
 */
export function bindSqliteSidecarEntanglement(
  options: SidecarEntanglePlanOptions & {
    readonly entryBytes: Uint8Array;
    readonly sidecarBytes: readonly Uint8Array[];
  },
): SidecarSqliteBindResult {
  const plan = planSidecarEntanglement(withBoundFileBytes(options));
  if (options.sidecarBytes.length !== plan.sidecarPaths.length) {
    throw new Error("sidecarBytes length must match sidecarPaths length");
  }
  const stripped = dropSqliteSidecarSchemaView(options.entryBytes);
  if (!canRewriteSqliteSidecar(stripped)) {
    throw new Error("entryBytes is not a structurally rewritable SQLite database");
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
  const inject = generateSidecarSqliteSchemaComment({
    entryPath: options.entryPath,
    sidecarPaths: plan.sidecarPaths,
    seedTag: plan.seedTag,
    expectedHex: digest.hex,
    softFold: plan.softFold,
  });
  const bytes = plantSqliteSidecarSchemaComment(stripped, inject.noteJson);
  const boundPlan: SidecarEntanglePlan = {
    ...plan,
    entryHookKind: "sqlite-schema-comment",
    status: "bound",
    note: "Bound — SQLite bla.sidecar.v1 schema-comment view planted; ship sidecars alongside and verify via verifySqliteSidecarSchemaComment. Host verify fails closed on strip/alter; SQLite ignores the unused WHERE 0 view unless a same-directory Python load-time hook is auto-wired. User tables, rows, query results, WAL/FK, and application_id/user_version stay unchanged.",
  };
  return {
    plan: boundPlan,
    digest,
    inject,
    bytes,
  };
}

/**
 * Convenience: given final on-disk sidecar bytes + SQLite entry bytes, produce
 * the strip⇒fail-bound database. Returns null when there are no sidecars to
 * bind or when the buffer is not a standalone rewritable SQLite snapshot.
 */
export function entangleSqliteEntryWithSidecars(options: {
  readonly entryPath: string;
  readonly entryBytes: Uint8Array;
  readonly sidecars: readonly SidecarBindingPart[];
  readonly seedTag?: string;
  readonly softFold?: boolean;
  readonly allowEmptySidecars?: boolean;
}): SidecarSqliteBindResult | null {
  if (options.sidecars.length === 0 && options.allowEmptySidecars !== true) return null;
  if (!canRewriteSqliteSidecar(options.entryBytes)) {
    return null;
  }
  return bindSqliteSidecarEntanglement({
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

export interface SqliteSidecarVerifyOptions {
  readonly entryBytes: Uint8Array;
  readonly baseDir?: string;
  readonly sidecarBytes?: Readonly<Record<string, Uint8Array>>;
}

export interface SqliteSidecarVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly note?: SqliteSidecarMetadataNote;
  readonly expectedHex?: string;
  readonly measuredHex?: string;
  readonly measuredU32?: number;
  readonly softFold?: boolean;
}

function parseSqliteSidecarNoteJson(jsonText: string): SqliteSidecarMetadataNote | null {
  try {
    const parsed = JSON.parse(jsonText) as SqliteSidecarMetadataNote;
    if (
      parsed.schema !== SIDECAR_ENTANGLE_SCHEMA ||
      parsed.kind !== SQLITE_SIDECAR_METADATA_KIND ||
      typeof parsed.digest !== "string" ||
      !/^[0-9a-f]{64}$/i.test(parsed.digest)
    ) {
      return null;
    }
    return {
      schema: SIDECAR_ENTANGLE_SCHEMA,
      kind: SQLITE_SIDECAR_METADATA_KIND,
      key: SQLITE_SIDECAR_METADATA_KEY,
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
 * Extract the `bla.sidecar.v1` schema-comment note from a SQLite buffer.
 * Returns null when the reserved view is absent or not well-formed.
 */
export function extractSqliteSidecarSchemaComment(
  entryBytes: Uint8Array,
): SqliteSidecarMetadataNote | null {
  const json = extractSqliteSidecarSchemaCommentJson(entryBytes);
  if (json === null) return null;
  return parseSqliteSidecarNoteJson(json);
}

/**
 * Remove a previously planted SQLite sidecar schema-comment view (idempotent).
 * User tables, rows, and identity pragmas stay unchanged.
 */
export function stripSqliteSidecarSchemaComment(entryBytes: Uint8Array): Buffer {
  return dropSqliteSidecarSchemaView(entryBytes);
}

/**
 * Host-side strip⇒fail check for SQLite schema-comment notes: extract the
 * note, re-hash sibling sidecar bytes with the same layout as
 * `computeSidecarBindingDigest` (sidecars mode), and compare to the embedded
 * digest. Missing note / missing sibling / altered sibling ⇒ ok:false.
 *
 * DEFENSIVE ONLY. SQLite ignores the unused WHERE 0 view, so strip does not
 * break load unless a same-directory Python load-time hook is auto-wired (same
 * honesty bar as DEX / GGUF / Safetensors / .pyc host-verify notes).
 */
export function verifySqliteSidecarSchemaComment(
  options: SqliteSidecarVerifyOptions,
): SqliteSidecarVerifyResult {
  const note = extractSqliteSidecarSchemaComment(options.entryBytes);
  if (!note) {
    return { ok: false, reason: "sqlite sidecar schema-comment note missing" };
  }
  const collected = collectSidecarVerifyParts({
    sidecarPaths: note.sidecarPaths,
    overrides: options.sidecarBytes,
    baseDir: options.baseDir,
    requireBaseDir: true,
    missingPolicy: "fail",
  });
  if (!collected.ok) {
    return {
      ok: false,
      reason: collected.reason,
      note,
      expectedHex: note.digest,
      softFold: note.softFold,
    };
  }
  const measured = computeSidecarBindingDigest(
    { pathLabel: note.entryPath, bytes: options.entryBytes },
    collected.parts,
    note.seedTag,
    "sidecars",
  );
  if (measured.hex !== note.digest) {
    return {
      ok: false,
      reason: "sqlite sidecar digest mismatch",
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

/**
 * Idempotence marker inserted with the optional SQLite load-time hook.
 */
export const SQLITE_SIDECAR_LOADER_MARKER =
  "_installSqliteSidecarLoaderHook" as const;

export interface SidecarSqliteLoaderInjectOptions {
  /**
   * SHA-256 hex (or list) of the protected SQLite database's logical
   * identity (`computeSqliteSidecarCodeIdentity`). Databases whose
   * identity matches MUST present a valid `bla.sidecar.v1` schema-comment
   * view; other SQLite files pass through to later path attempts.
   */
  readonly codeIdentityHex: string | readonly string[];
  /**
   * Paths to the protected `.sqlite` / `.sqlite3` / `.db`, relative to
   * the loader file's directory (`Path(__file__).resolve().parent`).
   * Sidecar paths inside the note are resolved against the database
   * file's own directory.
   */
  readonly sqliteRelPaths: readonly string[];
  readonly bindingName?: string;
}

export interface SidecarSqliteLoaderInjectResult {
  readonly schema: typeof SIDECAR_ENTANGLE_SCHEMA;
  readonly preamble: string;
  readonly bindingName: string;
  readonly codeIdentityHexes: readonly string[];
  readonly sqliteRelPaths: readonly string[];
}

function normalizeSqliteCodeIdentity(hex: string): string {
  const value = hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("codeIdentityHex must be a 64-char lowercase hex SHA-256 digest");
  }
  return value;
}

/**
 * Emit a self-contained host Python snippet that, at import time of the
 * loader it is inserted into, opens the sibling SQLite database read-only
 * and, when the logical identity matches, verifies the `bla.sidecar.v1`
 * schema-comment view and sibling sidecar digest. Missing targets or siblings
 * and mismatches fail closed.
 *
 * The hook does not rewrite the database (user tables, rows, query
 * results, WAL/FK, and application_id / user_version stay unchanged; the
 * existing unused `bla_sidecar_v1` WHERE 0 view is the only SQLite
 * mutation, and it is planted separately). It is host-opt-in:
 * `protectTarget` / `hardenProject` auto-wire it only into a known
 * same-directory Python loader (`loader.py`, `__init__.py`,
 * `__main__.py`) that already mentions the database basename — never a
 * test / already-entangled / self-seal file. Only then is
 * `sqlite-sidecar-entangle` recorded and
 * `sqlite-sidecar-host-verify-only` cleared.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function generateSidecarSqliteLoaderSnippet(
  options: SidecarSqliteLoaderInjectOptions,
): SidecarSqliteLoaderInjectResult {
  const raw = options.codeIdentityHex;
  const list = (Array.isArray(raw) ? raw : [raw]).map((hex) =>
    normalizeSqliteCodeIdentity(hex),
  );
  if (list.length === 0) {
    throw new Error("codeIdentityHex must contain at least one digest");
  }
  const relPaths = (options.sqliteRelPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (relPaths.length === 0) {
    throw new Error("sqliteRelPaths must contain at least one path");
  }
  const tag = list[0]!.slice(0, 8);
  const bindingName =
    options.bindingName ?? `${SQLITE_SIDECAR_LOADER_MARKER}_${tag}`;
  assertPythonBindingName(bindingName);
  const idsLiteral = JSON.stringify(list);
  const pathsLiteral = JSON.stringify(relPaths);
  const keyLiteral = JSON.stringify(SQLITE_SIDECAR_METADATA_KEY);
  const schemaLiteral = JSON.stringify(SIDECAR_ENTANGLE_SCHEMA);
  const kindLiteral = JSON.stringify(SQLITE_SIDECAR_METADATA_KIND);
  const viewLiteral = JSON.stringify(SQLITE_SIDECAR_VIEW_NAME);
  // The view SQL uses: AS "bla.sidecar.v1"
  const asMarker = `AS "${SQLITE_SIDECAR_NOTE_COLUMN.replace(/"/g, '""')}"`;
  const asMarkerLiteral = JSON.stringify(asMarker);
  const identPrefixLiteral = JSON.stringify("bla.sqlite.sidecar.identity.v1\0");

  const lines: string[] = [];
  lines.push(`# ${SQLITE_SIDECAR_LOADER_MARKER}`);
  lines.push(`def ${bindingName}():`);
  lines.push(`    import hashlib as _sc_hashlib_${tag}`);
  lines.push(`    import json as _sc_json_${tag}`);
  lines.push(`    import os as _sc_os_${tag}`);
  lines.push(`    import pathlib as _sc_pathlib_${tag}`);
  lines.push(`    import sqlite3 as _sc_sqlite3_${tag}`);
  lines.push(`    import struct as _sc_struct_${tag}`);
  lines.push(`    import tempfile as _sc_tempfile_${tag}`);
  lines.push(`    _sc_ids_${tag} = ${idsLiteral}`);
  lines.push(`    _sc_idset_${tag} = set(_sc_ids_${tag})`);
  lines.push(`    _sc_paths_${tag} = ${pathsLiteral}`);
  lines.push(`    _sc_key_${tag} = ${keyLiteral}`);
  lines.push(`    _sc_schema_${tag} = ${schemaLiteral}`);
  lines.push(`    _sc_kind_${tag} = ${kindLiteral}`);
  lines.push(`    _sc_view_${tag} = ${viewLiteral}`);
  lines.push(`    _sc_as_${tag} = ${asMarkerLiteral}`);
  lines.push(`    _sc_prefix_${tag} = ${identPrefixLiteral}`);
  lines.push(`    _sc_base_${tag} = _sc_pathlib_${tag}.Path(__file__).resolve().parent`);
  lines.push(`    def _sc_qid_${tag}(_sc_n_${tag}):`);
  lines.push(`        return '"' + str(_sc_n_${tag}).replace('"', '""') + '"'`);
  lines.push(`    def _sc_pref_${tag}(_sc_h_${tag}, _sc_s_${tag}):`);
  lines.push(`        _sc_b_${tag} = _sc_s_${tag}.encode("utf-8")`);
  lines.push(`        _sc_h_${tag}.update(len(_sc_b_${tag}).to_bytes(4, "big"))`);
  lines.push(`        _sc_h_${tag}.update(_sc_b_${tag})`);
  lines.push(`    def _sc_val_${tag}(_sc_h_${tag}, _sc_typ_${tag}, _sc_v_${tag}):`);
  lines.push(`        if _sc_typ_${tag} == "null" or _sc_v_${tag} is None:`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`            return`);
  lines.push(`        if _sc_typ_${tag} == "integer":`);
  lines.push(`            _sc_h_${tag}.update(b"\\x01")`);
  lines.push(`            _sc_h_${tag}.update(int(_sc_v_${tag}).to_bytes(8, "big", signed=True))`);
  lines.push(`            return`);
  lines.push(`        if _sc_typ_${tag} == "real":`);
  lines.push(`            _sc_h_${tag}.update(b"\\x02")`);
  lines.push(`            _sc_h_${tag}.update(_sc_struct_${tag}.pack(">d", float(_sc_v_${tag})))`);
  lines.push(`            return`);
  lines.push(`        if _sc_typ_${tag} == "text":`);
  lines.push(`            _sc_b_${tag} = _sc_v_${tag}.encode("utf-8") if isinstance(_sc_v_${tag}, str) else bytes(_sc_v_${tag})`);
  lines.push(`            _sc_h_${tag}.update(b"\\x03")`);
  lines.push(`            _sc_h_${tag}.update(len(_sc_b_${tag}).to_bytes(4, "big"))`);
  lines.push(`            _sc_h_${tag}.update(_sc_b_${tag})`);
  lines.push(`            return`);
  lines.push(`        if _sc_typ_${tag} == "blob":`);
  lines.push(`            _sc_b_${tag} = bytes(_sc_v_${tag})`);
  lines.push(`            _sc_h_${tag}.update(b"\\x04")`);
  lines.push(`            _sc_h_${tag}.update(len(_sc_b_${tag}).to_bytes(4, "big"))`);
  lines.push(`            _sc_h_${tag}.update(_sc_b_${tag})`);
  lines.push(`            return`);
  lines.push(`        raise RuntimeError("integrity binding mismatch")`);
  lines.push(`    def _sc_parse_view_${tag}(_sc_sql_${tag}):`);
  lines.push(`        if not isinstance(_sc_sql_${tag}, str) or len(_sc_sql_${tag}) == 0:`);
  lines.push(`            return None`);
  lines.push(`        import re as _sc_re_${tag}`);
  lines.push(`        _sc_sel_${tag} = _sc_re_${tag}.search(r"SELECT\\s+", _sc_sql_${tag}, _sc_re_${tag}.I)`);
  lines.push(`        if _sc_sel_${tag} is None:`);
  lines.push(`            return None`);
  lines.push(`        _sc_asidx_${tag} = _sc_sql_${tag}.find(_sc_as_${tag}, _sc_sel_${tag}.start())`);
  lines.push(`        if _sc_asidx_${tag} < 0:`);
  lines.push(`            return None`);
  lines.push(`        _sc_end_${tag} = _sc_asidx_${tag} - 1`);
  lines.push(`        while _sc_end_${tag} >= 0 and _sc_sql_${tag}[_sc_end_${tag}].isspace():`);
  lines.push(`            _sc_end_${tag} -= 1`);
  lines.push(`        if _sc_end_${tag} < 1 or _sc_sql_${tag}[_sc_end_${tag}] != "'":`);
  lines.push(`            return None`);
  lines.push(`        _sc_start_${tag} = _sc_end_${tag} - 1`);
  lines.push(`        while _sc_start_${tag} >= 0:`);
  lines.push(`            if _sc_sql_${tag}[_sc_start_${tag}] == "'":`);
  lines.push(`                _sc_quotes_${tag} = 1`);
  lines.push(`                _sc_k_${tag} = _sc_start_${tag}`);
  lines.push(`                while _sc_k_${tag} - 1 >= 0 and _sc_sql_${tag}[_sc_k_${tag} - 1] == "'":`);
  lines.push(`                    _sc_quotes_${tag} += 1`);
  lines.push(`                    _sc_k_${tag} -= 1`);
  lines.push(`                if _sc_quotes_${tag} % 2 == 1:`);
  lines.push(`                    return _sc_sql_${tag}[_sc_start_${tag} + 1:_sc_end_${tag}].replace("''", "'")`);
  lines.push(`                _sc_start_${tag} = _sc_k_${tag} - 1`);
  lines.push(`                continue`);
  lines.push(`            _sc_start_${tag} -= 1`);
  lines.push(`        return None`);
  lines.push(`    def _sc_identity_${tag}(_sc_buf_${tag}):`);
  lines.push(`        if len(_sc_buf_${tag}) < 100 or _sc_buf_${tag}[0:16] != b"SQLite format 3\\x00":`);
  lines.push(`            return _sc_hashlib_${tag}.sha256(_sc_buf_${tag}).hexdigest()`);
  lines.push(`        _sc_app_${tag} = int.from_bytes(_sc_buf_${tag}[68:72], "big")`);
  lines.push(`        _sc_uver_${tag} = int.from_bytes(_sc_buf_${tag}[60:64], "big")`);
  lines.push(`        _sc_fd_${tag} = -1`);
  lines.push(`        _sc_tmp_${tag} = None`);
  lines.push(`        _sc_conn_${tag} = None`);
  lines.push(`        try:`);
  lines.push(`            _sc_fd_${tag}, _sc_tmp_${tag} = _sc_tempfile_${tag}.mkstemp(suffix=".sqlite")`);
  lines.push(`            _sc_os_${tag}.write(_sc_fd_${tag}, _sc_buf_${tag})`);
  lines.push(`            _sc_os_${tag}.close(_sc_fd_${tag})`);
  lines.push(`            _sc_fd_${tag} = -1`);
  lines.push(`            _sc_conn_${tag} = _sc_sqlite3_${tag}.connect("file:" + _sc_tmp_${tag} + "?mode=ro", uri=True)`);
  lines.push(`            _sc_h_${tag} = _sc_hashlib_${tag}.sha256()`);
  lines.push(`            _sc_h_${tag}.update(_sc_prefix_${tag}.encode("utf-8") if isinstance(_sc_prefix_${tag}, str) else _sc_prefix_${tag})`);
  lines.push(`            _sc_h_${tag}.update(_sc_app_${tag}.to_bytes(4, "big") + _sc_uver_${tag}.to_bytes(4, "big"))`);
  lines.push(`            _sc_cur_${tag} = _sc_conn_${tag}.execute(`);
  lines.push(`                "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name IS NOT NULL AND name != ? AND name NOT LIKE 'sqlite_%' ORDER BY type, name",`);
  lines.push(`                (_sc_view_${tag},),`);
  lines.push(`            )`);
  lines.push(`            for _sc_row_${tag} in _sc_cur_${tag}:`);
  lines.push(`                _sc_pref_${tag}(_sc_h_${tag}, _sc_row_${tag}[0] or "")`);
  lines.push(`                _sc_pref_${tag}(_sc_h_${tag}, _sc_row_${tag}[1] or "")`);
  lines.push(`                _sc_pref_${tag}(_sc_h_${tag}, _sc_row_${tag}[2] or "")`);
  lines.push(`                _sc_pref_${tag}(_sc_h_${tag}, _sc_row_${tag}[3] or "")`);
  lines.push(`            _sc_h_${tag}.update(b"\\xff")`);
  lines.push(`            _sc_tables_${tag} = list(_sc_conn_${tag}.execute(`);
  lines.push(`                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != ? ORDER BY name",`);
  lines.push(`                (_sc_view_${tag},),`);
  lines.push(`            ))`);
  lines.push(`            for (_sc_tname_${tag},) in _sc_tables_${tag}:`);
  lines.push(`                _sc_pref_${tag}(_sc_h_${tag}, _sc_tname_${tag})`);
  lines.push(`                _sc_info_${tag} = list(_sc_conn_${tag}.execute("PRAGMA table_xinfo(" + _sc_qid_${tag}(_sc_tname_${tag}) + ")"))`);
  lines.push(`                _sc_stored_${tag} = [str(_sc_col_${tag}[1]) for _sc_col_${tag} in _sc_info_${tag} if int(_sc_col_${tag}[6]) == 0]`);
  lines.push(`                _sc_pref_${tag}(_sc_h_${tag}, "\\x00".join(_sc_stored_${tag}))`);
  lines.push(`                if len(_sc_stored_${tag}) == 0:`);
  lines.push(`                    _sc_h_${tag}.update(b"\\xfe")`);
  lines.push(`                    continue`);
  lines.push(`                _sc_sellist_${tag} = ", ".join(`);
  lines.push(`                    "typeof(" + _sc_qid_${tag}(_sc_c_${tag}) + ") AS " + _sc_qid_${tag}("t" + str(_sc_i_${tag})) + ", " + _sc_qid_${tag}(_sc_c_${tag}) + " AS " + _sc_qid_${tag}("v" + str(_sc_i_${tag}))`);
  lines.push(`                    for _sc_i_${tag}, _sc_c_${tag} in enumerate(_sc_stored_${tag})`);
  lines.push(`                )`);
  lines.push(`                _sc_tsql_${tag} = "SELECT " + _sc_sellist_${tag} + " FROM " + _sc_qid_${tag}(_sc_tname_${tag})`);
  lines.push(`                try:`);
  lines.push(`                    _sc_rows_${tag} = list(_sc_conn_${tag}.execute(_sc_tsql_${tag} + " ORDER BY rowid"))`);
  lines.push(`                except Exception:`);
  lines.push(`                    _sc_rows_${tag} = list(_sc_conn_${tag}.execute(_sc_tsql_${tag} + " ORDER BY " + ", ".join(_sc_qid_${tag}(_sc_c_${tag}) for _sc_c_${tag} in _sc_stored_${tag})))`);
  lines.push(`                for _sc_row_${tag} in _sc_rows_${tag}:`);
  lines.push(`                    for _sc_i_${tag} in range(len(_sc_stored_${tag})):`);
  lines.push(`                        _sc_val_${tag}(_sc_h_${tag}, str(_sc_row_${tag}[_sc_i_${tag} * 2] or "null"), _sc_row_${tag}[_sc_i_${tag} * 2 + 1])`);
  lines.push(`                _sc_h_${tag}.update(b"\\xfe")`);
  lines.push(`            return _sc_h_${tag}.hexdigest()`);
  lines.push(`        except Exception:`);
  lines.push(`            return _sc_hashlib_${tag}.sha256(_sc_buf_${tag}).hexdigest()`);
  lines.push(`        finally:`);
  lines.push(`            if _sc_conn_${tag} is not None:`);
  lines.push(`                try:`);
  lines.push(`                    _sc_conn_${tag}.close()`);
  lines.push(`                except Exception:`);
  lines.push(`                    pass`);
  lines.push(`            if _sc_fd_${tag} >= 0:`);
  lines.push(`                try:`);
  lines.push(`                    _sc_os_${tag}.close(_sc_fd_${tag})`);
  lines.push(`                except Exception:`);
  lines.push(`                    pass`);
  lines.push(`            if _sc_tmp_${tag}:`);
  lines.push(`                try:`);
  lines.push(`                    _sc_os_${tag}.unlink(_sc_tmp_${tag})`);
  lines.push(`                except Exception:`);
  lines.push(`                    pass`);
  lines.push(`    def _sc_extract_${tag}(_sc_buf_${tag}):`);
  lines.push(`        if len(_sc_buf_${tag}) < 100 or _sc_buf_${tag}[0:16] != b"SQLite format 3\\x00":`);
  lines.push(`            return None`);
  lines.push(`        _sc_fd_${tag} = -1`);
  lines.push(`        _sc_tmp_${tag} = None`);
  lines.push(`        _sc_conn_${tag} = None`);
  lines.push(`        try:`);
  lines.push(`            _sc_fd_${tag}, _sc_tmp_${tag} = _sc_tempfile_${tag}.mkstemp(suffix=".sqlite")`);
  lines.push(`            _sc_os_${tag}.write(_sc_fd_${tag}, _sc_buf_${tag})`);
  lines.push(`            _sc_os_${tag}.close(_sc_fd_${tag})`);
  lines.push(`            _sc_fd_${tag} = -1`);
  lines.push(`            _sc_conn_${tag} = _sc_sqlite3_${tag}.connect("file:" + _sc_tmp_${tag} + "?mode=ro", uri=True)`);
  lines.push(`            _sc_row_${tag} = _sc_conn_${tag}.execute(`);
  lines.push(`                "SELECT sql FROM sqlite_schema WHERE type = 'view' AND name = ?",`);
  lines.push(`                (_sc_view_${tag},),`);
  lines.push(`            ).fetchone()`);
  lines.push(`            if _sc_row_${tag} is None or not isinstance(_sc_row_${tag}[0], str):`);
  lines.push(`                return None`);
  lines.push(`            _sc_rawnote_${tag} = _sc_parse_view_${tag}(_sc_row_${tag}[0])`);
  lines.push(`            if not isinstance(_sc_rawnote_${tag}, str) or len(_sc_rawnote_${tag}) == 0:`);
  lines.push(`                return None`);
  lines.push(`            try:`);
  lines.push(`                _sc_obj_${tag} = _sc_json_${tag}.loads(_sc_rawnote_${tag})`);
  lines.push(`            except Exception:`);
  lines.push(`                return None`);
  lines.push(`            if _sc_obj_${tag}.get("schema") != _sc_schema_${tag} or _sc_obj_${tag}.get("kind") != _sc_kind_${tag}:`);
  lines.push(`                return None`);
  lines.push(`            _sc_dig_${tag} = _sc_obj_${tag}.get("digest")`);
  lines.push(`            if not isinstance(_sc_dig_${tag}, str) or len(_sc_dig_${tag}) != 64:`);
  lines.push(`                return None`);
  lines.push(`            return _sc_obj_${tag}`);
  lines.push(`        except Exception:`);
  lines.push(`            return None`);
  lines.push(`        finally:`);
  lines.push(`            if _sc_conn_${tag} is not None:`);
  lines.push(`                try:`);
  lines.push(`                    _sc_conn_${tag}.close()`);
  lines.push(`                except Exception:`);
  lines.push(`                    pass`);
  lines.push(`            if _sc_fd_${tag} >= 0:`);
  lines.push(`                try:`);
  lines.push(`                    _sc_os_${tag}.close(_sc_fd_${tag})`);
  lines.push(`                except Exception:`);
  lines.push(`                    pass`);
  lines.push(`            if _sc_tmp_${tag}:`);
  lines.push(`                try:`);
  lines.push(`                    _sc_os_${tag}.unlink(_sc_tmp_${tag})`);
  lines.push(`                except Exception:`);
  lines.push(`                    pass`);
  lines.push(`    def _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}):`);
  lines.push(`        _sc_h_${tag} = _sc_hashlib_${tag}.sha256()`);
  lines.push(`        _sc_h_${tag}.update(_sc_entry_${tag}.encode("utf-8"))`);
  lines.push(`        _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        for _sc_sp_${tag}, _sc_data_${tag} in _sc_parts_${tag}:`);
  lines.push(`            _sc_h_${tag}.update(_sc_sp_${tag}.encode("utf-8"))`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`            _sc_h_${tag}.update(_sc_data_${tag})`);
  lines.push(`            _sc_h_${tag}.update(b"\\x00")`);
  lines.push(`        _sc_h_${tag}.update(_sc_seed_${tag}.encode("utf-8"))`);
  lines.push(`        return _sc_h_${tag}.hexdigest()`);
  lines.push(`    for _sc_rel_${tag} in _sc_paths_${tag}:`);
  lines.push(`        _sc_path_${tag} = _sc_pathlib_${tag}.Path(_sc_rel_${tag})`);
  lines.push(`        if not _sc_path_${tag}.is_absolute():`);
  lines.push(`            _sc_path_${tag} = _sc_base_${tag} / _sc_rel_${tag}`);
  lines.push(`        try:`);
  lines.push(`            _sc_raw_${tag} = _sc_path_${tag}.read_bytes()`);
  lines.push(`        except Exception:`);
  lines.push(`            continue`);
  lines.push(`        _sc_ident_${tag} = _sc_identity_${tag}(_sc_raw_${tag})`);
  lines.push(`        if _sc_ident_${tag} not in _sc_idset_${tag}:`);
  lines.push(`            continue`);
  lines.push(`        _sc_note_${tag} = _sc_extract_${tag}(_sc_raw_${tag})`);
  lines.push(`        if _sc_note_${tag} is None:`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        _sc_parts_${tag} = []`);
  lines.push(`        _sc_dir_${tag} = _sc_path_${tag}.parent`);
  lines.push(`        _sc_sp_list_${tag} = _sc_note_${tag}.get("sidecarPaths") or []`);
  lines.push(`        if not isinstance(_sc_sp_list_${tag}, list):`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        for _sc_sp_${tag} in _sc_sp_list_${tag}:`);
  lines.push(`            if not isinstance(_sc_sp_${tag}, str) or len(_sc_sp_${tag}) == 0:`);
  lines.push(`                continue`);
  lines.push(`            _sc_sib_${tag} = _sc_pathlib_${tag}.Path(_sc_sp_${tag})`);
  lines.push(`            if not _sc_sib_${tag}.is_absolute():`);
  lines.push(`                _sc_sib_${tag} = _sc_dir_${tag} / _sc_sp_${tag}`);
  lines.push(`            try:`);
  lines.push(`                _sc_parts_${tag}.append((_sc_sp_${tag}, _sc_sib_${tag}.read_bytes()))`);
  lines.push(`            except Exception:`);
  lines.push(`                raise RuntimeError("integrity binding mismatch") from None`);
  lines.push(`        _sc_seed_${tag} = _sc_note_${tag}.get("seedTag")`);
  lines.push(`        if not isinstance(_sc_seed_${tag}, str) or len(_sc_seed_${tag}) == 0:`);
  lines.push(`            _sc_seed_${tag} = "bla-sidecar-v1"`);
  lines.push(`        _sc_entry_${tag} = _sc_note_${tag}.get("entryPath")`);
  lines.push(`        if not isinstance(_sc_entry_${tag}, str):`);
  lines.push(`            _sc_entry_${tag} = ""`);
  lines.push(`        if _sc_digest_${tag}(_sc_entry_${tag}, _sc_parts_${tag}, _sc_seed_${tag}) != str(_sc_note_${tag}.get("digest")).lower():`);
  lines.push(`            raise RuntimeError("integrity binding mismatch")`);
  lines.push(`        return`);
  lines.push(`    raise RuntimeError("integrity binding mismatch")`);
  lines.push(`try:`);
  lines.push(`    ${bindingName}()`);
  lines.push(`finally:`);
  lines.push(`    del ${bindingName}`);

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    preamble: lines.join("\n"),
    bindingName,
    codeIdentityHexes: list,
    sqliteRelPaths: relPaths,
  };
}

/**
 * Insert a SQLite load-time hook after shebang / encoding / docstring /
 * `from __future__`, idempotent when {@link SQLITE_SIDECAR_LOADER_MARKER}
 * is already present. Preserves surrounding newlines the same way
 * `bindPythonSidecarEntanglement` does.
 */
export function prependSqliteSidecarLoaderHook(
  entrySource: string,
  preamble: string,
): string {
  if (entrySource.includes(SQLITE_SIDECAR_LOADER_MARKER)) return entrySource;
  const eol = entrySource.includes("\r\n") ? "\r\n" : "\n";
  const analysis = findPythonPrologueInsertionOffset(entrySource);
  const headRaw = entrySource.slice(0, analysis.insertOffset);
  const tailRaw = entrySource.slice(analysis.insertOffset);
  const head = headRaw.replace(/(?:\r?\n)+$/, "");
  const tail = tailRaw.replace(/^(?:\r?\n)+/, "");
  const body = preamble.replace(/\r?\n/g, eol).replace(/(?:\r?\n)+$/, "");
  const parts: string[] = [];
  if (head.length > 0) parts.push(head);
  parts.push(body);
  if (tail.length > 0) parts.push(tail);
  return (
    parts.join(eol) +
    (entrySource.endsWith("\n") || entrySource.endsWith("\r\n") ? eol : "")
  );
}

/**
 * Convenience: prepend a loader hook bound to this SQLite file's
 * logical identity. Idempotent when the marker is already present.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function entangleSqliteLoaderWithSidecars(options: {
  readonly loaderSource: string;
  readonly sqliteBytes: Uint8Array;
  readonly sqliteRelPath: string | readonly string[];
}): { readonly code: string; readonly identity: string } {
  const identity = computeSqliteSidecarCodeIdentity(options.sqliteBytes);
  const paths = (
    Array.isArray(options.sqliteRelPath)
      ? options.sqliteRelPath
      : [options.sqliteRelPath]
  ).filter((p) => p.length > 0);
  const inject = generateSidecarSqliteLoaderSnippet({
    codeIdentityHex: identity,
    sqliteRelPaths: paths,
  });
  return {
    code: prependSqliteSidecarLoaderHook(options.loaderSource, inject.preamble),
    identity,
  };
}

const MAX_SQLITE_LOADER_CANDIDATE_BYTES = 2 * 1024 * 1024;
const MAX_SQLITE_LOADER_AUTOWIRE_CHARS = 64 * 1024;
const SQLITE_LOADER_BASENAME_RE = /\.(sqlite3?|db)$/i;

/**
 * True when `source` mentions `sqliteBasename` in a quoted string /
 * template.
 */
export function sourceMentionsSqliteFile(
  source: string,
  sqliteBasename: string,
): boolean {
  const name = (sqliteBasename.replaceAll("\\", "/").split("/").pop() ?? "");
  if (!name || !SQLITE_LOADER_BASENAME_RE.test(name)) return false;
  const quoted = new RegExp(
    `['"\`](?:[^'"\`\\\\]|\\\\.)*${escapeRegExpLiteral(name)}['"\`]`,
  );
  return quoted.test(source);
}

/**
 * Conservative auto-wire predicate: a Python file with a known loader name
 * (`loader.py`, `__init__.py`, `__main__.py`) that already mentions the
 * target database basename. Test, already-entangled, and oversized
 * files return false.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function isSafePythonSqliteLoader(options: {
  readonly source: string;
  readonly filename: string;
  readonly sqliteBasename: string;
}): boolean {
  if (!isPythonPycLoaderFilename(options.filename)) return false;
  if (options.source.length > MAX_SQLITE_LOADER_AUTOWIRE_CHARS) return false;
  if (ALREADY_ENTANGLED_PY_RE.test(options.source)) return false;
  return sourceMentionsSqliteFile(options.source, options.sqliteBasename);
}

function sqliteLoaderPreference(loaderName: string): number {
  const base = basename(loaderName);
  if (/^loader\.py$/i.test(base)) return 0;
  if (/^__init__\.py$/i.test(base)) return 1;
  if (/^__main__\.py$/i.test(base)) return 2;
  return 3;
}

export interface PythonSqliteLoaderCandidate {
  readonly name: string;
  readonly source: string;
}

/**
 * Pick a single same-directory Python loader, or `null` when none qualify
 * or several unranked files all qualify (do not guess). Preferred names:
 * `loader.py`, then `__init__.py`, then `__main__.py`.
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function selectPythonSqliteLoader(
  sqliteBasename: string,
  candidates: readonly PythonSqliteLoaderCandidate[],
): string | null {
  const qualifying = candidates.filter((c) =>
    isSafePythonSqliteLoader({
      source: c.source,
      filename: c.name,
      sqliteBasename,
    }),
  );
  if (qualifying.length === 0) return null;
  const scored = qualifying.map((c) => ({
    c,
    score: sqliteLoaderPreference(c.name),
  }));
  scored.sort((a, b) => a.score - b.score || a.c.name.localeCompare(b.c.name));
  const best = scored[0]!;
  if (best.score >= 3) return null;
  const ties = scored.filter((s) => s.score === best.score);
  if (ties.length > 1) return null;
  return best.c.name;
}

export interface DiscoveredPythonSqliteLoader {
  readonly absPath: string;
  readonly name: string;
  readonly source: string;
}

function readSqliteLoaderCandidateSource(absPath: string): string | null {
  try {
    const st = statSync(absPath);
    if (st.isFile() === false || st.size <= 0 || st.size > MAX_SQLITE_LOADER_CANDIDATE_BYTES) {
      return null;
    }
    return readFileSync(absPath, "utf8");
  } catch {
    return null;
  }
}

/** Directories to search for a Python loader next to a SQLite database. */
export function listSqliteLoaderSearchDirectories(sqlitePath: string): string[] {
  return [dirname(sqlitePath)];
}

/**
 * List same-directory `.py` candidates (no recursion). Unreadable or
 * oversized files are skipped.
 */
export function listSameDirPythonSqliteLoaderCandidates(
  directory: string,
): DiscoveredPythonSqliteLoader[] {
  let names: string[] = [];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  const out: DiscoveredPythonSqliteLoader[] = [];
  for (const name of names) {
    if (!isPythonPycLoaderFilename(name)) continue;
    const absPath = join(directory, name);
    const source = readSqliteLoaderCandidateSource(absPath);
    if (source === null) continue;
    out.push({ absPath, name, source });
  }
  return out;
}

/**
 * Discover the unique safe Python loader for `sqliteBasename` in the
 * first search directory that yields a selection. Later directories are
 * not consulted once one directory produces a hit (output dir wins over
 * source).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice.
 */
export function discoverPythonSqliteLoader(options: {
  readonly sqliteBasename: string;
  readonly searchDirectories: readonly string[];
}): DiscoveredPythonSqliteLoader | null {
  const seen = new Set<string>();
  for (const directory of options.searchDirectories) {
    if (typeof directory !== "string" || directory.length === 0) continue;
    if (seen.has(directory)) continue;
    seen.add(directory);
    const candidates = listSameDirPythonSqliteLoaderCandidates(directory);
    const selected = selectPythonSqliteLoader(
      options.sqliteBasename,
      candidates,
    );
    if (!selected) continue;
    const hit = candidates.find((c) => c.name === selected || c.absPath === selected);
    if (hit) return hit;
  }
  return null;
}

/**
 * True when a same-directory Python file already carries the SQLite
 * load-time hook bound to this file's code identity (used by defenseScore
 * honesty).
 *
 * DEFENSIVE ONLY.
 */
export function isSqliteSidecarLoaderHookWired(options: {
  readonly sqliteBytes: Uint8Array;
  readonly sqlitePath: string;
}): boolean {
  const identity = computeSqliteSidecarCodeIdentity(options.sqliteBytes);
  const directories = listSqliteLoaderSearchDirectories(options.sqlitePath);
  return directories.some((directory) =>
    listSameDirPythonSqliteLoaderCandidates(directory).some(
      (c) =>
        c.source.includes(SQLITE_SIDECAR_LOADER_MARKER) &&
        c.source.includes(identity),
    ),
  );
}

/** Relative path from a loader file's directory to the protected SQLite database. */
export function relativeSqlitePathFromLoader(
  loaderPath: string,
  sqlitePath: string,
): string {
  const rel = relative(dirname(loaderPath), sqlitePath).split("\\").join("/");
  return rel.length === 0 ? basename(sqlitePath) : rel;
}
