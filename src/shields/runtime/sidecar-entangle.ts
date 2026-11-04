/**
 * Sidecar / entry entanglement planner (issue #40 / Direction-3).
 *
 * Elevates the former planned-stub into a coverage-matrix planner that assigns
 * interleaved SHA-256 check edges across entry + sidecar paths. Full binary
 * rewriting of non-JS sidecars remains out of scope (see
 * `docs/design/sidecar-entry-entanglement.md`); JS checker hosts receive
 * `generateSelfSealSnippet` payloads via protect/harden.
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
  readonly status: "ready" | "incomplete";
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
  const checkerHosts = fileNodes.filter(isJsChecker);
  // Prefer entry as a checker host even if list empty.
  const hosts =
    checkerHosts.length > 0
      ? checkerHosts
      : isJsChecker(options.entryPath)
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
