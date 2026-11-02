/**
 * Sidecar / entry entanglement planner stub (issue #40 / STATE).
 *
 * Full binary rewriting is intentionally deferred — see
 * `docs/design/sidecar-entry-entanglement.md`. This module returns a typed plan
 * agents can inspect before enabling the future opt-in flag.
 *
 * DEFENSIVE ONLY.
 */

import { createHash } from "node:crypto";

export const SIDECAR_ENTANGLE_SCHEMA = "bla-sidecar-entangle/v1" as const;

export interface SidecarEntanglePlanOptions {
  readonly entryPath: string;
  readonly sidecarPaths: readonly string[];
  readonly seedTag?: string;
  /** When true, plan folds the binding into self-seal / opaque seed rather than a hard throw. */
  readonly softFold?: boolean;
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
  readonly status: "planned-stub";
  readonly note: string;
}

function guessHookKind(entryPath: string): SidecarEntanglePlan["entryHookKind"] {
  const lower = entryPath.toLowerCase();
  if (/\.(mjs|cjs|js|ts|tsx|jsx)$/.test(lower)) return "js-preamble";
  if (/\.py$/.test(lower)) return "python-preamble";
  if (/\.wasm$/.test(lower)) return "wasm-custom-section";
  return "unspecified";
}

/**
 * Plan a sidecar↔entry entanglement binding. Does not read or rewrite files.
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

  return {
    schema: SIDECAR_ENTANGLE_SCHEMA,
    entryPath: options.entryPath,
    sidecarPaths: sidecars,
    digestAlgorithm: "sha256",
    seedTag,
    softFold: options.softFold === true,
    planId,
    entryHookKind: guessHookKind(options.entryPath),
    status: "planned-stub",
    note:
      "Stub planner only — enable full rewrite when sidecarEntangle lands in protect paths. See docs/design/sidecar-entry-entanglement.md.",
  };
}
