/**
 * Unified packaging-footgun gate pipeline (red-blue R1–R12 → BLA 2.0).
 *
 * Aggregates every bankrupt refuse lint that harden already runs at project
 * level, plus advisory lane / panel-derive discovery (protect still refuses
 * those per-file). Agents call this via `bla lint` / MCP `bla_lint` instead of
 * eight separate tools.
 *
 * Honesty: gates close *packaging* footguns. They do **not** claim white-box
 * secrecy against full WASM RE / online guessing / SMT (R8–R12 residual).
 */

import { basename, relative, resolve, sep } from "node:path";
import type { ProtectionIntensity } from "../core/types.js";
import {
  discoverAndLintSealSidecars,
  intensityEnforcesSealRefusal,
  sealCommitmentRefuseMessage,
  type SealCommitmentReport,
} from "./seal-commitment-lint.js";
import {
  discoverAndLintWasmParamCarriers,
  intensityEnforcesWasmParamRefusal,
  wasmParamCarrierRefuseMessage,
  type WasmParamCarrierReport,
} from "./wasm-param-carrier-lint.js";
import {
  discoverAndLintJsAesUnwrap,
  intensityEnforcesJsAesUnwrapRefusal,
  jsAesUnwrapRefuseMessage,
  type JsAesUnwrapReport,
} from "./js-aes-unwrap-lint.js";
import {
  discoverAndLintJsWasmHydrateDump,
  intensityEnforcesJsWasmHydrateDumpRefusal,
  jsWasmHydrateDumpRefuseMessage,
  type JsWasmHydrateDumpReport,
} from "./js-wasm-hydrate-dump-lint.js";
import {
  discoverAndLintWasmXorMaskSidecars,
  intensityEnforcesWasmXorMaskSidecarRefusal,
  wasmXorMaskSidecarRefuseMessage,
  type WasmXorMaskSidecarReport,
} from "./wasm-xor-mask-sidecar-lint.js";
import {
  discoverAndLintWasmSealXorKnownPlaintext,
  intensityEnforcesWasmSealXorKnownPlaintextRefusal,
  wasmSealXorKnownPlaintextRefuseMessage,
  type WasmSealXorKnownPlaintextReport,
} from "./wasm-seal-xor-known-plaintext-lint.js";
import {
  discoverAndLintLaneIndependence,
  laneIndependenceRefuseMessage,
  type LaneIndependenceReport,
} from "./lane-independence-lint.js";
import {
  discoverAndLintPanelDerive,
  intensityEnforcesPanelOracleRefusal,
  panelDeriveRefuseMessage,
  type PanelDeriveAbiReport,
} from "./panel-derive-abi-lint.js";
import {
  discoverAndLintPlaintextSecrets,
  intensityEnforcesPlaintextSecretRefusal,
  plaintextSecretRefuseMessage,
  type PlaintextSecretReport,
} from "./plaintext-secret-lint.js";
import {
  discoverAndLintIntegrityCoverage,
  integrityCoverageRefuseMessage,
  type IntegrityCoverageFileReport,
} from "./integrity-coverage.js";
import {
  bindScopeRefuseMessage,
  discoverAndLintBindScope,
  intensityEnforcesBindScopeRefusal,
  type BindScopeLintReport,
} from "./bind-scope.js";

export const PACKAGING_GATES_SCHEMA = "bla-packaging-gates/v1" as const;

export type PackagingGateId =
  | "seal-commitment"
  | "wasm-param-carrier"
  | "js-aes-unwrap"
  | "js-wasm-hydrate-dump"
  | "wasm-xor-mask-sidecar"
  | "wasm-seal-xor-known-plaintext"
  | "lane-independence"
  | "panel-derive"
  | "plaintext-secret"
  | "integrity-coverage"
  | "bind-scope";

export interface PackagingGateFinding {
  readonly gate: PackagingGateId;
  readonly path: string;
  readonly relativePath: string;
  readonly shouldRefuseBankrupt: boolean;
  readonly refuseMessage?: string;
  readonly oneLineAdvice: string;
  readonly findingCount: number;
  readonly remediationRecipe?: string;
  readonly recommendedMcpTool?: string;
}

export interface PackagingGateRemediation {
  readonly gate: PackagingGateId;
  readonly path: string;
  readonly relativePath: string;
  readonly priority: "critical" | "high" | "medium";
  readonly owner: "agent-source-refactor" | "mcp-tool-call";
  readonly recommendedMcpTool?: string;
  readonly sourceRefactorRecipe: string;
  readonly verifyCommand: string;
}

export interface PackagingGatesAllowOptions {
  readonly allowPlaintextSeal?: boolean;
  readonly allowWasmClearParamCarriers?: boolean;
  readonly allowJsAesUnwrap?: boolean;
  readonly allowJsWasmHydrateDump?: boolean;
  readonly allowWasmXorMaskSidecar?: boolean;
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  readonly allowLaneIndependentGates?: boolean;
  readonly allowPanelOfflineOracle?: boolean;
  readonly allowStablePanelDeriveAbi?: boolean;
  readonly allowPlaintextString?: boolean;
  /** Lab escape: allow bankrupt despite failing integrity coverage matrix. */
  readonly allowSinglePointIntegrity?: boolean;
  /** Lab escape: allow bind-scope contract without runtime check / non-public fields. */
  readonly allowMissingBindRuntime?: boolean;
}

export interface PackagingGatesScanOptions extends PackagingGatesAllowOptions {
  readonly directory: string;
  /** Intensity used to decide which findings refuse bankrupt (default bankrupt). */
  readonly intensity?: ProtectionIntensity;
  /**
   * When true (default), also scan JS/HTML for lane-independence + panel-derive.
   * Harden project-level refuse historically used the six carrier/JS/WASM gates
   * only — lanes/panel stay protect-time unless includeProtectTimeGates.
   */
  readonly includeProtectTimeGates?: boolean;
}

export interface PackagingGatesReport {
  readonly schema: typeof PACKAGING_GATES_SCHEMA;
  readonly directory: string;
  readonly intensity: ProtectionIntensity;
  readonly findings: readonly PackagingGateFinding[];
  /** Findings that would refuse bankrupt/maximum under current allow flags. */
  readonly blocking: readonly PackagingGateFinding[];
  /** Structured Agent remediation plan for autonomous source refactoring before harden. */
  readonly remediationPlan: readonly PackagingGateRemediation[];
  readonly shouldRefuseBankrupt: boolean;
  readonly gateCounts: Readonly<Record<PackagingGateId, number>>;
  readonly oneLineAdvice: string;
  readonly honestyNote: string;
  /** Raw per-gate reports for agents that need detail. */
  readonly details: {
    readonly seals: readonly SealCommitmentReport[];
    readonly wasmParams: readonly WasmParamCarrierReport[];
    readonly jsAes: readonly JsAesUnwrapReport[];
    readonly jsHydrateDump: readonly JsWasmHydrateDumpReport[];
    readonly wasmXorMask: readonly WasmXorMaskSidecarReport[];
    readonly wasmSealXor: readonly WasmSealXorKnownPlaintextReport[];
    readonly lanes: ReadonlyArray<LaneIndependenceReport & { readonly path: string }>;
    readonly panelDerive: readonly PanelDeriveAbiReport[];
    readonly plaintextSecrets: readonly PlaintextSecretReport[];
    readonly integrityCoverage: readonly IntegrityCoverageFileReport[];
    readonly bindScope: readonly BindScopeLintReport[];
  };
}

const HONESTY_NOTE =
  "Packaging gates close shipping footguns (R1–R7 refuse + R8–R12 engine hygiene). " +
  "They do not claim white-box secrecy against full WASM RE / online guessing / SMT.";

function relPath(absDir: string, filePath: string): string {
  return (relative(absDir, filePath) || basename(filePath)).split(sep).join("/");
}

function emptyCounts(): Record<PackagingGateId, number> {
  return {
    "seal-commitment": 0,
    "wasm-param-carrier": 0,
    "js-aes-unwrap": 0,
    "js-wasm-hydrate-dump": 0,
    "wasm-xor-mask-sidecar": 0,
    "wasm-seal-xor-known-plaintext": 0,
    "lane-independence": 0,
    "panel-derive": 0,
    "plaintext-secret": 0,
    "integrity-coverage": 0,
    "bind-scope": 0,
  };
}

function buildGateRemediationMeta(
  gate: PackagingGateId,
  rel: string,
): {
  readonly owner: "agent-source-refactor" | "mcp-tool-call";
  readonly recommendedMcpTool?: string;
  readonly sourceRefactorRecipe: string;
} {
  switch (gate) {
    case "lane-independence":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, replace per-byte / per-segment independent comparisons (e.g. \`key[i] === ...\` or \`parts[0] === ...\`) with a single whole-key chained ARX/FNV/SHA-256 accumulator so no byte can be solved in isolation, or move unlock verification into WASM.`,
      };
    case "seal-commitment":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove plaintext keys/flags/seeds and replace reversible \`(scheduleSalt + rounds + revision)\` fields with a one-way \`SHA-256\` commitment (\`certificateSha256\`), keeping the materialization \`seed\` private.`,
      };
    case "wasm-param-carrier":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove clear ASCII magic headers (\`R3PARM\`/\`R3CIPH\`/\`R2SEAL\`) from WASM data segments and derive mask keys via one-way \`SHA-256(key)\` inside WASM.`,
      };
    case "js-aes-unwrap":
      return {
        owner: "agent-source-refactor",
        recommendedMcpTool: "bla_encrypt_strings",
        sourceRefactorRecipe: `In \`${rel}\`, remove hardcoded AES wrap-key material + \`createDecipheriv\` from JS; move payload unlocking inside WASM or use \`bla_encrypt_strings\` (seed-derived XOR stream) for non-cryptographic literal masking.`,
      };
    case "js-wasm-hydrate-dump":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, stop reading \`memory.buffer\` salt/rounds/cipher layouts in JS after WASM instantiation; keep the entire ARX/KDF + certificate check inside WASM \`unlock(keyPtr, keyLen) -> outLen\`.`,
      };
    case "wasm-xor-mask-sidecar":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, do not store a static 32-byte XOR mask beside the masked blob in WASM linear memory; derive the keystream from user key bytes via one-way KDF at runtime.`,
      };
    case "wasm-seal-xor-known-plaintext":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove public \`seal.revision\` digests from the XOR-masked WASM payload (known-plaintext recovers the repeating XOR mask without a key); store public commitments in a separate unmasked segment.`,
      };
    case "panel-derive":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove the offline oracle combo (\`deriveLocal\` + plaintext \`panelTokenSha256\`) and let \`bla_harden\` at \`bankrupt\` intensity rewrite \`__vaultPanelDerive_*\` symbols to seed-stable identifiers.`,
      };
    case "plaintext-secret":
      return {
        owner: "mcp-tool-call",
        recommendedMcpTool: "bla_encrypt_strings",
        sourceRefactorRecipe: `Call MCP \`bla_encrypt_strings\` on \`${rel}\` with your project seed to XOR-mask cleartext sensitive literals (\`FLAG{...}\`, high-entropy tokens, derive key names), then re-run \`bla_lint\`.`,
      };
    case "integrity-coverage":
      return {
        owner: "mcp-tool-call",
        recommendedMcpTool: "bla_harden",
        sourceRefactorRecipe: `Ensure \`${rel}\` forms a strongly-connected interleaved verification graph where each node checks >=1 sibling and no single node is a single point of failure, or re-run \`bla_harden\` with \`self_seal: true\`.`,
      };
    case "bind-scope":
      return {
        owner: "mcp-tool-call",
        recommendedMcpTool: "bla_bind_scope",
        sourceRefactorRecipe: `Ensure \`${rel}\` sets \`"public": true\`, valid ISO dates / domain globs, and inject \`BLA_BIND_SCOPE_CHECK\` into the entry module via MCP \`bla_bind_scope\`.`,
      };
  }
}

/**
 * Scan a project (or file) for every packaging footgun lint.
 * Read-only — never writes.
 */
export function scanPackagingGates(
  options: PackagingGatesScanOptions,
): PackagingGatesReport {
  const absDir = resolve(options.directory);
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";
  const includeProtectTime = options.includeProtectTimeGates !== false;

  const seals = discoverAndLintSealSidecars(absDir);
  const wasmParams = discoverAndLintWasmParamCarriers(absDir);
  const jsAes = discoverAndLintJsAesUnwrap(absDir);
  const jsHydrateDump = discoverAndLintJsWasmHydrateDump(absDir);
  const wasmXorMask = discoverAndLintWasmXorMaskSidecars(absDir);
  const wasmSealXor = discoverAndLintWasmSealXorKnownPlaintext(absDir);
  const lanes = includeProtectTime
    ? discoverAndLintLaneIndependence(absDir)
    : [];
  const panelDerive = includeProtectTime
    ? discoverAndLintPanelDerive(absDir)
    : [];
  const plaintextSecrets = discoverAndLintPlaintextSecrets(absDir, {
    allowPlaintextString: options.allowPlaintextString,
  });
  const integrityCoverage = discoverAndLintIntegrityCoverage(absDir);
  const bindScope = discoverAndLintBindScope(absDir);

  const findings: PackagingGateFinding[] = [];
  const counts = emptyCounts();

  for (const r of seals) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["seal-commitment"] += 1;
    findings.push({
      gate: "seal-commitment",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? sealCommitmentRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of wasmParams) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["wasm-param-carrier"] += 1;
    findings.push({
      gate: "wasm-param-carrier",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? wasmParamCarrierRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of jsAes) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["js-aes-unwrap"] += 1;
    findings.push({
      gate: "js-aes-unwrap",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? jsAesUnwrapRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of jsHydrateDump) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["js-wasm-hydrate-dump"] += 1;
    findings.push({
      gate: "js-wasm-hydrate-dump",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? jsWasmHydrateDumpRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of wasmXorMask) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["wasm-xor-mask-sidecar"] += 1;
    findings.push({
      gate: "wasm-xor-mask-sidecar",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? wasmXorMaskSidecarRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of wasmSealXor) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["wasm-seal-xor-known-plaintext"] += 1;
    findings.push({
      gate: "wasm-seal-xor-known-plaintext",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? wasmSealXorKnownPlaintextRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of lanes) {
    if (!r.looksLaneIndependent) continue;
    counts["lane-independence"] += 1;
    findings.push({
      gate: "lane-independence",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: true,
      refuseMessage: laneIndependenceRefuseMessage(r, r.path),
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of panelDerive) {
    const refuse =
      r.shouldRefuseBankrupt ||
      (r.stableSymbols.length > 0 || r.localDeriveSymbols.length > 0);
    if (r.findings.length === 0 && !refuse) continue;
    counts["panel-derive"] += 1;
    findings.push({
      gate: "panel-derive",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage:
        r.shouldRefuseBankrupt || r.stableSymbols.length > 0
          ? panelDeriveRefuseMessage(r, r.path)
          : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of plaintextSecrets) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["plaintext-secret"] += 1;
    findings.push({
      gate: "plaintext-secret",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? plaintextSecretRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
    });
  }
  for (const r of integrityCoverage) {
    if (r.ok && !r.shouldRefuseBankrupt) continue;
    counts["integrity-coverage"] += 1;
    findings.push({
      gate: "integrity-coverage",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? integrityCoverageRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.reasons.length,
    });
  }
  for (const r of bindScope) {
    if (r.ok && !r.shouldRefuseBankrupt) continue;
    counts["bind-scope"] += 1;
    findings.push({
      gate: "bind-scope",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? bindScopeRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.reasons.length,
    });
  }

  const enrichedFindings: PackagingGateFinding[] = findings.map((f) => {
    const meta = buildGateRemediationMeta(f.gate, f.relativePath);
    return {
      ...f,
      remediationRecipe: meta.sourceRefactorRecipe,
      ...(meta.recommendedMcpTool !== undefined
        ? { recommendedMcpTool: meta.recommendedMcpTool }
        : {}),
    };
  });

  const blocking = filterBlockingFindings(enrichedFindings, intensity, options);

  const remediationPlan: PackagingGateRemediation[] = enrichedFindings.map((f) => {
    const meta = buildGateRemediationMeta(f.gate, f.relativePath);
    const isBlocking = blocking.some(
      (b) => b.gate === f.gate && b.path === f.path,
    );
    return {
      gate: f.gate,
      path: f.path,
      relativePath: f.relativePath,
      priority: isBlocking ? "critical" : f.shouldRefuseBankrupt ? "high" : "medium",
      owner: meta.owner,
      ...(meta.recommendedMcpTool !== undefined
        ? { recommendedMcpTool: meta.recommendedMcpTool }
        : {}),
      sourceRefactorRecipe: meta.sourceRefactorRecipe,
      verifyCommand: "bla_lint",
    };
  });

  const oneLineAdvice =
    blocking.length === 0
      ? enrichedFindings.length === 0
        ? "No packaging footgun findings (heuristic). Gates ≠ white-box secrecy."
        : `Packaging scan: ${enrichedFindings.length} finding(s), none refuse under current intensity/allows.`
      : `ERROR: ${blocking.length} packaging gate(s) would refuse bankrupt harden. Follow remediationPlan to refactor source or pass the matching --allow-* / allow_* flag (lab only).`;

  return {
    schema: PACKAGING_GATES_SCHEMA,
    directory: absDir,
    intensity,
    findings: enrichedFindings,
    blocking,
    remediationPlan,
    shouldRefuseBankrupt: blocking.length > 0,
    gateCounts: counts,
    oneLineAdvice,
    honestyNote: HONESTY_NOTE,
    details: {
      seals,
      wasmParams,
      jsAes,
      jsHydrateDump,
      wasmXorMask,
      wasmSealXor,
      lanes,
      panelDerive,
      plaintextSecrets,
      integrityCoverage,
      bindScope,
    },
  };
}

function filterBlockingFindings(
  findings: readonly PackagingGateFinding[],
  intensity: ProtectionIntensity,
  allow: PackagingGatesAllowOptions,
): PackagingGateFinding[] {
  return findings.filter((f) => {
    if (!f.shouldRefuseBankrupt && f.gate !== "lane-independence") {
      // panel stable-ABI rewrite is not a harden project-level refuse today
      return false;
    }
    switch (f.gate) {
      case "seal-commitment":
        return intensityEnforcesSealRefusal(intensity) && allow.allowPlaintextSeal !== true;
      case "wasm-param-carrier":
        return (
          intensityEnforcesWasmParamRefusal(intensity) &&
          allow.allowWasmClearParamCarriers !== true
        );
      case "js-aes-unwrap":
        return (
          intensityEnforcesJsAesUnwrapRefusal(intensity) &&
          allow.allowJsAesUnwrap !== true
        );
      case "js-wasm-hydrate-dump":
        return (
          intensityEnforcesJsWasmHydrateDumpRefusal(intensity) &&
          allow.allowJsWasmHydrateDump !== true
        );
      case "wasm-xor-mask-sidecar":
        return (
          intensityEnforcesWasmXorMaskSidecarRefusal(intensity) &&
          allow.allowWasmXorMaskSidecar !== true
        );
      case "wasm-seal-xor-known-plaintext":
        return (
          intensityEnforcesWasmSealXorKnownPlaintextRefusal(intensity) &&
          allow.allowWasmSealXorKnownPlaintext !== true
        );
      case "lane-independence":
        // Project-level lint reports lanes; harden project refuse historically
        // left lanes to protect-time. Blocking list for `bla lint` treats them
        // as refuse-worthy so agents see the same footgun before harden.
        return allow.allowLaneIndependentGates !== true && f.shouldRefuseBankrupt;
      case "panel-derive":
        return (
          intensityEnforcesPanelOracleRefusal(intensity) &&
          allow.allowPanelOfflineOracle !== true &&
          f.shouldRefuseBankrupt
        );
      case "plaintext-secret":
        return (
          intensityEnforcesPlaintextSecretRefusal(intensity) &&
          allow.allowPlaintextString !== true &&
          f.shouldRefuseBankrupt
        );
      case "integrity-coverage":
        return (
          intensity === "bankrupt" &&
          allow.allowSinglePointIntegrity !== true &&
          f.shouldRefuseBankrupt
        );
      case "bind-scope":
        return (
          intensityEnforcesBindScopeRefusal(intensity) &&
          allow.allowMissingBindRuntime !== true &&
          f.shouldRefuseBankrupt
        );
      default:
        return false;
    }
  });
}

/**
 * Subset of packaging gates that hardenProject historically refuses at
 * project scope (excludes lane/panel — those remain protect-time).
 */
export function evaluateHardenProjectPackagingBlocks(
  options: PackagingGatesScanOptions,
): {
  readonly report: PackagingGatesReport;
  readonly blockingSeals: readonly SealCommitmentReport[];
  readonly blockingWasmParms: readonly WasmParamCarrierReport[];
  readonly blockingJsAes: readonly JsAesUnwrapReport[];
  readonly blockingJsHydrateDump: readonly JsWasmHydrateDumpReport[];
  readonly blockingWasmXorMask: readonly WasmXorMaskSidecarReport[];
  readonly blockingWasmSealXor: readonly WasmSealXorKnownPlaintextReport[];
} {
  // Harden project-level: do not include protect-time gates in the scan used
  // for the early refuse path (preserves prior semantics).
  const report = scanPackagingGates({
    ...options,
    includeProtectTimeGates: false,
  });
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";
  const blockingSeals =
    intensityEnforcesSealRefusal(intensity) && options.allowPlaintextSeal !== true
      ? report.details.seals.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingWasmParms =
    intensityEnforcesWasmParamRefusal(intensity) &&
    options.allowWasmClearParamCarriers !== true
      ? report.details.wasmParams.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingJsAes =
    intensityEnforcesJsAesUnwrapRefusal(intensity) &&
    options.allowJsAesUnwrap !== true
      ? report.details.jsAes.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingJsHydrateDump =
    intensityEnforcesJsWasmHydrateDumpRefusal(intensity) &&
    options.allowJsWasmHydrateDump !== true
      ? report.details.jsHydrateDump.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingWasmXorMask =
    intensityEnforcesWasmXorMaskSidecarRefusal(intensity) &&
    options.allowWasmXorMaskSidecar !== true
      ? report.details.wasmXorMask.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingWasmSealXor =
    intensityEnforcesWasmSealXorKnownPlaintextRefusal(intensity) &&
    options.allowWasmSealXorKnownPlaintext !== true
      ? report.details.wasmSealXor.filter((r) => r.shouldRefuseBankrupt)
      : [];
  return {
    report,
    blockingSeals,
    blockingWasmParms,
    blockingJsAes,
    blockingJsHydrateDump,
    blockingWasmXorMask,
    blockingWasmSealXor,
  };
}

/** Human-readable CLI/MCP text for a packaging-gates report. */
export function formatPackagingGatesReport(report: PackagingGatesReport): string {
  const lines: string[] = [
    `BLA packaging gates — ${report.directory}`,
    report.oneLineAdvice,
    report.honestyNote,
  ];
  if (report.findings.length === 0) {
    lines.push("  (no findings)");
    return lines.join("\n");
  }
  for (const f of report.findings) {
    const tag = f.shouldRefuseBankrupt ? "refuse" : "info";
    lines.push(
      `  [${tag}] ${f.gate} · ${f.relativePath} · ${f.findingCount} finding(s)`,
    );
    lines.push(`    ${f.oneLineAdvice}`);
  }
  if (report.blocking.length > 0) {
    lines.push(`blocking (${report.blocking.length}):`);
    for (const b of report.blocking) {
      lines.push(`  - ${b.gate} · ${b.relativePath}`);
      if (b.remediationRecipe) {
        lines.push(`    recipe: ${b.remediationRecipe}`);
      }
    }
  }
  return lines.join("\n");
}
