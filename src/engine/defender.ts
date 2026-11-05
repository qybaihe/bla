import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { BLA_IDENTITY } from "../identity.js";
import {
  inspectReleaseExposure,
  type ReleaseExposureReport,
} from "../core/release-exposure.js";
import type {
  AuditReport,
  ProtectionIntensity,
  ProtectionResult,
  VerificationReport,
} from "../core/types.js";
import { REA_BUDGET_BREAKER_MATRIX } from "../shields/exhaustion/index.js";
import { auditTarget } from "./auditor.js";
import { protectTarget } from "./protector.js";
import { verifyTarget } from "./verifier.js";
import {
  signManifestPayload,
  readManifestSigningKeyOrThrow,
} from "../core/manifest-signing.js";

export interface OneClickDefenseOptions {
  readonly inputPath: string;
  readonly outputPath?: string;
  readonly inPlace?: boolean;
  readonly intensity?: ProtectionIntensity;
  readonly seed?: string | number;
  readonly emitManifest?: boolean;
  /** Opt-in ed25519 signing of the stage-5 manifest. Requires emitManifest. */
  readonly signManifest?: boolean;
  /** Path to an ed25519 private key PEM used when signManifest is true. */
  readonly manifestSigningKeyPath?: string;
  readonly llmDirectives?: boolean;
  readonly weaveDecoys?: boolean;
  /** Opt-in self-seal / sibling-module integrity binding for JS/Node (issue #40.5). */
  readonly selfSeal?: boolean;
  /** Opt-in sidecar/entry entanglement strip⇒fail for JS (issue #40). */
  readonly sidecarEntangle?: boolean;
  /** Sibling sidecar paths measured when sidecarEntangle is true. */
  readonly sidecarEntanglePaths?: readonly string[];
  readonly sidecarEntangleSoftFold?: boolean;
  /** WASM public ABI export names to preserve when rename runs (issue #40.3). */
  readonly wasmPreserveExports?: readonly string[];
  /** Allow lane-independent JS gates (issue #40.1). Default false. */
  readonly allowLaneIndependentGates?: boolean;
  /** Allow bankrupt despite plaintext/reversible seal sidecars (red-blue round-2). Default false. */
  readonly allowPlaintextSeal?: boolean;
  /** Allow bankrupt despite clear WASM param/cipher carriers (red-blue round-3). Default false. */
  readonly allowWasmClearParamCarriers?: boolean;
  /** Keep stable __vaultPanelDerive_* ABI (red-blue round-3). Default false — rewrite. */
  readonly allowStablePanelDeriveAbi?: boolean;
  /** Allow bankrupt despite JS AES wrap-key unwrap footguns (red-blue round-4). Default false. */
  readonly allowJsAesUnwrap?: boolean;
  /** Allow bankrupt despite panel offline-oracle packaging (red-blue round-4). Default false. */
  readonly allowPanelOfflineOracle?: boolean;
  /** Allow bankrupt despite JS←WASM hydrate param-dump (red-blue round-5). Default false. */
  readonly allowJsWasmHydrateDump?: boolean;
  readonly allowWasmXorMaskSidecar?: boolean;
  /** Allow bankrupt despite seal.revision XOR known-plaintext packs (red-blue round-7). Default false. */
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  /** Sibling paths forwarded into self-seal when enabled (multi-artifact harden). */
  readonly selfSealSiblingPaths?: readonly string[];
}

export interface OneClickDefenseStageSummary {
  readonly stage:
    | "1-release-exposure-scan"
    | "2-preflight-rea-audit"
    | "3-exhaustion-and-deception-shield"
    | "4-counter-rea-invariant-verification"
    | "5-defense-attestation-manifest";
  readonly status: "passed" | "warn";
  readonly headline: string;
}

export interface OneClickDefenseReport {
  readonly blaVersion: string;
  readonly inputPath: string;
  readonly outputPath: string;
  readonly intensity: ProtectionIntensity;
  /** True when caller opted into weave-decoy labeling/hooks. */
  readonly weaveDecoys: boolean;
  /** True when caller opted into self-seal integrity binding. */
  readonly selfSeal: boolean;
  /** True when caller opted into sidecar entry entanglement. */
  readonly sidecarEntangle: boolean;
  /** True when stage 5 emitted an ed25519-signed manifest. */
  readonly manifestSigned?: boolean;
  readonly overallSuccess: boolean;
  readonly stages: readonly OneClickDefenseStageSummary[];
  readonly releaseExposure: ReleaseExposureReport | null;
  readonly beforeAudit: AuditReport;
  readonly protection: ProtectionResult;
  readonly verification: VerificationReport;
  readonly manifestPath?: string;
  readonly exhaustionSummary: {
    readonly reaBudgetsTripped: readonly string[];
    readonly obligationLedgerNodesBefore: number;
    readonly obligationLedgerNodesAfter: number;
    readonly tokenAmplificationFactor: number;
    readonly costAmplificationFactor: number;
    readonly attackerEstimatedBillUsd: number;
  };
  readonly deceptionSummary: {
    readonly decoyFunctionsInjected: number;
    readonly fakeCrossReferencesCreated: number;
    readonly chaffAndEvidenceLuresEmbedded: number;
    readonly ipcAmbiguityAndObligationSites: number;
    readonly decoyRoutesAndGrpcMethods: number;
  };
}

/**
 * One-Click Agent Defense Hardening Pipeline (`bla defend <target>` / MCP `bla_defend`).
 *
 * Designed so that once an AI Coding Agent attaches BLA via `npx bla-agents@latest setup`,
 * a single command or MCP tool invocation runs the entire 5-stage Counter-REA defense loop:
 *   1. Read-only source-map & symbol exposure check (`inspectReleaseExposure`)
 *   2. Pre-flight 16-vector REA vulnerability & token-cost audit (`auditTarget`)
 *   3. Maximum/Bankrupt Resource-Exhaustion + Model-Misjudgment shield injection (`protectTarget`)
 *   4. Counter-REA mathematical & structural invariant verification (`verifyTarget`)
 *   5. Defense attestation manifest generation
 */
export function defendTarget(options: OneClickDefenseOptions): OneClickDefenseReport {
  const absInput = resolve(options.inputPath);
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";

  // Fail closed before any pipeline work when signing is requested.
  let manifestSigningKeyPem: string | undefined;
  if (options.signManifest === true) {
    if (options.emitManifest !== true) {
      throw new Error(
        "signManifest requires emitManifest — a manifest must be emitted before it can be signed.",
      );
    }
    manifestSigningKeyPem = readManifestSigningKeyOrThrow(options.manifestSigningKeyPath ?? "");
  }

  // Stage 1: Release Exposure Scan (best-effort for local files/directories)
  let releaseExposure: ReleaseExposureReport | null = null;
  try {
    releaseExposure = inspectReleaseExposure(absInput);
  } catch {
    releaseExposure = null;
  }

  // Stage 2: Pre-flight REA Audit
  const beforeAudit = auditTarget(absInput);

  // Stage 3: Inject Exhaustion + Deception Shield
  const protection = protectTarget({
    inputPath: absInput,
    ...(options.outputPath !== undefined ? { outputPath: options.outputPath } : {}),
    ...(options.inPlace !== undefined ? { inPlace: options.inPlace } : {}),
    intensity,
    ...(options.seed !== undefined ? { seed: options.seed } : {}),
    ...(options.llmDirectives !== undefined
      ? { llmDirectives: options.llmDirectives }
      : {}),
    ...(options.weaveDecoys !== undefined
      ? { weaveDecoys: options.weaveDecoys }
      : {}),
    ...(options.selfSeal !== undefined
      ? { selfSeal: options.selfSeal }
      : {}),
    ...(options.wasmPreserveExports !== undefined && options.wasmPreserveExports.length > 0
      ? { wasmPreserveExports: options.wasmPreserveExports }
      : {}),
    ...(options.allowLaneIndependentGates === true
      ? { allowLaneIndependentGates: true }
      : {}),
    ...(options.allowPlaintextSeal === true ? { allowPlaintextSeal: true } : {}),
    ...(options.allowWasmClearParamCarriers === true
      ? { allowWasmClearParamCarriers: true }
      : {}),
    ...(options.allowStablePanelDeriveAbi === true
      ? { allowStablePanelDeriveAbi: true }
      : {}),
    ...(options.allowJsAesUnwrap === true ? { allowJsAesUnwrap: true } : {}),
    ...(options.allowPanelOfflineOracle === true
      ? { allowPanelOfflineOracle: true }
      : {}),
    ...(options.allowJsWasmHydrateDump === true
      ? { allowJsWasmHydrateDump: true }
      : {}),
    ...(options.allowWasmXorMaskSidecar === true
      ? { allowWasmXorMaskSidecar: true }
      : {}),
    ...(options.allowWasmSealXorKnownPlaintext === true
      ? { allowWasmSealXorKnownPlaintext: true }
      : {}),
    ...(options.selfSealSiblingPaths !== undefined &&
    options.selfSealSiblingPaths.length > 0
      ? { selfSealSiblingPaths: options.selfSealSiblingPaths }
      : {}),
    ...(options.sidecarEntangle !== undefined
      ? { sidecarEntangle: options.sidecarEntangle }
      : {}),
    ...(options.sidecarEntanglePaths !== undefined &&
    options.sidecarEntanglePaths.length > 0
      ? { sidecarEntanglePaths: options.sidecarEntanglePaths }
      : {}),
    ...(options.sidecarEntangleSoftFold === true
      ? { sidecarEntangleSoftFold: true }
      : {}),
    honeySourceMaps: true,
  });

  // Stage 4: Verify Counter-REA Invariants
  const verification = verifyTarget(protection.outputPath, absInput, {
    selfSealEnabled: options.selfSeal === true || protection.selfSeal === true,
    wasmExportRenameApplied: protection.wasmExportRenameApplied === true,
  });

  const afterEst = protection.afterAudit.agentEstimates[0]!;
  const exhaustionSummary = {
    reaBudgetsTripped: protection.afterAudit.reaSimulation.triggeredResourceLimits,
    obligationLedgerNodesBefore:
      beforeAudit.reaSimulation.obligationLedgerNodes,
    obligationLedgerNodesAfter:
      protection.afterAudit.reaSimulation.obligationLedgerNodes,
    tokenAmplificationFactor: verification.tokenAmplificationFactor,
    costAmplificationFactor: verification.costAmplificationFactor,
    attackerEstimatedBillUsd: afterEst.estimatedCostUsd,
  };

  const deceptionSummary = {
    decoyFunctionsInjected: protection.metrics.decoyFunctionsInjected,
    fakeCrossReferencesCreated: protection.metrics.fakeCrossReferencesCreated,
    chaffAndEvidenceLuresEmbedded: protection.metrics.chaffPayloadsEmbedded,
    ipcAmbiguityAndObligationSites:
      protection.metrics.ipcAmbiguitySitesInjected,
    decoyRoutesAndGrpcMethods: protection.metrics.decoyRoutesInjected,
  };

  const stages: OneClickDefenseStageSummary[] = [
    {
      stage: "1-release-exposure-scan",
      status: "passed",
      headline: releaseExposure
        ? `Inspected ${releaseExposure.filesInspected} file(s); ${releaseExposure.findings.length} raw source-map exposure finding(s) neutralized`
        : "Binary/container target validated for direct shield injection",
    },
    {
      stage: "2-preflight-rea-audit",
      status: "passed",
      headline: `Baseline REA exposure ${beforeAudit.exposureScore}/100 (${beforeAudit.protectionStatus}) audited across ${beforeAudit.exposedItems.length} surface items`,
    },
    {
      stage: "3-exhaustion-and-deception-shield",
      status: "passed",
      headline: `Injected ${deceptionSummary.decoyFunctionsInjected} tarpit/shadow procedures, ${deceptionSummary.fakeCrossReferencesCreated} SCC XRefs, and ${deceptionSummary.chaffAndEvidenceLuresEmbedded} Evidence Contract lures (preset: ${intensity})`,
    },
    {
      stage: "4-counter-rea-invariant-verification",
      status: verification.overallPassed ? "passed" : "warn",
      headline: `Defense score ${verification.defenseScore}/100 | Token amplification: ${verification.tokenAmplificationFactor}x | Attacker API bill: ~$${afterEst.estimatedCostUsd.toFixed(2)}`,
    },
  ];

  let manifestPath: string | undefined;
  let manifestSigned = false;
  if (options.emitManifest) {
    manifestPath = `${protection.outputPath}.bla-manifest.json`;
    const attestationKind =
      options.signManifest === true ? ("ed25519" as const) : ("unsigned" as const);
    const manifestPayload = {
      schema: "https://bla.tools/schemas/defense-manifest-v1.json",
      blaVersion: BLA_IDENTITY.version,
      protectedAt: new Date().toISOString(),
      // Honesty: this JSON is an attestation record, not a cryptographic signature.
      // Set attestationKind to "ed25519" only when a real signature is attached.
      attestationKind,
      inputSha256: protection.originalSha256,
      protectedSha256: protection.protectedSha256,
      detectedFormat: protection.detectedFormat,
      intensity,
      defenseScore: verification.defenseScore,
      counteredReaVectors: protection.counteredReaVectors,
      reaBudgetsTargeted: REA_BUDGET_BREAKER_MATRIX.map((b) => b.id),
      exhaustionSummary,
      deceptionSummary,
    };
    let payloadToWrite: Record<string, unknown> = manifestPayload;
    if (attestationKind === "ed25519") {
      // manifestSigningKeyPem is guaranteed non-undefined by the fail-closed
      // validation at function entry whenever signManifest is true.
      payloadToWrite = signManifestPayload(manifestPayload, manifestSigningKeyPem!);
      manifestSigned = true;
    }
    writeFileSync(manifestPath, JSON.stringify(payloadToWrite, null, 2) + "\n", "utf8");
    stages.push({
      stage: "5-defense-attestation-manifest",
      status: "passed",
      headline: `Emitted ${
        manifestSigned ? "ed25519-signed" : "unsigned"
      } Counter-REA attestation manifest${
        manifestSigned ? "" : " (not ed25519-signed)"
      } to ${manifestPath}`,
    });
  }

  return {
    blaVersion: BLA_IDENTITY.version,
    inputPath: absInput,
    outputPath: protection.outputPath,
    intensity,
    weaveDecoys: options.weaveDecoys === true,
    selfSeal: options.selfSeal === true,
    sidecarEntangle: options.sidecarEntangle === true,
    overallSuccess: verification.overallPassed,
    stages,
    releaseExposure,
    beforeAudit,
    protection,
    verification,
    ...(manifestPath !== undefined ? { manifestPath } : {}),
    ...(manifestSigned ? { manifestSigned } : {}),
    exhaustionSummary,
    deceptionSummary,
  };
}
