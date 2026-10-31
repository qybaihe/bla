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

export interface OneClickDefenseOptions {
  readonly inputPath: string;
  readonly outputPath?: string;
  readonly inPlace?: boolean;
  readonly intensity?: ProtectionIntensity;
  readonly seed?: string | number;
  readonly emitManifest?: boolean;
  readonly llmDirectives?: boolean;
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
    honeySourceMaps: true,
  });

  // Stage 4: Verify Counter-REA Invariants
  const verification = verifyTarget(protection.outputPath, absInput);

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
  if (options.emitManifest) {
    manifestPath = `${protection.outputPath}.bla-manifest.json`;
    const manifestPayload = {
      schema: "https://bla.tools/schemas/defense-manifest-v1.json",
      blaVersion: BLA_IDENTITY.version,
      protectedAt: new Date().toISOString(),
      // Honesty: this JSON is an attestation record, not a cryptographic signature.
      // Set attestationKind to "ed25519" only when a real signature is attached.
      attestationKind: "unsigned",
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
    writeFileSync(manifestPath, JSON.stringify(manifestPayload, null, 2) + "\n", "utf8");
    stages.push({
      stage: "5-defense-attestation-manifest",
      status: "passed",
      headline: `Emitted unsigned Counter-REA attestation manifest (not ed25519-signed) to ${manifestPath}`,
    });
  }

  return {
    blaVersion: BLA_IDENTITY.version,
    inputPath: absInput,
    outputPath: protection.outputPath,
    intensity,
    overallSuccess: verification.overallPassed,
    stages,
    releaseExposure,
    beforeAudit,
    protection,
    verification,
    ...(manifestPath !== undefined ? { manifestPath } : {}),
    exhaustionSummary,
    deceptionSummary,
  };
}
