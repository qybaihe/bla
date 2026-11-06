import { resolve } from "node:path";
import type {
  VerificationAgentAction,
  VerificationCheck,
  VerificationReport,
} from "../core/types.js";
import { auditTarget } from "./auditor.js";
import {
  applyDefenseScoreHonesty,
  DEFENSE_SCORE_DISCLAIMER,
} from "./defense-score-honesty.js";

export interface VerifyTargetOptions {
  readonly selfSealEnabled?: boolean;
  readonly wasmExportRenameApplied?: boolean;
  readonly numericTemplateLeakKnown?: boolean;
}

/**
 * Verifies a protected artifact against REA's analysis invariants (`bla verify`).
 * `defenseScore` is soft-capped when known product gaps still apply (issue #40.6).
 */
export function verifyTarget(
  targetPath: string,
  originalPath?: string,
  options: VerifyTargetOptions = {},
): VerificationReport {
  const absTarget = resolve(targetPath);
  const afterAudit = auditTarget(absTarget);
  const beforeAudit = originalPath ? auditTarget(resolve(originalPath)) : undefined;

  const sim = afterAudit.reaSimulation;
  const checks: VerificationCheck[] = [];

  // Check 1: REA Examination Status degraded to "limited"
  checks.push({
    id: "rea-examination-limited",
    name: "REA Static/Semantic Examination Degraded to Limited",
    targetReaComponent: "javascriptStaticAnalysis.ts / RustBinaryProvider / WabtWat.ts",
    passed: sim.examinationStatus === "limited" && sim.triggeredResourceLimits.length > 0,
    details:
      sim.triggeredResourceLimits.length > 0
        ? `Triggered resource limits: ${sim.triggeredResourceLimits.join(", ")}`
        : "No REA semantic resource limits triggered",
  });

  // Check 2: Algorithmic Tarpit & Obligation Graph Expansion
  checks.push({
    id: "obligation-graph-tarpit",
    name: "Algorithmic Tarpit & Call-Graph Labyrinth Active",
    targetReaComponent: "trace_application_feature / build_reconstruction_obligation_ledger",
    passed: sim.decoyFunctionsDetectedAsReal >= 5 && sim.obligationLedgerNodes >= 15,
    details: `Injected ${sim.decoyFunctionsDetectedAsReal} decoy tarpit nodes (${sim.obligationLedgerNodes} total obligation ledger nodes)`,
  });

  // Check 3: Architectural Chaff & Enclave Delegation Mirage
  checks.push({
    id: "architectural-chaff-mirage",
    name: "Defensive Architectural Chaff & Honey-Context Embedded",
    targetReaComponent: "Context Window / Evidence Dossier Summarizer",
    passed: sim.architecturalChaffPayloads >= 2,
    details: `${sim.architecturalChaffPayloads} enclave delegation & honey-contract payloads active`,
  });

  // Check 4: Electron IPC / Route / Binary Specific Invariant
  if (
    afterAudit.detectedFormat === "javascript" ||
    afterAudit.detectedFormat === "typescript" ||
    afterAudit.detectedFormat === "electron-asar" ||
    afterAudit.detectedFormat === "directory"
  ) {
    checks.push({
      id: "ipc-and-route-shield",
      name: "Electron IPC Pairing Ambiguity & Route Mirage",
      targetReaComponent: "electronStaticAnalysisIpc.ts / JavaScriptRouteScan.ts",
      passed:
        sim.ipcChannelsPairedUniquely === 0 &&
        (sim.ipcChannelsAmbiguousOrDynamic > 0 || sim.decoyRoutesHarvested > 0),
      details: `Uniquely paired IPC channels: ${sim.ipcChannelsPairedUniquely}; Ambiguous/Dynamic IPC sites: ${sim.ipcChannelsAmbiguousOrDynamic}; Decoy routes: ${sim.decoyRoutesHarvested}`,
    });
  } else {
    checks.push({
      id: "binary-container-shield",
      name: "Binary Container & Custom Section Shield",
      targetReaComponent: `inspect_${afterAudit.detectedFormat.replace("-", "_")}`,
      passed: afterAudit.protectionStatus === "BLA_PROTECTED",
      details: `Container status: ${afterAudit.protectionStatus} (Exposure score: ${afterAudit.exposureScore}/100)`,
    });
  }

  // Check 5: Token & Cost Bankruptcy Amplification
  const afterEst = afterAudit.agentEstimates[0]!;
  const beforeTokens = beforeAudit ? beforeAudit.agentEstimates[0]!.estimatedInputTokens : 3_200;
  const beforeCost = beforeAudit ? beforeAudit.agentEstimates[0]!.estimatedCostUsd : 0.12;
  const beforeNodes = beforeAudit ? Math.max(1, beforeAudit.reaSimulation.obligationLedgerNodes) : 3;

  const tokenAmp = Number((afterEst.estimatedInputTokens / Math.max(1, beforeTokens)).toFixed(1));
  const costAmp = Number((afterEst.estimatedCostUsd / Math.max(0.01, beforeCost)).toFixed(1));
  const graphAmp = Number((sim.obligationLedgerNodes / beforeNodes).toFixed(1));

  checks.push({
    id: "token-bankruptcy-amplification",
    name: "Agent Token & Cost Bankruptcy Amplification (>= 10x)",
    targetReaComponent: "MCP Context Window & Retained Evidence Paging",
    passed: tokenAmp >= 10 || afterEst.estimatedInputTokens >= 80_000,
    details: `Token amplification: ${tokenAmp}x (${afterEst.estimatedInputTokens.toLocaleString()} tokens, ~$${afterEst.estimatedCostUsd.toFixed(2)})`,
  });

  const passedCount = checks.filter((c) => c.passed).length;
  // Raw score = Counter-REA gate pass-rate + exposure drop only.
  // Soft-capped below when known gaps still apply (issue #40.6).
  const rawDefenseScore = Math.min(
    100,
    Math.round(
      (passedCount / checks.length) * 70 + Math.max(0, (100 - afterAudit.exposureScore) * 0.3),
    ),
  );
  const honesty = applyDefenseScoreHonesty(rawDefenseScore, {
    detectedFormat: afterAudit.detectedFormat,
    selfSealEnabled: options.selfSealEnabled === true,
    wasmExportRenameApplied: options.wasmExportRenameApplied === true,
    numericTemplateLeakKnown: options.numericTemplateLeakKnown === true,
  });

  const agentActions: VerificationAgentAction[] = [];
  for (const check of checks) {
    if (!check.passed) {
      agentActions.push({
        id: `fix-check-${check.id}`,
        priority: "high",
        reason: `Verification check '${check.id}' failed (${check.details}).`,
        instruction:
          `Re-run hardening at 'bankrupt' intensity with weave_decoys:true on ${absTarget}, then re-verify.`,
        recommendedMcpTool: "bla_defend",
        recommendedArgs: {
          input_path: originalPath ? resolve(originalPath) : absTarget,
          intensity: "bankrupt",
          weave_decoys: true,
          self_seal: true,
        },
      });
    }
  }

  for (const gap of honesty.gaps) {
    if (gap.id === "self-seal-not-enabled") {
      agentActions.push({
        id: "enable-self-seal",
        priority: "medium",
        reason: gap.summary,
        instruction:
          "Enable self_seal: true (and sidecar_entangle: true for multi-file trees) during bla_harden / bla_defend, and pass self_seal_enabled: true when calling bla_verify directly.",
        recommendedMcpTool: "bla_defend",
        recommendedArgs: {
          input_path: originalPath ? resolve(originalPath) : absTarget,
          intensity: "bankrupt",
          self_seal: true,
          sidecar_entangle: true,
          weave_decoys: true,
        },
      });
    } else if (gap.id === "wasm-export-rename-pending") {
      agentActions.push({
        id: "enable-wasm-export-rename",
        priority: "medium",
        reason: gap.summary,
        instruction:
          "Protect the WASM artifact at maximum/bankrupt intensity (specifying only public ABI exports in wasm_preserve_exports) and pass wasm_export_rename_applied: true to bla_verify.",
        recommendedMcpTool: "bla_defend",
        recommendedArgs: {
          input_path: originalPath ? resolve(originalPath) : absTarget,
          intensity: "bankrupt",
        },
      });
    }
  }

  return {
    targetPath: absTarget,
    ...(originalPath ? { originalPath: resolve(originalPath) } : {}),
    detectedFormat: afterAudit.detectedFormat,
    overallPassed: passedCount === checks.length,
    defenseScore: honesty.cappedScore,
    defenseScoreRaw: honesty.rawScore,
    defenseScoreGaps: honesty.gaps.map((g) => ({
      id: g.id,
      summary: g.summary,
      scoreCap: g.scoreCap,
    })),
    defenseScoreDisclaimer: DEFENSE_SCORE_DISCLAIMER,
    agentActions,
    checks,
    tokenAmplificationFactor: tokenAmp,
    costAmplificationFactor: costAmp,
    obligationGraphExpansionFactor: graphAmp,
    functionalIntegrityVerified: sim.parseStatus === "complete",
  };
}
