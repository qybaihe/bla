import { resolve } from "node:path";
import type { VerificationCheck, VerificationReport } from "../core/types.js";
import { auditTarget } from "./auditor.js";

/**
 * Verifies a protected artifact against REA's analysis invariants (`bla verify`).
 */
export function verifyTarget(
  targetPath: string,
  originalPath?: string,
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
  // defenseScore measures Counter-REA gate pass-rate + exposure drop only.
  // It is NOT a claim of cryptographic preimage hardness: numeric-literal
  // coverage, WASM export rename, opaque-predicate seed strength, and
  // opt-in self-seal helpers are tracked separately (issue #40).
  const defenseScore = Math.round(
    (passedCount / checks.length) * 70 + Math.max(0, (100 - afterAudit.exposureScore) * 0.3),
  );

  return {
    targetPath: absTarget,
    ...(originalPath ? { originalPath: resolve(originalPath) } : {}),
    detectedFormat: afterAudit.detectedFormat,
    overallPassed: passedCount === checks.length,
    defenseScore: Math.min(100, defenseScore),
    checks,
    tokenAmplificationFactor: tokenAmp,
    costAmplificationFactor: costAmp,
    obligationGraphExpansionFactor: graphAmp,
    functionalIntegrityVerified: sim.parseStatus === "complete",
  };
}
