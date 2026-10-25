import { resolve } from "node:path";
import type { VerificationCheck, VerificationReport } from "../core/types.js";
import { auditTarget } from "./auditor.js";

/**
 * Reports local heuristic indicators; does not execute REA or runtime equivalence checks (`bla verify`).
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
    name: "Local Indicators for Simulated Limited Examination",
    targetReaComponent: "javascriptStaticAnalysis.ts / RustBinaryProvider / WabtWat.ts",
    evidenceBasis: "local-heuristic",
    status: "not-run",
    passed: false,
    heuristicMatched: sim.examinationStatus === "limited" && sim.triggeredResourceLimits.length > 0,
    details:
      sim.triggeredResourceLimits.length > 0
        ? `Locally inferred resource-limit indicators: ${sim.triggeredResourceLimits.join(", ")}`
        : "No local resource-limit indicators found",
  });

  // Check 2: Algorithmic Tarpit & Obligation Graph Expansion
  checks.push({
    id: "obligation-graph-tarpit",
    name: "Local Decoy and Graph Indicators",
    targetReaComponent: "trace_application_feature / build_reconstruction_obligation_ledger",
    evidenceBasis: "local-heuristic",
    status: "not-run",
    passed: false,
    heuristicMatched: sim.decoyFunctionsDetectedAsReal >= 5 && sim.obligationLedgerNodes >= 15,
    details: `Injected ${sim.decoyFunctionsDetectedAsReal} decoy tarpit nodes (${sim.obligationLedgerNodes} total obligation ledger nodes)`,
  });

  // Check 3: Architectural Chaff & Enclave Delegation Mirage
  checks.push({
    id: "architectural-chaff-mirage",
    name: "Local Chaff Markers",
    targetReaComponent: "Context Window / Evidence Dossier Summarizer",
    evidenceBasis: "local-heuristic",
    status: "not-run",
    passed: false,
    heuristicMatched: sim.architecturalChaffPayloads >= 2,
    details: `${sim.architecturalChaffPayloads} enclave delegation & honey-contract payload markers found`,
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
      evidenceBasis: "local-heuristic",
      status: "not-run",
      passed: false,
      heuristicMatched:
        sim.ipcChannelsPairedUniquely === 0 &&
        (sim.ipcChannelsAmbiguousOrDynamic > 0 || sim.decoyRoutesHarvested > 0),
      details: `Uniquely paired IPC channels: ${sim.ipcChannelsPairedUniquely}; Ambiguous/Dynamic IPC sites: ${sim.ipcChannelsAmbiguousOrDynamic}; Decoy routes: ${sim.decoyRoutesHarvested}`,
    });
  } else {
    checks.push({
      id: "binary-container-shield",
      name: "Binary Container & Custom Section Shield",
      targetReaComponent: `inspect_${afterAudit.detectedFormat.replace("-", "_")}`,
      evidenceBasis: "local-heuristic",
      status: "not-run",
      passed: false,
      heuristicMatched: afterAudit.protectionStatus === "BLA_PROTECTED",
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
    name: "Hypothetical Token Amplification Indicator",
    targetReaComponent: "MCP Context Window & Retained Evidence Paging",
    evidenceBasis: "local-heuristic",
    status: "not-run",
    passed: false,
    heuristicMatched: tokenAmp >= 10 || afterEst.estimatedInputTokens >= 80_000,
    details: `Hypothetical token amplification: ${tokenAmp}x (${afterEst.estimatedInputTokens.toLocaleString()} tokens, ~$${afterEst.estimatedCostUsd.toFixed(2)})`,
  });

  const passedCount = checks.filter((c) => c.heuristicMatched).length;
  const defenseScore = Math.round(
    (passedCount / checks.length) * 70 + Math.max(0, (100 - afterAudit.exposureScore) * 0.3),
  );

  return {
    targetPath: absTarget,
    ...(originalPath ? { originalPath: resolve(originalPath) } : {}),
    detectedFormat: afterAudit.detectedFormat,
    evidenceBasis: "local-heuristic",
    verificationStatus: "unverified",
    functionalIntegrityStatus: "not-run",
    baselineBasis: beforeAudit ? "original-artifact-estimate" : "assumed-default",
    heuristicChecksPassed: passedCount === checks.length,
    overallPassed: false,
    defenseScore: Math.min(100, defenseScore),
    checks,
    tokenAmplificationFactor: tokenAmp,
    costAmplificationFactor: costAmp,
    obligationGraphExpansionFactor: graphAmp,
    functionalIntegrityVerified: false,
  };
}
