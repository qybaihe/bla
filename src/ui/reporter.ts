import { BLA_IDENTITY } from "../identity.js";
import type {
  AuditReport,
  BenchmarkReport,
  ProtectionResult,
  VerificationReport,
} from "../core/types.js";
import type { DoctorDiagnosticReport } from "../setup/doctor.js";
import type { SetupRunResult } from "../setup/setup.js";

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
};

export function formatBanner(): string {
  return [
    `${ANSI.bold}${ANSI.cyan}╔══════════════════════════════════════════════════════════════════════════════╗${ANSI.reset}`,
    `${ANSI.bold}${ANSI.cyan}║  🛡️  BLA: Blind LLM Agents (${BLA_IDENTITY.packageName} v${BLA_IDENTITY.version})                             ║${ANSI.reset}`,
    `${ANSI.bold}${ANSI.cyan}║  ${ANSI.yellow}Poison -> Exhaust -> Hallucinate. Make Reverse Engineering Bankrupt Again.${ANSI.cyan}  ║${ANSI.reset}`,
    `${ANSI.bold}${ANSI.cyan}╚══════════════════════════════════════════════════════════════════════════════╝${ANSI.reset}`,
  ].join("\n");
}

export function formatAuditReport(report: AuditReport): string {
  const statusColor =
    report.protectionStatus === "BLA_PROTECTED"
      ? ANSI.green
      : report.protectionStatus === "PARTIALLY_SHIELDED"
        ? ANSI.yellow
        : ANSI.red;

  const est = report.agentEstimates[0]!;
  const lines: string[] = [
    formatBanner(),
    "Evidence: local heuristics and hypothetical estimates; REA/LLM not executed. Runtime integrity is unverified unless a bounded sample check is stated.",
    "",
    `${ANSI.bold}Target Artifact:${ANSI.reset}    ${report.targetPath}`,
    `${ANSI.bold}Detected Format:${ANSI.reset}    ${ANSI.cyan}${report.detectedFormat}${ANSI.reset} (${report.byteSize.toLocaleString()} bytes, sha256: ${report.sha256.slice(0, 16)}...)`,
    `${ANSI.bold}Protection Status:${ANSI.reset}  ${statusColor}${ANSI.bold}${report.protectionStatus}${ANSI.reset} (Heuristic Exposure Score: ${statusColor}${report.exposureScore}/100${ANSI.reset})`,
    `${ANSI.bold}Simulated Examination:${ANSI.reset}    ${report.reaSimulation.examinationStatus === "limited" ? `${ANSI.green}LIMITED (local indicators)${ANSI.reset}` : `${ANSI.red}COMPLETE (local inspection)${ANSI.reset}`}`,
  ];

  if (report.reaSimulation.triggeredResourceLimits.length > 0) {
    lines.push(
      `${ANSI.bold}Inferred Limits:${ANSI.reset}   ${ANSI.green}${report.reaSimulation.triggeredResourceLimits.join(", ")}${ANSI.reset}`,
    );
  }

  lines.push(
    `${ANSI.bold}Obligation Graph:${ANSI.reset}   ${report.reaSimulation.obligationLedgerNodes} nodes (${report.reaSimulation.decoyFunctionsDetectedAsReal} decoy tarpit nodes, ${report.reaSimulation.architecturalChaffPayloads} chaff manifests)`,
    "",
    `${ANSI.bold}${ANSI.magenta}── Hypothetical Cost Scenario (fixed assumptions, not measured) ───────────────────────────${ANSI.reset}`,
  );

  for (const agent of report.agentEstimates) {
    const verdictColor = ANSI.yellow;
    lines.push(
      `  • ${ANSI.bold}${agent.modelName.padEnd(42)}${ANSI.reset} | Tokens: ${agent.estimatedInputTokens.toLocaleString().padStart(9)} | Calls: ${String(agent.estimatedMcpToolCalls).padStart(3)} | Time: ${String(agent.estimatedWallClockSeconds + "s").padStart(5)} | Cost: ${ANSI.bold}$${agent.estimatedCostUsd.toFixed(2).padStart(6)}${ANSI.reset} | ${verdictColor}${agent.outcomeVerdict}${ANSI.reset}`,
    );
  }

  lines.push("");
  if (report.protectionStatus !== "BLA_PROTECTED") {
    lines.push(
      `${ANSI.bold}${ANSI.red}⚠️  ${report.headlineWarning}${ANSI.reset}`,
    );
    lines.push(
      `   ${ANSI.bold}Fix now:${ANSI.reset} ${ANSI.cyan}${report.recommendedCommand}${ANSI.reset}`,
    );
  } else {
    lines.push(`${ANSI.bold}${ANSI.green}✅ ${report.headlineWarning}${ANSI.reset}`);
  }

  if (est && report.exposedItems.length > 0) {
    lines.push(
      "",
      `${ANSI.bold}Top Audited Surface Items (${Math.min(6, report.exposedItems.length)} of ${report.exposedItems.length}):${ANSI.reset}`,
    );
    for (const item of report.exposedItems.slice(0, 6)) {
      const badge = item.riskLevel === "critical" ? `${ANSI.red}[CRITICAL]${ANSI.reset}` : `${ANSI.green}[SHIELDED]${ANSI.reset}`;
      lines.push(`  ${badge} ${ANSI.bold}${item.name}${ANSI.reset} (${item.kind}) — ${item.reason}`);
    }
  }

  return lines.join("\n");
}

export function formatProtectionResult(res: ProtectionResult): string {
  const bEst = res.beforeAudit.agentEstimates[0]!;
  const aEst = res.afterAudit.agentEstimates[0]!;
  const tokenMult = (aEst.estimatedInputTokens / Math.max(1, bEst.estimatedInputTokens)).toFixed(1);
  const costMult = (aEst.estimatedCostUsd / Math.max(0.01, bEst.estimatedCostUsd)).toFixed(1);

  return [
    formatBanner(),
    "Evidence: local heuristics and hypothetical estimates; REA/LLM not executed. Runtime integrity is unverified unless a bounded sample check is stated.",
    "",
    `${ANSI.bold}${ANSI.green}🛡️  BLA Adversarial Shield Successfully Injected!${ANSI.reset} (${res.elapsedMs} ms)`,
    "",
    `  ${ANSI.bold}Input Target:${ANSI.reset}      ${res.inputPath}`,
    `  ${ANSI.bold}Protected Output:${ANSI.reset}  ${ANSI.cyan}${res.outputPath}${ANSI.reset}`,
    `  ${ANSI.bold}Format / Preset:${ANSI.reset}   ${res.detectedFormat} / ${ANSI.magenta}${res.intensity}${ANSI.reset} (seed: ${res.seed})`,
    "",
    `${ANSI.bold}${ANSI.yellow}── Counter-REA Defense Metrics ─────────────────────────────────────────────────${ANSI.reset}`,
    `  • Decoy Tarpit Functions Injected:    ${ANSI.bold}${res.metrics.decoyFunctionsInjected}${ANSI.reset} (${res.metrics.fakeCrossReferencesCreated} fake cross-references)`,
    `  • Primitive Candidate Branches:       ${ANSI.bold}${res.metrics.primitiveCandidateBranchesCreated}${ANSI.reset} (> REA's 256 candidate limit)`,
    `  • Alias Selection States:             ${ANSI.bold}${res.metrics.aliasSelectionStatesCreated.toLocaleString()}${ANSI.reset} (> REA's 512 state limit)`,
    `  • IPC Ambiguity Sites / Decoy Routes: ${ANSI.bold}${res.metrics.ipcAmbiguitySitesInjected}${ANSI.reset} IPC sites / ${ANSI.bold}${res.metrics.decoyRoutesInjected}${ANSI.reset} decoy routes`,
    `  • Enclave Chaff Manifests Embedded:   ${ANSI.bold}${res.metrics.chaffPayloadsEmbedded}${ANSI.reset}`,
    "",
    `${ANSI.bold}${ANSI.cyan}── Before vs. After Hypothetical Scenario (not a REA run) ──────────────────────${ANSI.reset}`,
    `  • Heuristic Exposure Score:       ${ANSI.red}${res.beforeAudit.exposureScore}/100 (${res.beforeAudit.protectionStatus})${ANSI.reset}  -->  ${ANSI.green}${ANSI.bold}${res.afterAudit.exposureScore}/100 (${res.afterAudit.protectionStatus})${ANSI.reset}`,
    `  • Simulated Examination Status:   ${ANSI.red}${res.beforeAudit.reaSimulation.examinationStatus.toUpperCase()}${ANSI.reset}                   -->  ${ANSI.green}${ANSI.bold}${res.afterAudit.reaSimulation.examinationStatus.toUpperCase()} (${res.afterAudit.reaSimulation.triggeredResourceLimits.join(", ")})${ANSI.reset}`,
    `  • Obligation Graph Nodes:   ${res.beforeAudit.reaSimulation.obligationLedgerNodes} nodes                    -->  ${ANSI.bold}${res.afterAudit.reaSimulation.obligationLedgerNodes} nodes${ANSI.reset}`,
    `  • Projected Tokens:      ${bEst.estimatedInputTokens.toLocaleString()} tokens                -->  ${ANSI.yellow}${ANSI.bold}${aEst.estimatedInputTokens.toLocaleString()} tokens (${tokenMult}x amplification)${ANSI.reset}`,
    `  • Projected Cost:        $${bEst.estimatedCostUsd.toFixed(2)}                      -->  ${ANSI.yellow}${ANSI.bold}$${aEst.estimatedCostUsd.toFixed(2)} (${costMult}x scenario multiplier)${ANSI.reset}`,
    `  • Observed Agent Outcome:            ${ANSI.red}${bEst.outcomeVerdict}${ANSI.reset}              -->  ${ANSI.green}${ANSI.bold}${aEst.outcomeVerdict}${ANSI.reset}`,
  ].join("\n");
}

export function formatVerificationReport(report: VerificationReport): string {
  const lines: string[] = [
    formatBanner(),
    "Evidence: local heuristics and hypothetical estimates; REA/LLM not executed. Runtime integrity is unverified unless a bounded sample check is stated.",
    "",
    `${ANSI.bold}Verification Target:${ANSI.reset} ${report.targetPath}`,
    `${ANSI.bold}Heuristic Score:${ANSI.reset}       ${report.overallPassed ? ANSI.green : ANSI.yellow}${ANSI.bold}${report.defenseScore}/100${ANSI.reset} (UNVERIFIED — empirical checks not run)`,
    `${ANSI.bold}Projected Amplification:${ANSI.reset}       ${ANSI.cyan}${report.tokenAmplificationFactor}x tokens${ANSI.reset} | ${ANSI.cyan}${report.costAmplificationFactor}x API cost${ANSI.reset} | ${ANSI.cyan}${report.obligationGraphExpansionFactor}x call-graph expansion${ANSI.reset}`,
    "",
    `Baseline: ${report.baselineBasis}; functional integrity: ${report.functionalIntegrityStatus}`,
    `${ANSI.bold}Local Heuristic Indicators (not empirical verification):${ANSI.reset}`,
  ];

  for (const check of report.checks) {
    const icon = `${ANSI.yellow}NOT RUN; heuristic ${check.heuristicMatched ? "matched" : "not matched"}${ANSI.reset}`;
    lines.push(`  [${icon}] ${ANSI.bold}${check.name}${ANSI.reset} (${ANSI.dim}${check.targetReaComponent}${ANSI.reset})`);
    lines.push(`         ${check.details}`);
  }

  return lines.join("\n");
}

export function formatBenchmarkReport(bench: BenchmarkReport): string {
  const lines: string[] = [
    formatBanner(),
    "Evidence: local heuristics and hypothetical estimates; REA/LLM not executed. Runtime integrity is unverified unless a bounded sample check is stated.",
    "",
    `${ANSI.bold}${ANSI.magenta}⚡ BLA — ${bench.cases.length} Synthetic Fixtures (not a REA/LLM benchmark)${ANSI.reset}`,
    "",
    `${ANSI.bold}Showcase Target                          | Before (projected)        | After (projected)       | Token Mult | Runtime Check${ANSI.reset}`,
    `─────────────────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────┼────────────┼──────────────`,
  ];

  for (const c of bench.cases) {
    const beforeCol = `${String(c.before.exposureScore).padStart(2)}/100 | ${c.before.estimatedTokens.toLocaleString().padStart(6)} tok | $${c.before.estimatedCostUsd.toFixed(2).padStart(5)}`;
    const afterCol = `${ANSI.green}${String(c.after.exposureScore).padStart(2)}/100 | ${c.after.estimatedTokens.toLocaleString().padStart(7)} tok | $${c.after.estimatedCostUsd.toFixed(2).padStart(6)} | ${c.after.examinationStatus.toUpperCase()} (simulated)${ANSI.reset}`;
    const multCol = `${ANSI.yellow}${ANSI.bold}${String(c.tokenMultiplier + "x").padStart(8)}${ANSI.reset}`;
    const fnCol = c.functionalCheckStatus === "not-run" ? `${ANSI.yellow}NOT RUN${ANSI.reset}` : c.functionalCheckPassed ? `${ANSI.green}SAMPLE PASSED${ANSI.reset}` : `${ANSI.red}SAMPLE FAILED${ANSI.reset}`;
    lines.push(
      `${c.title.padEnd(40)} | ${beforeCol.padEnd(29)} | ${afterCol} | ${multCol}   | ${fnCol}`,
    );
    lines.push(`  Scope: ${c.functionalCheckScope}`);
  }

  lines.push(
    `─────────────────────────────────────────┴───────────────────────────────┴──────────────────────────────────────────┴────────────┴──────────────`,
    `${ANSI.bold}Aggregate Projected Token Amplification:${ANSI.reset} ${ANSI.yellow}${ANSI.bold}${bench.aggregateTokenMultiplier}x${ANSI.reset}   |   ${ANSI.bold}Aggregate Cost Multiplier:${ANSI.reset} ${ANSI.yellow}${ANSI.bold}${bench.aggregateCostMultiplier}x${ANSI.reset}   |   ${ANSI.green}${ANSI.bold}Bounded runtime samples: ${bench.cases.filter((c) => c.functionalCheckStatus === "passed").length}/${bench.cases.length} passed; no general equivalence or REA resistance claim${ANSI.reset}`,
  );

  return lines.join("\n");
}

export function formatDoctorReport(doc: DoctorDiagnosticReport): string {
  const lines: string[] = [
    formatBanner(),
    "",
    `${ANSI.bold}BLA Doctor Readiness:${ANSI.reset} ${ANSI.green}HEALTHY${ANSI.reset} (v${doc.blaVersion} on Node ${doc.nodeVersion}, ${doc.platform})`,
    "",
    `${ANSI.bold}Protection Subsystems:${ANSI.reset}`,
    `  • JavaScript/TypeScript AST & Semantic Budget Breaker: ${ANSI.green}${doc.engines.javascriptAstShield}${ANSI.reset}`,
    `  • Electron .asar Unpacker & Integrity Repacker:        ${ANSI.green}${doc.engines.electronAsarPacker}${ANSI.reset}`,
    `  • WebAssembly (.wasm) Custom & Name Section Shield:    ${ANSI.green}${doc.engines.wasmBinaryShield}${ANSI.reset}`,
    `  • Python (.py / CPython .pyc) Marshal Tarpit Shield:   ${ANSI.green}${doc.engines.pythonPycMarshalShield}${ANSI.reset}`,
    `  • Native Binary (ELF / Mach-O / PE) Section Shield:    ${ANSI.green}${doc.engines.nativeElfMachoPeShield}${ANSI.reset}`,
    `  • Archive (ZIP / Android APK) Enclave Shield:          ${ANSI.green}${doc.engines.zipApkArchiveShield}${ANSI.reset}`,
    "",
    `${ANSI.bold}Detected Coding Agent Integrations:${ANSI.reset}`,
  ];

  for (const c of doc.agentClients) {
    const det = c.detected ? `${ANSI.green}detected${ANSI.reset}` : `${ANSI.dim}not found${ANSI.reset}`;
    const mcp = c.mcpRegistered ? `${ANSI.green}MCP registered${ANSI.reset}` : `${ANSI.yellow}MCP not registered${ANSI.reset}`;
    const skill = c.skillInstalled ? `${ANSI.green}Skill installed${ANSI.reset}` : `${ANSI.dim}Skill not installed${ANSI.reset}`;
    lines.push(`  • ${c.displayName.padEnd(22)} (${c.id.padEnd(15)}) : ${det} | ${mcp} | ${skill}`);
  }

  return lines.join("\n");
}

export function formatSetupReport(res: SetupRunResult): string {
  const lines: string[] = [
    formatBanner(),
    "",
    `${ANSI.bold}Setup Status:${ANSI.reset} ${res.status === "applied" ? `${ANSI.green}APPLIED${ANSI.reset}` : `${ANSI.yellow}PLANNED (Preview)${ANSI.reset}`}`,
    `  ${res.message}`,
    "",
    `${ANSI.bold}Agent Registrations (${res.actions.length}):${ANSI.reset}`,
  ];

  for (const a of res.actions) {
    lines.push(`  • ${ANSI.bold}${a.displayName}${ANSI.reset} (${a.clientId})`);
    lines.push(`      Config: ${a.configPath}`);
    lines.push(`      Skill:  ${a.skillPath}`);
    lines.push(`      MCP:    ${a.mcpCommand} ${a.mcpArgs.join(" ")}`);
  }

  return lines.join("\n");
}
