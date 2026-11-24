import { describe, expect, it } from "vitest";
import type {
  AuditReport,
  BenchmarkReport,
  VerificationReport,
} from "../src/core/types.js";
import type { SetupRunResult } from "../src/setup/setup.js";
import {
  formatAuditReport,
  formatBenchmarkReport,
  formatSetupReport,
  formatVerificationReport,
} from "../src/ui/reporter.js";

const estimate = {
  modelName: "Claude Opus 4",
  estimatedInputTokens: 1000,
  estimatedOutputTokens: 0,
  estimatedMcpToolCalls: 1,
  estimatedWallClockSeconds: 1,
  estimatedCostUsd: 0.01,
  contextWindowOverflowProbability: 0,
  outcomeVerdict: "TRIVIAL_CLONE" as const,
};

const simulation = {
  parseStatus: "complete" as const,
  examinationStatus: "complete" as const,
  triggeredResourceLimits: [] as string[],
  semanticUncertainties: [] as string[],
  visitedAstNodes: 0,
  totalFunctions: 0,
  decoyFunctionsDetectedAsReal: 0,
  staticStringsResolved: 0,
  staticStringsOpaque: 0,
  ipcChannelsTotal: 0,
  ipcChannelsPairedUniquely: 0,
  ipcChannelsAmbiguousOrDynamic: 0,
  routesDiscovered: 0,
  decoyRoutesHarvested: 0,
  obligationLedgerNodes: 1,
  architecturalChaffPayloads: 0,
};

describe("reporter branches", () => {
  it("renders the partial-shield warning, walk skips, and audited items", () => {
    const report = {
      targetPath: "app.js",
      detectedFormat: "javascript",
      sha256: "a".repeat(64),
      byteSize: 1,
      timestamp: "2026-01-01T00:00:00.000Z",
      exposureScore: 40,
      protectionStatus: "PARTIALLY_SHIELDED",
      reaSimulation: simulation,
      exposedItems: [{ name: "gate", kind: "function", riskLevel: "critical", reason: "plain gate" }],
      vulnerableReaVectors: [],
      agentEstimates: [estimate],
      headlineWarning: "partial shield warning",
      recommendedCommand: "bla protect app.js",
      walkSkipped: { files: 1, directories: 2, bytes: 3 },
    } as unknown as AuditReport;
    const out = formatAuditReport(report);
    expect(out).toContain("Walk Skipped");
    expect(out).toContain("Top Audited Surface Items");
    expect(out).toContain("partial shield warning");
  });

  it("renders the protected branch without a fix-now command", () => {
    const report = {
      targetPath: "app.js",
      detectedFormat: "javascript",
      sha256: "a".repeat(64),
      byteSize: 1,
      timestamp: "2026-01-01T00:00:00.000Z",
      exposureScore: 2,
      protectionStatus: "BLA_PROTECTED",
      reaSimulation: simulation,
      exposedItems: [],
      vulnerableReaVectors: [],
      agentEstimates: [estimate],
      headlineWarning: "protected",
      recommendedCommand: "bla protect app.js",
    } as unknown as AuditReport;
    const out = formatAuditReport(report);
    expect(out).toContain("✅ protected");
    expect(out).not.toContain("Fix now:");
  });

  it("renders verification honesty caps and known gaps", () => {
    const report = {
      targetPath: "app.js",
      detectedFormat: "javascript",
      overallPassed: false,
      defenseScore: 70,
      defenseScoreRaw: 90,
      defenseScoreGaps: [{ id: "gap", summary: "known gap", scoreCap: 70 }],
      checks: [
        { id: "c1", name: "counter-rea", targetReaComponent: "rea", passed: true, details: "ok" },
      ],
      tokenAmplificationFactor: 2,
      costAmplificationFactor: 3,
      obligationGraphExpansionFactor: 4,
      functionalIntegrityVerified: false,
    } as unknown as VerificationReport;
    const out = formatVerificationReport(report);
    expect(out).toContain("Honesty cap:");
    expect(out).toContain("Known gaps (score honesty):");
    expect(out).toContain("✓ PASS");
  });

  it("derives the benchmark footer from failed cases", () => {
    const base = {
      title: "case",
      reaShowcaseReference: "rea",
      format: "javascript",
      before: {
        exposureScore: 80,
        examinationStatus: "complete",
        obligationNodes: 1,
        estimatedTokens: 1000,
        estimatedCostUsd: 0.1,
        estimatedSeconds: 1,
        agentOutcome: "TRIVIAL_CLONE",
      },
      after: {
        exposureScore: 2,
        examinationStatus: "limited",
        triggeredLimits: [],
        obligationNodes: 1,
        estimatedTokens: 1000,
        estimatedCostUsd: 0.1,
        estimatedSeconds: 1,
        agentOutcome: "AGENT_HALLUCINATION_AND_BANKRUPTCY",
      },
      tokenMultiplier: 1,
      costMultiplier: 1,
    };
    const report = {
      timestamp: "2026-01-01T00:00:00.000Z",
      blaVersion: "3.5.9",
      cases: [
        { ...base, id: "a", functionalCheckPassed: true },
        { ...base, id: "b", functionalCheckPassed: false },
      ],
      aggregateTokenMultiplier: 1,
      aggregateCostMultiplier: 1,
    } as unknown as BenchmarkReport;
    expect(formatBenchmarkReport(report)).toContain("1 of 2 runtime checks failed");
  });

  it("marks a preserved disabled MCP registration in setup output", () => {
    const report = {
      status: "applied",
      message: "done",
      actions: [
        {
          displayName: "Claude Code",
          clientId: "claude_code",
          status: "applied",
          applied: true,
          mcpEnabled: false,
          configPath: "/tmp/config.json",
          skillPath: "/tmp/SKILL.md",
          mcpCommand: "npx",
          mcpArgs: [],
        },
      ],
      results: [],
      discoveredClients: [],
      explicitClients: [],
      selectionMode: "explicit",
      manifestPath: null,
    } as unknown as SetupRunResult;
    expect(formatSetupReport(report)).toContain("DISABLED (preserved)");
  });
});