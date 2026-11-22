import { describe, expect, it } from "vitest";
import { formatBenchmarkReport } from "../src/ui/reporter.js";
import type { BenchmarkReport, ShowcaseCaseResult } from "../src/core/types.js";

const ANSI_RE = /\x1b\[[0-9;]*m/g;

function makeCase(functionalCheckPassed: boolean): ShowcaseCaseResult {
  return {
    id: "showcase-js-1",
    title: "js-showcase",
    reaShowcaseReference: "rea://showcase/js",
    format: "javascript",
    before: {
      exposureScore: 100,
      examinationStatus: "complete",
      obligationNodes: 4,
      estimatedTokens: 1_000,
      estimatedCostUsd: 0.01,
      estimatedSeconds: 1,
      agentOutcome: "TRIVIAL_CLONE",
    },
    after: {
      exposureScore: 0,
      examinationStatus: "limited",
      triggeredLimits: ["candidate-limit"],
      obligationNodes: 20,
      estimatedTokens: 2_000,
      estimatedCostUsd: 0.02,
      estimatedSeconds: 1,
      agentOutcome: "AGENT_HALLUCINATION_AND_BANKRUPTCY",
    },
    tokenMultiplier: 2,
    costMultiplier: 2,
    functionalCheckPassed,
  };
}

function bench(cases: ShowcaseCaseResult[]): BenchmarkReport {
  return {
    timestamp: "2026-11-22T00:00:00Z",
    blaVersion: "0.0.0-test",
    cases,
    aggregateTokenMultiplier: 2,
    aggregateCostMultiplier: 2,
  } as BenchmarkReport;
}

function footer(bench: BenchmarkReport): string {
  const rendered = formatBenchmarkReport(bench);
  const lines = rendered.split("\n");
  return lines[lines.length - 1]!.replace(ANSI_RE, "");
}

describe("benchmark footer honesty", () => {
  it("does not claim 100% equivalence when a case failed", () => {
    const out = footer(bench([makeCase(true), makeCase(false)]));
    expect(out).not.toContain("100% Runtime-Equivalent");
    expect(out).toContain("1 of 2");
  });

  it("keeps the 100% claim when every case passed", () => {
    const out = footer(bench([makeCase(true), makeCase(true)]));
    expect(out).toContain("100% Runtime-Equivalent");
  });
});
