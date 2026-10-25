import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { estimateAgentReverseEngineeringCosts } from "../src/core/token-estimator.js";
import { auditTarget } from "../src/engine/auditor.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { runShowcaseBenchmark } from "../src/engine/benchmark.js";
import { runCli } from "../src/cli.js";
import { formatAuditReport, formatBenchmarkReport, formatVerificationReport } from "../src/ui/reporter.js";

describe("evidence semantics", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "bla-evidence-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); vi.restoreAllMocks(); });

  it("never infers functional equivalence from successfully parsed but different programs", () => {
    const original = join(dir, "original.js");
    const changed = join(dir, "changed.js");
    writeFileSync(original, "module.exports = () => 42;");
    writeFileSync(changed, "module.exports = () => { throw new Error('changed behavior'); };");
    expect(auditTarget(changed).reaSimulation.parseStatus).toBe("complete");
    const report = verifyTarget(changed, original);
    expect(report.functionalIntegrityVerified).toBe(false);
    expect(report.functionalIntegrityStatus).toBe("not-run");
    expect(report.overallPassed).toBe(false);
    expect(report.verificationStatus).toBe("unverified");
    expect(report.baselineBasis).toBe("original-artifact-estimate");
    expect(report.checks.every((c) => c.status === "not-run" && !c.passed)).toBe(true);
    expect(formatVerificationReport(report)).toContain("UNVERIFIED");
    expect(formatVerificationReport(report)).not.toContain("✓ PASS");
  });

  it("does not mark unknown formats or missing original baselines as verified", () => {
    const target = join(dir, "unknown.bin");
    writeFileSync(target, Buffer.from([0, 1, 2, 3]));
    expect(() => verifyTarget(target)).toThrow("unsupported format");
    const known = join(dir, "known.js");
    writeFileSync(known, "module.exports = 42;");
    const report = verifyTarget(known);
    expect(report.baselineBasis).toBe("assumed-default");
    expect(report.functionalIntegrityVerified).toBe(false);
    expect(report.overallPassed).toBe(false);
    expect(report.checks.every((c) => !c.passed)).toBe(true);
  });

  it("does not invent agent outcomes or calibrated probabilities", () => {
    const target = join(dir, "simple.js");
    writeFileSync(target, "module.exports = () => 42;");
    const audit = auditTarget(target);
    expect(audit.evidenceBasis).toBe("local-heuristic");
    expect(audit.reaExecuted).toBe(false);
    expect(audit.agentExecuted).toBe(false);
    const shieldedScenario = estimateAgentReverseEngineeringCosts({ ...audit.reaSimulation, examinationStatus: "limited" }, audit.byteSize);
    for (const estimate of [...audit.agentEstimates, ...shieldedScenario]) {
      expect(estimate.evidenceBasis).toBe("hypothetical-estimate");
      expect(estimate.assumptions).toContain("not calibrated");
      expect(estimate.contextWindowOverflowProbability).toBeNull();
      expect(estimate.outcomeVerdict).toBe("NOT_MEASURED");
    }
    expect(formatAuditReport(audit)).toContain("Hypothetical Cost Scenario");
    expect(formatAuditReport(audit)).not.toContain("100% Exposed");
  });

  it("returns a non-success verification exit code for parseable input, including JSON mode", async () => {
    const target = join(dir, "simple.js");
    writeFileSync(target, "module.exports = 42;");
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    expect(await runCli(["verify", target, "--json"])).toBe(2);
    const report = JSON.parse(log.mock.calls[0]![0] as string);
    expect(report.overallPassed).toBe(false);
    expect(report.functionalIntegrityStatus).toBe("not-run");
  });

  it("bounds real fixture samples and distinguishes omitted checks from failures", async () => {
    const report = await runShowcaseBenchmark();
    expect(report.reaExecuted).toBe(false);
    expect(report.agentExecuted).toBe(false);
    expect(report.evidenceBasis).toBe("synthetic-fixtures-and-hypothetical-estimates");
    expect(report.cases.filter((c) => c.functionalCheckStatus === "passed").map((c) => c.id))
      .toEqual(["dx-ball", "license-guard", "wasm-core"]);
    expect(report.cases.filter((c) => c.functionalCheckStatus === "not-run")).toHaveLength(5);
    for (const c of report.cases) {
      expect(c.functionalCheckPassed).toBe(c.functionalCheckStatus === "passed");
      expect(c.functionalCheckScope.length).toBeGreaterThan(20);
      expect(c.before.agentOutcome).toBe("NOT_MEASURED");
      expect(c.after.agentOutcome).toBe("NOT_MEASURED");
    }
    expect(report.cases[0]!.functionalCheckScope).toContain("Two calculateSoundPan");
    const text = formatBenchmarkReport(report);
    expect(text).toContain("SAMPLE PASSED");
    expect(text).toContain("NOT RUN");
    expect(text).not.toContain("100% EXACT");
    expect(text).not.toContain("Runtime-Equivalent & REA-Resistant");
    const failedSample = { ...report.cases[0]!, functionalCheckPassed: false, functionalCheckStatus: "failed" as const };
    expect(formatBenchmarkReport({ ...report, cases: [failedSample] })).toContain("SAMPLE FAILED");
  });
});
