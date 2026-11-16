import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import {
  buildPackagingGatesSarif,
  scanPackagingGates,
} from "../src/engine/packaging-gates.js";

const SECRET_ENTRY = `module.exports.unlock = function unlock(key) {
  const flag = "FLAG{lint_sarif_fixture}";
  return key === "ok" ? flag : null;
};
`;

async function runCliCapturingStdout(args: string[]) {
  const lines: string[] = [];
  const original = console.log;
  console.log = (...parts: unknown[]) => {
    lines.push(parts.map(String).join(" "));
  };
  try {
    const code = await runCli(args);
    return { code, stdout: lines.join("\n") };
  } finally {
    console.log = original;
  }
}

describe("bla lint SARIF 2.1.0 output", () => {
  it("maps packaging-gate findings onto SARIF rules and results", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-lint-sarif-"));
    try {
      writeFileSync(join(dir, "license.cjs"), SECRET_ENTRY, "utf8");
      const report = scanPackagingGates({
        directory: dir,
        intensity: "bankrupt",
        includeProtectTimeGates: true,
      });
      expect(report.shouldRefuseBankrupt).toBe(true);

      const sarif = buildPackagingGatesSarif(report);

      expect(sarif.version).toBe("2.1.0");
      expect(sarif.$schema).toContain("sarif-2.1.0.json");
      expect(sarif.runs[0].tool.driver.name).toBe("bla-agents");
      expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(0);

      const refusals = sarif.runs[0].results.filter((r) => r.level === "error");
      expect(refusals.length).toBeGreaterThan(0);
      expect(refusals[0]!.ruleId).toMatch(/^BLA-LINT-/);
      for (const result of sarif.runs[0].results) {
        const uri = result.locations[0].physicalLocation.artifactLocation.uri;
        expect(uri).not.toContain("\\");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("emits SARIF from `bla lint --sarif`", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-lint-sarif-cli-"));
    try {
      writeFileSync(join(dir, "license.cjs"), SECRET_ENTRY, "utf8");
      const { code, stdout } = await runCliCapturingStdout([
        "lint",
        dir,
        "--intensity",
        "bankrupt",
        "--sarif",
      ]);

      expect(code).toBe(2);
      const sarif = JSON.parse(stdout) as {
        version: string;
        runs: readonly { results: readonly { ruleId: string }[] }[];
      };
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs[0]!.results.length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});