import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateHardenProjectPackagingBlocks } from "../src/engine/packaging-gates.js";
import { hardenProject } from "../src/engine/harden.js";

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/**
 * A build output with a literal that the plaintext-secret gate refuses on.
 * The gate's walker only lints entitlement-shaped basenames (`license`, `gate`,
 * `auth`, ...), so the artifact is named `license.cjs` rather than `app.cjs`.
 */
const PLAINTEXT_SECRET = `const flag = "FLAG{bla_lint_gate_fixture_not_the_prize}";\nmodule.exports = { flag };\n`;

function project(): string {
  const dir = tempDir("bla-lint-gates-");
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "lint-gates", version: "1.0.0", main: "dist/license.cjs" }),
    "utf8",
  );
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "dist", "license.cjs"), PLAINTEXT_SECRET, "utf8");
  return dir;
}

/**
 * `plaintext-secret`, `integrity-coverage` and `bind-scope` are lint-only gates:
 * `bla lint` refuses on them, `harden` deliberately did not. A pipeline that
 * treats `harden` as its release gate therefore had no way to gate on them.
 * `requireLintGates` opts in without changing the default for anyone else.
 */
describe("harden requireLintGates", () => {
  it("the plaintext gate is reported but not enforced by default", () => {
    const dir = project();
    const blocks = evaluateHardenProjectPackagingBlocks({ directory: dir, intensity: "bankrupt" });
    expect(blocks.report.details.plaintextSecrets.some((r) => r.shouldRefuseBankrupt)).toBe(true);
    expect(blocks.blockingPlaintextSecrets).toHaveLength(0);
    expect(blocks.report.findings.some((f) => f.gate === "plaintext-secret")).toBe(true);
    expect(
      blocks.report.findings
        .filter((f) => f.gate === "plaintext-secret")
        .every((f) => f.enforcedByHarden === false),
    ).toBe(true);
  });

  it("marks the gate enforced only when the caller opts in", () => {
    const dir = project();
    const blocks = evaluateHardenProjectPackagingBlocks({
      directory: dir,
      intensity: "bankrupt",
      requireLintGates: true,
    });
    expect(blocks.blockingPlaintextSecrets.length).toBeGreaterThan(0);
    expect(
      blocks.report.findings
        .filter((f) => f.gate === "plaintext-secret")
        .some((f) => f.enforcedByHarden === true),
    ).toBe(true);
  });

  it("harden succeeds by default and refuses once it is asked to gate", () => {
    const dir = project();
    const options = {
      directory: dir,
      intensity: "bankrupt" as const,
      seed: "lint-gate-seed",
    };

    const lenient = hardenProject(options);
    expect(lenient.overallSuccess).toBe(true);

    const strict = hardenProject({ ...options, requireLintGates: true });
    expect(strict.overallSuccess).toBe(false);
    expect(strict.hardenedCount).toBe(0);
    expect(strict.artifacts.map((a) => a.error ?? "").join("\n")).toMatch(
      /Plaintext sensitive literals/,
    );
  });

  it("an explicit allow flag still wins over the opt-in", () => {
    const dir = project();
    const blocks = evaluateHardenProjectPackagingBlocks({
      directory: dir,
      intensity: "bankrupt",
      requireLintGates: true,
      allowPlaintextString: true,
    });
    expect(blocks.blockingPlaintextSecrets).toHaveLength(0);
  });
});
