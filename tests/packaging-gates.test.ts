import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  PACKAGING_GATES_SCHEMA,
  evaluateHardenProjectPackagingBlocks,
  formatPackagingGatesReport,
  scanPackagingGates,
} from "../src/engine/packaging-gates.js";
import { buildTestWasmWithXorMaskSidecar } from "../src/engine/wasm-xor-mask-sidecar-lint.js";

describe("packaging-gates (unified R1–R7 scan)", () => {
  it("reports clean on an empty project tree", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-clean-"));
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    expect(report.schema).toBe(PACKAGING_GATES_SCHEMA);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toEqual([]);
    expect(report.honestyNote.length).toBeGreaterThan(20);
    expect(formatPackagingGatesReport(report)).toContain("no findings");
  });

  it("refuses bankrupt when a WASM XOR-mask sidecar is present", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-xor-"));
    writeFileSync(join(dir, "core.wasm"), buildTestWasmWithXorMaskSidecar());
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.blocking.some((b) => b.gate === "wasm-xor-mask-sidecar")).toBe(
      true,
    );
    const blocks = evaluateHardenProjectPackagingBlocks({
      directory: dir,
      intensity: "bankrupt",
    });
    expect(blocks.blockingWasmXorMask.length).toBeGreaterThan(0);
  });

  it("allow_wasm_xor_mask_sidecar clears project-level refuse", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-allow-"));
    writeFileSync(join(dir, "core.wasm"), buildTestWasmWithXorMaskSidecar());
    const blocks = evaluateHardenProjectPackagingBlocks({
      directory: dir,
      intensity: "bankrupt",
      allowWasmXorMaskSidecar: true,
    });
    expect(blocks.blockingWasmXorMask).toEqual([]);
  });

  it("surfaces lane-independence when includeProtectTimeGates", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-lane-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "gate.js"),
      `
const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];
function check(key) {
  return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]);
}
module.exports = { check };
`,
    );
    const report = scanPackagingGates({
      directory: dir,
      intensity: "bankrupt",
      includeProtectTimeGates: true,
    });
    expect(report.findings.some((f) => f.gate === "lane-independence")).toBe(true);
    expect(report.shouldRefuseBankrupt).toBe(true);
  });

  it("panel-derive: every recorded finding carries a truthful refuseMessage", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-panel-msg-"));
    writeFileSync(
      join(dir, "local-only.js"),
      `function deriveLocal(k) { return k; }\nconsole.log(deriveLocal("x"));\n`,
    );
    writeFileSync(
      join(dir, "stable-only.js"),
      `globalThis.__vaultPanelDerive_r3 = (s) => s;\nexport function use(sb) { return sb.__vaultPanelDerive_r3("x"); }\n`,
    );
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    const panelFindings = report.findings.filter((f) => f.gate === "panel-derive");
    expect(panelFindings.length).toBeGreaterThanOrEqual(2);

    // Recorded panel-derive findings must all carry remediation text.
    for (const f of panelFindings) {
      expect(f.refuseMessage, `missing refuseMessage for ${f.path}`).toBeTruthy();
    }

    // Local-only and stable-only findings are rewrite findings, not blockers:
    // they must not claim a refusal that filterBlockingFindings will not honor.
    const localOnly = panelFindings.find((f) =>
      f.relativePath.includes("local-only"),
    )!;
    expect(localOnly.shouldRefuseBankrupt).toBe(false);
    expect(localOnly.refuseMessage).not.toContain("Refusing bankrupt");
    expect(localOnly.refuseMessage).toContain("deriveLocal");

    const stableOnly = panelFindings.find((f) =>
      f.relativePath.includes("stable-only"),
    )!;
    expect(stableOnly.shouldRefuseBankrupt).toBe(false);
    expect(stableOnly.refuseMessage).not.toContain("Refusing bankrupt");
    expect(stableOnly.refuseMessage).toContain("__vaultPanelDerive_r3");
  });

  it("panel-derive: offline oracle keeps its refusal message", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-panel-oracle-"));
    writeFileSync(
      join(dir, "oracle.js"),
      `function deriveLocal(k) { return k; }\nconst panelTokenSha256 = "a".repeat(64);\nif (panelTokenSha256) console.log(deriveLocal("x"));\n`,
    );
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    const oracle = report.findings.find(
      (f) => f.gate === "panel-derive" && f.shouldRefuseBankrupt,
    );
    expect(oracle).toBeDefined();
    expect(oracle!.refuseMessage).toContain("Refusing bankrupt");
    expect(oracle!.refuseMessage).toContain("panel offline oracle");
  });
});

describe("a finding on a build-output file and on the source it was made from", () => {
  // Assembled here so no digest-shaped literal sits in the repository.
  const DIGEST = ["2f0f6f0d4c6f0b8c", "1a0e2f6d7f3a9a51", "f1c2b7d5e8a4c3b2", "a1908f7e6d5c4b3a"].join("");
  const license = (quote: string): string =>
    `const EXPECTED = ${quote}${DIGEST}${quote};\nmodule.exports = { check: (h) => h === EXPECTED };\n`;
  function project(files: Readonly<Record<string, string>>): string {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-twin-"));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(join(dir, rel, ".."), { recursive: true });
      writeFileSync(join(dir, rel), text);
    }
    return dir;
  }

  it("is listed once, on the file that ships, and names the source", () => {
    const dir = project({
      "src/license.cjs": license("'"),
      "dist/license.cjs": license("'"),
    });
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    const secrets = report.findings.filter((f) => f.gate === "plaintext-secret");
    expect(secrets.map((f) => f.relativePath)).toEqual(["dist/license.cjs"]);
    expect(secrets[0]!.sameFindingInSource).toEqual(["src/license.cjs"]);
    expect(report.gateCounts["plaintext-secret"]).toBe(1);

    // The plan no longer sends anyone to rewrite the source file.
    const plan = report.remediationPlan.filter((p) => p.gate === "plaintext-secret");
    expect(plan.map((p) => p.relativePath)).toEqual(["dist/license.cjs"]);
    expect(plan[0]!.sourceRefactorRecipe).toContain("`bla_encrypt_strings` on `dist/license.cjs`");
    expect(plan[0]!.sourceRefactorRecipe).not.toContain("on `src/license.cjs`");
    expect(plan[0]!.sourceRefactorRecipe).toMatch(
      /Also in `src\/license\.cjs` — the source this file is built from, not listed as a finding of its own\. A fix made there needs a rebuild; .* belong on the build output, never on the source\./,
    );
    expect(report.oneLineAdvice).toMatch(
      /1 finding\(s\) repeat in the source a build-output file was made from; they are listed once, on the file that ships \(sameFindingInSource\)\./,
    );
    expect(formatPackagingGatesReport(report)).toContain("same finding in its source: src/license.cjs");

    // The raw per-file reports still hold both: that is what harden refuses on.
    const raw = report.details.plaintextSecrets.filter((r) => r.findings.length > 0);
    expect(raw.map((r) => r.path.split(/[\\/]/).slice(-2).join("/")).sort()).toEqual([
      "dist/license.cjs",
      "src/license.cjs",
    ]);
  });

  it("matches a transpiled file by stem: the extension and the line numbers may differ", () => {
    const dir = project({
      "src/license.ts": `// licence check\n\nexport const EXPECTED: string = "${DIGEST}";\n`,
      "dist/license.js": `"use strict";\nexports.EXPECTED = "${DIGEST}";\n`,
    });
    const secrets = scanPackagingGates({ directory: dir, intensity: "bankrupt" }).findings.filter(
      (f) => f.gate === "plaintext-secret",
    );
    expect(secrets.map((f) => f.relativePath)).toEqual(["dist/license.js"]);
    expect(secrets[0]!.sameFindingInSource).toEqual(["src/license.ts"]);
  });

  it("keeps findings that are not the same finding", () => {
    const other = DIGEST.split("").reverse().join("");
    // Different value in the source, and a source file with no build output of that name.
    const dir = project({
      "src/license.cjs": `const EXPECTED = '${other}';\nmodule.exports = { EXPECTED };\n`,
      "dist/license.cjs": license("'"),
      "src/vault.cjs": license("'"),
    });
    const secrets = scanPackagingGates({ directory: dir, intensity: "bankrupt" }).findings.filter(
      (f) => f.gate === "plaintext-secret",
    );
    expect(secrets.map((f) => f.relativePath).sort()).toEqual([
      "dist/license.cjs",
      "src/license.cjs",
      "src/vault.cjs",
    ]);
    for (const f of secrets) expect(f.sameFindingInSource).toBeUndefined();
  });

  it("a project with no build output is reported file by file, as before", () => {
    const dir = project({ "src/license.cjs": license("'"), "lib/license.cjs": license("'") });
    const secrets = scanPackagingGates({ directory: dir, intensity: "bankrupt" }).findings.filter(
      (f) => f.gate === "plaintext-secret",
    );
    expect(secrets.map((f) => f.relativePath).sort()).toEqual(["lib/license.cjs", "src/license.cjs"]);
    expect(secrets.every((f) => f.sameFindingInSource === undefined)).toBe(true);
  });
});
