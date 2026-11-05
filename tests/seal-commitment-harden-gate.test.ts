import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const ROUND2_SEAL = {
  schema: "bla-redblue-r2-seal/v1",
  rounds: 28,
  scheduleSalt: 1374179543,
  revision: "7f325fec37206b637a224e9630b67c4a",
  certificateCipherHex: "0cd3dfe5e342eb542a3666d6e706ede34c58416b00bb853921b9c82397ff716237",
};

const ONE_WAY_SEAL = {
  schema: "bla-entitlement-seal/v1",
  algorithm: "sha256",
  revision: "b38091d4a394ded9012846e8d4b647083b260beb6ee5ad1e42265fe6f107c660",
};

const SAFE_JS = `
  export function activate(key) {
    let h = 2166136261;
    for (let i = 0; i < key.length; i++) {
      h ^= key.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(16);
  }
`;

describe("harden/protect seal-sidecar gate (red-blue round-2 P1)", () => {
  it("bankrupt harden refuses reversible plaintext seal.json by default", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-refuse-"));
    dirs.push(root);
    writeFileSync(join(root, "gate.js"), SAFE_JS, "utf8");
    writeFileSync(join(root, "seal.json"), JSON.stringify(ROUND2_SEAL), "utf8");
    const report = hardenProject({
      directory: root,
      intensity: "bankrupt",
      seed: "seal-refuse",
      outputDirectory: join(root, "out"),
    });
    expect(report.overallSuccess).toBe(false);
    expect(
      report.artifacts.some(
        (a) => a.error && /allowPlaintextSeal|plaintext\/reversible seal|reversible/i.test(a.error),
      ),
    ).toBe(true);
    // Per-artifact attribution: the blocker carries its specific refusal, an
    // unrelated planned artifact says the run was blocked, and every artifact
    // is counted as failed.
    const blocker = report.artifacts.find((a) => a.inputPath.endsWith("seal.json"));
    const planned = report.artifacts.find((a) => a.inputPath.endsWith("gate.js"));
    expect(blocker?.error).toMatch(/reversible|plaintext/i);
    expect(planned?.error).toMatch(/run blocked by/);
    expect(report.failedCount).toBe(report.artifacts.length);
  });

  it("bankrupt harden allows one-way sha256 seal.json", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-ok-"));
    dirs.push(root);
    writeFileSync(join(root, "gate.js"), SAFE_JS, "utf8");
    writeFileSync(join(root, "seal.json"), JSON.stringify(ONE_WAY_SEAL), "utf8");
    const report = hardenProject({
      directory: root,
      intensity: "bankrupt",
      seed: "seal-ok",
      outputDirectory: join(root, "out"),
    });
    expect(report.overallSuccess).toBe(true);
    expect(report.hardenedCount).toBeGreaterThanOrEqual(1);
  });

  it("allowPlaintextSeal overrides bankrupt refuse", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-allow-"));
    dirs.push(root);
    writeFileSync(join(root, "gate.js"), SAFE_JS, "utf8");
    writeFileSync(join(root, "seal.json"), JSON.stringify(ROUND2_SEAL), "utf8");
    const report = hardenProject({
      directory: root,
      intensity: "bankrupt",
      seed: "seal-allow",
      outputDirectory: join(root, "out"),
      allowPlaintextSeal: true,
    });
    expect(report.overallSuccess).toBe(true);
  });

  it("balanced intensity does not refuse (warning path only via lint)", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-bal-"));
    dirs.push(root);
    writeFileSync(join(root, "gate.js"), SAFE_JS, "utf8");
    writeFileSync(join(root, "seal.json"), JSON.stringify(ROUND2_SEAL), "utf8");
    const report = hardenProject({
      directory: root,
      intensity: "balanced",
      seed: "seal-bal",
      outputDirectory: join(root, "out"),
    });
    expect(report.overallSuccess).toBe(true);
  });

  it("bankrupt protect refuses sibling seal.json", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-prot-"));
    dirs.push(root);
    const src = join(root, "gate.js");
    writeFileSync(src, SAFE_JS, "utf8");
    writeFileSync(join(root, "seal.json"), JSON.stringify(ROUND2_SEAL), "utf8");
    expect(() =>
      protectTarget({
        inputPath: src,
        outputPath: join(root, "out.js"),
        intensity: "bankrupt",
        seed: "seal-prot",
      }),
    ).toThrow(/allowPlaintextSeal|plaintext\/reversible seal/i);
  });
});
