import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  lintSealCommitmentSource,
  lintSealCommitmentFile,
  discoverAndLintSealSidecars,
  findSiblingSealSidecars,
  sealCommitmentRefuseMessage,
  intensityEnforcesSealRefusal,
  SEAL_COMMITMENT_SCHEMA,
} from "../src/engine/seal-commitment-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** Round-2 seal shape (reversible ARX + cipher package). */
const ROUND2_SEAL = {
  schema: "bla-redblue-r2-seal/v1",
  product: "round-2-product-chained-entitlement",
  seed: "bla-redblue-r2-product-gate-2026-11",
  rounds: 28,
  scheduleSalt: 1374179543,
  revision: "7f325fec37206b637a224e9630b67c4a",
  panelToken: "f805ed0c2a763bc5",
  certificateCipherHex:
    "0cd3dfe5e342eb542a3666d6e706ede34c58416b00bb853921b9c82397ff716237",
  certificateSha256:
    "b38091d4a394ded9012846e8d4b647083b260beb6ee5ad1e42265fe6f107c660",
};

const ONE_WAY_SEAL = {
  schema: "bla-entitlement-seal/v1",
  algorithm: "sha256",
  revision: "b38091d4a394ded9012846e8d4b647083b260beb6ee5ad1e42265fe6f107c660",
  product: "ok-product",
};

describe("seal-commitment lint (red-blue round-2)", () => {
  it("flags round-2 reversible ARX seal.json as error + refuse", () => {
    const report = lintSealCommitmentSource(JSON.stringify(ROUND2_SEAL, null, 2), {
      path: "/tmp/seal.json",
    });
    expect(report.schema).toBe(SEAL_COMMITMENT_SCHEMA);
    expect(report.looksExposed).toBe(true);
    expect(report.shouldRefuseBankrupt).toBe(true);
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain("reversible-public-commitment");
    expect(ids).toContain("seal-offline-oracle-package");
    expect(report.findings.every((f) => f.severity === "error" || f.id === "plaintext-seal-sidecar")).toBe(
      true,
    );
    expect(report.findings.some((f) => f.severity === "error")).toBe(true);
  });

  it("passes one-way SHA-256 seal without invertible ARX params", () => {
    const report = lintSealCommitmentSource(JSON.stringify(ONE_WAY_SEAL), {
      path: "/tmp/seal.json",
    });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings.some((f) => f.id === "reversible-public-commitment")).toBe(false);
    expect(report.findings.some((f) => f.id === "seal-offline-oracle-package")).toBe(false);
    // Filename still yields a plaintext-sidecar warning (not refuse).
    expect(report.findings.some((f) => f.id === "plaintext-seal-sidecar" && f.severity === "warning")).toBe(
      true,
    );
  });

  it("discovers seal.json under a project tree", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-disc-"));
    dirs.push(root);
    mkdirSync(join(root, "dist"));
    writeFileSync(join(root, "dist", "seal.json"), JSON.stringify(ROUND2_SEAL), "utf8");
    writeFileSync(join(root, "dist", "app.js"), "export const x = 1;\n", "utf8");
    const reports = discoverAndLintSealSidecars(root);
    expect(reports.length).toBeGreaterThanOrEqual(1);
    expect(reports.some((r) => r.shouldRefuseBankrupt)).toBe(true);
  });

  it("finds sibling seal next to a protect target", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-seal-sib-"));
    dirs.push(root);
    writeFileSync(join(root, "license.cjs"), "console.log(1)\n", "utf8");
    writeFileSync(join(root, "app.seal.json"), JSON.stringify(ROUND2_SEAL), "utf8");
    const sibs = findSiblingSealSidecars(root);
    expect(sibs.some((p) => p.endsWith("app.seal.json"))).toBe(true);
    const report = lintSealCommitmentFile(sibs[0]!);
    expect(report.shouldRefuseBankrupt).toBe(true);
  });

  it("refuse message names the allow flag", () => {
    const report = lintSealCommitmentSource(JSON.stringify(ROUND2_SEAL), {
      path: "/tmp/seal.json",
    });
    expect(sealCommitmentRefuseMessage(report, "/tmp/seal.json")).toMatch(
      /allowPlaintextSeal|allow-plaintext-seal/i,
    );
    expect(intensityEnforcesSealRefusal("bankrupt")).toBe(true);
    expect(intensityEnforcesSealRefusal("balanced")).toBe(false);
  });

  it("lints the round-2 hardened seal fixture when present", () => {
    const fixture = "/workspace/bla-redblue/round-2/hardened/seal.json";
    try {
      readFileSync(fixture, "utf8");
    } catch {
      return; // fixture absent on some runners — unit cases above still cover shape
    }
    const report = lintSealCommitmentFile(fixture);
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.findings.some((f) => f.id === "reversible-public-commitment")).toBe(true);
  });
});
