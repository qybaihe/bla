import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";
import {
  buildKeystream,
  deriveEntryKeystream,
  encryptStrings,
  xorEncodeToBytes,
} from "../src/engine/encrypt-strings.js";
import { evaluateCoverageMatrix } from "../src/engine/integrity-coverage.js";
import { SeededPrng } from "../src/core/prng.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { buildWeavePlan } from "../src/shields/weave/weave-decoy.js";
import { BLA_IDENTITY } from "../src/identity.js";

function runNode(scriptPath: string, args: string[] = []) {
  return spawnSync(process.execPath, [scriptPath, ...args], { encoding: "utf8" });
}

describe("Audit & Subagent Red-Team Reinforcements", () => {
  it("enforces entry self-digest and non-JS sibling binding when --self-seal runs on single-JS + Python trees", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-selfseal-polyglot-"));
    try {
      const srcDir = join(root, "app");
      mkdirSync(srcDir, { recursive: true });
      writeFileSync(
        join(srcDir, "risk_model.py"),
        [
          "_state = {'epoch': 1}",
          "def compute_bps(x):",
          "    return x * 10 + (_state['epoch'] & 0)",
          "",
        ].join("\n"),
        "utf8",
      );
      writeFileSync(
        join(srcDir, "cli.cjs"),
        [
          '"use strict";',
          "function computeQuote(n) { return n * 100 + 25; }",
          "if (require.main === module) console.log('QUOTE=' + computeQuote(7));",
          "module.exports = { computeQuote };",
          "",
        ].join("\n"),
        "utf8",
      );

      const outDir = join(root, "hardened");
      const report = hardenProject({
        directory: srcDir,
        outputDirectory: outDir,
        intensity: "bankrupt",
        seed: "polyglot-selfseal-seed-v1",
        selfSeal: true,
        sidecarEntangle: true,
        weaveDecoys: true,
      });

      expect(report.overallSuccess).toBe(true);
      expect(report.integrityCoverageSelfVerified).toBe(true);
      expect(report.integrityCoveragePath).toBeTruthy();
      const matrix = JSON.parse(readFileSync(report.integrityCoveragePath!, "utf8"));
      expect(evaluateCoverageMatrix(matrix).ok).toBe(true);

      const cliOut = join(outDir, "cli.cjs");
      const pyOut = join(outDir, "risk_model.py");
      const intact = runNode(cliOut);
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout).toContain("QUOTE=725");

      // Tampering with the non-JS sibling (`risk_model.py`) must hard-fail
      const origPy = readFileSync(pyOut);
      appendFileSync(pyOut, "\n# sibling tamper\n");
      const sibTampered = runNode(cliOut);
      expect(sibTampered.status).not.toBe(0);
      expect(`${sibTampered.stderr}${sibTampered.stdout}`).toMatch(
        /integrity (?:binding mismatch|check failed)/,
      );

      // Restore sibling; tampering with `cli.cjs` ITSELF must now also hard-fail!
      writeFileSync(pyOut, origPy);
      expect(runNode(cliOut).status).toBe(0);
      appendFileSync(cliOut, "\n// entry self-tamper\n");
      const selfTampered = runNode(cliOut);
      expect(selfTampered.status).not.toBe(0);
      expect(`${selfTampered.stderr}${selfTampered.stdout}`).toMatch(
        /integrity check failed/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("enforces entry self-digest on standalone single-file protectTarget(..., { selfSeal: true })", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-standalone-"));
    try {
      const input = join(dir, "standalone.cjs");
      const output = join(dir, "standalone.hardened.cjs");
      writeFileSync(
        input,
        '"use strict";\nif (require.main === module) console.log("STANDALONE_OK");\n',
        "utf8",
      );
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "balanced",
        seed: "standalone-selfseal-v1",
        selfSeal: true,
      });

      const intact = runNode(output);
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout).toContain("STANDALONE_OK");

      appendFileSync(output, "\n// patched entry\n");
      const tampered = runNode(output);
      expect(tampered.status).not.toBe(0);
      expect(`${tampered.stderr}${tampered.stdout}`).toMatch(/integrity check failed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("eliminates many-time-pad reuse across encryptStrings rows and strips blaS/blaT markers after harden", () => {
    const prng = new SeededPrng("mtp-check-seed").derive("string.encrypt");
    const ks = buildKeystream(prng, 64);
    const plain0 = "FLAG{secret_sovereign_token_alpha}";
    const plain1 = "SELECT region_code FROM pricing_v1";
    const row0 = xorEncodeToBytes(plain0, deriveEntryKeystream(ks, 0, plain0.length));
    const row1 = xorEncodeToBytes(plain1, deriveEntryKeystream(ks, 1, plain1.length));

    // Under a reused stream pad, row0[j] ^ row1[j] === plain0[j] ^ plain1[j] for every j.
    // With per-entry keystream derivation, cross-row XOR does not equal plaintext XOR.
    let matches = 0;
    const minLen = Math.min(plain0.length, plain1.length);
    for (let j = 0; j < minLen; j++) {
      if ((row0[j]! ^ row1[j]!) === (plain0.charCodeAt(j) ^ plain1.charCodeAt(j))) {
        matches++;
      }
    }
    expect(matches).toBeLessThan(minLen / 3);

    const dir = mkdtempSync(join(tmpdir(), "bla-enc-harden-clean-"));
    try {
      const file = join(dir, "license.cjs");
      writeFileSync(
        file,
        [
          '"use strict";',
          `function readPair() { return [${JSON.stringify(plain0)}, ${JSON.stringify(plain1)}]; }`,
          "module.exports = { readPair };",
          "",
        ].join("\n"),
        "utf8",
      );
      const enc = encryptStrings({ path: dir, seed: "clean-markers-seed" });
      expect(enc.status).toBe("ok");
      const stage2 = readFileSync(file, "utf8");
      expect(stage2).toContain("_blaS");
      expect(stage2).not.toMatch(/\bblaS[A-Z_]/);

      const outFile = join(dir, "license.hardened.cjs");
      protectTarget({
        inputPath: file,
        outputPath: outFile,
        intensity: "bankrupt",
        seed: "clean-markers-seed",
      });
      const hardened = readFileSync(outFile, "utf8");
      expect(hardened).not.toMatch(/\b_bla[ST]\b/);
      expect(hardened).not.toMatch(/\bbla[STK][A-Za-z0-9_]*\b/);

      const mod = require(outFile);
      expect(mod.readPair()).toEqual([plain0, plain1]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flags narrow 32-bit Math.imul auth gates in bla_weave_plan while sparing SHA-256 commitment gates", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-narrow-gate-"));
    try {
      writeFileSync(
        join(dir, "weak_gate.cjs"),
        [
          '"use strict";',
          "const state = { epoch: 1, acc: 0x811c9dc5 };",
          "function verifyPartnerLicense(voucher) {",
          "  let h = state.acc >>> 0;",
          "  for (let i = 0; i < voucher.length; i++) {",
          "    h = Math.imul(h ^ voucher.charCodeAt(i), 0x01000193) >>> 0;",
          "  }",
          "  return { matched: (h >>> 0) === 1966265351, epoch: state.epoch };",
          "}",
          "module.exports = { verifyPartnerLicense };",
          "",
        ].join("\n"),
        "utf8",
      );
      writeFileSync(
        join(dir, "strong_gate.cjs"),
        [
          '"use strict";',
          'const crypto = require("node:crypto");',
          "function verifySovereignLicense(voucher) {",
          '  const digest = crypto.createHash("sha256").update(voucher).digest("hex");',
          '  const tag = Math.imul(voucher.length, 31) >>> 0;',
          '  return { digest, tag };',
          "}",
          "module.exports = { verifySovereignLicense };",
          "",
        ].join("\n"),
        "utf8",
      );

      const plan = buildWeavePlan(dir);
      const weak = plan.targets.find((t) => t.relativePath === "weak_gate.cjs");
      const strong = plan.targets.find((t) => t.relativePath === "strong_gate.cjs");
      expect(
        weak?.surgicalWorkorder?.crownJewelCandidates.some(
          (c) => c.vulnerabilityKind === "narrow-32bit-gate",
        ),
      ).toBe(true);
      expect(
        strong?.surgicalWorkorder?.crownJewelCandidates.some(
          (c) => c.vulnerabilityKind === "narrow-32bit-gate",
        ),
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("de-literalizes plain and interpolated TemplateLiterals at bankrupt intensity while preserving tagged templates", () => {
    const src = [
      '"use strict";',
      "function buildQuery(region, limit) {",
      "  const sql = `SELECT fx_permille, tax_bps FROM region_pricing`;",
      "  const header = `Bearer-Scope/${region}/limit=${limit}/enterprise`;",
      "  const rawTag = String.raw`raw\\nkeep`;",
      "  return { sql, header, rawTag };",
      "}",
      "module.exports = { buildQuery };",
      "",
    ].join("\n");

    const res = transformJavaScriptWithBlaShield(src, {
      intensity: "bankrupt",
      seed: "template-delit-seed-1",
      sourceType: "commonjs",
    });

    expect(res.code).not.toContain("SELECT fx_permille, tax_bps FROM region_pricing");
    expect(res.code).not.toContain("Bearer-Scope/");
    expect(res.code).toContain("String.raw`raw\\nkeep`");

    const sandbox: Record<string, unknown> = {
      module: { exports: {} },
      exports: {},
      Math,
      String,
    };
    sandbox.exports = (sandbox.module as { exports: unknown }).exports;
    vm.runInNewContext(res.code, sandbox);
    const mod = (sandbox.module as { exports: { buildQuery: (r: string, l: number) => unknown } }).exports;
    expect(mod.buildQuery("eu-west", 50)).toEqual({
      sql: "SELECT fx_permille, tax_bps FROM region_pricing",
      header: "Bearer-Scope/eu-west/limit=50/enterprise",
      rawTag: "raw\\nkeep",
    });
  });

  it("keeps STATE.md version synced with BLA_IDENTITY.version after build", () => {
    const stateMd = readFileSync(join(__dirname, "..", "STATE.md"), "utf8");
    expect(stateMd).toContain(`**Version:** ${BLA_IDENTITY.version}`);
  });
});
