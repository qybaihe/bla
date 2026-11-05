import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { SeededPrng } from "../src/core/prng.js";
import {
  generateSelfSealSnippet,
  measureSelfSealDigestOffline,
  SELF_SEAL_SCHEMA,
} from "../src/shields/runtime/self-seal.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { parseCliArgs } from "../src/cli.js";
import { DEFAULT_BLA_CONFIG, initBlaConfig, loadBlaConfig } from "../src/core/config.js";
import { protectTarget } from "../src/engine/protector.js";

describe("self-seal helper (#40.5)", () => {
  it("DEFAULT_BLA_CONFIG exposes selfSeal:false (opt-in)", () => {
    expect(DEFAULT_BLA_CONFIG.selfSeal).toBe(false);
  });

  it("emits a bla-self-seal/v1 snippet with binding + helper names", () => {
    const prng = new SeededPrng("self-seal-unit-1");
    const snip = generateSelfSealSnippet(prng, {
      siblingPaths: ["./sib-a.js", "./sib-b.js"],
      envFingerprint: true,
      bindingName: "integrityDigestTest",
    });
    expect(snip.schema).toBe(SELF_SEAL_SCHEMA);
    expect(snip.bindingName).toBe("integrityDigestTest");
    expect(snip.siblingCount).toBe(2);
    expect(snip.envFingerprint).toBe(true);
    expect(snip.code).toContain("integrityDigestTest");
    expect(snip.code).toContain("node:crypto");
    expect(snip.code).toContain("./sib-a.js");
    // No greppable BLA brand markers in customer-facing code.
    expect(snip.code.toLowerCase()).not.toMatch(/\bbla[_-]?seal\b/);
  });

  it("offline digest helper is deterministic for identical inputs", () => {
    const a = measureSelfSealDigestOffline([
      { pathLabel: "main.js", bytes: Buffer.from("hello-module") },
      { pathLabel: "sib-1", bytes: Buffer.from("sib-1") },
      { pathLabel: "sib-2", bytes: Buffer.from("sib-2") },
    ]);
    const b = measureSelfSealDigestOffline([
      { pathLabel: "main.js", bytes: Buffer.from("hello-module") },
      { pathLabel: "sib-1", bytes: Buffer.from("sib-1") },
      { pathLabel: "sib-2", bytes: Buffer.from("sib-2") },
    ]);
    expect(a).toBe(b);
    expect(a).toBeGreaterThan(0);
    const c = measureSelfSealDigestOffline([
      { pathLabel: "main.js", bytes: Buffer.from("hello-module-TAMPERED") },
      { pathLabel: "sib-1", bytes: Buffer.from("sib-1") },
      { pathLabel: "sib-2", bytes: Buffer.from("sib-2") },
    ]);
    expect(c).not.toBe(a);
  });

  it("self-seal keeps opaque seed before top-level const uses (no TDZ)", () => {
    // Bankrupt-style string splitting references seedVar in top-level consts.
    // Self-seal used to push the seed decl to the program end → TDZ ReferenceError.
    const src = [
      '"use strict";',
      'const HONEYPOT = Object.freeze(["P4#kR9$vM2@xL7!q", "W9$mK3#pT7!vQ2@z"]);',
      'const LABEL = "bla-redblue-r4|wrap";',
      'function main(k) { return HONEYPOT.includes(k) ? "hp" : LABEL + ":" + String(k).length; }',
      'module.exports = { main, HONEYPOT };',
      'if (require.main === module) console.log(main(process.argv[2] || ""));',
      "",
    ].join("\n");
    const on = transformJavaScriptWithBlaShield(src, {
      intensity: "bankrupt",
      seed: "self-seal-tdz-r4",
      selfSeal: true,
    });
    expect(on.selfSealEnabled).toBe(true);
    expect(on.selfSealBindingName).toBeTruthy();
    // Seed const must appear before the first top-level Object.freeze / LABEL split use.
    const seedDecl = on.code.match(/const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\(\(\d+|\d+\s*\^)/);
    expect(seedDecl).toBeTruthy();
    const seedPos = on.code.indexOf(seedDecl![0]!);
    const freezePos = on.code.indexOf("Object.freeze");
    expect(seedPos).toBeGreaterThanOrEqual(0);
    if (freezePos >= 0) {
      expect(seedPos).toBeLessThan(freezePos);
    }

    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-tdz-"));
    try {
      const file = join(dir, "gate.cjs");
      writeFileSync(file, on.code, "utf8");
      const run = spawnSync(process.execPath, [file, "abc"], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
      expect(run.stderr || "").not.toMatch(/before initialization/i);
      expect(run.stdout).toMatch(/bla-redblue-r4\|wrap:3/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("AST shield injects self-seal only when opted in", () => {
    const src = "export function pay(n) { return n * 2; }\n";
    const off = transformJavaScriptWithBlaShield(src, {
      intensity: "balanced",
      seed: "seal-off",
    });
    expect(off.selfSealEnabled).toBeFalsy();
    expect(off.code).not.toContain("node:crypto");

    const on = transformJavaScriptWithBlaShield(src, {
      intensity: "balanced",
      seed: "seal-on",
      selfSeal: true,
    });
    expect(on.selfSealEnabled).toBe(true);
    expect(on.selfSealBindingName).toBeTruthy();
    expect(on.code).toContain("node:crypto");
    // Opaque seed folds the integrity binding.
    expect(on.code).toContain(on.selfSealBindingName!);
  });

  it("CLI --self-seal parses and .blarc selfSeal loads", () => {
    const parsed = parseCliArgs(["protect", "a.js", "--self-seal"]);
    expect(parsed.selfSeal).toBe(true);
    const off = parseCliArgs(["protect", "a.js"]);
    expect(off.selfSeal).toBe(false);

    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-cfg-"));
    try {
      writeFileSync(
        join(dir, ".blarc"),
        JSON.stringify({ selfSeal: true, seed: "bla-test-self-seal-seed-01" }),
        "utf8",
      );
      const loaded = loadBlaConfig(dir);
      expect(loaded.config.selfSeal).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("initBlaConfig writes selfSeal:false into starter config", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-init-"));
    try {
      const res = initBlaConfig(dir);
      expect(res.config.selfSeal).toBe(false);
      const loaded = loadBlaConfig(dir);
      expect(loaded.config.selfSeal).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("tiny fixture: sibling tamper changes offline digest (entanglement contract)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-fix-"));
    try {
      const mainPath = join(dir, "main.js");
      const sibPath = join(dir, "sib.js");
      writeFileSync(mainPath, "module.exports = { ok: true };\n", "utf8");
      writeFileSync(sibPath, "module.exports = 1;\n", "utf8");

      const base = measureSelfSealDigestOffline([
        { pathLabel: "main.js", bytes: readFileSync(mainPath) },
        { pathLabel: "sib.js", bytes: readFileSync(sibPath) },
      ]);
      writeFileSync(sibPath, "module.exports = 999;\n", "utf8");
      const tampered = measureSelfSealDigestOffline([
        { pathLabel: "main.js", bytes: readFileSync(mainPath) },
        { pathLabel: "sib.js", bytes: readFileSync(sibPath) },
      ]);
      expect(tampered).not.toBe(base);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

  it("embeds expected sibling SHA-256 and hard-fails on mismatch (round-4)", () => {
    const prng = new SeededPrng("self-seal-hardfail-1");
    const snip = generateSelfSealSnippet(prng, {
      siblingPaths: ["./core.wasm"],
      bindingName: "integrityDigestHf",
      expectedSiblingSha256: {
        "./core.wasm": "a".repeat(64),
      },
      hardFailOnSiblingMismatch: true,
    });
    expect(snip.expectedSiblingHashCount).toBe(1);
    expect(snip.hardFailOnSiblingMismatch).toBe(true);
    expect(snip.code).toContain("integrity check failed");
    expect(snip.code).toContain("a".repeat(64));
  });

  it("protect+self-seal hard-fails when an expected sibling is deleted", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-missing-"));
    try {
      const sib = join(dir, "core.wasm");
      writeFileSync(sib, Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xaa]));
      const src = [
        '"use strict";',
        "function main() { return 42; }",
        "module.exports = { main };",
        'if (require.main === module) console.log(main());',
        "",
      ].join("\n");
      const entry = join(dir, "gate.cjs");
      writeFileSync(entry, src, "utf8");

      const out = join(dir, "gate.out.cjs");
      protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "self-seal-missing-protect",
        selfSeal: true,
        selfSealSiblingPaths: ["core.wasm"],
      });

      const intact = spawnSync(process.execPath, [out], { encoding: "utf8" });
      expect(intact.status, intact.stderr).toBe(0);

      rmSync(sib, { force: true });
      const deleted = spawnSync(process.execPath, [out], { encoding: "utf8" });
      expect(deleted.status, deleted.stdout + deleted.stderr).not.toBe(0);
      expect((deleted.stderr || "") + (deleted.stdout || "")).toMatch(
        /integrity check failed/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protect+self-seal hard-fails when an on-disk sibling is tampered", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-hf-"));
    try {
      const sib = join(dir, "core.wasm");
      // Minimal wasm magic so file exists for hashing (content arbitrary).
      writeFileSync(sib, Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xaa]));
      const src = [
        '"use strict";',
        "function main() { return 42; }",
        "module.exports = { main };",
        'if (require.main === module) console.log(main());',
        "",
      ].join("\n");
      const entry = join(dir, "gate.cjs");
      writeFileSync(entry, src, "utf8");

      const out = join(dir, "gate.out.cjs");
      protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "self-seal-hardfail-protect",
        selfSeal: true,
        selfSealSiblingPaths: ["core.wasm"],
      });

      const intact = spawnSync(process.execPath, [out], { encoding: "utf8" });
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout.trim()).toBe("42");

      writeFileSync(sib, Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xbb]));
      const tampered = spawnSync(process.execPath, [out], { encoding: "utf8" });
      expect(tampered.status, tampered.stdout + tampered.stderr).not.toBe(0);
      expect((tampered.stderr || "") + (tampered.stdout || "")).toMatch(
        /integrity check failed/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
