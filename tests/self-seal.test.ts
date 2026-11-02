import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SeededPrng } from "../src/core/prng.js";
import {
  generateSelfSealSnippet,
  measureSelfSealDigestOffline,
  SELF_SEAL_SCHEMA,
} from "../src/shields/runtime/self-seal.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { parseCliArgs } from "../src/cli.js";
import { DEFAULT_BLA_CONFIG, initBlaConfig, loadBlaConfig } from "../src/core/config.js";

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
