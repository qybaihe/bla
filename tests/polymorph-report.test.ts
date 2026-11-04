import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { comparePolymorphArtifacts } from "../src/engine/polymorph-report.js";
import { protectTarget } from "../src/engine/protector.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import { deriveSeedLabel, SeededPrng } from "../src/core/prng.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const SRC = `
export function unlockPremium(token) {
  if (typeof token !== "string") return false;
  return token.length >= 8 && token.startsWith("LIVE");
}
export function describePlan() {
  return "premium";
}
`;

function hardenTo(dir: string, seed: string): string {
  mkdirSync(dir, { recursive: true });
  const input = join(dir, "app.js");
  writeFileSync(input, SRC, "utf8");
  const outDir = join(dir, "out");
  mkdirSync(outDir, { recursive: true });
  const out = join(outDir, "app.js");
  protectTarget({
    inputPath: input,
    outputPath: out,
    intensity: "bankrupt",
    seed,
  });
  return outDir;
}

describe("polymorph-report (seeded polymorphism)", () => {
  it("same seed → reproducible (expect=same passes)", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-poly-same-"));
    tempDirs.push(root);
    const a = hardenTo(join(root, "a"), "poly-seed-fixed");
    const b = hardenTo(join(root, "b"), "poly-seed-fixed");
    const report = comparePolymorphArtifacts({
      dirA: a,
      dirB: b,
      expect: "same",
    });
    expect(report.status).toBe("ok");
    expect(report.reproducible).toBe(true);
    expect(report.driftScore).toBeLessThan(0.01);
    expect(report.files.every((f) => f.byteEqual)).toBe(true);
  });

  it("different seeds → polymorphic (expect=different passes)", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-poly-diff-"));
    tempDirs.push(root);
    const a = hardenTo(join(root, "a"), "poly-seed-A");
    const b = hardenTo(join(root, "b"), "poly-seed-B");
    const report = comparePolymorphArtifacts({
      dirA: a,
      dirB: b,
      expect: "different",
    });
    expect(report.status).toBe("ok");
    expect(report.polymorphic).toBe(true);
    expect(report.driftScore).toBeGreaterThanOrEqual(0.25);
    // At least one file must differ in bytes
    expect(report.files.some((f) => !f.byteEqual)).toBe(true);
  });

  it("expect=same refuses when seeds differ", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-poly-refuse-"));
    tempDirs.push(root);
    const a = hardenTo(join(root, "a"), "seed-X");
    const b = hardenTo(join(root, "b"), "seed-Y");
    const report = comparePolymorphArtifacts({
      dirA: a,
      dirB: b,
      expect: "same",
    });
    expect(report.status).toBe("fail");
    expect(report.reproducible).toBe(false);
  });

  it("hardened output still exports unlockPremium (functional surface)", async () => {
    const root = mkdtempSync(join(tmpdir(), "bla-poly-fn-"));
    tempDirs.push(root);
    const outDir = hardenTo(root, "poly-fn-seed");
    const mod = await import(join(outDir, "app.js"));
    expect(typeof mod.unlockPremium).toBe("function");
    expect(mod.unlockPremium("LIVE-KEY-99")).toBe(true);
    expect(mod.unlockPremium("nope")).toBe(false);
  });

  it("MCP bla_polymorph_report wires through", async () => {
    const root = mkdtempSync(join(tmpdir(), "bla-poly-mcp-"));
    tempDirs.push(root);
    const a = hardenTo(join(root, "a"), "mcp-seed-1");
    const b = hardenTo(join(root, "b"), "mcp-seed-1");
    const res = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "bla_polymorph_report",
        arguments: { dir_a: a, dir_b: b, expect: "same" },
      },
    });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError: boolean;
      structuredContent: { status: string; reproducible: boolean; schema: string };
    };
    expect(result.isError).toBe(false);
    expect(result.structuredContent.schema).toBe("bla-polymorph-report/v1");
    expect(result.structuredContent.status).toBe("ok");
    expect(result.structuredContent.reproducible).toBe(true);
  });

  it("bundler-style deriveSeedLabel keeps chunk streams independent but stable", () => {
    const root = "build-root";
    const s1 = deriveSeedLabel(root, "chunk-a.js");
    const s2 = deriveSeedLabel(root, "chunk-a.js");
    const s3 = deriveSeedLabel(root, "chunk-b.js");
    expect(s1).toBe(s2);
    expect(s1).not.toBe(s3);
    const ids1 = new SeededPrng(s1).identifier({ style: "camel", hint: "x", entropy: 2 });
    const ids2 = new SeededPrng(s1).identifier({ style: "camel", hint: "x", entropy: 2 });
    expect(ids1).toBe(ids2);
  });
});
