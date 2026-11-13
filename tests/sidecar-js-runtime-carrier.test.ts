import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { protectTarget } from "../src/engine/protector.js";
import {
  detectJsCarrierForSource,
  transformJavaScriptWithBlaShield,
} from "../src/shields/javascript/ast-shield.js";

/**
 * Red 2026-11-13: the CommonJS strip⇒fail preamble was prepended to `.js`
 * entries that Node evaluates as ES modules even though they carry no static
 * import/export (top-level await, import.meta). The intact protected artifact
 * then died with `integrity binding mismatch` (require undefined) — a
 * functional-equivalence break, not a protection.
 */
function protectWithSidecar(dir: string, name: string, source: string) {
  const entry = join(dir, name);
  writeFileSync(entry, source, "utf8");
  writeFileSync(join(dir, "honey.txt"), "honey\n", "utf8");
  const out = join(dir, `out-${name}`);
  const run = () =>
    protectTarget({
      inputPath: entry,
      outputPath: out,
      intensity: "balanced",
      seed: "esm-runtime-carrier",
      honeySourceMaps: false,
      sidecarEntangle: true,
      sidecarEntanglePaths: ["honey.txt"],
    });
  return { out, run };
}

function runNode(file: string) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return spawnSync(process.execPath, [file], { encoding: "utf8", env });
}

describe("sidecar entangle: module-only syntax is an ES module carrier", () => {
  const moduleOnly: [string, string][] = [
    ["top-level await", 'const n = await Promise.resolve(2);\nconsole.log("RESULT", n + 3);\n'],
    ["import.meta", 'console.log("RESULT", 5, import.meta.url.length > 0);\n'],
  ];

  for (const [label, source] of moduleOnly) {
    it(`detects ${label} in a .js entry as module`, () => {
      expect(detectJsCarrierForSource(source, "/x/app.js")).toBe("module");
      expect(
        transformJavaScriptWithBlaShield(source, { filename: "app.js", seed: "c" })
          .carrierType,
      ).toBe("module");
    });

    it(`refuses a ${label} .js entry instead of shipping a broken preamble`, () => {
      const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-modsyntax-"));
      try {
        const { out, run } = protectWithSidecar(dir, "app.js", source);
        expect(run).toThrow(/ES module entry/);
        expect(existsSync(out)).toBe(false);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  it("CommonJS .js entry is still bound: intact runs, sidecar delete fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-cjs-ctl-"));
    try {
      const { out, run } = protectWithSidecar(
        dir,
        "app.js",
        'const p = require("node:path");\nconsole.log("RESULT", p.sep.length + 4);\n',
      );
      expect(run().sidecarEntangle).toBe(true);
      const intact = runNode(out);
      expect(intact.status).toBe(0);
      expect(intact.stdout).toContain("RESULT 5");
      rmSync(join(dir, "honey.txt"));
      const stripped = runNode(out);
      expect(stripped.status).not.toBe(0);
      expect(stripped.stdout).not.toContain("RESULT 5");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('sidecar entangle: package.json "type": "module" decides a .js carrier', () => {
  const plain = 'import("node:path").then((p) => console.log("RESULT", p.sep.length + 4));\n';

  it("resolves the nearest package.json type like Node", async () => {
    const { resolveNodePackageModuleType } = await import(
      "../src/shields/javascript/node-runtime-carrier.js"
    );
    const dir = mkdtempSync(join(tmpdir(), "bla-pkgtype-"));
    try {
      writeFileSync(join(dir, "package.json"), '{"type":"module"}\n', "utf8");
      const nested = join(dir, "cjs");
      mkdirSync(nested);
      writeFileSync(join(nested, "package.json"), "{}\n", "utf8");
      expect(resolveNodePackageModuleType(join(dir, "a.js"))).toBe("module");
      expect(resolveNodePackageModuleType(join(nested, "b.js"))).toBe("commonjs");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a .js entry under a type:module package (no import/export syntax)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-pkgtype-"));
    try {
      writeFileSync(join(dir, "package.json"), '{"type":"module"}\n', "utf8");
      const { out, run } = protectWithSidecar(dir, "app.js", plain);
      expect(run).toThrow(/ES module entry/);
      expect(existsSync(out)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protects the same entry without sidecarEntangle and it still runs as ESM", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-pkgtype-off-"));
    try {
      writeFileSync(join(dir, "package.json"), '{"type":"module"}\n', "utf8");
      const entry = join(dir, "app.js");
      writeFileSync(entry, plain, "utf8");
      const out = join(dir, "out-app.js");
      protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "esm-runtime-carrier",
        honeySourceMaps: false,
      });
      const r = runNode(out);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain("RESULT 5");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
