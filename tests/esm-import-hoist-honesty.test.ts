import { describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, unlinkSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import {
  applyDefenseScoreHonesty,
  collectDefenseScoreGaps,
} from "../src/engine/defense-score-honesty.js";
import { jsModuleHasHoistedDependencyGraph } from "../src/shields/javascript/ast-shield.js";

/**
 * Red 2026-11-16: ESM static import / export-from bindings are instantiated
 * before any statement in the entry, including the prepended sidecarEntangle
 * / self-seal IIFE. Deleting a sidecar still fail-closes the entry body, but
 * imported module side effects already ran. CJS require() after the preamble
 * does not have this gap.
 */
function makeDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return dir;
}

function runNode(file: string, cwd?: string) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return spawnSync(process.execPath, [file], { encoding: "utf8", env, cwd });
}

describe("jsModuleHasHoistedDependencyGraph", () => {
  it("is false for CommonJS require graphs and for ESM entries without imports", () => {
    expect(
      jsModuleHasHoistedDependencyGraph(
        'const { n } = require("./lib.js");\nconsole.log(n);\n',
        "app.js",
      ),
    ).toBe(false);
    expect(
      jsModuleHasHoistedDependencyGraph(
        'const n = await Promise.resolve(2);\nconsole.log(n);\n',
        "app.js",
      ),
    ).toBe(false);
  });

  it("ignores the BLA createRequire preamble and flags user import / export-from", () => {
    const preamble =
      'import { createRequire as _resolveModuleRequire_deadbeef } from "node:module";\n(function(){})();\n';
    expect(jsModuleHasHoistedDependencyGraph(preamble, "app.js")).toBe(false);
    expect(
      jsModuleHasHoistedDependencyGraph(
        `${preamble}import { n } from "./lib.js";\nconsole.log(n);\n`,
        "app.js",
      ),
    ).toBe(true);
    expect(
      jsModuleHasHoistedDependencyGraph('export { n } from "./lib.js";\n', "app.mjs"),
    ).toBe(true);
    expect(jsModuleHasHoistedDependencyGraph('export const n = 1;\n', "app.mjs")).toBe(
      false,
    );
  });
});

describe("defenseScore honesty: esm-import-hoist-before-hooks", () => {
  it("annotates JS ESM entries with a hoisted graph when sidecar or self-seal is on", () => {
    const off = collectDefenseScoreGaps({
      detectedFormat: "javascript",
      selfSealEnabled: true,
      sidecarEntangleEnabled: true,
      esmImportHoistBeforeHooks: false,
    });
    expect(off.map((g) => g.id)).not.toContain("esm-import-hoist-before-hooks");

    const on = applyDefenseScoreHonesty(99, {
      detectedFormat: "javascript",
      selfSealEnabled: true,
      sidecarEntangleEnabled: true,
      esmImportHoistBeforeHooks: true,
    });
    expect(on.gaps.map((g) => g.id)).toContain("esm-import-hoist-before-hooks");
    expect(on.cappedScore).toBe(93);
    expect(on.appliedCap).toBe(93);
  });

  it("does not annotate the gap when neither sidecar nor self-seal is enabled", () => {
    const gaps = collectDefenseScoreGaps({
      detectedFormat: "javascript",
      selfSealEnabled: false,
      sidecarEntangleEnabled: false,
      esmImportHoistBeforeHooks: true,
    });
    expect(gaps.map((g) => g.id)).not.toContain("esm-import-hoist-before-hooks");
  });
});

describe("ESM sidecarEntangle hoist vs CJS process-start (red 2026-11-16)", () => {
  it("ESM imported side effects still run after sidecar delete; entry body fail-closes; honesty gap is annotated", () => {
    const dir = makeDir("bla-esm-hoist-");
    try {
      mkdirSync(join(dir, "in"));
      mkdirSync(join(dir, "out"));
      writeFileSync(join(dir, "in", "package.json"), JSON.stringify({ type: "module" }) + "\n");
      writeFileSync(join(dir, "out", "package.json"), JSON.stringify({ type: "module" }) + "\n");
      writeFileSync(join(dir, "in", "lib.js"), 'console.log("SIDEEFFECT");\nexport const n = 2;\n');
      writeFileSync(join(dir, "out", "lib.js"), 'console.log("SIDEEFFECT");\nexport const n = 2;\n');
      writeFileSync(
        join(dir, "in", "app.js"),
        'import { n } from "./lib.js";\nconsole.log("RESULT", n + 3);\n',
      );
      writeFileSync(join(dir, "out", "honey.txt"), "honey\n");

      const before = runNode(join(dir, "in", "app.js"));
      expect(before.status, before.stderr).toBe(0);
      expect(before.stdout).toContain("SIDEEFFECT");
      expect(before.stdout).toContain("RESULT 5");

      protectTarget({
        inputPath: join(dir, "in", "app.js"),
        outputPath: join(dir, "out", "app.js"),
        intensity: "balanced",
        seed: "esm-import-hoist-red-20261116",
        honeySourceMaps: false,
        sidecarEntangle: true,
        sidecarEntanglePaths: ["honey.txt"],
      });

      const intact = runNode(join(dir, "out", "app.js"));
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout).toContain("SIDEEFFECT");
      expect(intact.stdout).toContain("RESULT 5");

      const verification = verifyTarget(join(dir, "out", "app.js"), join(dir, "in", "app.js"), {
        sidecarEntangleEnabled: true,
      });
      expect(verification.defenseScoreGaps?.some((g) => g.id === "esm-import-hoist-before-hooks")).toBe(
        true,
      );
      expect(verification.defenseScore).toBeLessThanOrEqual(93);

      unlinkSync(join(dir, "out", "honey.txt"));
      const stripped = runNode(join(dir, "out", "app.js"));
      expect(stripped.status).not.toBe(0);
      expect(stripped.stderr).toMatch(/integrity binding mismatch/i);
      expect(stripped.stdout).toContain("SIDEEFFECT");
      expect(stripped.stdout).not.toContain("RESULT");
      expect(readFileSync(join(dir, "out", "app.js"), "utf8")).toContain("createRequire");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("CommonJS require graphs do not run imported side effects after sidecar delete, and the hoist gap stays off", () => {
    const dir = makeDir("bla-cjs-hoist-ctrl-");
    try {
      mkdirSync(join(dir, "in"));
      mkdirSync(join(dir, "out"));
      writeFileSync(join(dir, "in", "lib.js"), 'console.log("SIDEEFFECT");\nmodule.exports = { n: 2 };\n');
      writeFileSync(join(dir, "out", "lib.js"), 'console.log("SIDEEFFECT");\nmodule.exports = { n: 2 };\n');
      writeFileSync(
        join(dir, "in", "app.js"),
        'const { n } = require("./lib.js");\nconsole.log("RESULT", n + 3);\n',
      );
      writeFileSync(join(dir, "out", "honey.txt"), "honey\n");

      protectTarget({
        inputPath: join(dir, "in", "app.js"),
        outputPath: join(dir, "out", "app.js"),
        intensity: "balanced",
        seed: "cjs-import-hoist-ctrl-20261116",
        honeySourceMaps: false,
        sidecarEntangle: true,
        sidecarEntanglePaths: ["honey.txt"],
      });

      const intact = runNode(join(dir, "out", "app.js"));
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout).toContain("RESULT 5");

      const verification = verifyTarget(join(dir, "out", "app.js"), join(dir, "in", "app.js"), {
        sidecarEntangleEnabled: true,
      });
      expect(
        verification.defenseScoreGaps?.some((g) => g.id === "esm-import-hoist-before-hooks") ?? false,
      ).toBe(false);

      unlinkSync(join(dir, "out", "honey.txt"));
      const stripped = runNode(join(dir, "out", "app.js"));
      expect(stripped.status).not.toBe(0);
      expect(stripped.stderr).toMatch(/integrity binding mismatch/i);
      expect(stripped.stdout).not.toContain("SIDEEFFECT");
      expect(stripped.stdout).not.toContain("RESULT");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
