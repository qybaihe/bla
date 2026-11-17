import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseCliArgs } from "../src/cli.js";
import { validateBlaConfigShape } from "../src/core/config.js";
import {
  compileExcludeMatcher,
  discoverHardenTargets,
  hardenProject,
  restoreHardenedProject,
} from "../src/engine/harden.js";
import { handleMcpRequest } from "../src/mcp/server.js";

/**
 * `exclude` is the way out when one hardened file breaks the program or makes
 * a hot path too slow: everything else stays protected, and the report says
 * which files ship as they were. Without it the only recovery was "harden
 * nothing".
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(root: string, rel: string, content: string): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), content, "utf8");
}

const APP = "const { hot } = require('./vendor/heavy.cjs');\nmodule.exports = { run: () => hot(20) + 1 };\n";
const HEAVY = "module.exports = { hot: (n) => { let s = 0; for (let i = 0; i < n; i++) s += i; return s; } };\n";
const UTIL = "module.exports = { id: (x) => x };\n";

function project(extraConfig?: Record<string, unknown>): string {
  const dir = tempDir("bla-exclude-");
  put(dir, "package.json", JSON.stringify({ name: "x", version: "1.0.0", main: "dist/app.cjs" }));
  put(dir, "dist/app.cjs", APP);
  put(dir, "dist/util.cjs", UTIL);
  put(dir, "dist/vendor/heavy.cjs", HEAVY);
  put(dir, "dist/vendor/lib.min.js", "var a=1;\n");
  if (extraConfig) put(dir, ".blarc", JSON.stringify(extraConfig));
  return dir;
}

describe("exclude patterns", () => {
  const matches = (patterns: string[], path: string): boolean =>
    compileExcludeMatcher(patterns)!(path);

  it("an anchored pattern names a file, a directory, or a glob below the project root", () => {
    expect(matches(["dist/vendor/heavy.cjs"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["./dist/vendor/heavy.cjs"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["dist\\vendor\\heavy.cjs"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["dist/vendor"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["dist/vendor/"], "dist/vendor/deep/x.js")).toBe(true);
    expect(matches(["dist/vendor"], "dist/vendor-old/x.js")).toBe(false);
    expect(matches(["dist/*.cjs"], "dist/app.cjs")).toBe(true);
    expect(matches(["dist/*.cjs"], "dist/vendor/heavy.cjs")).toBe(false);
    expect(matches(["dist/**/*.cjs"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["dist/**/*.cjs"], "dist/app.cjs")).toBe(true);
    expect(matches(["dist/chunk-?.js"], "dist/chunk-a.js")).toBe(true);
    expect(matches(["dist/chunk-?.js"], "dist/chunk-ab.js")).toBe(false);
    // Anchored means anchored.
    expect(matches(["vendor/heavy.cjs"], "dist/vendor/heavy.cjs")).toBe(false);
  });

  it("a pattern without a slash matches any path segment", () => {
    expect(matches(["vendor"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["*.min.js"], "dist/vendor/lib.min.js")).toBe(true);
    expect(matches(["*.min.js"], "dist/app.js")).toBe(false);
    expect(matches(["heavy.cjs"], "dist/vendor/heavy.cjs")).toBe(true);
    expect(matches(["heavy"], "dist/vendor/heavy.cjs")).toBe(false);
  });

  it("treats regex punctuation literally and ignores empty patterns", () => {
    expect(matches(["dist/a+b(1).js"], "dist/a+b(1).js")).toBe(true);
    expect(matches(["dist/a+b(1).js"], "dist/aab1.js")).toBe(false);
    expect(matches(["dist/app.cjs"], "dist/appxcjs")).toBe(false);
    expect(compileExcludeMatcher(["", "  ", "./"])).toBeUndefined();
    expect(compileExcludeMatcher(undefined)).toBeUndefined();
  });
});

describe("harden with an exclude list", () => {
  it("discovery reports what the list left out", () => {
    const dir = project();
    const found = discoverHardenTargets(dir, {
      stateRoot: tempDir("bla-exclude-state-"),
      exclude: ["dist/vendor"],
    });
    expect(found.artifacts.map((a) => a.relativePath)).toEqual(["dist/app.cjs", "dist/util.cjs"]);
    expect(found.excluded).toEqual(["dist/vendor/heavy.cjs", "dist/vendor/lib.min.js"]);
  });

  it("hardens everything else and says which files ship unprotected", () => {
    const dir = project();
    const report = hardenProject({
      directory: dir,
      intensity: "balanced",
      seed: "exclude-seed",
      exclude: ["dist/vendor/heavy.cjs"],
      applyStateRoot: tempDir("bla-exclude-state-"),
    });
    expect(report.overallSuccess).toBe(true);
    expect(report.artifacts.map((a) => a.relativePath)).toEqual([
      "dist/app.cjs",
      "dist/util.cjs",
      "dist/vendor/lib.min.js",
    ]);
    expect(report.excluded).toEqual(["dist/vendor/heavy.cjs"]);
    expect(existsSync(join(dir, ".bla-hardened", "dist", "vendor", "heavy.cjs"))).toBe(false);
    expect(report.nextSteps?.join("\n")).toMatch(
      /1 file\(s\) matched the exclude list and were left exactly as they are — unprotected \(dist\/vendor\/heavy\.cjs\)/,
    );
  }, 240000);

  it("merges the project config's exclude with the call's", () => {
    const dir = project({ exclude: ["*.min.js"] });
    const report = hardenProject({
      directory: dir,
      intensity: "balanced",
      seed: "exclude-seed",
      exclude: ["dist/vendor/heavy.cjs"],
      dryRun: true,
      applyStateRoot: tempDir("bla-exclude-state-"),
    });
    expect(report.artifacts.map((a) => a.relativePath)).toEqual(["dist/app.cjs", "dist/util.cjs"]);
    expect([...(report.excluded ?? [])].sort()).toEqual(["dist/vendor/heavy.cjs", "dist/vendor/lib.min.js"]);

    expect(() => validateBlaConfigShape({ exclude: "dist/vendor" }, "test")).toThrow(
      /'exclude' must be an array of strings/,
    );
    expect(validateBlaConfigShape({ exclude: ["dist/vendor"] }, "test").exclude).toEqual(["dist/vendor"]);
  });

  it("the recovery loop: apply, find the file that hurts, apply again without it", () => {
    const dir = project();
    const stateRoot = tempDir("bla-exclude-state-");
    const options = { directory: dir, intensity: "balanced" as const, seed: "exclude-seed", applyStateRoot: stateRoot };

    const first = hardenProject({ ...options, apply: true });
    expect(first.apply?.status).toBe("applied");
    expect(readFileSync(join(dir, "dist/vendor/heavy.cjs"), "utf8")).not.toBe(HEAVY);

    // "heavy.cjs is the hot path" → same call again, minus that one file.
    const second = hardenProject({ ...options, apply: true, exclude: ["dist/vendor/heavy.cjs"] });
    expect(second.apply?.status).toBe("applied");
    expect(second.excluded).toEqual(["dist/vendor/heavy.cjs"]);
    // The excluded file is the build's original again; the rest is still hardened.
    expect(readFileSync(join(dir, "dist/vendor/heavy.cjs"), "utf8")).toBe(HEAVY);
    expect(readFileSync(join(dir, "dist/app.cjs"), "utf8")).not.toBe(APP);
    expect(readFileSync(join(dir, "dist/util.cjs"), "utf8")).not.toBe(UTIL);
    expect(second.apply?.applied).not.toContain("dist/vendor/heavy.cjs");
    // The mixed tree runs.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    expect(require(join(dir, "dist/app.cjs")).run()).toBe(191);

    // And restore still returns every original.
    const restored = restoreHardenedProject(dir, { applyStateRoot: stateRoot });
    expect(restored.status).toBe("restored");
    expect(readFileSync(join(dir, "dist/app.cjs"), "utf8")).toBe(APP);
    expect(readFileSync(join(dir, "dist/util.cjs"), "utf8")).toBe(UTIL);
    expect(readFileSync(join(dir, "dist/vendor/heavy.cjs"), "utf8")).toBe(HEAVY);
  }, 240000);

  it("is reachable from MCP and the CLI", async () => {
    const dir = project();
    const call = async (name: string, args: Record<string, unknown>) =>
      handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });

    const discover = (await call("bla_discover", { directory: dir, exclude: ["vendor"] }))!.result as {
      structuredContent: { artifacts: { relativePath: string }[]; excluded: string[] };
    };
    expect(discover.structuredContent.artifacts.map((a) => a.relativePath)).toEqual([
      "dist/app.cjs",
      "dist/util.cjs",
    ]);
    expect(discover.structuredContent.excluded).toHaveLength(2);

    const harden = (await call("bla_harden", {
      directory: dir,
      intensity: "balanced",
      seed: "exclude-seed",
      dry_run: true,
      exclude: ["dist/vendor/heavy.cjs"],
    }))!.result as { structuredContent: { excluded: string[]; discoveredCount: number } };
    expect(harden.structuredContent.excluded).toEqual(["dist/vendor/heavy.cjs"]);
    expect(harden.structuredContent.discoveredCount).toBe(3);

    const bad = await call("bla_harden", { directory: dir, exclude: "dist/vendor" });
    expect(bad?.error?.code).toBe(-32602);
    expect(bad?.error?.message).toMatch(/'exclude' must be an array/);

    const parsed = parseCliArgs(["harden", ".", "--exclude", "dist/vendor, *.min.js", "--exclude", "dist/x.js"]);
    expect(parsed.exclude).toEqual(["dist/vendor", "*.min.js", "dist/x.js"]);
    expect(parseCliArgs(["harden", "."]).exclude).toEqual([]);
  }, 240000);
});
