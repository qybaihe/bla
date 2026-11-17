import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  isKnownBlaOutput,
  listKnownBlaOutputs,
  registerBlaOutput,
  resolveBlaStateRoot,
} from "../src/core/output-registry.js";
import { discoverHardenTargets, hardenProject } from "../src/engine/harden.js";
import { scanPackagingGates } from "../src/engine/packaging-gates.js";
import { handleMcpRequest } from "../src/mcp/server.js";

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function callTool(name: string, args: Record<string, unknown>) {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
  expect(res?.error).toBeUndefined();
  return res!.result as { isError?: boolean; structuredContent: Record<string, any> };
}

const LICENSE_SOURCE = `const crypto = require("node:crypto");
const EXPECTED = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
function check(key) { return crypto.createHash("sha256").update(String(key)).digest("hex") === EXPECTED; }
module.exports = { check };
`;

function makeProject(): string {
  const dir = tempDir("bla-registry-proj-");
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "dist", "license.cjs"), LICENSE_SOURCE, "utf8");
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "registry-fixture", version: "1.0.0", main: "dist/license.cjs" }),
    "utf8",
  );
  return dir;
}

describe("registry of files BLA wrote", () => {
  it("knows a file exactly while it holds the registered bytes", () => {
    const stateRoot = tempDir("bla-registry-state-");
    const dir = tempDir("bla-registry-files-");
    const file = join(dir, "out.js");
    writeFileSync(file, "console.log('hardened bytes');\n", "utf8");

    expect(isKnownBlaOutput(file, stateRoot)).toBe(false);
    registerBlaOutput(file, stateRoot);
    expect(isKnownBlaOutput(file, stateRoot)).toBe(true);

    // The same bytes under another name are the same output (copied / promoted).
    const copy = join(dir, "copy.js");
    copyFileSync(file, copy);
    expect(isKnownBlaOutput(copy, stateRoot)).toBe(true);

    // A rebuild or an edit makes it an ordinary input again.
    appendFileSync(file, "// edited\n", "utf8");
    expect(isKnownBlaOutput(file, stateRoot)).toBe(false);

    // Another state root knows nothing.
    expect(isKnownBlaOutput(copy, tempDir("bla-registry-other-"))).toBe(false);
    expect(listKnownBlaOutputs(dir, { stateRoot })).toEqual(["copy.js"]);
  });

  it("never throws and never registers directories or missing paths", () => {
    const stateRoot = tempDir("bla-registry-state-");
    const dir = tempDir("bla-registry-files-");
    expect(() => registerBlaOutput(join(dir, "missing.js"), stateRoot)).not.toThrow();
    expect(() => registerBlaOutput(dir, stateRoot)).not.toThrow();
    expect(isKnownBlaOutput(join(dir, "missing.js"), stateRoot)).toBe(false);
    expect(isKnownBlaOutput(dir, stateRoot)).toBe(false);
    expect(listKnownBlaOutputs(join(dir, "missing"), { stateRoot })).toEqual([]);
  });

  it("keeps test runs out of the developer's real BLA state", () => {
    // vitest.config.ts points BLA_STATE_DIR at a throwaway directory.
    expect(process.env.BLA_STATE_DIR).toBeTruthy();
    expect(resolveBlaStateRoot()).toBe(process.env.BLA_STATE_DIR);
  });

  it("does not feed a bla_defend output inside the project back into harden or lint", async () => {
    const dir = makeProject();
    const hardened = join(dir, "dist", "license.hard.cjs");

    const defend = await callTool("bla_defend", {
      input_path: join(dir, "dist", "license.cjs"),
      output_path: hardened,
      seed: "registry-seed",
    });
    expect(defend.isError).toBeFalsy();
    expect(existsSync(hardened)).toBe(true);

    // Before the registry this listed license.hard.cjs as a fresh artifact …
    const discovery = (await callTool("bla_discover", { directory: dir })).structuredContent;
    expect(discovery.artifacts.map((a: { relativePath: string }) => a.relativePath)).toEqual([
      "dist/license.cjs",
    ]);
    expect(discovery.skippedHardenedOutputs).toEqual(["dist/license.hard.cjs"]);

    // … the lint called BLA's own decoys plaintext secrets and lane gates …
    const lint = (await callTool("bla_lint", { directory: dir })).structuredContent;
    const lintedPaths = lint.findings.map((f: { relativePath: string }) => f.relativePath);
    expect(lintedPaths).not.toContain("dist/license.hard.cjs");
    expect(lint.skippedHardenedOutputs).toEqual(["dist/license.hard.cjs"]);
    expect(lint.oneLineAdvice).toMatch(/1 BLA-hardened output file\(s\) were not linted/);

    // … and bla_harden refused the run on them.
    const harden = await callTool("bla_harden", { directory: dir, seed: "registry-seed" });
    expect(harden.isError).toBeFalsy();
    expect(harden.structuredContent.overallSuccess).toBe(true);
    expect(harden.structuredContent.hardenedCount).toBe(1);
    expect(harden.structuredContent.skippedHardenedOutputs).toEqual(["dist/license.hard.cjs"]);
    expect(harden.structuredContent.nextSteps.join("\n")).toMatch(
      /already BLA output from an earlier run \(dist\/license\.hard\.cjs\)/,
    );
  }, 60000);

  it("tells the agent when everything found is already hardened", () => {
    const stateRoot = tempDir("bla-registry-state-");
    const dir = tempDir("bla-registry-proj-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    const first = hardenProject({
      directory: (() => {
        writeFileSync(join(dir, "dist", "app.cjs"), "module.exports = { answer: () => 42 };\n", "utf8");
        return dir;
      })(),
      intensity: "balanced",
      seed: "registry-seed",
      applyStateRoot: stateRoot,
    });
    expect(first.overallSuccess).toBe(true);

    // Simulate "copied the mirror over the build output by hand".
    copyFileSync(first.artifacts[0]!.outputPath, join(dir, "dist", "app.cjs"));
    rmSync(join(dir, ".bla-hardened"), { recursive: true, force: true });

    const promotedBytes = readFileSync(join(dir, "dist", "app.cjs"));

    const discovery = discoverHardenTargets(dir, { stateRoot });
    expect(discovery.artifacts).toHaveLength(0);
    expect(discovery.skippedHardenedOutputs).toEqual(["dist/app.cjs"]);

    const again = hardenProject({
      directory: dir,
      intensity: "balanced",
      seed: "registry-seed",
      applyStateRoot: stateRoot,
    });
    expect(again.discoveredCount).toBe(0);
    expect(again.overallSuccess).toBe(false);
    expect(again.nextSteps?.[0]).toMatch(/Nothing new to harden/);
    expect(again.nextSteps?.[0]).toMatch(/Rebuild the project/);
    // Nothing was hardened twice, and no second mirror was written.
    expect(readFileSync(join(dir, "dist", "app.cjs")).equals(promotedBytes)).toBe(true);
    expect(existsSync(join(dir, ".bla-hardened", "dist", "app.cjs"))).toBe(false);
  }, 60000);

  it("skips a custom output directory of an earlier run even when it is named like build output", () => {
    const stateRoot = tempDir("bla-registry-state-");
    const dir = tempDir("bla-registry-proj-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(join(dir, "dist", "app.cjs"), "module.exports = { answer: () => 42 };\n", "utf8");

    const first = hardenProject({
      directory: dir,
      outputDirectory: join(dir, "release"),
      intensity: "balanced",
      seed: "registry-seed",
      applyStateRoot: stateRoot,
    });
    expect(first.overallSuccess).toBe(true);
    expect(existsSync(join(dir, "release", "dist", "app.cjs"))).toBe(true);

    // A fresh state root proves the directory rule on its own (no registry hit).
    const next = discoverHardenTargets(dir, { stateRoot: tempDir("bla-registry-empty-") });
    expect(next.artifacts.map((a) => a.relativePath)).toEqual(["dist/app.cjs"]);
  }, 60000);

  it("lint walks skip registered outputs but an explicitly named file is still linted", () => {
    const dir = tempDir("bla-registry-lint-");
    const gate = join(dir, "license-gate.js");
    writeFileSync(
      gate,
      `const lanes = [0x41, 0x42, 0x43, 0x44];\nfunction check(key) { return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]); }\n`,
      "utf8",
    );
    const before = scanPackagingGates({ directory: dir });
    expect(before.gateCounts["lane-independence"]).toBe(1);

    registerBlaOutput(gate); // default (test) state root, as the lints use it
    const after = scanPackagingGates({ directory: dir });
    expect(after.gateCounts["lane-independence"]).toBe(0);
    expect(after.skippedHardenedOutputs).toEqual(["license-gate.js"]);

    const explicit = scanPackagingGates({ directory: gate });
    expect(explicit.gateCounts["lane-independence"]).toBe(1);
  });
});
