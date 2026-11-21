import { execFileSync } from "node:child_process";
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject, restoreHardenedProject } from "../src/engine/harden.js";
import {
  applyHardenedOutputs,
  listAppliedFiles,
  resolveApplyStateDirectory,
} from "../src/engine/harden-apply.js";
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

const MAIN = `const { check } = require("./license.cjs");
const cfg = require("./config.json");
console.log(cfg.name, check("password"), check("nope"));
`;
const LICENSE = `const crypto = require("node:crypto");
const EXPECTED = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
function check(key) { return crypto.createHash("sha256").update(String(key)).digest("hex") === EXPECTED; }
module.exports = { check };
`;

/** A built project: two JS artifacts plus a JSON file BLA does not touch. */
function makeBuiltProject(): string {
  const dir = tempDir("bla-apply-proj-");
  mkdirSync(join(dir, "dist"), { recursive: true });
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "dist", "main.cjs"), MAIN, "utf8");
  writeFileSync(join(dir, "dist", "license.cjs"), LICENSE, "utf8");
  writeFileSync(join(dir, "dist", "config.json"), JSON.stringify({ name: "demo" }), "utf8");
  writeFileSync(join(dir, "src", "main.ts"), "export const source = true;\n", "utf8");
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "apply-fixture", version: "1.0.0", main: "dist/main.cjs" }),
    "utf8",
  );
  return dir;
}

function runMain(dir: string): string {
  return execFileSync(process.execPath, [join(dir, "dist", "main.cjs")], { encoding: "utf8" }).trim();
}

function listFilesRecursive(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, rel: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const next = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(join(dir, entry.name), next);
      else out.push(next);
    }
  };
  walk(root, "");
  return out.sort();
}

/** Windows needs Developer Mode or elevation to create symlinks; probe instead of assuming. */
const canCreateSymlinks = (() => {
  try {
    const probe = tempDir("bla-symlink-probe-");
    writeFileSync(join(probe, "target"), "x", "utf8");
    symlinkSync(join(probe, "target"), join(probe, "link"));
    return true;
  } catch {
    return false;
  }
})();

describe("harden apply / restore", () => {
  it("promotes hardened build output in place and restores the exact originals", () => {
    const dir = makeBuiltProject();
    const stateRoot = tempDir("bla-apply-state-");
    const before = listFilesRecursive(dir);
    expect(runMain(dir)).toBe("demo true false");

    const report = hardenProject({
      directory: dir,
      apply: true,
      applyStateRoot: stateRoot,
      intensity: "balanced",
      seed: "apply-seed",
    });
    expect(report.overallSuccess).toBe(true);
    expect(report.apply?.status).toBe("applied");
    expect([...(report.apply?.applied ?? [])].sort()).toEqual(["dist/license.cjs", "dist/main.cjs"]);

    // The project tree is the same set of files — no mirror, no backups inside it.
    expect(listFilesRecursive(dir)).toEqual(before);
    expect(existsSync(join(dir, ".bla-hardened"))).toBe(false);
    expect(report.apply?.backupDirectory?.startsWith(stateRoot)).toBe(true);

    // The build output now holds hardened code, and the program still works
    // because the untouched config.json is right where it was.
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).not.toBe(LICENSE);
    expect(readFileSync(join(dir, "dist", "main.cjs"), "utf8")).not.toBe(MAIN);
    expect(readFileSync(join(dir, "src", "main.ts"), "utf8")).toBe("export const source = true;\n");
    expect(runMain(dir)).toBe("demo true false");
    expect(report.nextSteps?.join("\n")).toMatch(/Run the project's own tests/);
    expect(report.nextSteps?.join("\n")).toMatch(/restore/);

    const restored = restoreHardenedProject(dir, { applyStateRoot: stateRoot });
    expect(restored.status).toBe("restored");
    expect([...(restored.restored ?? [])].sort()).toEqual(["dist/license.cjs", "dist/main.cjs"]);
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).toBe(LICENSE);
    expect(readFileSync(join(dir, "dist", "main.cjs"), "utf8")).toBe(MAIN);
    expect(listFilesRecursive(dir)).toEqual(before);
    expect(restoreHardenedProject(dir, { applyStateRoot: stateRoot }).status).toBe(
      "nothing-to-restore",
    );
  }, 60000);

  it("re-hardens from the saved originals instead of hardening hardened code", () => {
    const dir = makeBuiltProject();
    const stateRoot = tempDir("bla-apply-state-");
    const options = {
      directory: dir,
      apply: true,
      applyStateRoot: stateRoot,
      intensity: "balanced" as const,
      seed: "apply-seed",
    };
    expect(hardenProject(options).apply?.status).toBe("applied");
    const firstBytes = readFileSync(join(dir, "dist", "license.cjs"));
    const firstSize = statSync(join(dir, "dist", "main.cjs")).size;

    const second = hardenProject(options);
    expect(second.apply?.status).toBe("applied");
    // Same inputs + same seed ⇒ same output; a double harden would have grown it.
    expect(readFileSync(join(dir, "dist", "license.cjs")).equals(firstBytes)).toBe(true);
    expect(statSync(join(dir, "dist", "main.cjs")).size).toBe(firstSize);
    expect(runMain(dir)).toBe("demo true false");

    // The backup is still the ORIGINAL, not the first hardened version.
    restoreHardenedProject(dir, { applyStateRoot: stateRoot });
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).toBe(LICENSE);
  }, 60000);

  it("treats a rebuilt file as a new original", () => {
    const dir = makeBuiltProject();
    const stateRoot = tempDir("bla-apply-state-");
    const options = {
      directory: dir,
      apply: true,
      applyStateRoot: stateRoot,
      intensity: "balanced" as const,
      seed: "apply-seed",
    };
    hardenProject(options);
    // The build ran again and regenerated main.cjs with new code.
    const rebuilt = MAIN.replace("cfg.name,", 'cfg.name, "v2",');
    writeFileSync(join(dir, "dist", "main.cjs"), rebuilt, "utf8");

    expect(hardenProject(options).apply?.status).toBe("applied");
    expect(runMain(dir)).toBe("demo v2 true false");
    restoreHardenedProject(dir, { applyStateRoot: stateRoot });
    expect(readFileSync(join(dir, "dist", "main.cjs"), "utf8")).toBe(rebuilt);
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).toBe(LICENSE);
  }, 60000);

  it("refuses to overwrite source files", () => {
    const dir = tempDir("bla-apply-src-");
    mkdirSync(join(dir, "src"), { recursive: true });
    const source = "module.exports = { answer: () => 42 };\n";
    writeFileSync(join(dir, "src", "app.js"), source, "utf8");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "src-only", version: "1.0.0" }), "utf8");

    const report = hardenProject({
      directory: dir,
      apply: true,
      applyStateRoot: tempDir("bla-apply-state-"),
      intensity: "balanced",
      seed: "apply-seed",
    });
    expect(report.overallSuccess).toBe(false);
    expect(report.apply?.status).toBe("refused");
    expect(report.apply?.reason).toMatch(/source files/);
    expect(report.apply?.sourceFiles).toEqual(["src/app.js"]);
    expect(readFileSync(join(dir, "src", "app.js"), "utf8")).toBe(source);
    expect(report.nextSteps?.[0]).toMatch(/apply did not promote anything/);
  }, 60000);

  it("keeps the previous hardened build when a re-harden fails", () => {
    const dir = makeBuiltProject();
    const stateRoot = tempDir("bla-apply-state-");
    const options = {
      directory: dir,
      apply: true,
      applyStateRoot: stateRoot,
      intensity: "balanced" as const,
      seed: "apply-seed",
    };
    hardenProject(options);
    const hardenedLicense = readFileSync(join(dir, "dist", "license.cjs"));
    const hardenedMain = readFileSync(join(dir, "dist", "main.cjs"));

    // A rebuilt artifact that cannot be parsed makes the next run fail.
    writeFileSync(join(dir, "dist", "main.cjs"), "function ( {\n", "utf8");
    const failed = hardenProject(options);
    expect(failed.overallSuccess).toBe(false);
    expect(failed.apply?.status).toBe("refused");
    expect(failed.apply?.reason).toMatch(/nothing was promoted/);

    // license.cjs is still the earlier hardened file, main.cjs the broken rebuild.
    expect(readFileSync(join(dir, "dist", "license.cjs")).equals(hardenedLicense)).toBe(true);
    expect(readFileSync(join(dir, "dist", "main.cjs"), "utf8")).toBe("function ( {\n");
    expect(hardenedMain.length).toBeGreaterThan(0);
    expect(listAppliedFiles(dir, resolveApplyStateDirectory(dir, stateRoot))).toContain(
      "dist/license.cjs",
    );
  }, 60000);

  it("a plain harden refuses to run over build output promoted by apply", () => {
    const dir = makeBuiltProject();
    const stateRoot = tempDir("bla-apply-state-");
    hardenProject({
      directory: dir,
      apply: true,
      applyStateRoot: stateRoot,
      intensity: "balanced",
      seed: "apply-seed",
    });
    expect(() =>
      hardenProject({ directory: dir, applyStateRoot: stateRoot, intensity: "balanced", seed: "apply-seed" }),
    ).toThrow(/already hardened output promoted by an earlier apply run/);
  }, 60000);

  it("dry-run previews the promotion without touching anything", () => {
    const dir = makeBuiltProject();
    const stateRoot = tempDir("bla-apply-state-");
    const report = hardenProject({
      directory: dir,
      apply: true,
      dryRun: true,
      applyStateRoot: stateRoot,
      intensity: "balanced",
      seed: "apply-seed",
    });
    expect(report.apply?.status).toBe("planned");
    expect([...(report.apply?.applied ?? [])].sort()).toEqual(["dist/license.cjs", "dist/main.cjs"]);
    expect([...report.wouldOverwrite].sort()).toEqual(
      [join(dir, "dist", "license.cjs"), join(dir, "dist", "main.cjs")].sort(),
    );
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).toBe(LICENSE);
    expect(readdirSync(stateRoot)).toEqual([]);
  }, 60000);

  it("MCP: apply and restore both wait for confirm_overwrite, and failures are isError", async () => {
    const dir = makeBuiltProject();
    const call = async (args: Record<string, unknown>) => {
      const res = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "bla_harden", arguments: args },
      });
      expect(res?.error).toBeUndefined();
      return res!.result as { isError?: boolean; structuredContent: Record<string, any> };
    };
    const base = { directory: dir, intensity: "balanced", seed: "apply-seed" };

    const unconfirmed = await call({ ...base, apply: true });
    expect(unconfirmed.isError).toBe(true);
    expect(unconfirmed.structuredContent.status).toBe("confirmation_required");
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).toBe(LICENSE);

    const applied = await call({ ...base, apply: true, confirm_overwrite: true });
    expect(applied.isError).toBeFalsy();
    expect(applied.structuredContent.apply.status).toBe("applied");
    expect(runMain(dir)).toBe("demo true false");

    const restoreUnconfirmed = await call({ directory: dir, restore: true });
    expect(restoreUnconfirmed.isError).toBe(true);
    expect(restoreUnconfirmed.structuredContent.status).toBe("confirmation_required");

    const restored = await call({ directory: dir, restore: true, confirm_overwrite: true });
    expect(restored.isError).toBeFalsy();
    expect(restored.structuredContent.status).toBe("restored");
    expect(readFileSync(join(dir, "dist", "license.cjs"), "utf8")).toBe(LICENSE);

    // A run that hardens nothing is an error result, not a quiet success.
    const empty = tempDir("bla-apply-empty-");
    const nothing = await call({ directory: empty });
    expect(nothing.isError).toBe(true);
    expect(nothing.structuredContent.overallSuccess).toBe(false);
    expect(nothing.structuredContent.nextSteps[0]).toMatch(/Nothing protectable was found/);
  }, 90000);

  it("refuses to promote a hardened artifact over a hardlinked destination", () => {
    const dir = makeBuiltProject();
    const hardenedMirror = tempDir("bla-apply-mirror-");
    const hardened = join(hardenedMirror, "main.cjs");
    writeFileSync(hardened, "/* hardened */\n", "utf8");

    const outside = tempDir("bla-apply-outside-");
    const victim = join(outside, "victim.txt");
    writeFileSync(victim, "untouched\n", "utf8");

    const destination = join(dir, "dist", "main.cjs");
    rmSync(destination, { force: true });
    linkSync(victim, destination);
    expect(statSync(destination).nlink).toBeGreaterThan(1);

    const report = applyHardenedOutputs({
      projectDirectory: dir,
      stateDirectory: tempDir("bla-apply-state-"),
      runId: "link-refusal",
      candidates: [{ outputPath: hardened, destinationPath: destination }],
      buildDirNames: ["dist"],
    });

    // The promotion must fail closed instead of writing through the alias.
    expect(report.status).toBe("failed");
    expect(report.reason).toMatch(/symlink or hardlinked output/);
    expect(readFileSync(victim, "utf8")).toBe("untouched\n");
    expect(readdirSync(join(dir, "dist")).some((n) => n.includes(".bla-tmp"))).toBe(false);
  }, 30000);

  it.skipIf(!canCreateSymlinks)(
    "refuses to promote a hardened artifact over a symlinked destination",
    () => {
      const dir = makeBuiltProject();
      const hardenedMirror = tempDir("bla-apply-mirror-");
      const hardened = join(hardenedMirror, "main.cjs");
      writeFileSync(hardened, "/* hardened */\n", "utf8");

      const outside = tempDir("bla-apply-outside-");
      const victim = join(outside, "victim.txt");
      writeFileSync(victim, "untouched\n", "utf8");

      const destination = join(dir, "dist", "main.cjs");
      rmSync(destination, { force: true });
      symlinkSync(victim, destination);

      const report = applyHardenedOutputs({
        projectDirectory: dir,
        stateDirectory: tempDir("bla-apply-state-"),
        runId: "symlink-refusal",
        candidates: [{ outputPath: hardened, destinationPath: destination }],
        buildDirNames: ["dist"],
      });

      expect(report.status).toBe("failed");
      expect(report.reason).toMatch(/symlink or hardlinked output/);
      expect(readFileSync(victim, "utf8")).toBe("untouched\n");
    },
    30000,
  );
});
