import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-harden-seed-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

const JS = "export const add = (a, b) => a + b;\n";

describe("harden seed location", () => {
  it("writes a minted .blarc next to the project, not inside the build output", async () => {
    const project = createTempDir();
    const build = join(project, "dist");
    mkdirSync(build, { recursive: true });
    writeFileSync(join(build, "app.mjs"), JS, "utf8");

    const previousCwd = process.cwd();
    process.chdir(project);
    try {
      await runCli(["harden", "./dist", "--json"]);

      const projectConfig = join(project, ".blarc");
      expect(existsSync(projectConfig)).toBe(true);
      expect(JSON.parse(readFileSync(projectConfig, "utf8")).seed).toMatch(/^bla-[0-9a-f]{32}$/);
      // The seed must not be written into the directory the user publishes.
      expect(existsSync(join(build, ".blarc"))).toBe(false);
    } finally {
      process.chdir(previousCwd);
    }
  });

  it("keeps using an existing project seed across runs", async () => {
    const project = createTempDir();
    const build = join(project, "dist");
    mkdirSync(build, { recursive: true });
    writeFileSync(join(build, "app.mjs"), JS, "utf8");
    writeFileSync(join(project, ".blarc"), JSON.stringify({ seed: "bla-existing-seed" }), "utf8");

    const previousCwd = process.cwd();
    process.chdir(project);
    try {
      await runCli(["harden", "./dist", "--json"]);
      expect(JSON.parse(readFileSync(join(project, ".blarc"), "utf8")).seed).toBe("bla-existing-seed");
      expect(existsSync(join(build, ".blarc"))).toBe(false);
    } finally {
      process.chdir(previousCwd);
    }
  });
});