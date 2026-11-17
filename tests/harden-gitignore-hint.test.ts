import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";

/**
 * A harden run leaves a `.bla-hardened/` mirror in the project. In a git work
 * tree that does not ignore it, the next `git add -A` commits megabytes of
 * hardened copies — so the report says so, and only then.
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

function put(dir: string, rel: string, text: string): void {
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), text);
}

const APP = "exports.add = function add(a, b) { return a + b; };\n";
const HINT = /is generated output and git does not ignore it: add it to \.gitignore/;

/** A repository with one package in it; `files` are relative to the repository root. */
function repository(files: Readonly<Record<string, string>> = {}, withGit = true): string {
  const root = tempDir("bla-gitignore-");
  if (withGit) mkdirSync(join(root, ".git", "info"), { recursive: true });
  put(root, "dist/app.cjs", APP);
  put(root, "package.json", '{ "name": "p", "version": "1.0.0", "main": "dist/app.cjs" }');
  for (const [rel, text] of Object.entries(files)) put(root, rel, text);
  return root;
}

function steps(directory: string, extra: Record<string, unknown> = {}): string {
  const report = hardenProject({
    directory,
    seed: "gitignore-hint",
    intensity: "stealth",
    applyStateRoot: tempDir("bla-gitignore-state-"),
    ...extra,
  });
  expect(report.discoveredCount).toBeGreaterThan(0);
  return report.nextSteps?.join("\n") ?? "";
}

describe("the mirror directory and git", () => {
  it("says so when a git work tree does not ignore .bla-hardened", () => {
    expect(steps(repository())).toMatch(
      /^\.bla-hardened is generated output and git does not ignore it: add it to \.gitignore so hardened copies are not committed by accident\.$/m,
    );
    // Patterns that do not cover it change nothing.
    expect(steps(repository({ ".gitignore": "node_modules/\n# .bla-hardened\n!.bla-hardened\ndocs/.bla-hardened\n*.log\n" }))).toMatch(HINT);
  });

  it("stays quiet once the mirror is ignored, however that is spelled", () => {
    for (const pattern of [".bla-hardened", ".bla-hardened/", "/.bla-hardened/", "**/.bla-hardened", ".bla-*", ".*", "*"]) {
      expect(steps(repository({ ".gitignore": `node_modules\n${pattern}\n` })), pattern).not.toMatch(HINT);
    }
    expect(steps(repository({ ".git/info/exclude": ".bla-hardened\n" }))).not.toMatch(HINT);
  });

  it("stays quiet outside a git work tree and for a preview", () => {
    expect(steps(repository({}, false))).not.toMatch(HINT);
    expect(steps(repository(), { dryRun: true })).not.toMatch(HINT);
  });

  it("reads the ignore files between the repository root and a nested project", () => {
    const nested = (files: Readonly<Record<string, string>>): string => {
      const root = tempDir("bla-gitignore-mono-");
      mkdirSync(join(root, ".git"), { recursive: true });
      put(root, "packages/app/dist/app.cjs", APP);
      put(root, "packages/app/package.json", '{ "name": "app", "version": "1.0.0", "main": "dist/app.cjs" }');
      for (const [rel, text] of Object.entries(files)) put(root, rel, text);
      return steps(join(root, "packages", "app"));
    };
    expect(nested({})).toMatch(HINT);
    expect(nested({ ".gitignore": "packages/other/.bla-hardened\n" })).toMatch(HINT);
    expect(nested({ ".gitignore": "packages/app/.bla-hardened\n" })).not.toMatch(HINT);
    expect(nested({ ".gitignore": "packages/*/.bla-hardened/\n" })).not.toMatch(HINT);
    expect(nested({ ".gitignore": "/packages/app\n" })).not.toMatch(HINT);
    expect(nested({ "packages/app/.gitignore": ".bla-hardened\n" })).not.toMatch(HINT);
    // An anchored pattern only applies from the directory of its own ignore file.
    expect(nested({ "packages/app/.gitignore": "packages/app/.bla-hardened\n" })).toMatch(HINT);
  });
});
