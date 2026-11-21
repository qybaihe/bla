import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const APP = "const cfg = require('./cfg.json');\nmodule.exports = { n: cfg.n };\n";
const OUTSIDE_APP = "module.exports = { token: 'not-yours' };\n";

/** Windows needs Developer Mode or elevation for a symlink; a junction does not. */
function linkDir(target: string, link: string): void {
  symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
}

const canLinkDirs = (() => {
  try {
    const probe = tempDir("bla-link-probe-");
    mkdirSync(join(probe, "target"));
    linkDir(join(probe, "target"), join(probe, "link"));
    return true;
  } catch {
    return false;
  }
})();

function project(): string {
  const dir = tempDir("bla-root-containment-");
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "root-containment", version: "1.0.0", main: "dist/app.cjs" }),
    "utf8",
  );
  return dir;
}

/**
 * `walkBounded` is symlink-safe for the *entries* it sees, but it reads its own
 * root with `readdirSync`, which follows a link. Discovery therefore has to
 * refuse a build directory that resolves outside the project, otherwise a
 * planted `dist -> elsewhere` link steers what gets inventoried and mirrored.
 */
describe("harden discovery root containment", () => {
  it("still discovers a real build directory", () => {
    const dir = project();
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(join(dir, "dist", "app.cjs"), APP, "utf8");

    const report = hardenProject({ directory: dir, intensity: "balanced", seed: "root-seed" });
    expect(report.artifacts.map((a) => a.relativePath)).toContain("dist/app.cjs");
  });

  it.skipIf(!canLinkDirs)("refuses a build directory that resolves outside the project", () => {
    const outside = tempDir("bla-root-outside-");
    writeFileSync(join(outside, "app.cjs"), OUTSIDE_APP, "utf8");

    const dir = project();
    linkDir(outside, join(dir, "dist"));

    const report = hardenProject({ directory: dir, intensity: "balanced", seed: "root-seed" });
    const discovered = report.artifacts.map((a) => a.relativePath);
    expect(discovered).not.toContain("dist/app.cjs");
    expect(discovered.some((p) => p.includes("outside"))).toBe(false);

    // The linked tree is only read, never rewritten.
    expect(readFileSync(join(outside, "app.cjs"), "utf8")).toBe(OUTSIDE_APP);
  });
});
