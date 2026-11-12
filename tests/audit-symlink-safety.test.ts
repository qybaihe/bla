import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "bla-audit-symlink-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// Creating symlinks needs a privilege on Windows; the assertion runs on POSIX CI.
const canSymlink = (() => {
  try {
    const probe = dir();
    writeFileSync(join(probe, "a"), "a");
    symlinkSync(join(probe, "a"), join(probe, "b"));
    return true;
  } catch {
    return false;
  }
})();

describe("directory audits stay inside the audited tree", () => {
  it.skipIf(!canSymlink)("does not follow a file symlink that points outside the tree", () => {
    const root = dir();
    const outside = dir();
    const insideSource = `module.exports = { license: () => true };\n`;
    const outsideSource = `module.exports = { license: () => "OUTSIDE_SECRET_PAYLOAD" };\n`;
    writeFileSync(join(root, "app.js"), insideSource);
    writeFileSync(join(outside, "secret.js"), outsideSource);
    symlinkSync(join(outside, "secret.js"), join(root, "linked.js"));

    const report = auditTarget(root);

    // The audited bytes are exactly the in-tree file, not the symlink target.
    expect(report.byteSize).toBe(Buffer.byteLength(insideSource));
    expect(JSON.stringify(report)).not.toContain("OUTSIDE_SECRET_PAYLOAD");
  });
});