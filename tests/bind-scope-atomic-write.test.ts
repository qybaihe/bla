import { existsSync, linkSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BIND_SCOPE_RUNTIME_MARKER, applyBindScope } from "../src/engine/bind-scope.js";

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "bla-bind-atomic-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const ENTRY = `"use strict";
module.exports.unlock = function unlock(key) {
  return key === "ok" ? "FLAG{in_scope}" : null;
};
`;

function hardlinkOrSkip(target: string, linkPath: string): boolean {
  try {
    linkSync(target, linkPath);
    return true;
  } catch {
    return false;
  }
}

describe("bind-scope writes through the shared atomic writer", () => {
  it("writes the contract and the rewritten entry into outDir", () => {
    const src = dir();
    const out = dir();
    writeFileSync(join(src, "license.cjs"), ENTRY);

    const report = applyBindScope({
      directory: src,
      entryPath: join(src, "license.cjs"),
      outDir: out,
      domains: ["allowed.example"],
      validFrom: "2020-01-01T00:00:00.000Z",
      validUntil: "2099-01-01T00:00:00.000Z",
    });

    expect(report.status).toBe("ok");
    expect(existsSync(join(out, "bind-scope.json"))).toBe(true);
    expect(readFileSync(join(out, "license.cjs"), "utf8")).toContain(BIND_SCOPE_RUNTIME_MARKER);
  });

  it("refuses to write the contract through a hardlinked path", () => {
    const src = dir();
    const out = dir();
    const outside = join(dir(), "outside-target.json");
    writeFileSync(join(src, "license.cjs"), ENTRY);
    writeFileSync(outside, "keep me");

    if (!hardlinkOrSkip(outside, join(out, "bind-scope.json"))) {
      // Filesystem without hardlink support: nothing to assert here.
      return;
    }

    expect(() =>
      applyBindScope({
        directory: src,
        entryPath: join(src, "license.cjs"),
        outDir: out,
        domains: ["allowed.example"],
        validFrom: "2020-01-01T00:00:00.000Z",
        validUntil: "2099-01-01T00:00:00.000Z",
      }),
    ).toThrow(/Refusing to write through a symlink or hardlinked output/);
    expect(readFileSync(outside, "utf8")).toBe("keep me");
  });
});