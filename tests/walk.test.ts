import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { walkBounded } from "../src/core/walk.js";
import { discoverHardenTargets } from "../src/engine/harden.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-walk-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("walkBounded read-error surfacing", () => {
  it("reports ENOENT for a missing root instead of silently returning []", () => {
    const missing = join(tmpdir(), `bla-walk-missing-${Date.now()}`);
    const seen: Array<{ path: string; code?: string }> = [];
    const files = walkBounded(missing, {
      maxDepth: 2,
      maxFiles: 10,
      onError: (path, error) => {
        seen.push({ path, code: (error as NodeJS.ErrnoException).code });
      },
    });
    expect(files).toEqual([]);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.path).toBe(missing);
    expect(seen[0]!.code).toBe("ENOENT");
  });

  it("reports ENOTDIR when the root is a regular file", () => {
    const dir = makeTempDir();
    const file = join(dir, "not-a-dir.txt");
    writeFileSync(file, "hello\n", "utf8");
    const seen: Array<{ path: string; code?: string }> = [];
    const files = walkBounded(file, {
      maxDepth: 2,
      maxFiles: 10,
      onError: (path, error) => {
        seen.push({ path, code: (error as NodeJS.ErrnoException).code });
      },
    });
    expect(files).toEqual([]);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.path).toBe(file);
    expect(seen[0]!.code).toBe("ENOTDIR");
  });

  it("stays silent on the happy path and keeps the no-onError contract", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "a.js"), "1\n", "utf8");
    const seen: string[] = [];
    const files = walkBounded(dir, {
      maxDepth: 2,
      maxFiles: 10,
      onError: (path) => seen.push(path),
    });
    expect(files).toHaveLength(1);
    expect(seen).toEqual([]);
    // Back-compat: omitting onError still returns [] for a missing root.
    const missing = join(tmpdir(), `bla-walk-quiet-${Date.now()}`);
    expect(walkBounded(missing, { maxDepth: 1, maxFiles: 10 })).toEqual([]);
  });

  it("discoverHardenTargets exposes discovery readErrors (empty on healthy trees)", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "app.js"), "module.exports = {};\n", "utf8");
    const result = discoverHardenTargets(dir, { maxArtifacts: 10 });
    expect(result.readErrors).toEqual([]);
  });
});
