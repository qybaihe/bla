import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const CLI = resolve(process.cwd(), "dist/cli.js");
const HAS_DIST = existsSync(CLI);

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "bla-emit-headers-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("bla emit-headers --output", () => {
  it.skipIf(!HAS_DIST)("writes the header into a nested output path that does not exist yet", () => {
    const base = dir();
    const outPath = join(base, "generated", "include", "bla_defense.h");

    const res = spawnSync(process.execPath, [CLI, "emit-headers", "--output", outPath], {
      encoding: "utf8",
      timeout: 30_000,
    });

    expect(res.status, res.stderr).toBe(0);
    expect(existsSync(outPath)).toBe(true);
    expect(readFileSync(outPath, "utf8").length).toBeGreaterThan(0);
    // No leftover temp file from the atomic write.
    expect(existsSync(`${outPath}.bla-tmp-1`)).toBe(false);
  });

  it.skipIf(!HAS_DIST)("leaves no partial file behind when the target directory cannot be created", () => {
    const base = dir();
    const outPath = join(base, "blocked", "out.h");
    // A regular file where the parent directory would have to be created.
    spawnSync(process.execPath, ["-e", `require("node:fs").writeFileSync(${JSON.stringify(join(base, "blocked"))}, "x")`]);

    const res = spawnSync(process.execPath, [CLI, "emit-headers", "--output", outPath], {
      encoding: "utf8",
      timeout: 30_000,
    });

    expect(res.status).not.toBe(0);
    expect(existsSync(outPath)).toBe(false);
  });
});