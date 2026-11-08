import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyWebsiteDirectory } from "../scripts/verify-website.mjs";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-website-verify-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("website static verification", () => {
  it("passes on the repository website directory", () => {
    const res = verifyWebsiteDirectory();
    expect(res.ok).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.pagesChecked).toBe(7);
    expect(res.linksChecked).toBeGreaterThan(50);
  });

  it("flags missing CSP or broken internal links", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "assets"), { recursive: true });
    writeFileSync(
      join(dir, "index.html"),
      "<!doctype html><html><head></head><body><a href=\"missing.html\">x</a></body></html>",
      "utf8",
    );
    const res = verifyWebsiteDirectory(dir);
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("missing Content-Security-Policy"))).toBe(true);
    expect(res.errors.some((e) => e.includes("broken link target 'missing.html'"))).toBe(true);
  });
});
