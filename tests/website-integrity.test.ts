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

  it("reports i18n coverage for every supported locale", () => {
    const res = verifyWebsiteDirectory();
    expect(res.i18nCoverage).not.toBeNull();
    expect(res.i18nCoverage!.referenceLocale).toBe("en");
    expect(res.i18nCoverage!.referenceKeys).toBeGreaterThan(100);
    expect(Object.keys(res.i18nCoverage!.locales)).toEqual([
      "en",
      "zh-CN",
      "zh-TW",
      "ja",
      "ko",
      "es",
      "fr",
      "de",
    ]);
    expect(res.i18nCoverage!.locales.en!.missingFromEnglish).toBe(0);
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

  it("verifies pages discovered on disk, not only the hardcoded list", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "assets"), { recursive: true });
    writeFileSync(
      join(dir, "index.html"),
      "<!doctype html><html><head></head><body></body></html>",
      "utf8",
    );
    mkdirSync(join(dir, "extra"), { recursive: true });
    writeFileSync(
      join(dir, "extra", "index.html"),
      "<!doctype html><html><head></head><body><a href=\"missing.html\">x</a></body></html>",
      "utf8",
    );
    const res = verifyWebsiteDirectory(dir);
    expect(res.pagesChecked).toBe(2);
    expect(
      res.errors.some((e) => e.includes("extra/index.html") && e.includes("broken link target")),
    ).toBe(true);
    // The declared pages are still required even when discovery finds others.
    expect(res.errors.some((e) => e.includes("Missing required HTML page: get-started/index.html"))).toBe(
      true,
    );
  });

  it("flags markup keys that have no English string", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "assets"), { recursive: true });
    writeFileSync(
      join(dir, "assets", "i18n.js"),
      'window.BLA_I18N = {"en":{"known":"Known"},"zh-CN":{"known":"已知"},"zh-TW":{},"ja":{},"ko":{},"es":{},"fr":{},"de":{}};\n',
      "utf8",
    );
    writeFileSync(
      join(dir, "index.html"),
      '<!doctype html><html><head></head><body><span data-i18n="missing.key">x</span></body></html>',
      "utf8",
    );
    const res = verifyWebsiteDirectory(dir);
    expect(res.errors.some((e) => e.includes("missing.key") && e.includes("no English string"))).toBe(
      true,
    );
    expect(res.i18nCoverage!.referenceKeys).toBe(1);
  });

  it("flags missing SEO metadata, canonical/sitemap drift, or malformed JSON-LD", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "assets"), { recursive: true });
    writeFileSync(join(dir, "sitemap.xml"), "<urlset><url><loc>https://bla.tools/</loc></url></urlset>", "utf8");
    writeFileSync(
      join(dir, "index.html"),
      '<!doctype html><html><head><link rel="canonical" href="https://bla.tools/unlisted/" /><script type="application/ld+json">{bad json}</script></head><body></body></html>',
      "utf8",
    );
    const res = verifyWebsiteDirectory(dir);
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("missing or too-short <meta name=\"description\">"))).toBe(true);
    expect(res.errors.some((e) => e.includes("missing from sitemap.xml"))).toBe(true);
    expect(res.errors.some((e) => e.includes("invalid JSON-LD syntax"))).toBe(true);
  });
});