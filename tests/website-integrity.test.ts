import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const WEBSITE_ROOT = resolve(process.cwd(), "website");
const SCRIPT = resolve(process.cwd(), "scripts/verify-website.mjs");

const tempRoots: string[] = [];

afterAll(() => {
  for (const dir of tempRoots) rmSync(dir, { recursive: true, force: true });
});

/** Copies the real website tree into a scratch directory the test may mutate. */
function copyWebsite(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-website-"));
  tempRoots.push(dir);
  cpSync(WEBSITE_ROOT, dir, { recursive: true });
  return dir;
}

/** Runs the checker against `root` and returns its exit code, stdout and stderr. */
function verify(root: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [SCRIPT, "--root", root], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Rewrites one page in place inside a scratch copy. */
function editPage(root: string, page: string, edit: (html: string) => string): void {
  const path = join(root, page);
  writeFileSync(path, edit(readFileSync(path, "utf8")), "utf8");
}

describe("website link and CSP verification", () => {
  it("passes on the checked-in website", () => {
    const result = verify(WEBSITE_ROOT);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Website OK");
    // Every page in the tree is covered, including the CrackMe page the old
    // required-file list in website-pages.yml never mentioned.
    const pages = readdirSync(WEBSITE_ROOT, { recursive: true })
      .map((entry) => String(entry))
      .filter((entry) => entry.endsWith(".html"));
    expect(pages.length).toBeGreaterThanOrEqual(6);
  });

  it("fails when an internal link stops resolving", () => {
    const root = copyWebsite();
    editPage(root, "index.html", (html) => html.replace('href="guides/"', 'href="guides-missing/"'));

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("does not resolve");
    expect(result.stderr).toContain("guides-missing/");
  });

  it("fails when a required page is removed", () => {
    const root = copyWebsite();
    rmSync(join(root, "crackme", "index.html"));

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("missing required file: crackme/index.html");
  });

  it("fails when a page drops the Content-Security-Policy", () => {
    const root = copyWebsite();
    editPage(root, "faq/index.html", (html) =>
      html.replace(/^.*http-equiv="Content-Security-Policy".*$/m, ""),
    );

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("faq/index.html: no Content-Security-Policy meta tag");
  });

  it("fails when one page drifts from the shared policy", () => {
    const root = copyWebsite();
    editPage(root, "guides/index.html", (html) =>
      html.replace("object-src 'none';", "object-src 'self';"),
    );

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Content-Security-Policy differs between pages");
  });

  it("fails when a page introduces inline script", () => {
    const root = copyWebsite();
    editPage(root, "index.html", (html) =>
      html.replace("</body>", "    <script>console.log('inline');</script>\n  </body>"),
    );

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("inline <script> without src");
  });

  it("fails when script-src starts allowing inline script", () => {
    const root = copyWebsite();
    for (const page of ["index.html", "faq/index.html", "guides/index.html", "get-started/index.html", "showcase/index.html", "crackme/index.html"]) {
      editPage(root, page, (html) => html.replace("script-src 'self';", "script-src 'self' 'unsafe-inline';"));
    }

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-src allows inline script");
  });

  it("fails when a link escapes the site root", () => {
    const root = copyWebsite();
    editPage(root, "index.html", (html) => html.replace('href="guides/"', 'href="../outside/"'));

    const result = verify(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("escapes the site root");
  });
});