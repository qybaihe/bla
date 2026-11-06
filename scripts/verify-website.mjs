#!/usr/bin/env node
/**
 * Verifies the checked-in `website/` tree before it is published.
 *
 * The site is served from a separate repository (`qybaihe/bla-site`) that
 * `scripts/sync-site.mjs` fills by copying `website/` verbatim, so a broken link
 * or a dropped Content-Security-Policy here ships straight to the public site.
 * This checker is the only gate in that pipeline.
 *
 * Checks, in order:
 *  1. required files exist (pages, assets, schemas, `.nojekyll`);
 *  2. every page carries a Content-Security-Policy that is identical across
 *     pages and declares the expected directives;
 *  3. `script-src` does not allow inline script;
 *  4. no page introduces an inline `<script>` or an inline event handler;
 *  5. every internal `href`/`src` resolves to a file inside the site, or to a
 *     directory that has an `index.html`.
 *
 * Usage: node scripts/verify-website.mjs [--root <dir>]
 * Exits 0 when every check passes and 1 with a list of problems otherwise.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Files the site cannot work without; paths are relative to the website root. */
export const REQUIRED_FILES = [
  "index.html",
  "get-started/index.html",
  "showcase/index.html",
  "guides/index.html",
  "faq/index.html",
  "crackme/index.html",
  "assets/styles.css",
  "assets/main.js",
  "assets/i18n.js",
  "assets/home.js",
  "assets/logo.png",
  "assets/favicon.png",
  "assets/favicon.svg",
  "assets/social-card.svg",
  "schemas/defense-manifest-v1.json",
  "schemas/bla.config.v1.json",
  ".nojekyll",
];

/** Directives every page must declare. */
export const REQUIRED_CSP_DIRECTIVES = [
  "default-src",
  "script-src",
  "style-src",
  "img-src",
  "connect-src",
  "object-src",
  "base-uri",
  "form-action",
];

/** Attributes that point at another file. */
const REF_ATTRIBUTES = ["href", "src"];

/** Recursively lists every `.html` file under `root`, sorted for stable output. */
export function listPages(root) {
  const pages = [];
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.endsWith(".html")) pages.push(full);
    }
  };
  visit(root);
  return pages.sort();
}

/** Returns the Content-Security-Policy value of a page, or null when absent. */
export function readCsp(html) {
  for (const tag of html.match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/http-equiv\s*=\s*["']Content-Security-Policy["']/i.test(tag)) continue;
    // The policy itself contains single quotes (`script-src 'self'`), so the value
    // must be captured by its own delimiter rather than a generic [^"'] class.
    const content = /content\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    if (content) return (content[1] ?? content[2] ?? "").trim();
  }
  return null;
}

/** Splits a CSP into directive name → source list. */
export function parseCsp(policy) {
  const directives = new Map();
  for (const part of policy.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    directives.set(tokens[0].toLowerCase(), tokens.slice(1));
  }
  return directives;
}

/** Yields `{ attribute, ref }` for every href/src value in the page. */
export function listRefs(html) {
  const refs = [];
  const re = new RegExp(
    `\\b(${REF_ATTRIBUTES.join("|")})\\s*=\\s*(?:"([^"]*)"|'([^']*)')`,
    "gi",
  );
  for (const match of html.matchAll(re)) {
    refs.push({ attribute: match[1].toLowerCase(), ref: (match[2] ?? match[3] ?? "").trim() });
  }
  return refs;
}

/** True for refs that point outside the site (absolute URLs, fragments, data URIs). */
function isExternal(ref) {
  return ref === "" || ref.startsWith("#") || ref.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(ref);
}

/**
 * Runs every check against `root`.
 * @returns {{ ok: boolean, problems: string[], stats: { pages: number, refs: number } }}
 */
export function verifyWebsite(root) {
  const problems = [];
  const websiteRoot = resolve(root);
  let refCount = 0;

  if (!existsSync(websiteRoot) || !statSync(websiteRoot).isDirectory()) {
    return { ok: false, problems: [`website root not found: ${websiteRoot}`], stats: { pages: 0, refs: 0 } };
  }

  for (const file of REQUIRED_FILES) {
    if (!existsSync(join(websiteRoot, file))) problems.push(`missing required file: ${file}`);
  }

  const pages = listPages(websiteRoot);
  if (pages.length === 0) problems.push("no .html pages found");

  const cspByPage = new Map();
  for (const page of pages) {
    const label = relative(websiteRoot, page).split("\\").join("/");
    const html = readFileSync(page, "utf8");
    const policy = readCsp(html);
    if (policy === null) {
      problems.push(`${label}: no Content-Security-Policy meta tag`);
    } else {
      cspByPage.set(label, policy);
    }

    // Inline script would be dead under `script-src 'self'`, so treat it as a bug:
    // either the page is broken today or someone is about to weaken the policy.
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) {
      if (!/\bsrc\s*=/i.test(tag)) problems.push(`${label}: inline <script> without src`);
    }
    const handler = /\son[a-z]+\s*=\s*["']/i.exec(html);
    if (handler) problems.push(`${label}: inline event handler '${handler[0].trim()}'`);

    for (const { attribute, ref } of listRefs(html)) {
      if (isExternal(ref)) continue;
      refCount += 1;
      const cleaned = ref.split("#")[0].split("?")[0];
      if (cleaned === "") continue; // in-page fragment only

      const target = resolve(dirname(page), cleaned);
      const inside = relative(websiteRoot, target);
      if (inside.startsWith("..") || isAbsolute(inside)) {
        problems.push(`${label}: ${attribute}="${ref}" escapes the site root`);
        continue;
      }
      if (!existsSync(target)) {
        problems.push(`${label}: ${attribute}="${ref}" does not resolve (missing ${inside.split("\\").join("/")})`);
        continue;
      }
      if (statSync(target).isDirectory() && !existsSync(join(target, "index.html"))) {
        problems.push(`${label}: ${attribute}="${ref}" points at a directory without index.html`);
      }
    }
  }

  // A single policy across the site keeps `sync-site.mjs`'s verbatim copy honest:
  // a directive tightened in one page must be tightened in all of them.
  const distinct = new Set(cspByPage.values());
  if (distinct.size > 1) {
    const detail = [...cspByPage].map(([page, policy]) => `  ${page}: ${policy}`).join("\n");
    problems.push(`Content-Security-Policy differs between pages:\n${detail}`);
  }
  for (const [page, policy] of cspByPage) {
    const directives = parseCsp(policy);
    for (const required of REQUIRED_CSP_DIRECTIVES) {
      if (!directives.has(required)) problems.push(`${page}: CSP is missing '${required}'`);
    }
    const scriptSrc = directives.get("script-src") ?? [];
    if (scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes("*")) {
      problems.push(`${page}: script-src allows inline script ('${scriptSrc.join(" ")}')`);
    }
  }

  return { ok: problems.length === 0, problems, stats: { pages: pages.length, refs: refCount } };
}

function main(argv) {
  const flag = argv.indexOf("--root");
  const root = flag >= 0 && argv[flag + 1] ? argv[flag + 1] : resolve(dirname(fileURLToPath(import.meta.url)), "..", "website");
  const result = verifyWebsite(root);

  if (result.ok) {
    console.log(
      `Website OK: ${result.stats.pages} pages, ${result.stats.refs} internal refs, CSP consistent across all pages.`,
    );
    return 0;
  }
  console.error(`Website verification failed with ${result.problems.length} problem(s):`);
  for (const problem of result.problems) console.error(`  - ${problem}`);
  return 1;
}

// Run only when invoked as a script, so tests can import the exported helpers.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}