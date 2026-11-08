#!/usr/bin/env node
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const REQUIRED_HTML_PAGES = [
  "index.html",
  "get-started/index.html",
  "showcase/index.html",
  "crackme/index.html",
  "guides/index.html",
  "faq/index.html",
  "enterprise/index.html",
];

const REQUIRED_ASSETS = [
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
];

function extractIds(html) {
  const ids = new Set();
  const re = /\bid\s*=\s*(?:"([^"]+)"|'([^']+)')/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    ids.add(m[1] ?? m[2]);
  }
  return ids;
}

function extractCspContent(html) {
  const metaRe = /<meta\b[^>]*http-equiv\s*=\s*(?:"Content-Security-Policy"|'Content-Security-Policy')[^>]*>/i;
  const tag = metaRe.exec(html)?.[0];
  if (!tag) return null;
  const contentRe = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i;
  const m = contentRe.exec(tag);
  return m ? (m[1] ?? m[2] ?? "") : null;
}

function extractLocalRefs(html) {
  const refs = [];
  const re = /\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const val = (m[1] ?? m[2] ?? "").trim();
    if (
      !val ||
      val.startsWith("http://") ||
      val.startsWith("https://") ||
      val.startsWith("mailto:") ||
      val.startsWith("data:") ||
      val.startsWith("javascript:")
    ) {
      continue;
    }
    refs.push(val);
  }
  return refs;
}

/**
 * Verify all static website HTML pages, assets, CSP headers, and internal links/anchors.
 *
 * @param {string} [websiteRoot]
 * @returns {{ ok: boolean, pagesChecked: number, linksChecked: number, errors: string[] }}
 */
export function verifyWebsiteDirectory(websiteRoot = resolve(REPO_ROOT, "website")) {
  const absRoot = resolve(websiteRoot);
  const errors = [];
  let pagesChecked = 0;
  let linksChecked = 0;

  for (const rel of REQUIRED_ASSETS) {
    const full = resolve(absRoot, rel);
    if (!existsSync(full) || !statSync(full).isFile()) {
      errors.push(`Missing required asset: ${rel}`);
    }
  }

  const pageCache = new Map();
  const idCache = new Map();

  for (const rel of REQUIRED_HTML_PAGES) {
    const full = resolve(absRoot, rel);
    if (!existsSync(full) || !statSync(full).isFile()) {
      errors.push(`Missing required HTML page: ${rel}`);
      continue;
    }
    const html = readFileSync(full, "utf8");
    pageCache.set(full, html);
    idCache.set(full, extractIds(html));
  }

  for (const rel of REQUIRED_HTML_PAGES) {
    const full = resolve(absRoot, rel);
    const html = pageCache.get(full);
    if (html === undefined) continue;
    pagesChecked++;

    const csp = extractCspContent(html);
    if (!csp) {
      errors.push(`${rel}: missing Content-Security-Policy <meta> tag`);
    } else {
      if (!/default-src\s+[^;]*'self'/i.test(csp)) {
        errors.push(`${rel}: CSP missing default-src 'self'`);
      }
      if (!/script-src\s+[^;]*'self'/i.test(csp)) {
        errors.push(`${rel}: CSP missing script-src 'self'`);
      }
      if (!/object-src\s+[^;]*'none'/i.test(csp)) {
        errors.push(`${rel}: CSP missing object-src 'none'`);
      }
      if (/'unsafe-eval'/i.test(csp)) {
        errors.push(`${rel}: CSP must not allow 'unsafe-eval'`);
      }
    }

    const pageDir = dirname(full);
    for (const ref of extractLocalRefs(html)) {
      linksChecked++;
      const [rawPath, rawHash] = ref.split("#", 2);
      let targetFile = full;
      if (rawPath && rawPath.length > 0) {
        const candidate = resolve(pageDir, rawPath);
        if (!candidate.startsWith(absRoot)) {
          errors.push(`${rel}: link escapes website root (${ref})`);
          continue;
        }
        if (existsSync(candidate) && statSync(candidate).isDirectory()) {
          targetFile = resolve(candidate, "index.html");
        } else {
          targetFile = candidate;
        }
        if (!existsSync(targetFile) || !statSync(targetFile).isFile()) {
          errors.push(`${rel}: broken link target '${ref}'`);
          continue;
        }
      }
      if (rawHash && rawHash.length > 0) {
        let ids = idCache.get(targetFile);
        if (!ids && existsSync(targetFile) && statSync(targetFile).isFile()) {
          const targetHtml = readFileSync(targetFile, "utf8");
          ids = extractIds(targetHtml);
          idCache.set(targetFile, ids);
        }
        if (!ids || !ids.has(rawHash)) {
          errors.push(`${rel}: broken anchor '#${rawHash}' in '${ref}'`);
        }
      }
    }
  }

  return {
    ok: errors.length === 0,
    pagesChecked,
    linksChecked,
    errors,
  };
}

const isDirectRun =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  const res = verifyWebsiteDirectory();
  if (!res.ok) {
    for (const err of res.errors) {
      console.error(`Website verification error: ${err}`);
    }
    process.exit(1);
  }
  console.log(
    `Verified ${res.pagesChecked} website HTML pages and ${res.linksChecked} internal links/assets.`,
  );
}
