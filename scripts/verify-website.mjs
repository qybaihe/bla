#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

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
  "assets/live-stats.mjs",
  "assets/i18n.js",
  "assets/home.js",
  "assets/logo.png",
  "assets/favicon.png",
  "assets/favicon.svg",
  "assets/social-card.svg",
  "schemas/defense-manifest-v1.json",
  "schemas/bla.config.v1.json",
];

const SUPPORTED_LOCALES = ["en", "zh-CN", "zh-TW", "ja", "ko", "es", "fr", "de"];

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

function extractI18nKeys(html) {
  const keys = new Set();
  const re = /\bdata-i18n(?:-html)?\s*=\s*(?:"([^"]+)"|'([^']+)')/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    keys.add(m[1] ?? m[2]);
  }
  return keys;
}

/**
 * Every HTML page under the site root, repo-relative with POSIX separators.
 * A page added later is verified automatically instead of silently skipped.
 */
function discoverHtmlPages(absRoot) {
  const pages = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = resolve(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".html")) {
        pages.push(full.slice(absRoot.length + 1).replaceAll("\\", "/"));
      }
    }
  };
  if (existsSync(absRoot)) walk(absRoot);
  return pages.sort();
}

function loadI18nDictionary(absRoot) {
  const i18nPath = resolve(absRoot, "assets/i18n.js");
  if (!existsSync(i18nPath)) return null;
  try {
    const sandbox = { window: {} };
    runInNewContext(readFileSync(i18nPath, "utf8"), sandbox, { timeout: 1000 });
    const dict = sandbox.window?.BLA_I18N;
    return dict !== null && typeof dict === "object" ? dict : null;
  } catch {
    return null;
  }
}

function computeI18nCoverage(dict, usedKeys, errors) {
  const en = dict.en ?? {};
  const englishKeys = Object.keys(en);
  for (const key of usedKeys) {
    if (!englishKeys.includes(key)) {
      errors.push(`assets/i18n.js: data-i18n key '${key}' has no English string`);
    }
  }
  const locales = {};
  for (const locale of SUPPORTED_LOCALES) {
    const table = dict[locale];
    if (table === null || typeof table !== "object") {
      errors.push(`assets/i18n.js: locale '${locale}' is missing`);
      locales[locale] = { keys: 0, missingFromEnglish: englishKeys.length };
      continue;
    }
    locales[locale] = {
      keys: Object.keys(table).length,
      missingFromEnglish: englishKeys.filter((key) => !(key in table)).length,
    };
  }
  return {
    referenceLocale: "en",
    referenceKeys: englishKeys.length,
    locales,
  };
}

/**
 * Verify all static website HTML pages, assets, CSP headers, and internal links/anchors.
 *
 * @param {string} [websiteRoot]
 * @returns {{
 *   ok: boolean,
 *   pagesChecked: number,
 *   linksChecked: number,
 *   errors: string[],
 *   i18nCoverage: { referenceLocale: string, referenceKeys: number, locales: Record<string, { keys: number, missingFromEnglish: number }> } | null,
 * }}
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
  const usedI18nKeys = new Set();

  const discovered = discoverHtmlPages(absRoot);
  const pageList = [...new Set([...REQUIRED_HTML_PAGES, ...discovered])].sort();

  for (const rel of pageList) {
    const full = resolve(absRoot, rel);
    if (!existsSync(full) || !statSync(full).isFile()) {
      errors.push(`Missing required HTML page: ${rel}`);
      continue;
    }
    const html = readFileSync(full, "utf8");
    pageCache.set(full, html);
    idCache.set(full, extractIds(html));
    for (const key of extractI18nKeys(html)) usedI18nKeys.add(key);
  }

  for (const rel of pageList) {
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
      if (/script-src\s+[^;]*'unsafe-inline'/i.test(csp)) {
        errors.push(`${rel}: CSP must not allow script-src 'unsafe-inline'`);
      }
      if (!/connect-src[^;]*https:\/\/api\.github\.com/i.test(csp)) {
        errors.push(`${rel}: CSP must allow https://api.github.com for live figures`);
      }
    }

    if (/data-gh-stars[^>]*>\s*\d/.test(html) || /data-gh-stars[^>]*>\s*★/.test(html)) {
      errors.push(`${rel}: star pill must not ship a hardcoded count`);
    }
    if (!html.includes('data-live-stamp="stars"')) {
      errors.push(`${rel}: missing visible GitHub star source stamp`);
    }
    if (!/<script\s+type="module"\s+src="(?:\.\.\/)?assets\/main\.js"><\/script>/.test(html)) {
      errors.push(`${rel}: main.js must load as a module`);
    }
    if (rel === "crackme/index.html" && !html.includes("data-crackme-live")) {
      errors.push(`${rel}: missing repository challenge status panel`);
    }

    if (/brand-badge|data-i18n=["']nav\.badge["']|蓝军防护|藍軍防護|BLUE SHIELD v1\./.test(html)) {
      errors.push(`${rel}: navigation shield badge must be removed`);
    }
    if (/\bonclick\s*=/i.test(html)) {
      errors.push(`${rel}: inline onclick is not allowed`);
    }
    if (!html.includes('class="nav-toggle"') || !html.includes('id="site-nav"')) {
      errors.push(`${rel}: accessible nav collapse control is missing`);
    }
    if (!html.includes('aria-controls="site-nav"') || !html.includes('aria-expanded="false"')) {
      errors.push(`${rel}: nav toggle missing aria-expanded or aria-controls`);
    }
    if (!html.includes('class="nav-links"') || !html.includes('id="bla-lang-select"') || !html.includes('class="nav-cta"')) {
      errors.push(`${rel}: language switch, primary nav, or Star control is missing`);
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

  const i18nDict = loadI18nDictionary(absRoot);
  let i18nCoverage = null;
  if (i18nDict !== null) {
    i18nCoverage = computeI18nCoverage(i18nDict, usedI18nKeys, errors);
  }

  const i18nPath = resolve(absRoot, "assets/i18n.js");
  if (existsSync(i18nPath)) {
    const i18n = readFileSync(i18nPath, "utf8");
    if (/nav\.badge/.test(i18n)) {
      errors.push("assets/i18n.js: nav.badge must be removed");
    }
    for (const key of [
      "nav.menu",
      "nav.menuClose",
      "nav.primary",
      "nav.lang",
      "live.stars.live",
      "live.stars.stale",
      "live.stars.unavailable",
      "live.crackme.noSolve",
      "live.crackme.commitment",
    ]) {
      const count = i18n.split(`"${key}"`).length - 1;
      if (count < 8) {
        errors.push(`assets/i18n.js: ${key} must exist in all 8 languages (found ${count})`);
      }
    }
  }

  const livePath = resolve(absRoot, "assets/live-stats.mjs");
  if (existsSync(livePath)) {
    const live = readFileSync(livePath, "utf8");
    if (!live.includes("STAR_REFRESH_MS = 5 * 60 * 1000")) {
      errors.push("assets/live-stats.mjs: star refresh must stay at 5 minutes");
    }
    if (!live.includes("CRACKME_REFRESH_MS = 10 * 60 * 1000")) {
      errors.push("assets/live-stats.mjs: CrackMe refresh must stay at 10 minutes");
    }
    if (!live.includes("FETCH_TIMEOUT_MS = 8000")) {
      errors.push("assets/live-stats.mjs: fetch timeout must stay at 8 seconds");
    }
    if (!live.includes("stargazers_count")) {
      errors.push("assets/live-stats.mjs: stars must come from stargazers_count");
    }
  }

  const cssPath = resolve(absRoot, "assets/styles.css");
  if (existsSync(cssPath)) {
    const css = readFileSync(cssPath, "utf8");
    if (/\.brand-badge\b/.test(css)) {
      errors.push("assets/styles.css: .brand-badge must be removed");
    }
    if (!/\.nav-link\s*\{[^}]*white-space:\s*nowrap/.test(css)) {
      errors.push("assets/styles.css: .nav-link must stay on one line (white-space: nowrap)");
    }
    if (!/@media\s*\(\s*max-width:\s*1023px\s*\)/.test(css)) {
      errors.push("assets/styles.css: missing max-width 1023px nav collapse breakpoint");
    }
  }

  const mainPath = resolve(absRoot, "assets/main.js");
  if (existsSync(mainPath)) {
    const main = readFileSync(mainPath, "utf8");
    if (!main.includes("initNavMenu") || !main.includes('addEventListener("click"')) {
      errors.push("assets/main.js: nav toggle must be wired without inline handlers");
    }
    if (!main.includes('from "./live-stats.mjs"') || !main.includes("startLiveFigures")) {
      errors.push("assets/main.js: live star and CrackMe figures must be wired");
    }
    if (main.includes("toFixed") || main.includes("bla_gh_stars")) {
      errors.push("assets/main.js: do not abbreviate stars or reuse the untimed star cache");
    }
  }

  return {
    ok: errors.length === 0,
    pagesChecked,
    linksChecked,
    errors,
    i18nCoverage,
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
  if (res.i18nCoverage !== null) {
    const summary = Object.entries(res.i18nCoverage.locales)
      .map(([locale, counts]) => `${locale} ${counts.keys}`)
      .join(", ");
    console.log(
      `i18n coverage against ${res.i18nCoverage.referenceLocale} (${res.i18nCoverage.referenceKeys} keys): ${summary}. Missing keys fall back to English at runtime.`,
    );
  }
}