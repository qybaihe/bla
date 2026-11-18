/**
 * Which JavaScript artifacts run in a browser rather than in Node?
 *
 * The self-seal and sidecar-entanglement bindings are Node programs: they read
 * sibling files with `node:fs` and hash them with `node:crypto` when the entry
 * module loads. Prepended to a front-end bundle they do not protect anything —
 * `import … from "node:module"` makes the browser refuse the whole module, and
 * a `require("node:crypto")` preamble throws "integrity binding mismatch" on
 * an untouched build. So a browser bundle is hardened without them, and the
 * report says so.
 *
 * Evidence, strongest first:
 *  1. an HTML page loads the file (`<script src>`, `<link rel="modulepreload">`);
 *  2. a file from (1) statically imports it (code-split chunks, workers);
 *  3. it uses browser globals and shows no sign of Node at all.
 *
 * A wrong "browser" verdict only costs an optional integrity binding (and is
 * reported); a wrong "Node" verdict ships an application that cannot start.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

export interface BrowserBundleCandidate {
  /** Absolute path of the JS/TS artifact as it sits in the project. */
  readonly path: string;
  readonly relativePath: string;
}

const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const MAX_HTML_FILES = 64;

const HTML_SCRIPT_REF_RE =
  /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))|<link\b[^>]*?\brel\s*=\s*["']?(?:modulepreload|preload|prefetch)["']?[^>]*?\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))|<link\b[^>]*?\bhref\s*=\s*(?:"([^"]+\.m?js(?:[?#][^"]*)?)"|'([^']+\.m?js(?:[?#][^']*)?)')[^>]*?\brel\s*=\s*["']?(?:modulepreload|preload|prefetch)/gi;

/** Relative specifiers a module pulls in: static / dynamic imports and `new URL(…, import.meta.url)`. */
const RELATIVE_IMPORT_RE =
  /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s*|\bimportScripts\s*\(\s*|new\s+URL\s*\(\s*)["'`](\.{1,2}\/[^"'`\n]+?)["'`]/g;

const BROWSER_GLOBAL_RE =
  /\b(?:document\s*\.\s*(?:getElementById|querySelector|querySelectorAll|createElement|addEventListener|body|head|cookie|documentElement)|window\s*\.\s*(?:addEventListener|location|document|localStorage|sessionStorage|history|matchMedia|requestAnimationFrame|innerWidth|innerHeight)|customElements\s*\.\s*define|localStorage\s*\.\s*(?:getItem|setItem)|sessionStorage\s*\.\s*(?:getItem|setItem)|navigator\s*\.\s*(?:userAgent|serviceWorker|clipboard|language)|requestAnimationFrame\s*\(|\bHTMLElement\b)/;

const NODE_MARKER_RE =
  /\brequire\s*\(\s*["'`]|\bmodule\s*\.\s*exports\b|\b__dirname\b|\b__filename\b|\bprocess\s*\.\s*(?:env|argv|cwd|exit|platform|versions|stdout|stderr|stdin|on|nextTick|binding)\b|["'`]node:[a-z_/]+["'`]|\bfrom\s*["'`](?:fs|path|os|crypto|child_process|http|https|net|url|util|stream|worker_threads|electron)["'`]|\bimport\s*\.\s*meta\s*\.\s*(?:dirname|filename)\b|^#!.*\bnode\b/m;

function readText(path: string): string | undefined {
  try {
    if (statSync(path).size > MAX_SCAN_BYTES) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

function stripQueryAndHash(ref: string): string {
  const cut = ref.search(/[?#]/);
  return cut === -1 ? ref : ref.slice(0, cut);
}

/**
 * Map of absolute artifact path → why it is a browser bundle. Artifacts that
 * run in Node (or cannot be told) are absent.
 */
export function classifyBrowserBundles(
  candidates: readonly BrowserBundleCandidate[],
  rootDirectory: string,
): ReadonlyMap<string, string> {
  const verdicts = new Map<string, string>();
  if (candidates.length === 0) return verdicts;
  const byPath = new Map(candidates.map((c) => [resolve(c.path), c]));
  const byBasename = new Map<string, BrowserBundleCandidate[]>();
  for (const candidate of candidates) {
    const key = basename(candidate.path);
    byBasename.set(key, [...(byBasename.get(key) ?? []), candidate]);
  }
  const root = resolve(rootDirectory);

  // 1. HTML pages beside the artifacts (their directory and the one above it).
  const htmlDirs = new Set<string>();
  for (const candidate of candidates) {
    const dir = dirname(resolve(candidate.path));
    htmlDirs.add(dir);
    const parent = dirname(dir);
    if (parent.startsWith(root)) htmlDirs.add(parent);
  }
  htmlDirs.add(root);
  const htmlFiles: string[] = [];
  for (const dir of htmlDirs) {
    if (htmlFiles.length >= MAX_HTML_FILES) break;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (/\.html?$/i.test(name)) htmlFiles.push(join(dir, name));
      if (htmlFiles.length >= MAX_HTML_FILES) break;
    }
  }
  const queue: string[] = [];
  const mark = (path: string, reason: string): void => {
    if (verdicts.has(path)) return;
    verdicts.set(path, reason);
    queue.push(path);
  };
  for (const htmlPath of htmlFiles) {
    const html = readText(htmlPath);
    if (html === undefined) continue;
    const htmlDir = dirname(htmlPath);
    for (const match of html.matchAll(HTML_SCRIPT_REF_RE)) {
      const raw = match.slice(1).find((group) => group !== undefined);
      if (raw === undefined) continue;
      const ref = stripQueryAndHash(raw.trim());
      if (ref.length === 0 || /^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(ref) || /^data:/i.test(ref)) {
        continue;
      }
      // `/assets/app.js` is relative to the web root — taken to be the page's directory.
      const resolved = resolve(htmlDir, ref.replace(/^\/+/, ""));
      const reason = `loaded by ${basename(htmlPath)}`;
      if (byPath.has(resolved)) {
        mark(resolved, reason);
        continue;
      }
      const sameName = byBasename.get(basename(ref));
      if (sameName !== undefined && sameName.length === 1) {
        mark(resolve(sameName[0]!.path), reason);
      }
    }
  }

  // 2. Everything a browser module imports is a browser module too.
  while (queue.length > 0) {
    const current = queue.shift()!;
    const source = readText(current);
    if (source === undefined) continue;
    for (const match of source.matchAll(RELATIVE_IMPORT_RE)) {
      const spec = stripQueryAndHash(match[1]!);
      const target = resolve(dirname(current), spec);
      for (const candidatePath of [target, `${target}.js`, `${target}.mjs`]) {
        if (byPath.has(candidatePath) && existsSync(candidatePath)) {
          mark(candidatePath, `imported by ${basename(current)}, which a web page loads`);
          break;
        }
      }
    }
  }

  // 3. Browser globals and nothing Node about it.
  for (const candidate of candidates) {
    const path = resolve(candidate.path);
    if (verdicts.has(path)) continue;
    const source = readText(path);
    if (source === undefined) continue;
    if (BROWSER_GLOBAL_RE.test(source) && !NODE_MARKER_RE.test(source)) {
      verdicts.set(path, "uses browser globals (document / window / navigator) and no Node API");
    }
  }
  return verdicts;
}
