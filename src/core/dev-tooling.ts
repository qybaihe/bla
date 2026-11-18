import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

/**
 * Toolchain files are never the product: hardening `vite.config.ts`, a test
 * suite, or the script behind `npm run build` protects nothing, inflates the
 * artifact list an agent has to reason about, and — on any write-back path —
 * risks breaking the build that produces the real artifacts.
 *
 * Everything here is a filename / manifest heuristic, deliberately narrow:
 * a false "tooling" verdict silently leaves a file unprotected, so ambiguous
 * names (`config.js`, `tasks.py`, `manage.py`, `server.js`) are NOT matched.
 */

const SCRIPT_EXT = String.raw`[cm]?[jt]sx?`;

/** `x.test.ts`, `x.spec.mjs`, `test_x.py`, `x_test.py`, `conftest.py`. */
const TEST_FILE_RE = new RegExp(
  String.raw`(?:\.(?:test|spec|e2e|bench|stories)\.${SCRIPT_EXT}$|^test_[^/\\]*\.py$|_test\.py$|^conftest\.py$)`,
  "i",
);

/**
 * Tool configuration that only means "config" when it sits at a package root:
 * `vite.config.ts`, `webpack.prod.config.js`, `jest.config.cjs`, …
 * (An Angular `src/app/app.config.ts` is shipped application code.)
 */
const PACKAGE_ROOT_CONFIG_RE = new RegExp(
  String.raw`^[\w-]+(?:\.[\w-]+)*\.config(?:\.[\w-]+)?\.${SCRIPT_EXT}$`,
  "i",
);

/** Task-runner / harness entry files with a fixed conventional name. */
const TOOLING_BASENAMES: ReadonlySet<string> = new Set(
  [
    "gruntfile.js",
    "gruntfile.cjs",
    "gruntfile.ts",
    "gulpfile.js",
    "gulpfile.cjs",
    "gulpfile.mjs",
    "gulpfile.ts",
    "gulpfile.babel.js",
    "jakefile.js",
    "karma.conf.js",
    "karma.conf.cjs",
    "karma.conf.ts",
    "protractor.conf.js",
    "wdio.conf.js",
    "wdio.conf.ts",
    "jest.setup.js",
    "jest.setup.ts",
    "vitest.setup.js",
    "vitest.setup.ts",
    "setuptests.js",
    "setuptests.ts",
    "setup.py",
    "noxfile.py",
    "fabfile.py",
  ].map((n) => n.toLowerCase()),
);

/**
 * Release-engineering scripts: unambiguous task names inside a directory that
 * holds helper scripts (`scripts/deploy.py`, `ci/publish.mjs`). Only these
 * names — `scripts/` can also hold console scripts a Python project ships.
 */
const HELPER_SCRIPT_DIR_NAMES: ReadonlySet<string> = new Set([
  "scripts",
  "script",
  "ci",
  "hack",
  "devtools",
  "dev-tools",
  "tooling",
]);
const RELEASE_TASK_NAME_RE = new RegExp(
  String.raw`^(?:deploy|release|publish|bump[-_]?version|make[-_]?release|update[-_]?changelog|lint|fmt|format)\.(?:${SCRIPT_EXT}|py)$`,
  "i",
);

/** Formats where a leading-dot file is tool state (`.eslintrc.js`, `.pnp.cjs`). */
const HIDDEN_SCRIPT_RE = new RegExp(String.raw`^\.[^/\\]*\.(?:${SCRIPT_EXT}|py)$`, "i");

export function isTestFileName(name: string): boolean {
  return TEST_FILE_RE.test(name);
}

const packageRootCache = new Map<string, boolean>();

function isPackageRoot(dir: string): boolean {
  const cached = packageRootCache.get(dir);
  if (cached !== undefined) return cached;
  const result =
    existsSync(join(dir, "package.json")) ||
    existsSync(join(dir, "pyproject.toml")) ||
    existsSync(join(dir, "deno.json")) ||
    existsSync(join(dir, "deno.jsonc"));
  packageRootCache.set(dir, result);
  return result;
}

/**
 * True for toolchain configuration / task-runner / test files (see module doc).
 * `fullPath` is needed because config-by-pattern only applies at a package root.
 */
export function isDevToolingFile(fullPath: string, name: string): boolean {
  if (isTestFileName(name)) return true;
  if (HIDDEN_SCRIPT_RE.test(name)) return true;
  if (TOOLING_BASENAMES.has(name.toLowerCase())) return true;
  if (PACKAGE_ROOT_CONFIG_RE.test(name) && isPackageRoot(dirname(fullPath))) return true;
  if (
    RELEASE_TASK_NAME_RE.test(name) &&
    HELPER_SCRIPT_DIR_NAMES.has(basename(dirname(fullPath)).toLowerCase())
  ) {
    return true;
  }
  return false;
}

interface PackageManifest {
  readonly main?: unknown;
  readonly module?: unknown;
  readonly browser?: unknown;
  readonly bin?: unknown;
  readonly exports?: unknown;
  readonly scripts?: unknown;
}

function readPackageManifest(packageRoot: string): PackageManifest | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as PackageManifest)
      : undefined;
  } catch {
    return undefined;
  }
}

function collectStringLeaves(value: unknown, out: string[], depth = 0): void {
  if (depth > 8) return;
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStringLeaves(item, out, depth + 1);
  } else if (typeof value === "object" && value !== null) {
    for (const item of Object.values(value)) collectStringLeaves(item, out, depth + 1);
  }
}

/**
 * Absolute paths `package.json` declares as runtime entry points
 * (`main` / `module` / `browser` / `bin` / `exports`). Wildcard export targets
 * are ignored. Empty when there is no readable manifest.
 */
export function readPackageRuntimeEntries(packageRoot: string): ReadonlySet<string> {
  const manifest = readPackageManifest(packageRoot);
  const out = new Set<string>();
  if (!manifest) return out;
  const leaves: string[] = [];
  collectStringLeaves(manifest.main, leaves);
  collectStringLeaves(manifest.module, leaves);
  collectStringLeaves(manifest.browser, leaves);
  collectStringLeaves(manifest.bin, leaves);
  collectStringLeaves(manifest.exports, leaves);
  for (const leaf of leaves) {
    if (leaf.length === 0 || leaf.includes("*") || leaf.includes("\0")) continue;
    out.add(resolve(packageRoot, leaf));
  }
  return out;
}

const PYPROJECT_SCRIPT_TABLES: ReadonlySet<string> = new Set([
  "project.scripts",
  "project.gui-scripts",
  "tool.poetry.scripts",
]);
const SETUP_CFG_SCRIPT_GROUPS: ReadonlySet<string> = new Set(["console_scripts", "gui_scripts"]);
const PYTHON_MODULE_PATH_RE = /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/;
const PYTHON_MANIFEST_MAX_BYTES = 512 * 1024;

function readSmallTextFile(path: string): string | undefined {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > PYTHON_MANIFEST_MAX_BYTES) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * Dotted module names a Python project declares as the way to start it:
 * console / GUI scripts in `pyproject.toml` (`[project.scripts]`,
 * `[project.gui-scripts]`, `[tool.poetry.scripts]`), `setup.cfg`
 * (`[options.entry_points]`) and `setup.py` (`console_scripts`). An installed
 * script imports that module directly — no `run.py` beside the package is
 * involved. In declaration order, without duplicates; empty when the project
 * declares none. Line-based and bounded on purpose: it never executes or fully
 * parses the manifests.
 */
export function readPythonDeclaredEntryModules(projectRoot: string): string[] {
  const modules: string[] = [];
  const add = (target: string): void => {
    const module = target.split(":")[0]!.trim();
    if (PYTHON_MODULE_PATH_RE.test(module) && !modules.includes(module)) modules.push(module);
  };

  const pyproject = readSmallTextFile(join(projectRoot, "pyproject.toml"));
  if (pyproject !== undefined) {
    let table = "";
    for (const raw of pyproject.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.length === 0 || line.startsWith("#")) continue;
      const header = /^\[\s*([^\]]+?)\s*\]\s*(?:#.*)?$/.exec(line);
      if (header) {
        table = header[1]!.replace(/\s+/g, "");
        continue;
      }
      if (!PYPROJECT_SCRIPT_TABLES.has(table)) continue;
      // name = "pkg.mod:func"   |   name = { callable = "pkg.mod:func", … } (Poetry)
      const entry =
        /^[^=]+=\s*["']([^"']+)["']/.exec(line) ??
        /^[^=]+=\s*\{.*\b(?:callable|reference)\s*=\s*["']([^"']+)["']/.exec(line);
      if (entry) add(entry[1]!);
    }
  }

  const setupCfg = readSmallTextFile(join(projectRoot, "setup.cfg"));
  if (setupCfg !== undefined) {
    let inEntryPoints = false;
    let inScriptGroup = false;
    for (const raw of setupCfg.split(/\r?\n/)) {
      if (raw.trim().length === 0 || /^\s*[#;]/.test(raw)) continue;
      const header = /^\[\s*([^\]]+?)\s*\]\s*$/.exec(raw);
      if (header) {
        inEntryPoints = header[1] === "options.entry_points";
        inScriptGroup = false;
        continue;
      }
      if (!inEntryPoints) continue;
      const assignment = /^(\s*)([^=\s][^=]*?)\s*=\s*(.*)$/.exec(raw);
      if (!assignment) continue;
      if (assignment[1]!.length === 0) {
        // `console_scripts =` opens a group; a value on the same line belongs to it.
        inScriptGroup = SETUP_CFG_SCRIPT_GROUPS.has(assignment[2]!);
        const inline = /=\s*([\w.]+(?::[\w.]+)?)\s*$/.exec(assignment[3]!);
        if (inScriptGroup && inline) add(inline[1]!);
      } else if (inScriptGroup) {
        add(assignment[3]!.trim());
      }
    }
  }

  const setupPy = readSmallTextFile(join(projectRoot, "setup.py"));
  if (setupPy !== undefined && /\b(?:console|gui)_scripts\b/.test(setupPy)) {
    for (const match of setupPy.matchAll(/["'][\w.-]+\s*=\s*([A-Za-z_][\w.]*):[\w.]+["']/g)) {
      add(match[1]!);
    }
  }
  return modules;
}

/**
 * npm script names that build, check, or publish. `start` / `serve` / `dev` /
 * `watch` run the product itself and `*install` hooks ship with the package,
 * so none of those count as tooling.
 */
const TOOLING_SCRIPT_NAME_RE =
  /^(?:pre|post)?(?:build|compile|bundle|test|lint|format|fmt|clean|release|publish|prepare|prepack|pack|docs?|bench(?:mark)?|typecheck|check|coverage|e2e|storybook|version|deploy|generate|codegen|sync|verify|ci)(?:[:._-].*)?$/i;

const SCRIPT_FILE_TOKEN_RE = new RegExp(
  String.raw`(?:^|[\s"'=])((?:\.{1,2}/)?[\w@./-]+\.(?:${SCRIPT_EXT}|py))(?=$|[\s"';&|)])`,
  "gi",
);

/**
 * Absolute paths of local scripts that `package.json` invokes from build / test /
 * release scripts (`"build": "node build.js"`).
 *
 * A tooling script frequently runs the product too (`"benchmark": "node
 * dist/cli.js benchmark"`), and mistaking the product for tooling would leave it
 * unprotected. So anything under `excludeDirNames` (build-output directories),
 * every declared runtime entry, and the implicit `index.js` main are never
 * returned.
 */
export function readPackageToolingScripts(
  packageRoot: string,
  excludeDirNames: Iterable<string> = [],
): ReadonlySet<string> {
  const manifest = readPackageManifest(packageRoot);
  const out = new Set<string>();
  const scripts = manifest?.scripts;
  if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) return out;
  const root = resolve(packageRoot);
  const excludedDirs = new Set(excludeDirNames);
  const runtimeEntries = new Set(readPackageRuntimeEntries(root));
  if (manifest?.main === undefined) runtimeEntries.add(join(root, "index.js"));
  for (const [scriptName, command] of Object.entries(scripts)) {
    if (typeof command !== "string" || !TOOLING_SCRIPT_NAME_RE.test(scriptName)) continue;
    for (const match of command.matchAll(SCRIPT_FILE_TOKEN_RE)) {
      const token = match[1];
      if (token === undefined) continue;
      const segments = token.split("/").filter((s) => s.length > 0 && s !== ".");
      if (segments.includes("node_modules") || segments.includes("..")) continue;
      if (segments.length > 1 && excludedDirs.has(segments[0]!)) continue;
      const abs = resolve(root, token);
      if (runtimeEntries.has(abs)) continue;
      out.add(abs);
    }
  }
  return out;
}
