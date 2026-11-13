import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";

/**
 * Node resolves the module system of a `.js` (and, with type stripping, `.ts`)
 * file from the nearest `package.json` "type" field. Explicit extensions
 * (`.mjs` / `.cjs` / `.mts` / `.cts`) are already decided by the path alone.
 */
const PACKAGE_TYPE_SENSITIVE_EXTENSIONS: ReadonlySet<string> = new Set([".js", ".ts"]);

/**
 * Return the "type" of the nearest enclosing `package.json` for `filePath`,
 * following Node's lookup: the first `package.json` found walking up wins
 * (missing "type" means CommonJS). Returns `undefined` when no package.json
 * exists or the nearest one is unreadable / not JSON.
 */
export function resolveNodePackageModuleType(
  filePath: string,
): "module" | "commonjs" | undefined {
  let dir = dirname(resolve(filePath));
  for (;;) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const parsed: unknown = JSON.parse(readFileSync(candidate, "utf8"));
        const type =
          parsed !== null && typeof parsed === "object"
            ? (parsed as { type?: unknown }).type
            : undefined;
        return type === "module" ? "module" : "commonjs";
      } catch {
        return undefined;
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/**
 * Refine a syntax-derived JS carrier with the runtime location(s) the entry
 * will be evaluated from. A `.js` / `.ts` entry under a `"type": "module"`
 * package runs as an ES module even without import/export syntax, so callers
 * that emit CommonJS-only code (the sidecar strip⇒fail preamble) must treat it
 * as `"module"`. Any listed location saying module wins (fail-safe refusal).
 */
export function refineJsCarrierForRuntimePaths(
  carrier: "module" | "script" | "commonjs",
  runtimePaths: readonly string[],
): "module" | "script" | "commonjs" {
  if (carrier === "module") return carrier;
  for (const p of runtimePaths) {
    if (!PACKAGE_TYPE_SENSITIVE_EXTENSIONS.has(extname(p).toLowerCase())) continue;
    if (resolveNodePackageModuleType(p) === "module") return "module";
  }
  return carrier;
}
