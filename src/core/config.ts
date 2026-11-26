import { randomBytes } from "node:crypto";
import {
  chmodSync, closeSync, constants, fstatSync, lstatSync, mkdtempSync,
  openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync,
  type Stats,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import type { ProtectionIntensity } from "./types.js";

export interface BlaProjectConfig {
  readonly $schema?: string;
  readonly input?: string;
  readonly output?: string;
  readonly intensity?: ProtectionIntensity;
  /** Per-project PRNG seed. Prefer a random value persisted in `.blarc` — never a shared fixed fingerprint. */
  readonly seed?: string;
  /** When true, write `.bla-manifest.json` next to protected artifacts. Default false (opt-in via `--manifest`). */
  readonly emitManifest?: boolean;
  /** Opt-in risky LLM directive layers (COPPA/medical bait, dual-use imitation, AI chat markers). Default false. */
  readonly llmDirectives?: boolean;
  readonly honeySourceMaps?: boolean;
  readonly minDefenseScore?: number;
  /** Opt-in structural weave decoys (Python customer-def / .pyc co_consts weave; JS AST weave already on). Parity with CLI `--weave-decoys` / MCP `weave_decoys`. */
  readonly weaveDecoys?: boolean;
  /** Opt-in self-seal / sibling-module integrity binding for JS/Node (issue #40.5). Parity with CLI `--self-seal` / MCP `self_seal`. */
  readonly selfSeal?: boolean;
  /** Opt-in sidecar/entry entanglement strip⇒fail for JS/Python (issue #40). Parity with CLI `--sidecar-entangle` / MCP `sidecar_entangle`. */
  readonly sidecarEntangle?: boolean;
  /** Enforce Agent-First Closed-Loop: refuse hardening if source files lack verified Stage 2 surgical weave. */
  readonly requireAgentWeave?: boolean;
  /**
   * SQLite only, opt-in: evaluation-trap columns on the honey tables. They stop a
   * row read by an inspector, and also `PRAGMA integrity_check`, `VACUUM` and a
   * dump/restore in the application. Parity with CLI `--sqlite-eval-trap` / MCP `sqlite_eval_trap`.
   */
  readonly sqliteEvalTrap?: boolean;
  /** WASM export names that must remain the public ABI when export rename runs (issue #40.3). */
  readonly wasmPreserveExports?: readonly string[];
  /**
   * Project-relative paths or globs `harden` leaves out (hot-path modules, a
   * file that cannot be hardened). They ship unprotected and are reported.
   */
  readonly exclude?: readonly string[];
  /** When true, allow harden/defend of lane-independent JS gates (issue #40.1). Default false. */
  readonly allowLaneIndependentGates?: boolean;
  /** When true, allow bankrupt harden despite plaintext/reversible seal sidecars (red-blue round-2). Default false. */
  readonly allowPlaintextSeal?: boolean;
  /** When true, allow bankrupt despite clear WASM param/cipher carriers (red-blue round-3). Default false. */
  readonly allowWasmClearParamCarriers?: boolean;
  /** When true, keep stable __vaultPanelDerive_* ABI (red-blue round-3). Default false. */
  readonly allowStablePanelDeriveAbi?: boolean;
  /** When true, allow bankrupt despite JS AES wrap-key unwrap footguns (red-blue round-4). Default false. */
  readonly allowJsAesUnwrap?: boolean;
  /** When true, allow bankrupt despite panel offline-oracle packaging (red-blue round-4). Default false. */
  readonly allowPanelOfflineOracle?: boolean;
  /** When true, allow bankrupt despite JS←WASM hydrate param-dump (red-blue round-5). Default false. */
  readonly allowJsWasmHydrateDump?: boolean;
  readonly allowWasmXorMaskSidecar?: boolean;
  /** When true, allow bankrupt despite seal.revision XOR known-plaintext packs (red-blue round-7). Default false. */
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  /** Lab-only: allow leaked SOLUTION/dotenv/private-key/debug-symbol files in release tree. Default false. */
  readonly allowReleaseHygieneLeak?: boolean;
}

/**
 * Starter defaults written by `initBlaConfig`.
 * `seed` is filled at init/resolve time with a per-project random value — never a global constant.
 * `emitManifest` defaults to false so customer artifacts are not accompanied by attestation JSON unless requested.
 */
export const DEFAULT_BLA_CONFIG: BlaProjectConfig = Object.freeze({
  $schema: "https://bla.tools/schemas/bla.config.v1.json",
  input: "./dist",
  intensity: "bankrupt",
  emitManifest: false,
  llmDirectives: false,
  honeySourceMaps: true,
  minDefenseScore: 90,
  weaveDecoys: false,
  selfSeal: false,
  sidecarEntangle: false,
});

/** Legacy fixed seeds that fingerprint every project the same way — never reuse as a default. */
export const LEGACY_FIXED_SEEDS: ReadonlySet<string> = new Set([
  "bla-project-seed-v1",
  "bla-shield-seed-v1",
  "bla-js-shield-v1",
]);

const CONFIG_FILENAMES = ["bla.config.json", ".blarc.json", ".blarc"] as const;

/** A project config is small; anything bigger is a mistake or an attack. */
const MAX_CONFIG_BYTES = 64 * 1024;

const INTENSITIES = ["stealth", "balanced", "maximum", "bankrupt"] as const;

const STRING_CONFIG_KEYS = ["$schema", "input", "output", "seed"] as const;
const BOOLEAN_CONFIG_KEYS = [
  "emitManifest",
  "llmDirectives",
  "honeySourceMaps",
  "weaveDecoys",
  "selfSeal",
  "sidecarEntangle",
  "requireAgentWeave",
  "sqliteEvalTrap",
  "allowLaneIndependentGates",
  "allowPlaintextSeal",
  "allowWasmClearParamCarriers",
  "allowStablePanelDeriveAbi",
  "allowJsAesUnwrap",
  "allowPanelOfflineOracle",
  "allowJsWasmHydrateDump",
  "allowWasmXorMaskSidecar",
  "allowWasmSealXorKnownPlaintext",
  "allowReleaseHygieneLeak",
] as const;

/**
 * Validate the shape of a parsed BLA config before merging it with defaults.
 * A malformed config must fail loudly: silently falling back changes the
 * effective intensity/seed/manifest behavior without telling the operator.
 */
export function validateBlaConfigShape(value: unknown, source: string): BlaProjectConfig {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid BLA config at ${source}: expected a JSON object`);
  }
  const obj = value as Record<string, unknown>;
  for (const key of STRING_CONFIG_KEYS) {
    if (obj[key] !== undefined && typeof obj[key] !== "string") {
      throw new Error(`Invalid BLA config at ${source}: '${key}' must be a string`);
    }
  }
  if (obj.intensity !== undefined && !INTENSITIES.includes(obj.intensity as ProtectionIntensity)) {
    throw new Error(
      `Invalid BLA config at ${source}: 'intensity' must be one of ${INTENSITIES.join(", ")}`,
    );
  }
  for (const key of BOOLEAN_CONFIG_KEYS) {
    if (obj[key] !== undefined && typeof obj[key] !== "boolean") {
      throw new Error(`Invalid BLA config at ${source}: '${key}' must be a boolean`);
    }
  }
  if (
    obj.minDefenseScore !== undefined &&
    (typeof obj.minDefenseScore !== "number" ||
      !Number.isFinite(obj.minDefenseScore) ||
      obj.minDefenseScore < 0 ||
      obj.minDefenseScore > 100)
  ) {
    throw new Error(`Invalid BLA config at ${source}: 'minDefenseScore' must be a number between 0 and 100`);
  }
  if (
    obj.wasmPreserveExports !== undefined &&
    (!Array.isArray(obj.wasmPreserveExports) ||
      !obj.wasmPreserveExports.every((v) => typeof v === "string"))
  ) {
    throw new Error(`Invalid BLA config at ${source}: 'wasmPreserveExports' must be an array of strings`);
  }
  if (
    obj.exclude !== undefined &&
    (!Array.isArray(obj.exclude) || !obj.exclude.every((v) => typeof v === "string"))
  ) {
    throw new Error(`Invalid BLA config at ${source}: 'exclude' must be an array of strings`);
  }
  return obj as BlaProjectConfig;
}

function configFileStats(path: string): Stats | undefined {
  const stats = lstatSync(path, { throwIfNoEntry: false });
  if (stats?.isSymbolicLink()) throw new Error(`Refusing symlinked BLA config: ${path}`);
  if (stats && !stats.isFile()) throw new Error(`BLA config is not a regular file: ${path}`);
  return stats;
}

function isSameConfigFile(a: Stats, b: Stats | undefined): boolean {
  return b !== undefined && a.dev === b.dev && a.ino === b.ino &&
    a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}

function readConfigFile(path: string, expected = configFileStats(path)): BlaProjectConfig {
  if (!expected) throw new Error(`BLA config file not found: ${path}`);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const stats = fstatSync(fd);
    if (!stats.isFile() || !isSameConfigFile(expected, stats)) {
      throw new Error(`BLA config changed while opening: ${path}`);
    }
    if (stats.size > MAX_CONFIG_BYTES) {
      throw new Error(`file is ${stats.size} bytes (limit ${MAX_CONFIG_BYTES})`);
    }
    return validateBlaConfigShape(JSON.parse(readFileSync(fd, "utf8")), path);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.startsWith("Invalid BLA config")) throw err;
    throw new Error(`Invalid BLA config at ${path}: ${message}`);
  } finally {
    closeSync(fd);
  }
}

export function generateProjectSeed(): string {
  return `bla-${randomBytes(16).toString("hex")}`;
}

function isUsableSeed(seed: unknown): seed is string {
  return typeof seed === "string" && seed.length > 0 && !LEGACY_FIXED_SEEDS.has(seed);
}

/**
 * Loads `bla.config.json`, `.blarc.json`, `.blarc`, or the `"bla"` field from `package.json`
 * in `cwd` (or an explicit config file path).
 */
export function loadBlaConfig(
  cwd: string = process.cwd(),
  explicitConfigPath?: string,
): { config: BlaProjectConfig; sourcePath: string | null } {
  const root = resolve(cwd);

  if (explicitConfigPath) {
    const absExplicit = resolve(root, explicitConfigPath);
    const parsed = readConfigFile(absExplicit);
    return {
      config: { ...DEFAULT_BLA_CONFIG, ...parsed },
      sourcePath: absExplicit,
    };
  }

  for (const name of CONFIG_FILENAMES) {
    const candidate = join(root, name);
    const stats = configFileStats(candidate);
    if (stats) {
      const parsed = readConfigFile(candidate, stats);
      return {
        config: { ...DEFAULT_BLA_CONFIG, ...parsed },
        sourcePath: candidate,
      };
    }
  }

  const pkgPath = join(root, "package.json");
  // The 64 KiB config cap applies to this fallback too. Reading a manifest
  // bigger than a config is a memory amplifier, and such a file is not a config
  // BLA can trust. Skipping keeps the fallback best effort: a large but
  // legitimate package.json without a `bla` field behaves exactly as before.
  const pkgStats = statSync(pkgPath, { throwIfNoEntry: false });
  if (pkgStats?.isFile() === true && pkgStats.size <= MAX_CONFIG_BYTES) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
        bla?: unknown;
      };
      if (pkg.bla !== undefined && pkg.bla !== null) {
        const parsed = validateBlaConfigShape(pkg.bla, `${pkgPath} (bla field)`);
        return {
          config: { ...DEFAULT_BLA_CONFIG, ...parsed },
          sourcePath: pkgPath,
        };
      }
    } catch (err) {
      // A broken package.json is not necessarily a BLA config; but if it parsed
      // and the `bla` field is invalid, surface that explicitly.
      if (err instanceof Error && err.message.startsWith("Invalid BLA config")) throw err;
    }
  }

  return {
    config: { ...DEFAULT_BLA_CONFIG },
    sourcePath: null,
  };
}

function createConfigFile(path: string, contents: string): void {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(path, flags, 0o600);
  try {
    writeFileSync(fd, contents, "utf8");
  } finally {
    closeSync(fd);
  }
}

function writeConfigFile(targetPath: string, config: BlaProjectConfig, existing?: Stats): void {
  const contents = JSON.stringify(config, null, 2) + "\n";
  if (!existing) {
    createConfigFile(targetPath, contents);
    return;
  }

  const tempDir = mkdtempSync(join(dirname(targetPath), ".bla-config-"));
  const tempPath = join(tempDir, "config.json");
  try {
    createConfigFile(tempPath, contents);
    chmodSync(tempPath, existing.mode & 0o777);
    if (!isSameConfigFile(existing, configFileStats(targetPath))) {
      throw new Error(`BLA config changed before it could be replaced: ${targetPath}`);
    }
    renameSync(tempPath, targetPath);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Resolves the PRNG seed for a project:
 * 1. Explicit CLI/`--seed` / caller override
 * 2. Non-legacy seed already stored in project config
 * 3. Otherwise mint a random per-project seed and persist it to `.blarc` (or update the existing config file)
 *
 * This kills the shared `bla-shield-seed-v1` / `bla-project-seed-v1` fingerprint across unrelated projects.
 */
export function resolveProjectSeed(
  cwd: string = process.cwd(),
  explicitSeed?: string | number,
  explicitConfigPath?: string,
): { seed: string; sourcePath: string | null; persisted: boolean } {
  if (explicitSeed !== undefined && explicitSeed !== null && String(explicitSeed).length > 0) {
    const seed = String(explicitSeed);
    if (!LEGACY_FIXED_SEEDS.has(seed)) {
      return { seed, sourcePath: null, persisted: false };
    }
    // Explicit legacy string: honor it (power users / tests) but do not persist as a "fresh" project seed.
    return { seed, sourcePath: null, persisted: false };
  }

  const loaded = loadBlaConfig(cwd, explicitConfigPath);
  if (isUsableSeed(loaded.config.seed)) {
    return { seed: loaded.config.seed, sourcePath: loaded.sourcePath, persisted: false };
  }

  const root = resolve(cwd);
  const targetPath = loaded.sourcePath && basename(loaded.sourcePath) !== "package.json"
    ? loaded.sourcePath
    : join(root, ".blarc");
  const stats = configFileStats(targetPath);
  if (!stats && targetPath === loaded.sourcePath) {
    throw new Error(`BLA config disappeared before seed persistence: ${targetPath}`);
  }
  const existing = stats ? readConfigFile(targetPath, stats) : loaded.config;
  if (isUsableSeed(existing.seed)) {
    return { seed: existing.seed, sourcePath: targetPath, persisted: false };
  }
  const seed = generateProjectSeed();
  writeConfigFile(targetPath, { ...DEFAULT_BLA_CONFIG, ...existing, seed }, stats);
  return { seed, sourcePath: targetPath, persisted: true };
}

/**
 * Writes a starter `bla.config.json` in `targetDir` with a fresh per-project random seed.
 */
export function initBlaConfig(
  targetDir: string = process.cwd(),
  overwrite = false,
): { configPath: string; created: boolean; config: BlaProjectConfig } {
  const configPath = join(resolve(targetDir), "bla.config.json");
  const stats = configFileStats(configPath);
  if (stats && !overwrite) {
    const existing = readConfigFile(configPath, stats);
    const merged = { ...DEFAULT_BLA_CONFIG, ...existing };
    if (!isUsableSeed(merged.seed)) {
      const seed = generateProjectSeed();
      writeConfigFile(configPath, { ...merged, seed }, stats);
      return {
        configPath,
        created: false,
        config: { ...merged, seed },
      };
    }
    return {
      configPath,
      created: false,
      config: merged,
    };
  }

  const config: BlaProjectConfig = {
    ...DEFAULT_BLA_CONFIG,
    seed: generateProjectSeed(),
  };
  writeConfigFile(configPath, config, stats);
  return {
    configPath,
    created: true,
    config,
  };
}
