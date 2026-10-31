import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
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
});

/** Legacy fixed seeds that fingerprint every project the same way — never reuse as a default. */
export const LEGACY_FIXED_SEEDS: ReadonlySet<string> = new Set([
  "bla-project-seed-v1",
  "bla-shield-seed-v1",
  "bla-js-shield-v1",
]);

const CONFIG_FILENAMES = ["bla.config.json", ".blarc.json", ".blarc"] as const;

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
    if (!existsSync(absExplicit)) {
      throw new Error(`BLA config file not found: ${absExplicit}`);
    }
    const parsed = JSON.parse(readFileSync(absExplicit, "utf8")) as BlaProjectConfig;
    return {
      config: { ...DEFAULT_BLA_CONFIG, ...parsed },
      sourcePath: absExplicit,
    };
  }

  for (const name of CONFIG_FILENAMES) {
    const candidate = join(root, name);
    if (existsSync(candidate)) {
      try {
        const parsed = JSON.parse(readFileSync(candidate, "utf8")) as BlaProjectConfig;
        return {
          config: { ...DEFAULT_BLA_CONFIG, ...parsed },
          sourcePath: candidate,
        };
      } catch {
        // ignore malformed optional config
      }
    }
  }

  const pkgPath = join(root, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
        bla?: BlaProjectConfig;
      };
      if (pkg.bla && typeof pkg.bla === "object") {
        return {
          config: { ...DEFAULT_BLA_CONFIG, ...pkg.bla },
          sourcePath: pkgPath,
        };
      }
    } catch {
      // ignore
    }
  }

  return {
    config: { ...DEFAULT_BLA_CONFIG },
    sourcePath: null,
  };
}

function persistSeed(targetPath: string, seed: string, existing: BlaProjectConfig): void {
  const next: BlaProjectConfig = {
    ...DEFAULT_BLA_CONFIG,
    ...existing,
    seed,
  };
  writeFileSync(targetPath, JSON.stringify(next, null, 2) + "\n", "utf8");
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

  const seed = generateProjectSeed();
  const root = resolve(cwd);
  let targetPath: string;
  if (loaded.sourcePath && !loaded.sourcePath.endsWith("package.json")) {
    targetPath = loaded.sourcePath;
    const existing = JSON.parse(readFileSync(targetPath, "utf8")) as BlaProjectConfig;
    persistSeed(targetPath, seed, existing);
  } else {
    targetPath = join(root, ".blarc");
    persistSeed(targetPath, seed, loaded.config);
  }
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
  if (existsSync(configPath) && !overwrite) {
    const existing = JSON.parse(readFileSync(configPath, "utf8")) as BlaProjectConfig;
    const merged = { ...DEFAULT_BLA_CONFIG, ...existing };
    if (!isUsableSeed(merged.seed)) {
      const seed = generateProjectSeed();
      persistSeed(configPath, seed, existing);
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
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf8");
  return {
    configPath,
    created: true,
    config,
  };
}
