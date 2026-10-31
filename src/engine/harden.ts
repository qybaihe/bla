import {
  existsSync,
  mkdirSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { detectArtifactFormat } from "../core/detector.js";
import type { ArtifactFormat, ProtectionIntensity } from "../core/types.js";
import { BLA_IDENTITY } from "../identity.js";
import {
  defendTarget,
  type OneClickDefenseReport,
} from "./defender.js";

/** Preferred build-output directory names, searched first under a project root. */
export const BLA_BUILD_OUTPUT_DIR_NAMES = Object.freeze([
  "dist",
  "build",
  "out",
  "release",
  "Release",
  "Debug",
  "x64",
  "Win32",
  "bin",
  ".next",
  "target",
] as const);

const SKIP_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  ".bla-hardened",
  "coverage",
  ".turbo",
  ".cache",
  "__pycache__",
  ".venv",
  "venv",
]);

/**
 * Source / docs trees skipped only on the *supplemental* project-root walk
 * (when dist/build/… already exist). Full-tree walks with no build dir still
 * descend into these so pure-source projects harden cleanly.
 */
const SUPPLEMENTAL_SKIP_DIR_NAMES = new Set([
  ...SKIP_DIR_NAMES,
  ...BLA_BUILD_OUTPUT_DIR_NAMES,
  "src",
  "lib",
  "test",
  "tests",
  "docs",
  "examples",
  "__tests__",
  "fixtures",
  "scripts",
  "benchmarks",
]);

const MAX_DISCOVERED_ARTIFACTS = 64;
const MAX_WALK_DEPTH = 8;

export interface DiscoveredArtifact {
  readonly path: string;
  readonly format: ArtifactFormat;
  readonly relativePath: string;
}

export interface HardenArtifactSummary {
  readonly inputPath: string;
  readonly relativePath: string;
  readonly format: ArtifactFormat;
  readonly outputPath: string;
  readonly success: boolean;
  readonly defenseScore: number;
  readonly tokenAmplificationFactor: number;
  readonly costAmplificationFactor: number;
  readonly error?: string;
}

export interface HardenProjectOptions {
  /** Project or build directory (default: cwd). A single file is also accepted. */
  readonly directory?: string;
  readonly intensity?: ProtectionIntensity;
  readonly seed?: string | number;
  readonly emitManifest?: boolean;
  readonly llmDirectives?: boolean;
  /** Optional output root; defaults to `<dir>/.bla-hardened`. */
  readonly outputDirectory?: string;
  readonly maxArtifacts?: number;
}

export interface HardenProjectReport {
  readonly blaVersion: string;
  readonly directory: string;
  readonly intensity: ProtectionIntensity;
  readonly overallSuccess: boolean;
  readonly discoveredCount: number;
  readonly hardenedCount: number;
  readonly failedCount: number;
  readonly outputDirectory: string;
  readonly artifacts: readonly HardenArtifactSummary[];
  readonly oneSentenceUsage: string;
}

function isProtectableFormat(format: ArtifactFormat): boolean {
  return format !== "unknown" && format !== "directory";
}

/**
 * Prefer known build-output directories when present; otherwise walk the project
 * root. Always skips VCS/dependency caches.
 */
function resolveSearchRoots(absRoot: string): {
  readonly preferred: readonly string[];
  readonly includeProjectRootSupplemental: boolean;
} {
  const preferred: string[] = [];
  for (const name of BLA_BUILD_OUTPUT_DIR_NAMES) {
    const candidate = join(absRoot, name);
    try {
      if (statSync(candidate).isDirectory()) preferred.push(candidate);
    } catch {
      /* absent */
    }
  }
  // Rust/cargo nested release
  const cargoRelease = join(absRoot, "target", "release");
  try {
    if (statSync(cargoRelease).isDirectory() && !preferred.includes(cargoRelease)) {
      preferred.push(cargoRelease);
    }
  } catch {
    /* absent */
  }
  if (preferred.length === 0) {
    return { preferred: [absRoot], includeProjectRootSupplemental: false };
  }
  // Build dirs win for deep discovery, but also scan the project root so
  // root-level .sqlite / .safetensors / .wasm / binaries / .py are not skipped.
  return { preferred, includeProjectRootSupplemental: true };
}

function walkCollect(
  dir: string,
  root: string,
  depth: number,
  out: DiscoveredArtifact[],
  maxArtifacts: number,
  skipDirs: ReadonlySet<string> = SKIP_DIR_NAMES,
): void {
  if (out.length >= maxArtifacts || depth > MAX_WALK_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= maxArtifacts) return;
    if (entry.name.startsWith(".") && entry.name !== ".asar") {
      // Still allow probing files that begin with '.', but skip hidden dirs.
      if (entry.isDirectory()) continue;
    }
    if (entry.isDirectory()) {
      if (skipDirs.has(entry.name)) continue;
      walkCollect(join(dir, entry.name), root, depth + 1, out, maxArtifacts, skipDirs);
      continue;
    }
    const full = join(dir, entry.name);
    const format = detectArtifactFormat(full);
    if (!isProtectableFormat(format)) continue;
    // Skip already-shielded outputs to avoid re-hardening loops.
    if (/\.shielded(\.|$)/i.test(entry.name)) continue;
    if (entry.name.endsWith(".bla-manifest.json")) continue;
    if (entry.name.endsWith(".bunfs-snapshot")) continue;
    out.push({
      path: full,
      format,
      // Normalize to POSIX separators so reports, manifests, and MCP
      // structuredContent stay platform-independent (`dist/app.js`).
      relativePath: (relative(root, full) || basename(full)).split(sep).join("/"),
    });
  }
}

/**
 * Auto-discovers protectable build artifacts under a project or build directory.
 * Prefers dist/build/out/release/…, and also picks up root-level
 * .asar/native/.wasm/.py/.pyc/.sqlite/.safetensors/.gguf/.dex/.class/.dll
 * and magic-byte formats even when a build directory exists.
 */
export function discoverHardenableArtifacts(
  directory: string = process.cwd(),
  options: { readonly maxArtifacts?: number } = {},
): readonly DiscoveredArtifact[] {
  const abs = resolve(directory);
  const maxArtifacts = options.maxArtifacts ?? MAX_DISCOVERED_ARTIFACTS;
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const stats = statSync(abs);
  if (stats.isFile()) {
    const format = detectArtifactFormat(abs);
    if (!isProtectableFormat(format)) {
      throw new Error(`Unsupported artifact format at ${abs}`);
    }
    return [{ path: abs, format, relativePath: basename(abs) }];
  }
  if (!stats.isDirectory()) {
    throw new Error(`Not a file or directory: ${abs}`);
  }

  const found: DiscoveredArtifact[] = [];
  const { preferred, includeProjectRootSupplemental } = resolveSearchRoots(abs);
  for (const root of preferred) {
    walkCollect(root, abs, 0, found, maxArtifacts, SKIP_DIR_NAMES);
  }
  if (includeProjectRootSupplemental) {
    walkCollect(abs, abs, 0, found, maxArtifacts, SUPPLEMENTAL_SKIP_DIR_NAMES);
  }
  // De-dupe by absolute path (cargo release may overlap target/)
  const seen = new Set<string>();
  const unique: DiscoveredArtifact[] = [];
  for (const item of found) {
    if (seen.has(item.path)) continue;
    seen.add(item.path);
    unique.push(item);
  }
  return unique;
}

function deriveArtifactOutputPath(
  artifact: DiscoveredArtifact,
  projectRoot: string,
  outputRoot: string,
): string {
  const rel = artifact.relativePath;
  const dest = join(outputRoot, rel);
  const dir = dirname(dest);
  mkdirSync(dir, { recursive: true });
  // Keep original basename; place under .bla-hardened mirror tree.
  return dest;
}

/**
 * One-sentence Counter-REA hardening: discover every protectable build artifact
 * under a project/build directory and run the full audit→defend→verify pipeline
 * with the bankrupt profile. Modelled on REA's `npx rea-agents setup` simplicity.
 *
 * Usage: `bla harden .` / MCP `bla_harden` with `{ "directory": "." }`
 */
export function hardenProject(
  options: HardenProjectOptions = {},
): HardenProjectReport {
  const absDir = resolve(options.directory ?? process.cwd());
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";
  // Manifests are opt-in: do not ship `.bla-manifest.json` next to customer artifacts by default.
  const emitManifest = options.emitManifest === true;
  const maxArtifacts = options.maxArtifacts ?? MAX_DISCOVERED_ARTIFACTS;

  const discovered = discoverHardenableArtifacts(absDir, { maxArtifacts });
  const outputRoot = resolve(
    options.outputDirectory ??
      (statSync(absDir).isDirectory()
        ? join(absDir, ".bla-hardened")
        : join(dirname(absDir), ".bla-hardened")),
  );
  if (discovered.length > 0) {
    mkdirSync(outputRoot, { recursive: true });
  }

  const summaries: HardenArtifactSummary[] = [];
  for (const artifact of discovered) {
    const outputPath = deriveArtifactOutputPath(artifact, absDir, outputRoot);
    try {
      const report: OneClickDefenseReport = defendTarget({
        inputPath: artifact.path,
        outputPath,
        intensity,
        ...(options.seed !== undefined ? { seed: options.seed } : {}),
        ...(options.llmDirectives !== undefined
          ? { llmDirectives: options.llmDirectives }
          : {}),
        emitManifest,
      });
      summaries.push({
        inputPath: artifact.path,
        relativePath: artifact.relativePath,
        format: artifact.format,
        outputPath: report.outputPath,
        success: report.overallSuccess,
        defenseScore: report.verification.defenseScore,
        tokenAmplificationFactor:
          report.exhaustionSummary.tokenAmplificationFactor,
        costAmplificationFactor:
          report.exhaustionSummary.costAmplificationFactor,
      });
    } catch (err) {
      summaries.push({
        inputPath: artifact.path,
        relativePath: artifact.relativePath,
        format: artifact.format,
        outputPath,
        success: false,
        defenseScore: 0,
        tokenAmplificationFactor: 0,
        costAmplificationFactor: 0,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // Persist a project-level summary for agents to read back.
  if (discovered.length > 0) {
    try {
      writeFileSync(
        join(outputRoot, "bla-harden-summary.json"),
        JSON.stringify(
          {
            schema: "bla-harden-summary/v1",
            directory: absDir,
            intensity,
            artifacts: summaries,
          },
          null,
          2,
        ),
        "utf8",
      );
    } catch {
      /* best-effort */
    }
  }

  const hardenedCount = summaries.filter((s) => s.success).length;
  const failedCount = summaries.length - hardenedCount;
  return {
    blaVersion: BLA_IDENTITY.version,
    directory: absDir,
    intensity,
    overallSuccess: summaries.length > 0 && failedCount === 0,
    discoveredCount: discovered.length,
    hardenedCount,
    failedCount,
    outputDirectory: outputRoot,
    artifacts: summaries,
    oneSentenceUsage:
      'Harden my software against REA — call bla_harden with { "directory": "." } (or `bla harden .`).',
  };
}

export function formatHardenProjectReport(report: HardenProjectReport): string {
  const lines: string[] = [
    `BLA harden ${report.blaVersion} — ${report.directory}`,
    `Intensity: ${report.intensity} | discovered=${report.discoveredCount} hardened=${report.hardenedCount} failed=${report.failedCount}`,
    `Overall: ${report.overallSuccess ? "SUCCESS" : report.discoveredCount === 0 ? "NO ARTIFACTS" : "PARTIAL/FAILED"}`,
  ];
  for (const a of report.artifacts) {
    lines.push(
      a.success
        ? `  ✓ ${a.relativePath} [${a.format}] score=${a.defenseScore} tokens×${a.tokenAmplificationFactor.toFixed(1)} → ${a.outputPath}`
        : `  ✗ ${a.relativePath} [${a.format}] ${a.error ?? "failed"}`,
    );
  }
  if (report.discoveredCount === 0) {
    lines.push(
      "  (no protectable artifacts found — put build outputs under dist/, build/, out/, or release/, or place .wasm/.sqlite/.safetensors/binaries at the project root)",
    );
  } else {
    lines.push(`Output: ${report.outputDirectory}`);
    lines.push(
      "Next: ship or point your release at the hardened copies above (originals are untouched). See DISCLAIMER.md.",
    );
  }
  lines.push(`Tip: ${report.oneSentenceUsage}`);
  return lines.join("\n");
}
