import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { detectArtifactFormat } from "../core/detector.js";
import { walkBounded } from "../core/walk.js";
import type { ArtifactFormat, ProtectionIntensity } from "../core/types.js";
import { BLA_IDENTITY } from "../identity.js";
import {
  defendTarget,
  type OneClickDefenseReport,
} from "./defender.js";
import {
  sealCommitmentRefuseMessage,
} from "./seal-commitment-lint.js";
import {
  wasmParamCarrierRefuseMessage,
} from "./wasm-param-carrier-lint.js";
import {
  jsAesUnwrapRefuseMessage,
} from "./js-aes-unwrap-lint.js";
import {
  jsWasmHydrateDumpRefuseMessage,
} from "./js-wasm-hydrate-dump-lint.js";
import {
  wasmXorMaskSidecarRefuseMessage,
} from "./wasm-xor-mask-sidecar-lint.js";
import {
  wasmSealXorKnownPlaintextRefuseMessage,
} from "./wasm-seal-xor-known-plaintext-lint.js";
import {
  evaluateHardenProjectPackagingBlocks,
} from "./packaging-gates.js";
import {
  entangleJsEntryWithSidecars,
  entanglePythonEntryWithSidecars,
  planSidecarEntanglement,
} from "../shields/runtime/sidecar-entangle.js";
import {
  finalizeSelfSealSelfDigest,
  verifySelfSealSelfDigest,
} from "../shields/runtime/self-seal.js";
import { withoutHostSelfCoverage } from "./integrity-coverage.js";
import {
  computeHardenRunId,
  HARDEN_SUMMARY_FILE_NAME,
  HARDEN_SUMMARY_SCHEMA,
} from "./run-evidence.js";

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
  /** True when a file already existed at outputPath before this run (or would, in dry-run). */
  readonly outputExisted: boolean;
  readonly error?: string;
}

export interface HardenProjectOptions {
  /** Project or build directory (default: cwd). A single file is also accepted. */
  readonly directory?: string;
  readonly intensity?: ProtectionIntensity;
  readonly seed?: string | number;
  readonly emitManifest?: boolean;
  /** Opt-in ed25519 signing of each emitted manifest. Requires emitManifest. */
  readonly signManifest?: boolean;
  /** Path to an ed25519 private key PEM used when signManifest is true. */
  readonly manifestSigningKeyPath?: string;
  readonly llmDirectives?: boolean;
  readonly weaveDecoys?: boolean;
  /** Opt-in self-seal / sibling-module integrity binding for JS/Node (issue #40.5). */
  readonly selfSeal?: boolean;
  /** Opt-in sidecar/entry entanglement strip⇒fail for JS/Python (issue #40). */
  readonly sidecarEntangle?: boolean;
  /** WASM public ABI export names to preserve when rename runs (issue #40.3). */
  readonly wasmPreserveExports?: readonly string[];
  /** Allow lane-independent JS gates (issue #40.1). Default false — refuse. */
  readonly allowLaneIndependentGates?: boolean;
  /** Allow bankrupt despite plaintext/reversible seal sidecars (red-blue round-2). Default false — refuse. */
  readonly allowPlaintextSeal?: boolean;
  /** Allow bankrupt despite clear WASM param/cipher carriers (red-blue round-3). Default false — refuse. */
  readonly allowWasmClearParamCarriers?: boolean;
  /** Keep stable __vaultPanelDerive_* ABI (red-blue round-3). Default false — rewrite. */
  readonly allowStablePanelDeriveAbi?: boolean;
  /** Allow bankrupt despite JS AES wrap-key unwrap footguns (red-blue round-4). Default false. */
  readonly allowJsAesUnwrap?: boolean;
  /** Lab-only: allow JS←WASM hydrate memory dump of salt/rounds/cipher (red/blue r5). */
  readonly allowJsWasmHydrateDump?: boolean;
  readonly allowWasmXorMaskSidecar?: boolean;
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  /** Allow bankrupt despite panel offline-oracle packaging (red-blue round-4). Default false. */
  readonly allowPanelOfflineOracle?: boolean;
  /** Optional output root; defaults to `<dir>/.bla-hardened`. */
  readonly outputDirectory?: string;
  readonly maxArtifacts?: number;
  /**
   * Preview only: discover targets and plan output paths, but write zero bytes
   * (no `.bla-hardened/`, no summary JSON, no manifests).
   */
  readonly dryRun?: boolean;
  /**
   * Cooperative cancel (issue #75). Checked between artifacts — already-written
   * outputs are listed on the cancelled report; there is no silent half-harden.
   */
  readonly signal?: AbortSignal;
  /** Optional progress hook (index is 0-based into the planned artifact list). */
  readonly onProgress?: (event: HardenProgressEvent) => void;
}

export type HardenProgressPhase =
  | "start"
  | "artifact"
  | "cancelled"
  | "done";

export interface HardenProgressEvent {
  readonly phase: HardenProgressPhase;
  /** 0-based index of the artifact about to run / just finished; -1 for start/done. */
  readonly index: number;
  readonly total: number;
  readonly relativePath?: string;
  /** Absolute paths already written successfully when this event fires. */
  readonly written: readonly string[];
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
  readonly weaveDecoys: boolean;
  readonly selfSeal: boolean;
  /** True when caller opted into sidecar entry entanglement. */
  readonly sidecarEntangle: boolean;
  /**
   * True when bankrupt discovered a multi-artifact JS/WASM/HTML tree and
   * `selfSeal` was not enabled — agents should pass `self_seal: true`.
   * Never auto-enables for single-file trees.
   */
  readonly selfSealRecommended: boolean;
  /** Short advice when selfSealRecommended is true. */
  readonly selfSealRecommendation?: string;
  /** True when this report is a zero-write preview. */
  readonly dryRun: boolean;
  /** True when discovery stopped at `maxArtifacts`; more targets exist. */
  readonly truncated: boolean;
  readonly maxArtifacts: number;
  /** Planned/actual outputs that already existed before this run. */
  readonly wouldOverwrite: readonly string[];
  /**
   * Content-addressed id for this harden run (unsigned). Stable across identical
   * inputs/planned outputs; present even on dry-run so agents can correlate later.
   */
  readonly runId: string;
  /** Absolute path of the unsigned summary when written; omitted on dry-run. */
  readonly summaryPath?: string;
  /** Absolute path of bla-integrity-coverage/v1 matrix when selfSeal wrote one. */
  readonly integrityCoveragePath?: string;
  /**
   * True when the entry checker's canonical self-digest verifies on disk (entry
   * self-tamper hard-fails). When false the written matrix drops the entry's
   * self-coverage edges so packaging gates do not trust paper coverage.
   */
  readonly integrityCoverageSelfVerified?: boolean;
  /**
   * True when `signal` aborted mid-run (issue #75). `written` lists every
   * artifact already on disk — never a silent half-harden.
   */
  readonly cancelled?: boolean;
  /** Absolute output paths written before cancel or at completion. */
  readonly written?: readonly string[];
}

export interface HardenDiscoveryResult {
  readonly directory: string;
  readonly artifacts: readonly DiscoveredArtifact[];
  /** True when the walk hit `maxArtifacts` and further targets were not listed. */
  readonly truncated: boolean;
  readonly maxArtifacts: number;
  /** Zero-based index into the stable discovery order for this page. */
  readonly offset: number;
  /**
   * When `truncated` is true, pass this as the next `offset` to retrieve the
   * following page without losing the tail (issue #75 paging). Absent when
   * this page exhausted the inventory.
   */
  readonly nextOffset?: number;
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

function collectRootArtifacts(
  root: string,
  projectRoot: string,
  maxArtifacts: number,
  skipDirs: ReadonlySet<string>,
): DiscoveredArtifact[] {
  const formats = new Map<string, ArtifactFormat>();
  const files = walkBounded(root, {
    maxDepth: MAX_WALK_DEPTH,
    maxFiles: maxArtifacts,
    skipDirs,
    skipHiddenDirs: true,
    // Locale-independent name sort so offset paging is stable across platforms.
    sortEntries: true,
    accept: (full, name) => {
      const format = detectArtifactFormat(full);
      if (!isProtectableFormat(format)) return false;
      // Skip already-shielded outputs to avoid re-hardening loops.
      if (/\.shielded(\.|$)/i.test(name)) return false;
      if (name.endsWith(".bla-manifest.json")) return false;
      if (name.endsWith(".bunfs-snapshot")) return false;
      formats.set(full, format);
      return true;
    },
  });
  return files.map((full) => ({
    path: full,
    format: formats.get(full) ?? detectArtifactFormat(full),
    // Normalize to POSIX separators so reports, manifests, and MCP
    // structuredContent stay platform-independent (`dist/app.js`).
    relativePath: (relative(projectRoot, full) || basename(full)).split(sep).join("/"),
  }));
}

/**
 * Auto-discovers protectable build artifacts under a project or build directory.
 * Prefers dist/build/out/release/…, and also picks up root-level
 * .asar/native/.wasm/.py/.pyc/.sqlite/.safetensors/.gguf/.dex/.class/.dll
 * and magic-byte formats even when a build directory exists.
 */
export function discoverHardenableArtifacts(
  directory: string = process.cwd(),
  options: { readonly maxArtifacts?: number; readonly offset?: number } = {},
): readonly DiscoveredArtifact[] {
  return discoverHardenTargets(directory, options).artifacts;
}

/**
 * Read-only discovery that also reports truncation, so agents never mistake a
 * capped walk for the full inventory of a large repository.
 *
 * Pass `offset` (from a prior `nextOffset`) to page through 64+ trees without
 * raising the cap or losing the tail — acceptance for issue #75 paging.
 */
export function discoverHardenTargets(
  directory: string = process.cwd(),
  options: { readonly maxArtifacts?: number; readonly offset?: number } = {},
): HardenDiscoveryResult {
  const abs = resolve(directory);
  const maxArtifacts = Math.max(1, Math.floor(options.maxArtifacts ?? MAX_DISCOVERED_ARTIFACTS));
  const offset = Math.max(0, Math.floor(options.offset ?? 0));
  // Collect one past the page end so truncated/nextOffset stay honest.
  const all = collectHardenableArtifacts(abs, offset + maxArtifacts + 1);
  const page = all.slice(offset, offset + maxArtifacts);
  const truncated = all.length > offset + maxArtifacts;
  return {
    directory: abs,
    artifacts: page,
    truncated,
    maxArtifacts,
    offset,
    ...(truncated ? { nextOffset: offset + page.length } : {}),
  };
}

function collectHardenableArtifacts(
  abs: string,
  maxArtifacts: number,
): readonly DiscoveredArtifact[] {
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
    const remaining = maxArtifacts - found.length;
    if (remaining <= 0) break;
    found.push(...collectRootArtifacts(root, abs, remaining, SKIP_DIR_NAMES));
  }
  if (includeProjectRootSupplemental && found.length < maxArtifacts) {
    found.push(
      ...collectRootArtifacts(abs, abs, maxArtifacts - found.length, SUPPLEMENTAL_SKIP_DIR_NAMES),
    );
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

/** Mirror-tree destination under the output root (pure; no filesystem writes). */
function planArtifactOutputPath(artifact: DiscoveredArtifact, outputRoot: string): string {
  // Keep original basename; place under .bla-hardened mirror tree.
  return join(outputRoot, artifact.relativePath);
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
  if (options.signManifest === true && emitManifest !== true) {
    throw new Error("signManifest requires emitManifest in hardenProject");
  }
  const maxArtifacts = options.maxArtifacts ?? MAX_DISCOVERED_ARTIFACTS;

  const dryRun = options.dryRun === true;
  const discovery = discoverHardenTargets(absDir, { maxArtifacts });
  const discovered = discovery.artifacts;

  const packagingBlocks = evaluateHardenProjectPackagingBlocks({
    directory: absDir,
    intensity,
    allowPlaintextSeal: options.allowPlaintextSeal,
    allowWasmClearParamCarriers: options.allowWasmClearParamCarriers,
    allowJsAesUnwrap: options.allowJsAesUnwrap,
    allowJsWasmHydrateDump: options.allowJsWasmHydrateDump,
    allowWasmXorMaskSidecar: options.allowWasmXorMaskSidecar,
    allowWasmSealXorKnownPlaintext: options.allowWasmSealXorKnownPlaintext,
  });
  const blockingSeals = packagingBlocks.blockingSeals;
  const blockingWasmParms = packagingBlocks.blockingWasmParms;
  const blockingJsAes = packagingBlocks.blockingJsAes;
  const blockingJsHydrateDump = packagingBlocks.blockingJsHydrateDump;
  const blockingWasmXorMask = packagingBlocks.blockingWasmXorMask;
  const blockingWasmSealXor = packagingBlocks.blockingWasmSealXor;
  const outputRoot = resolve(
    options.outputDirectory ??
      (statSync(absDir).isDirectory()
        ? join(absDir, ".bla-hardened")
        : join(dirname(absDir), ".bla-hardened")),
  );
  let plannedOutputs = discovered.map((artifact) => {
    const outputPath = planArtifactOutputPath(artifact, outputRoot);
    return { artifact, outputPath, outputExisted: existsSync(outputPath) };
  });
  // When self-seal is on, protect non-JS bindable siblings first so JS entry
  // modules can embed expected SHA-256 hard-fail hashes (red/blue round-4).
  if (options.selfSeal === true) {
    const jsLike = new Set(["javascript", "typescript"]);
    plannedOutputs = [
      ...plannedOutputs.filter((p) => !jsLike.has(p.artifact.format)),
      ...plannedOutputs.filter((p) => jsLike.has(p.artifact.format)),
    ];
  }

  const wouldOverwrite = plannedOutputs.filter((p) => p.outputExisted).map((p) => p.outputPath);

  const bindableFormats = new Set(["javascript", "typescript", "wasm", "html-bundle"]);
  const bindable = discovered.filter((a) => bindableFormats.has(a.format));
  const selfSealRecommended =
    intensity === "bankrupt" &&
    bindable.length >= 2 &&
    options.selfSeal !== true;
  const selfSealRecommendation = selfSealRecommended
    ? "Multi-artifact entitlement tree detected — pass self_seal / --self-seal so Node entry modules bind sibling JS/WASM/HTML bytes. Single-file trees stay opt-in only (never auto-enabled)."
    : undefined;

  const runId = computeHardenRunId({
    blaVersion: BLA_IDENTITY.version,
    directory: absDir,
    intensity,
    weaveDecoys: options.weaveDecoys === true,
    selfSeal: options.selfSeal === true,
    artifacts: plannedOutputs.map(({ artifact, outputPath }) => ({
      relativePath: artifact.relativePath,
      format: artifact.format,
      outputPath,
    })),
  });

  const reportBase = {
    blaVersion: BLA_IDENTITY.version,
    directory: absDir,
    intensity,
    discoveredCount: discovered.length,
    outputDirectory: outputRoot,
    oneSentenceUsage:
      'Harden my software against REA — call bla_harden with { "directory": "." } (or `bla harden .`).',
    weaveDecoys: options.weaveDecoys === true,
    selfSeal: options.selfSeal === true,
    sidecarEntangle: options.sidecarEntangle === true,
    selfSealRecommended,
    ...(selfSealRecommendation !== undefined
      ? { selfSealRecommendation }
      : {}),
    dryRun,
    truncated: discovery.truncated,
    maxArtifacts: discovery.maxArtifacts,
    wouldOverwrite,
    runId,
  } as const;

  if (blockingSeals.length > 0 || blockingWasmParms.length > 0 || blockingJsAes.length > 0 || blockingJsHydrateDump.length > 0 || blockingWasmXorMask.length > 0 || blockingWasmSealXor.length > 0) {
    const sealArtifacts = blockingSeals.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "unknown" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: sealCommitmentRefuseMessage(r, r.path),
    }));
    const wasmArtifacts = blockingWasmParms.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "wasm" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: wasmParamCarrierRefuseMessage(r, r.path),
    }));
    const jsAesArtifacts = blockingJsAes.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "javascript" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: jsAesUnwrapRefuseMessage(r, r.path),
    }));
    const jsHydrateDumpArtifacts = blockingJsHydrateDump.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "javascript" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: jsWasmHydrateDumpRefuseMessage(r, r.path),
    }));
    const wasmXorMaskArtifacts = blockingWasmXorMask.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "wasm" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: wasmXorMaskSidecarRefuseMessage(r, r.path),
    }));
    const wasmSealXorArtifacts = blockingWasmSealXor.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "wasm" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: wasmSealXorKnownPlaintextRefuseMessage(r, r.path),
    }));
    const blockParts: string[] = [];
    if (blockingSeals.length > 0) blockParts.push("plaintext/reversible seal sidecar");
    if (blockingWasmParms.length > 0) blockParts.push("clear WASM param carrier");
    if (blockingJsAes.length > 0) blockParts.push("JS AES wrap-key unwrap");
    if (blockingJsHydrateDump.length > 0) blockParts.push("JS WASM hydrate param-dump");
    if (blockingWasmXorMask.length > 0) blockParts.push("WASM XOR-mask sidecar");
    if (blockingWasmSealXor.length > 0) blockParts.push("WASM seal.revision XOR known-plaintext");
    const blockedExtras = [...sealArtifacts, ...wasmArtifacts, ...jsAesArtifacts, ...jsHydrateDumpArtifacts, ...wasmXorMaskArtifacts, ...wasmSealXorArtifacts];
    // Attribute the specific refusal to the artifact that triggered the gate;
    // every other planned artifact is skipped because the run was blocked.
    const refusalByPath = new Map(
      blockedExtras.map((artifact) => [resolve(artifact.inputPath), artifact.error]),
    );
    const planned = plannedOutputs.map(({ artifact, outputPath, outputExisted }) => ({
      inputPath: artifact.path,
      relativePath: artifact.relativePath,
      format: artifact.format,
      outputPath,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted,
      error: refusalByPath.get(resolve(artifact.path)) ?? `skipped: run blocked by ${blockParts.join(" / ")}`,
    }));
    return {
      ...reportBase,
      overallSuccess: false,
      hardenedCount: 0,
      failedCount: planned.length + blockedExtras.length,
      artifacts: [
        ...planned,
        ...blockedExtras,
      ],
    };
  }

  if (dryRun) {
    // Preview only: never claim overallSuccess — nothing was hardened.
    return {
      ...reportBase,
      overallSuccess: false,
      hardenedCount: 0,
      failedCount: 0,
      artifacts: plannedOutputs.map(({ artifact, outputPath, outputExisted }) => ({
        inputPath: artifact.path,
        relativePath: artifact.relativePath,
        format: artifact.format,
        outputPath,
        success: false,
        defenseScore: 0,
        tokenAmplificationFactor: 0,
        costAmplificationFactor: 0,
        outputExisted,
      })),
    };
  }

  if (discovered.length > 0) {
    mkdirSync(outputRoot, { recursive: true });
  }

  const summaries: HardenArtifactSummary[] = [];
  const written: string[] = [];
  const total = plannedOutputs.length;
  const emitProgress = (
    phase: HardenProgressPhase,
    index: number,
    relativePath?: string,
  ): void => {
    options.onProgress?.({
      phase,
      index,
      total,
      ...(relativePath !== undefined ? { relativePath } : {}),
      written: written.slice(),
    });
  };
  emitProgress("start", -1);
  let cancelled = false;

  // Identify the primary JS entry artifact so its siblings are hardened first
  // (allowing the entry's selfSeal expectedSiblingSha256 map to hash final
  // sibling bytes on disk without circular JS<->JS hash deadlocks).
  const jsPlanned = plannedOutputs.filter(({ artifact }) =>
    /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(artifact.relativePath.replaceAll("\\", "/")),
  );
  const designatedEntryOutput =
    (jsPlanned.find(({ artifact }) =>
      /license\.(cjs|js)$/i.test(artifact.relativePath),
    ) ?? jsPlanned[0])?.outputPath;

  const executionIndices =
    options.selfSeal === true
      ? plannedOutputs
          .map((_, idx) => idx)
          .sort((a, b) => {
            const aIsEntry =
              plannedOutputs[a]!.outputPath === designatedEntryOutput ? 1 : 0;
            const bIsEntry =
              plannedOutputs[b]!.outputPath === designatedEntryOutput ? 1 : 0;
            return aIsEntry - bIsEntry;
          })
      : plannedOutputs.map((_, idx) => idx);
  const summaryByIndex = new Map<number, HardenArtifactSummary>();

  for (let step = 0; step < executionIndices.length; step++) {
    const i = executionIndices[step]!;
    if (options.signal?.aborted) {
      cancelled = true;
      emitProgress("cancelled", step);
      break;
    }
    const { artifact, outputPath, outputExisted } = plannedOutputs[i]!;
    emitProgress("artifact", step, artifact.relativePath);
    mkdirSync(dirname(outputPath), { recursive: true });
    try {
      const report: OneClickDefenseReport = defendTarget({
        inputPath: artifact.path,
        outputPath,
        intensity,
        ...(options.seed !== undefined ? { seed: options.seed } : {}),
        ...(options.llmDirectives !== undefined
          ? { llmDirectives: options.llmDirectives }
          : {}),
        ...(options.weaveDecoys !== undefined
          ? { weaveDecoys: options.weaveDecoys }
          : {}),
        ...(options.selfSeal !== undefined
          ? { selfSeal: options.selfSeal }
          : {}),
        ...(options.wasmPreserveExports !== undefined &&
        options.wasmPreserveExports.length > 0
          ? { wasmPreserveExports: options.wasmPreserveExports }
          : {}),
        ...(options.allowLaneIndependentGates === true
          ? { allowLaneIndependentGates: true }
          : {}),
        ...(options.allowPlaintextSeal === true ? { allowPlaintextSeal: true } : {}),
        ...(options.allowWasmClearParamCarriers === true
          ? { allowWasmClearParamCarriers: true }
          : {}),
        ...(options.allowStablePanelDeriveAbi === true
          ? { allowStablePanelDeriveAbi: true }
          : {}),
        ...(options.allowJsAesUnwrap === true ? { allowJsAesUnwrap: true } : {}),
        ...(options.allowJsWasmHydrateDump === true ? { allowJsWasmHydrateDump: true } : {}),
        ...(options.allowWasmXorMaskSidecar === true ? { allowWasmXorMaskSidecar: true } : {}),
        ...(options.allowWasmSealXorKnownPlaintext === true ? { allowWasmSealXorKnownPlaintext: true } : {}),
        ...(options.allowPanelOfflineOracle === true
          ? { allowPanelOfflineOracle: true }
          : {}),
        ...((() => {
          if (options.selfSeal !== true) return {};
          if (designatedEntryOutput !== undefined && outputPath !== designatedEntryOutput) {
            return {};
          }
          const siblings = plannedOutputs
            .filter(
              (p) =>
                p.outputPath !== outputPath &&
                bindableFormats.has(p.artifact.format),
            )
            .map((p) => relative(dirname(outputPath), p.outputPath).split(sep).join("/"))
            .filter((rel) => rel.length > 0 && !rel.startsWith(".."));
          // Prefer same-directory / nested siblings; still pass upward-relative
          // paths when the mirror tree places artifacts beside each other.
          const loose = plannedOutputs
            .filter(
              (p) =>
                p.outputPath !== outputPath &&
                bindableFormats.has(p.artifact.format),
            )
            .map((p) => relative(dirname(outputPath), p.outputPath).split(sep).join("/"))
            .filter((rel) => rel.length > 0);
          const list = siblings.length > 0 ? siblings : loose;
          return list.length > 0 ? { selfSealSiblingPaths: list } : {};
        })()),
        emitManifest,
        ...(options.signManifest === true
          ? { signManifest: true, manifestSigningKeyPath: options.manifestSigningKeyPath ?? "" }
          : {}),
      });
      summaryByIndex.set(i, {
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
        outputExisted,
      });
      if (report.overallSuccess && existsSync(report.outputPath)) {
        written.push(report.outputPath);
      }
    } catch (err) {
      summaryByIndex.set(i, {
        inputPath: artifact.path,
        relativePath: artifact.relativePath,
        format: artifact.format,
        outputPath,
        success: false,
        defenseScore: 0,
        tokenAmplificationFactor: 0,
        costAmplificationFactor: 0,
        outputExisted,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  for (let i = 0; i < plannedOutputs.length; i++) {
    const s = summaryByIndex.get(i);
    if (s) summaries.push(s);
  }

  // Persist a project-level summary for agents to read back (unsigned).
  let summaryPath: string | undefined;
  if (discovered.length > 0) {
    summaryPath = join(outputRoot, HARDEN_SUMMARY_FILE_NAME);
    try {
      writeFileSync(
        summaryPath,
        JSON.stringify(
          {
            schema: HARDEN_SUMMARY_SCHEMA,
            runId,
            signature: "unsigned",
            directory: absDir,
            intensity,
            weaveDecoys: options.weaveDecoys === true,
            selfSeal: options.selfSeal === true,
            sidecarEntangle: options.sidecarEntangle === true,
            artifacts: summaries,
            written,
            ...(cancelled ? { cancelled: true } : {}),
          },
          null,
          2,
        ),
        "utf8",
      );
    } catch {
      summaryPath = undefined;
    }
  }

  // Sidecar entanglement post-pass: rewrite the primary entry (JS preferred,
  // else Python) with a strip⇒fail preamble measured against FINAL sibling
  // bytes (after all protects wrote). Per-artifact protect skips inject when
  // harden did not pass explicit sidecarEntanglePaths (avoids partial/double
  // prepend). Only one entry is rewritten so sibling digests stay stable.
  if (options.sidecarEntangle === true && !dryRun && summaries.some((s) => s.success)) {
    try {
      const jsLike = summaries.filter(
        (s) =>
          s.success &&
          /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const jsEntry =
        jsLike.find((s) => /license\.(cjs|js)$/i.test(s.relativePath)) ??
        jsLike[0];
      if (jsEntry) {
        const entryAbs = join(outputRoot, jsEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of summaries) {
            if (!s.success || s.relativePath === jsEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entrySource = readFileSync(entryAbs, "utf8");
            const bound = entangleJsEntryWithSidecars({
              entryPath: basename(entryAbs),
              entrySource,
              sidecars,
              seedTag: String(options.seed ?? runId),
            });
            if (bound) {
              const finalized = finalizeSelfSealSelfDigest(bound.code);
              writeFileSync(entryAbs, finalized.content, "utf8");
            }
          }
        }
      }

      // Python entry entanglement only when no JS entry was bound — rewriting
      // a Python sibling after the JS digest sealed would invalidate strip⇒fail.
      const pyLike = summaries.filter(
        (s) =>
          s.success && /\.py$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const pyEntry =
        !jsEntry
          ? pyLike.find((s) => /policy\.py$/i.test(s.relativePath)) ?? pyLike[0]
          : undefined;
      if (pyEntry) {
        const entryAbs = join(outputRoot, pyEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of summaries) {
            if (!s.success || s.relativePath === pyEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entrySource = readFileSync(entryAbs, "utf8");
            const bound = entanglePythonEntryWithSidecars({
              entryPath: basename(entryAbs),
              entrySource,
              sidecars,
              seedTag: String(options.seed ?? runId),
            });
            if (bound) {
              writeFileSync(entryAbs, bound.code, "utf8");
            }
          }
        }
      }
    } catch {
      /* best-effort — leave entry as-is */
    }
  }

  let integrityCoveragePath: string | undefined;
  let integrityCoverageSelfVerified: boolean | undefined;
  if (options.selfSeal === true && !dryRun && summaries.some((s) => s.success)) {
    try {
      const jsLike = summaries.filter(
        (s) =>
          s.success &&
          /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const entry =
        jsLike.find((s) => /license\.(cjs|js)$/i.test(s.relativePath)) ??
        jsLike[0];
      if (entry) {
        const sidecars = summaries
          .filter((s) => s.success && s.relativePath !== entry.relativePath)
          .map((s) => s.relativePath.replaceAll("\\", "/"));
        const plan = planSidecarEntanglement({
          entryPath: entry.relativePath.replaceAll("\\", "/"),
          sidecarPaths: sidecars,
          seedTag: String(options.seed ?? runId),
          baseDir: outputRoot,
        });
        const entryRel = entry.relativePath.replaceAll("\\", "/");
        const entryAbs = join(outputRoot, entryRel);
        integrityCoverageSelfVerified =
          existsSync(entryAbs) && verifySelfSealSelfDigest(readFileSync(entryAbs)).verified;
        const matrix = integrityCoverageSelfVerified
          ? plan.coverageMatrix
          : withoutHostSelfCoverage(plan.coverageMatrix, entryRel);
        integrityCoveragePath = join(outputRoot, "integrity-coverage.json");
        writeFileSync(
          integrityCoveragePath,
          `${JSON.stringify(matrix, null, 2)}\n`,
          "utf8",
        );
      }
    } catch {
      integrityCoveragePath = undefined;
    }
  }

  const hardenedCount = summaries.filter((s) => s.success).length;
  const failedCount = summaries.length - hardenedCount;
  if (!cancelled) {
    emitProgress("done", total > 0 ? total - 1 : -1);
  }
  return {
    ...reportBase,
    overallSuccess: !cancelled && summaries.length > 0 && failedCount === 0,
    hardenedCount,
    failedCount,
    artifacts: summaries,
    written: written.slice(),
    ...(cancelled ? { cancelled: true } : {}),
    ...(summaryPath !== undefined ? { summaryPath } : {}),
    ...(integrityCoveragePath !== undefined
      ? { integrityCoveragePath }
      : {}),
    ...(integrityCoverageSelfVerified !== undefined
      ? { integrityCoverageSelfVerified }
      : {}),
  };
}

export function formatHardenProjectReport(report: HardenProjectReport): string {
  const lines: string[] = [
    `BLA harden ${report.blaVersion} — ${report.directory}${report.dryRun ? " (dry-run: nothing written)" : ""}`,
    `Run: ${report.runId} (unsigned)`,
    `Intensity: ${report.intensity} | discovered=${report.discoveredCount} hardened=${report.hardenedCount} failed=${report.failedCount}`,
    `Overall: ${
      report.dryRun
        ? report.discoveredCount === 0
          ? "NO ARTIFACTS"
          : "DRY-RUN (nothing written)"
        : report.cancelled
          ? "CANCELLED"
          : report.overallSuccess
            ? "SUCCESS"
            : report.discoveredCount === 0
              ? "NO ARTIFACTS"
              : "PARTIAL/FAILED"
    }`,
  ];
  if (report.cancelled) {
    lines.push(
      `  ⚠ cancelled after ${(report.written ?? []).length} written artifact(s); list is authoritative — no silent half-harden`,
    );
    for (const w of report.written ?? []) {
      lines.push(`    · written: ${w}`);
    }
  }
  if (report.selfSealRecommended) {
    lines.push(
      `  ⚠ self_seal recommended: ${report.selfSealRecommendation ?? "multi-artifact tree — pass --self-seal / self_seal:true"}`,
    );
  }
  for (const a of report.artifacts) {
    if (report.dryRun) {
      lines.push(
        `  • ${a.relativePath} [${a.format}] → ${a.outputPath}${a.outputExisted ? " (exists; would overwrite)" : ""}`,
      );
      continue;
    }
    lines.push(
      a.success
        ? `  ✓ ${a.relativePath} [${a.format}] score=${a.defenseScore} tokens×${a.tokenAmplificationFactor.toFixed(1)} → ${a.outputPath}`
        : `  ✗ ${a.relativePath} [${a.format}] ${a.error ?? "failed"}`,
    );
  }
  if (report.truncated) {
    lines.push(
      `  ⚠ discovery truncated at ${report.maxArtifacts} artifacts; more targets exist (raise maxArtifacts or harden a narrower directory)`,
    );
  }
  if (report.discoveredCount === 0) {
    lines.push(
      "  (no protectable artifacts found — put build outputs under dist/, build/, out/, or release/, or place .wasm/.sqlite/.safetensors/binaries at the project root)",
    );
  } else {
    lines.push(`Output: ${report.outputDirectory}`);
    lines.push(
      report.dryRun
        ? "Next: re-run without --dry-run (MCP: dry_run=false) to write the hardened copies."
        : "Next: ship or point your release at the hardened copies above (originals are untouched). See DISCLAIMER.md.",
    );
  }
  lines.push(`Tip: ${report.oneSentenceUsage}`);
  return lines.join("\n");
}
