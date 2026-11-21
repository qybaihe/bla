import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { detectArtifactFormat, isTypeScriptDeclarationPath } from "../core/detector.js";
import { generateProjectSeed, loadBlaConfig, type BlaProjectConfig } from "../core/config.js";
import { physicalPath } from "../core/output-path.js";
import { classifyBrowserBundles } from "./browser-bundle.js";
import { isKnownBlaOutput, registerBlaOutput } from "../core/output-registry.js";
import { lintPlaintextSecretsFile } from "./plaintext-secret-lint.js";
import {
  BLA_BUILD_OUTPUT_DIR_NAMES,
  applyHardenedOutputs,
  collectApplyCandidates,
  isInsideBuildOutput,
  listAppliedFiles,
  resolveApplyStateDirectory,
  restoreAppliedOriginals,
  suspendAppliedOutputs,
  type HardenApplyReport,
} from "./harden-apply.js";
import { sanitizeTerminalText } from "../core/terminal-text.js";
import { walkBounded } from "../core/walk.js";
import {
  isDevToolingFile,
  readPackageRuntimeEntries,
  readPythonDeclaredEntryModules,
  readPackageToolingScripts,
} from "../core/dev-tooling.js";
import type { ArtifactFormat, ProtectionIntensity } from "../core/types.js";
import { BLA_IDENTITY } from "../identity.js";
import {
  defendTarget,
  type OneClickDefenseReport,
} from "./defender.js";
import {
  formatSupportsLaneIndependenceLint,
  laneIndependenceRefuseMessage,
  lintLaneIndependence,
  type LaneIndependenceReport,
} from "./lane-independence-lint.js";
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
  releaseHygieneRefuseMessage,
} from "./release-hygiene-lint.js";
import {
  evaluateHardenProjectPackagingBlocks,
} from "./packaging-gates.js";
import {
  ASAR_SIDECAR_ARCHIVE_NOTE_PATH,
  ASAR_SIDECAR_MAIN_JS_MARKER,
  BUN_SIDECAR_COMPANION_SUFFIX,
  derivePublicSidecarSeedTag,
  entangleAsarEntryWithSidecars,
  entangleAsarMainJsWithSidecars,
  entangleBunEntryWithSidecars,
  entangleJsEntryWithSidecars,
  entanglePycEntryWithSidecars,
  entangleGgufEntryWithSidecars,
  entangleSafetensorsEntryWithSidecars,
  entangleDexEntryWithSidecars,
  entangleSqliteEntryWithSidecars,
  entanglePythonEntryWithSidecars,
  entangleWasmEntryWithSidecars,
  generateSidecarWasmLoaderSnippet,
  prependWasmSidecarLoaderHook,
  selectNodeWasmJsLoader,
  detectWasmJsLoaderCarrier,
  isNodeWasmJsLoaderFilename,
  computeWasmSidecarCodeIdentity,
  WASM_SIDECAR_LOADER_MARKER,
  WASM_SIDECAR_SECTION_NAME,
  generateSidecarPycLoaderSnippet,
  prependPycSidecarLoaderHook,
  selectPythonPycLoader,
  isPythonPycLoaderFilename,
  computePycSidecarCodeIdentity,
  extractPycSidecarMarshalNote,
  relativePycPathFromLoader,
  PYC_SIDECAR_LOADER_MARKER,
  generateSidecarGgufLoaderSnippet,
  prependGgufSidecarLoaderHook,
  selectPythonGgufLoader,
  computeGgufSidecarCodeIdentity,
  extractGgufSidecarMetadataNote,
  relativeGgufPathFromLoader,
  GGUF_SIDECAR_LOADER_MARKER,
  generateSidecarSafetensorsLoaderSnippet,
  prependSafetensorsSidecarLoaderHook,
  selectPythonSafetensorsLoader,
  computeSafetensorsSidecarCodeIdentity,
  extractSafetensorsSidecarMetadataNote,
  relativeSafetensorsPathFromLoader,
  SAFETENSORS_SIDECAR_LOADER_MARKER,
  verifyAsarSidecarArchiveNote,
} from "../shields/runtime/sidecar-entangle.js";
import { packAsarBuffer, unpackAsarBuffer } from "../shields/formats/asar.js";
import { inspectWasmBinary, isAbiMandatedWasmExport } from "../shields/formats/wasm.js";
import { detectJsCarrierForSource } from "../shields/javascript/ast-shield.js";
import { refineJsCarrierForRuntimePaths } from "../shields/javascript/node-runtime-carrier.js";
import {
  finalizeSelfSealSelfDigest,
  verifySelfSealSelfDigest,
} from "../shields/runtime/self-seal.js";
import {
  buildInterleavedCoverageMatrix,
  sha256Hex,
  withoutHostSelfCoverage,
} from "./integrity-coverage.js";
import { writeFileAtomicSync } from "./protector.js";
import {
  computeHardenRunId,
  HARDEN_SUMMARY_FILE_NAME,
  HARDEN_SUMMARY_SCHEMA,
  sha256File,
} from "./run-evidence.js";
import {
  readManifestSigningKeyOrThrow,
  signManifestPayload,
} from "../core/manifest-signing.js";
import {
  buildWeavePlan,
  verifyWeaveTarget,
  type WeaveAgentAction,
  type WeaveSurgicalWorkorder,
  type WeaveVerifyScope,
} from "../shields/weave/weave-decoy.js";

export { BLA_BUILD_OUTPUT_DIR_NAMES };

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

/**
 * Whole-project walks (no build-output directory) still descend into `src/`,
 * `lib/`, `scripts/` … because the sources ARE the artifact there, but a test
 * suite, the documentation, and sample programs are never shipped product
 * logic. (`scripts/` stays in: in a source-only project it is as often the
 * product as it is tooling.)
 */
const FULL_TREE_SKIP_DIR_NAMES = new Set([
  ...SKIP_DIR_NAMES,
  "test",
  "tests",
  "__tests__",
  "__mocks__",
  "__fixtures__",
  "fixtures",
  // Documentation and sample programs are not the product either
  // (`docs/conf.py` is Sphinx configuration).
  "docs",
  "doc",
  "examples",
  "example",
  "benchmarks",
]);

const MAX_DISCOVERED_ARTIFACTS = 64;
const MAX_WALK_DEPTH = 8;
/** Cap on how many skipped toolchain paths a discovery result lists verbatim. */
const MAX_REPORTED_SKIPPED_TOOLING = 24;

/**
 * Which kind of root a discovery walk is covering:
 * - `build`: a recognised build-output directory — everything in it ships.
 * - `full`: the whole project when no build-output directory exists.
 * - `supplemental`: the project root *beside* build-output directories, where
 *   JS/TS/HTML files are the inputs of that build, not release artifacts.
 */
type DiscoveryWalkMode = "build" | "full" | "supplemental";

/** Text formats that are build inputs whenever a build-output directory exists. */
const SOURCE_TEXT_FORMATS: ReadonlySet<ArtifactFormat> = new Set<ArtifactFormat>([
  "javascript",
  "typescript",
  "html-bundle",
  "sourcemap",
]);

/** Formats a toolchain file can have (configs, task runners, test suites). */
const TOOLING_CAPABLE_FORMATS: ReadonlySet<ArtifactFormat> = new Set<ArtifactFormat>([
  "javascript",
  "typescript",
  "python-source",
]);

interface DiscoverySkipLedger {
  readonly devTooling: string[];
  sourceFiles: number;
  /** Files that still hold the bytes an earlier BLA run wrote. */
  readonly hardenedOutputs: string[];
  /** Protectable files the caller's `exclude` list left out. */
  readonly excluded: string[];
}

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
  /** Size of the input file, in bytes. */
  readonly inputBytes?: number;
  /** Size of the hardened file as it will ship, in bytes (absent on dry-run / failure). */
  readonly outputBytes?: number;
  readonly error?: string;
  /**
   * WASM only: exports this run renamed (`from` → `to`). Anything that calls
   * one by its old name is now broken until it is updated from this map.
   */
  readonly wasmExportRenames?: readonly {
    readonly from: string;
    readonly to: string;
    readonly kind: string;
  }[];
  /**
   * WASM only: exports kept under their original name because another file in
   * the project refers to them (`referencedBy`, project-relative). They remain
   * a stable hook surface; rename them in your own source and its callers if
   * they guard entitlement logic.
   */
  readonly wasmExportsAutoPreserved?: readonly {
    readonly name: string;
    readonly referencedBy: string;
  }[];
  /**
   * JS/TS/HTML only: sensitive-looking literals of the input (digests, keys,
   * tokens — what `bla_lint` reports as `plaintext-secret`) that can still be
   * read verbatim in the hardened output. `maximum`/`bankrupt` split string
   * and template text, and a secret-looking value wherever it is written
   * (object key, regular expression, a string of up to 4,096 characters), so
   * what is left there is what the shield cannot reach — HTML attributes,
   * tagged templates, class member names, the keys and `as const` values of a
   * TypeScript source, anything longer. `stealth` and `balanced` do not
   * encode strings at all. Previews are clipped.
   */
  readonly plaintextSurvivors?: {
    readonly count: number;
    readonly samples: readonly {
      readonly id: string;
      readonly preview: string;
      readonly line?: number;
    }[];
  };
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
  /** Lab-only: allow leaked SOLUTION/dotenv/private-key/debug-symbol files in release tree. */
  readonly allowReleaseHygieneLeak?: boolean;
  readonly allowWasmXorMaskSidecar?: boolean;
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  /** Allow bankrupt despite panel offline-oracle packaging (red-blue round-4). Default false. */
  readonly allowPanelOfflineOracle?: boolean;
  /**
   * Enforce Agent-First Closed Loop: refuse mechanical hardening when source
   * files have not yet passed Host-Agent structural weave verification
   * (`bla_verify_weave`), returning surgicalWorkorders and agentActions so the
   * Host Agent performs source surgery first.
   */
  readonly requireAgentWeave?: boolean;
  /**
   * SQLite only, opt-in: evaluation-trap columns on the honey tables (see
   * `ProtectionOptions.sqliteEvalTrap`). The report names the databases it
   * was applied to and what stops working on them.
   */
  readonly sqliteEvalTrap?: boolean;
  /** Optional output root; defaults to `<dir>/.bla-hardened`. */
  readonly outputDirectory?: string;
  /**
   * Project-relative paths or globs to leave out (merged with the project
   * config's `exclude`). For the artifact that breaks or slows the program
   * when hardened: everything else is still protected, and the report lists
   * what was left out (`excluded`). See `compileExcludeMatcher` for the syntax.
   */
  readonly exclude?: readonly string[];
  /**
   * Promote the hardened files over the build output they came from, so the
   * tree that ships is the protected one. Only files inside a build-output
   * directory are ever overwritten (never source); the originals are backed up
   * outside the project and `restoreHardenedProject` puts them back. Re-running
   * re-hardens from those originals instead of hardening twice. Without an
   * explicit `outputDirectory` nothing but the promoted files is written into
   * the project.
   */
  readonly apply?: boolean;
  /** Override the per-user directory that holds apply backups (tests / CI caches). */
  readonly applyStateRoot?: string;
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

export interface AgentWeaveAssessment {
  readonly weaveVerified: boolean;
  readonly weaveScore: number;
  /**
   * Which files decided `weaveVerified` (`crown-jewels`: the files holding
   * gate / entitlement logic; `agent-selected`: none is recognizable by name,
   * so at least one file must pass; `all`: every source file).
   */
  readonly weaveScope?: WeaveVerifyScope;
  /** Required source files that have not passed weave verification yet. */
  readonly unwovenSourceFiles: readonly string[];
  /** Verified source files that never block the verdict (no gate logic). */
  readonly advisorySourceFiles?: readonly string[];
  readonly agentActions: readonly WeaveAgentAction[];
  /**
   * Surgical workorders for `unwovenSourceFiles`. Populated only when
   * `requireAgentWeave` refused the run (the agent needs them for Stage 2);
   * otherwise empty — call `bla_weave_plan` for the full plan.
   */
  readonly surgicalWorkorders: Readonly<Record<string, WeaveSurgicalWorkorder>>;
  readonly agentPlaybookDirective: string;
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
   * Present when `sidecarEntangle` was requested but the entry rewrite failed,
   * leaving the entry without the strip⇒fail binding. Such a run never reports
   * `overallSuccess`.
   */
  readonly sidecarEntangleError?: string;
  /**
   * True when `requireAgentWeave` blocked mechanical hardening because source
   * files still need Host-Agent source surgery (`bla_verify_weave` failed).
   */
  readonly agentWeaveGateBlocked?: boolean;
  /**
   * Host-Agent source weave readiness assessment (`weaveScore`, `unwovenSourceFiles`,
   * `agentActions`, and `surgicalWorkorders` per file).
   */
  readonly agentWeaveAssessment?: AgentWeaveAssessment;
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
   * Paths the discovery walk could not read (`path: CODE`). Present only when
   * non-empty — a non-empty list means the discovered inventory may be incomplete.
   */
  readonly discoveryReadErrors?: readonly string[];
  /**
   * Artifacts hardened WITHOUT the requested self-seal / sidecar-entanglement
   * binding, each with the reason: a browser bundle (the bindings need
   * `node:fs` / `node:crypto` and would stop the page from loading), mutable
   * data such as a SQLite database the app writes to, or a file the entry
   * module does not check. Tampering with these is NOT detected at load time.
   * Present only when a binding was requested.
   */
  readonly integrityBindingSkipped?: readonly {
    readonly relativePath: string;
    readonly reason: string;
  }[];
  /**
   * Python module that now checks its hardened sibling files when it is
   * imported (sidecar entanglement). The check needs those files as shipped:
   * loose on disk or inside a zipapp. A bytecode-only tree or a frozen bundle
   * ships no sibling sources; the module starts there without verifying them.
   */
  readonly pythonSidecarEntry?: string;
  /**
   * JS module that carries the cross-file check (project-relative): it pins
   * its hardened siblings and refuses to load when one was changed, replaced
   * or removed. The check runs when this module is loaded, and only then.
   */
  readonly integrityBindingEntry?: string;
  /**
   * Entry points `package.json` declares (`main` / `bin` / `exports`) that do
   * not load `integrityBindingEntry`: started there, a replaced sibling goes
   * unnoticed (under self-seal each file still checks its own bytes). Present
   * only when non-empty.
   */
  readonly integrityBindingUncoveredEntries?: readonly string[];
  /**
   * Console-script modules the Python project declares (`pyproject.toml`,
   * `setup.cfg`, `setup.py`) that never import `pythonSidecarEntry`: started
   * through one of them, nothing is verified. Present only when non-empty.
   */
  readonly pythonSidecarUncoveredEntries?: readonly string[];
  /** Toolchain files discovery left out on purpose (see `HardenDiscoveryResult`). */
  readonly skippedDevTooling?: readonly string[];
  /** Count of JS/TS/HTML sources beside a build-output directory left out on purpose. */
  readonly skippedSourceFiles?: number;
  /** Files discovery left out because they are already BLA output (see `HardenDiscoveryResult`). */
  readonly skippedHardenedOutputs?: readonly string[];
  /** Protectable files left out by the `exclude` list: they ship unprotected. */
  readonly excluded?: readonly string[];
  /**
   * What hardening costs to ship: total bytes of the hardened artifacts before
   * and after, and the artifact that grew the most. Decoys are the mechanism,
   * so growth is expected — a fixed amount per file, and megabytes per WASM
   * module at `bankrupt`. Present when at least one artifact was written.
   */
  readonly outputSize?: {
    readonly inputBytes: number;
    readonly outputBytes: number;
    readonly largestGrowth?: { readonly relativePath: string; readonly growthBytes: number };
  };
  /**
   * SQLite databases hardened with the opt-in evaluation trap
   * (`sqliteEvalTrap`). On these, a connection that does not register
   * `enclave_unseal_payload()` cannot read the honey tables — and cannot run
   * `PRAGMA integrity_check`, `VACUUM` or a dump/restore either.
   */
  readonly sqliteEvalTrapArtifacts?: readonly string[];
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
  /** Outcome of the `apply` promotion (present whenever `apply` was requested). */
  readonly apply?: HardenApplyReport;
  /**
   * Protectable artifacts outside every build-output directory that an `apply`
   * run left alone (project-relative). Harden them without `apply` if they ship.
   */
  readonly notPromoted?: readonly string[];
  /** What the caller should do next, most important first. */
  readonly nextSteps?: readonly string[];
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
   * Directories/files the bounded walk could not read during this discovery
   * pass (`path: CODE`). Non-empty means the inventory may be incomplete.
   */
  readonly readErrors: readonly string[];
  /**
   * When `truncated` is true, pass this as the next `offset` to retrieve the
   * following page without losing the tail (issue #75 paging). Absent when
   * this page exhausted the inventory.
   */
  readonly nextOffset?: number;
  /**
   * Toolchain files deliberately left out (tool configs, test files, scripts
   * that `package.json` runs for build/test/release), project-relative and
   * capped. Present only when non-empty. Name one explicitly (`bla defend
   * <file>` / `bla_defend`) if it really is shipped product code.
   */
  readonly skippedDevTooling?: readonly string[];
  /**
   * Count of JS/TS/HTML source files beside a build-output directory that were
   * left out because the build output is the release artifact. Present only
   * when non-zero.
   */
  readonly skippedSourceFiles?: number;
  /**
   * Files left out because they still hold exactly the bytes an earlier BLA
   * run on this machine wrote (project-relative, capped): hardened output is
   * never hardened twice. Rebuild to get fresh, unprotected output.
   */
  readonly skippedHardenedOutputs?: readonly string[];
  /**
   * Protectable files left out because they match the caller's `exclude` list
   * (project-relative, capped). They ship unprotected.
   */
  readonly excluded?: readonly string[];
}

/**
 * Compile an `exclude` list into a matcher over project-relative POSIX paths.
 *
 * gitignore-like, deliberately small. A pattern containing a slash is anchored
 * at the project root and also excludes everything beneath a matching
 * directory (`dist/vendor`, `dist/chunks/heavy-*.js`); a pattern without one
 * matches any path segment (`vendor`, `*.min.js`). A single star stays inside
 * one segment, a double star crosses segments, `?` is one character. There is
 * no negation.
 */
export function compileExcludeMatcher(
  patterns: readonly string[] | undefined,
): ((relativePath: string) => boolean) | undefined {
  const compiled: { readonly anchored: boolean; readonly re: RegExp }[] = [];
  for (const raw of patterns ?? []) {
    const pattern = raw
      .trim()
      .replaceAll("\\", "/")
      .replace(/^(?:\.\/)+/, "")
      .replace(/\/+$/, "");
    if (pattern.length === 0) continue;
    let source = "";
    for (let i = 0; i < pattern.length; i++) {
      const ch = pattern[i]!;
      if (ch === "*") {
        if (pattern[i + 1] === "*") {
          i++;
          if (pattern[i + 1] === "/") {
            i++;
            source += "(?:.*/)?";
          } else {
            source += ".*";
          }
        } else {
          source += "[^/]*";
        }
      } else if (ch === "?") {
        source += "[^/]";
      } else {
        source += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      }
    }
    compiled.push({ anchored: pattern.includes("/"), re: new RegExp(`^${source}$`) });
  }
  if (compiled.length === 0) return undefined;
  return (relativePath: string): boolean => {
    const rel = relativePath.replaceAll("\\", "/");
    const segments = rel.split("/");
    for (const { anchored, re } of compiled) {
      if (anchored) {
        // The path itself, or any directory above it.
        for (let end = segments.length; end >= 1; end--) {
          if (re.test(segments.slice(0, end).join("/"))) return true;
        }
      } else if (segments.some((segment) => re.test(segment))) {
        return true;
      }
    }
    return false;
  };
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
  // `release` and `Release` are one directory on a case-insensitive file
  // system (macOS, Windows): walk it once, under the name it has on disk.
  const seenPhysical = new Set<string>();
  const physicalRoot = realpathSync.native(absRoot);
  /**
   * True when `physical` is `absRoot` itself or lives under it.
   *
   * `walkBounded` skips symlinked directory *entries*, but it reads its own root
   * with `readdirSync`, which follows a link. Without this check a build
   * directory that is a symlink — or that sits behind one — would let discovery
   * (and therefore the report and the mirror) read files from outside the
   * project. Both sides are canonicalised first, so a case-insensitive file
   * system cannot make a legitimate build directory look like an escape.
   */
  const isInsideProject = (physical: string): boolean => {
    const rel = relative(physicalRoot, physical);
    return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
  };
  const addRoot = (candidate: string): void => {
    try {
      if (!statSync(candidate).isDirectory()) return;
      // The output of an earlier `bla harden -o ./release` is not build output.
      if (existsSync(join(candidate, HARDEN_SUMMARY_FILE_NAME))) return;
      const physical = realpathSync.native(candidate);
      if (!isInsideProject(physical)) return;
      if (seenPhysical.has(physical)) return;
      seenPhysical.add(physical);
      const onDiskName = basename(physical);
      preferred.push(
        onDiskName.toLowerCase() === basename(candidate).toLowerCase()
          ? join(dirname(candidate), onDiskName)
          : candidate,
      );
    } catch {
      /* absent */
    }
  };
  for (const name of BLA_BUILD_OUTPUT_DIR_NAMES) addRoot(join(absRoot, name));
  // Rust/cargo nested release
  addRoot(join(absRoot, "target", "release"));
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
  excludeDir: string | undefined,
  readErrors: string[],
  mode: DiscoveryWalkMode,
  manifest: {
    readonly toolingScripts: ReadonlySet<string>;
    readonly runtimeEntries: ReadonlySet<string>;
  },
  skipped: DiscoverySkipLedger,
  stateRoot: string | undefined,
  isExcluded: ((relativePath: string) => boolean) | undefined,
): DiscoveredArtifact[] {
  const formats = new Map<string, ArtifactFormat>();
  const relOf = (full: string): string =>
    (relative(projectRoot, full) || basename(full)).split(sep).join("/");
  const files = walkBounded(root, {
    maxDepth: MAX_WALK_DEPTH,
    maxFiles: maxArtifacts,
    skipDirs,
    // A directory holding a harden summary is the output of an earlier run
    // (`bla harden . -o ./release-hardened`): never feed it back in as input.
    skipDir: (full) => existsSync(join(full, HARDEN_SUMMARY_FILE_NAME)),
    skipHiddenDirs: true,
    // Locale-independent name sort so offset paging is stable across platforms.
    sortEntries: true,
    onError: (path, error) => {
      const code = (error as NodeJS.ErrnoException).code;
      readErrors.push(`${path.split(sep).join("/")}: ${code ?? error.message}`);
    },
    accept: (full, name) => {
      if (excludeDir && (full === excludeDir || full.startsWith(excludeDir + sep))) {
        return false;
      }
      // Ambient declarations carry no runtime logic; "protecting" one breaks
      // every TypeScript consumer of the package.
      if (isTypeScriptDeclarationPath(name)) return false;
      const format = detectArtifactFormat(full);
      if (!isProtectableFormat(format)) return false;
      // Skip already-shielded outputs to avoid re-hardening loops.
      if (/\.shielded(\.|$)/i.test(name)) return false;
      if (name.endsWith(".bla-manifest.json")) return false;
      if (name.endsWith(".bunfs-snapshot")) return false;
      if (name.endsWith(".bla-sidecar.v1.json")) return false;
      // The caller's explicit keep-out list: reported, never silently dropped.
      if (isExcluded?.(relOf(full)) === true) {
        if (skipped.excluded.length < MAX_REPORTED_SKIPPED_TOOLING) {
          skipped.excluded.push(relOf(full));
        }
        return false;
      }
      // Output of an earlier run written anywhere else (`bla_defend` with an
      // explicit output path, build output promoted by `apply`): hardening it
      // again hardens the decoys, and the packaging gates then refuse them.
      if (isKnownBlaOutput(full, stateRoot)) {
        if (skipped.hardenedOutputs.length < MAX_REPORTED_SKIPPED_TOOLING) {
          skipped.hardenedOutputs.push(relOf(full));
        }
        return false;
      }
      // A declared runtime entry (package.json main/bin/exports) is product
      // code by definition, whatever its name or location looks like.
      const declaredEntry = manifest.runtimeEntries.has(full);
      if (
        !declaredEntry &&
        mode !== "build" &&
        TOOLING_CAPABLE_FORMATS.has(format) &&
        (isDevToolingFile(full, name) || manifest.toolingScripts.has(full))
      ) {
        if (skipped.devTooling.length < MAX_REPORTED_SKIPPED_TOOLING) {
          skipped.devTooling.push(relOf(full));
        }
        return false;
      }
      if (mode === "supplemental" && SOURCE_TEXT_FORMATS.has(format) && !declaredEntry) {
        skipped.sourceFiles += 1;
        return false;
      }
      formats.set(full, format);
      return true;
    },
  });
  return files.map((full) => ({
    path: full,
    format: formats.get(full) ?? detectArtifactFormat(full),
    // Normalize to POSIX separators so reports, manifests, and MCP
    // structuredContent stay platform-independent (`dist/app.js`).
    relativePath: relOf(full),
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
  options: { readonly maxArtifacts?: number; readonly offset?: number; readonly outputDirectory?: string } = {},
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
  options: {
    readonly maxArtifacts?: number;
    readonly offset?: number;
    readonly outputDirectory?: string;
    /** Only walk build-output directories (no project-root supplement). */
    readonly buildOutputOnly?: boolean;
    /** Per-user state root override (tests, sandboxes); see `resolveBlaStateRoot`. */
    readonly stateRoot?: string;
    /** Paths / globs to leave out (see `compileExcludeMatcher`). */
    readonly exclude?: readonly string[];
  } = {},
): HardenDiscoveryResult {
  const abs = resolve(directory);
  const maxArtifacts = Math.max(1, Math.floor(options.maxArtifacts ?? MAX_DISCOVERED_ARTIFACTS));
  const offset = Math.max(0, Math.floor(options.offset ?? 0));
  const excludeDir = options.outputDirectory ? resolve(options.outputDirectory) : undefined;
  // Collect one past the page end so truncated/nextOffset stay honest.
  const { artifacts: all, readErrors, skipped } = collectHardenableArtifacts(
    abs,
    offset + maxArtifacts + 1,
    excludeDir,
    options.buildOutputOnly === true,
    options.stateRoot,
    compileExcludeMatcher(options.exclude),
  );
  const page = all.slice(offset, offset + maxArtifacts);
  const truncated = all.length > offset + maxArtifacts;
  return {
    directory: abs,
    artifacts: page,
    truncated,
    maxArtifacts,
    offset,
    readErrors,
    ...(truncated ? { nextOffset: offset + page.length } : {}),
    ...(skipped.devTooling.length > 0 ? { skippedDevTooling: skipped.devTooling.slice() } : {}),
    ...(skipped.sourceFiles > 0 ? { skippedSourceFiles: skipped.sourceFiles } : {}),
    ...(skipped.hardenedOutputs.length > 0
      ? { skippedHardenedOutputs: skipped.hardenedOutputs.slice() }
      : {}),
    ...(skipped.excluded.length > 0 ? { excluded: skipped.excluded.slice() } : {}),
  };
}

function collectHardenableArtifacts(
  abs: string,
  maxArtifacts: number,
  excludeDir?: string,
  buildOutputOnly = false,
  stateRoot?: string,
  isExcluded?: (relativePath: string) => boolean,
): {
  readonly artifacts: readonly DiscoveredArtifact[];
  readonly readErrors: readonly string[];
  readonly skipped: DiscoverySkipLedger;
} {
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const skipped: DiscoverySkipLedger = {
    devTooling: [],
    sourceFiles: 0,
    hardenedOutputs: [],
    excluded: [],
  };
  const stats = statSync(abs);
  if (stats.isFile()) {
    const format = detectArtifactFormat(abs);
    if (!isProtectableFormat(format)) {
      throw new Error(`Unsupported artifact format at ${abs}`);
    }
    return {
      artifacts: [{ path: abs, format, relativePath: basename(abs) }],
      readErrors: [],
      skipped,
    };
  }
  if (!stats.isDirectory()) {
    throw new Error(`Not a file or directory: ${abs}`);
  }

  const readErrors: string[] = [];
  const found: DiscoveredArtifact[] = [];
  const { preferred, includeProjectRootSupplemental } = resolveSearchRoots(abs);
  const manifest = {
    toolingScripts: readPackageToolingScripts(abs, BLA_BUILD_OUTPUT_DIR_NAMES),
    runtimeEntries: readPackageRuntimeEntries(abs),
  };
  for (const root of preferred) {
    const remaining = maxArtifacts - found.length;
    if (remaining <= 0) break;
    // Pointing straight at `dist/` is a build walk, not a project walk.
    const fullTree =
      !includeProjectRootSupplemental &&
      !(BLA_BUILD_OUTPUT_DIR_NAMES as readonly string[]).includes(basename(abs));
    found.push(
      ...collectRootArtifacts(
        root,
        abs,
        remaining,
        fullTree ? FULL_TREE_SKIP_DIR_NAMES : SKIP_DIR_NAMES,
        excludeDir,
        readErrors,
        fullTree ? "full" : "build",
        manifest,
        skipped,
        stateRoot,
        isExcluded,
      ),
    );
  }
  if (includeProjectRootSupplemental && !buildOutputOnly && found.length < maxArtifacts) {
    found.push(
      ...collectRootArtifacts(
        abs,
        abs,
        maxArtifacts - found.length,
        SUPPLEMENTAL_SKIP_DIR_NAMES,
        excludeDir,
        readErrors,
        "supplemental",
        manifest,
        skipped,
        stateRoot,
        isExcluded,
      ),
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
  return { artifacts: unique, readErrors, skipped };
}

/** Mirror-tree destination under the output root (pure; no filesystem writes). */
function planArtifactOutputPath(artifact: DiscoveredArtifact, outputRoot: string): string {
  // Keep original basename; place under .bla-hardened mirror tree.
  return join(outputRoot, artifact.relativePath);
}

const PLAINTEXT_SURVIVOR_FORMATS: ReadonlySet<ArtifactFormat> = new Set<ArtifactFormat>([
  "javascript",
  "typescript",
  "html-bundle",
]);
const MAX_SURVIVOR_INPUT_BYTES = 4 * 1024 * 1024;
const MAX_SURVIVOR_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_SURVIVOR_SAMPLES = 6;

/**
 * Which sensitive-looking literals of `inputPath` are still readable in the
 * hardened `outputPath`? Best effort and conservative: only verbatim matches
 * count, so a literal the output spells with escapes is not reported.
 */
function findPlaintextSurvivors(
  artifact: DiscoveredArtifact,
  outputPath: string,
): HardenArtifactSummary["plaintextSurvivors"] {
  if (!PLAINTEXT_SURVIVOR_FORMATS.has(artifact.format)) return undefined;
  try {
    if (statSync(artifact.path).size > MAX_SURVIVOR_INPUT_BYTES) return undefined;
    if (statSync(outputPath).size > MAX_SURVIVOR_OUTPUT_BYTES) return undefined;
    const flagged = lintPlaintextSecretsFile(artifact.path, {
      allowPlaintextString: true,
    }).findings.filter((f) => f.severity === "error");
    if (flagged.length === 0) return undefined;
    const hardened = readFileSync(outputPath, "utf8");
    const seen = new Set<string>();
    const samples: { id: string; preview: string; line?: number }[] = [];
    let count = 0;
    for (const finding of flagged) {
      // Findings clip long literals to 200 chars + "…".
      const needle =
        finding.literal.length === 201 && finding.literal.endsWith("…")
          ? finding.literal.slice(0, 200)
          : finding.literal;
      if (needle.length < 8 || seen.has(needle)) continue;
      seen.add(needle);
      if (!hardened.includes(needle)) continue;
      count += 1;
      if (samples.length < MAX_SURVIVOR_SAMPLES) {
        samples.push({
          id: finding.id,
          preview: needle.length > 20 ? `${needle.slice(0, 20)}…` : needle,
          ...(finding.line !== undefined ? { line: finding.line } : {}),
        });
      }
    }
    return count > 0 ? { count, samples } : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Artifacts the running application itself rewrites. Pinning their SHA-256
 * into an integrity binding turns the app's first legitimate write into a
 * permanent "integrity check failed" on every later start.
 */
const MUTABLE_DATA_FORMATS: ReadonlySet<ArtifactFormat> = new Set<ArtifactFormat>(["sqlite"]);

/** Text files that can hold a call site of a WASM export. */
const WASM_CONSUMER_EXT_RE =
  /\.(?:[cm]?[jt]sx?|html?|vue|svelte|astro|py|pyw|go|rs|c|cc|cpp|h|hpp|cs|java|kt|swift|rb|php|dart|zig)$/i;
const MAX_WASM_CONSUMER_FILES = 600;
const MAX_WASM_CONSUMER_FILE_BYTES = 4 * 1024 * 1024;

interface WasmConsumerIndex {
  /** Project-relative path of the first file that mentions `exportName`, if any. */
  findReference(exportName: string): string | undefined;
}

/**
 * Index the identifiers used by the project's own code so a WASM export that
 * something still calls by name is not renamed out from under it. A plain
 * token match — it over-preserves (a comment mentioning `add` keeps `add`),
 * which is the safe direction: an unnecessary keep costs a little obscurity, a
 * wrong rename breaks the program.
 */
function buildWasmConsumerIndex(absDir: string, outputRoot: string): WasmConsumerIndex {
  let scanRoot = absDir;
  try {
    if (!statSync(absDir).isDirectory()) scanRoot = dirname(absDir);
  } catch {
    /* keep absDir */
  }
  // `bla harden dist`: the callers usually live beside it, in the project.
  if (
    (BLA_BUILD_OUTPUT_DIR_NAMES as readonly string[]).includes(basename(scanRoot)) &&
    (existsSync(join(dirname(scanRoot), "package.json")) ||
      existsSync(join(dirname(scanRoot), "pyproject.toml")) ||
      existsSync(join(dirname(scanRoot), "Cargo.toml")))
  ) {
    scanRoot = dirname(scanRoot);
  }
  const files: { readonly rel: string; readonly tokens: Set<string>; readonly text: string }[] = [];
  const stack = [scanRoot];
  let visitedDirs = 0;
  while (stack.length > 0 && files.length < MAX_WASM_CONSUMER_FILES && visitedDirs < 4000) {
    const dir = stack.pop()!;
    visitedDirs += 1;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (files.length >= MAX_WASM_CONSUMER_FILES) break;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIR_NAMES.has(entry.name) || full === outputRoot) continue;
        stack.push(full);
        continue;
      }
      if (!entry.isFile() || !WASM_CONSUMER_EXT_RE.test(entry.name)) continue;
      try {
        if (statSync(full).size > MAX_WASM_CONSUMER_FILE_BYTES) continue;
        const text = readFileSync(full, "utf8");
        files.push({
          rel: (relative(scanRoot, full) || entry.name).split(sep).join("/"),
          tokens: new Set(text.match(/[A-Za-z_$][\w$]*/g) ?? []),
          text,
        });
      } catch {
        /* unreadable: cannot be evidence either way */
      }
    }
  }
  // Name the file that really loads the module when there is one: a loader
  // (it mentions WebAssembly or a .wasm file) is better evidence than a file
  // that merely has a method called `add`.
  const looksLikeWasmHost = (text: string): boolean => /\bWebAssembly\b|\.wasm\b/.test(text);
  files.sort((a, b) => Number(looksLikeWasmHost(b.text)) - Number(looksLikeWasmHost(a.text)));
  return {
    findReference(exportName: string): string | undefined {
      const isIdentifier = /^[A-Za-z_$][\w$]*$/.test(exportName);
      for (const file of files) {
        if (isIdentifier ? file.tokens.has(exportName) : file.text.includes(exportName)) {
          return file.rel;
        }
      }
      return undefined;
    },
  };
}

/** Relative specifiers a module loads: `require("./x")`, `from "./x"`, `import("./x")`, `import "./x"`. */
const RELATIVE_LOAD_RE =
  /(?:\brequire\s*\(\s*|\bfrom\s*|\bimport\s*\(\s*|\bimport\s*)["'`](\.{1,2}\/[^"'`\n]+?)["'`]/g;
const MAX_ENTRY_GRAPH_SCAN_BYTES = 2 * 1024 * 1024;

/**
 * For every candidate, the candidates it loads through a relative
 * `require` / `import` (input paths). Textual and bounded: good enough to tell
 * "the CLI loads the library entry" from "two unrelated programs".
 */
function relativeLoadGraph(
  candidates: readonly { readonly inputPath: string }[],
): ReadonlyMap<string, ReadonlySet<string>> {
  const known = new Set(candidates.map((c) => c.inputPath));
  const graph = new Map<string, Set<string>>();
  for (const candidate of candidates) {
    const targets = new Set<string>();
    graph.set(candidate.inputPath, targets);
    let source: string;
    try {
      if (statSync(candidate.inputPath).size > MAX_ENTRY_GRAPH_SCAN_BYTES) continue;
      source = readFileSync(candidate.inputPath, "utf8");
    } catch {
      continue;
    }
    for (const match of source.matchAll(RELATIVE_LOAD_RE)) {
      const base = resolve(dirname(candidate.inputPath), match[1]!);
      const stem = base.replace(/\.[cm]?js$/i, "");
      for (const guess of [
        base,
        `${base}.js`,
        `${base}.cjs`,
        `${base}.mjs`,
        `${base}.ts`,
        `${stem}.ts`,
        `${stem}.tsx`,
        `${stem}.mts`,
        `${stem}.cts`,
        join(base, "index.js"),
        join(base, "index.cjs"),
        join(base, "index.mjs"),
        join(base, "index.ts"),
      ]) {
        if (guess !== candidate.inputPath && known.has(guess)) {
          targets.add(guess);
          break;
        }
      }
    }
  }
  return graph;
}

/** Input paths `start` loads, directly or through other candidates (itself included). */
function loadedFrom(
  start: string,
  graph: ReadonlyMap<string, ReadonlySet<string>>,
): ReadonlySet<string> {
  const seen = new Set<string>([start]);
  const queue = [start];
  while (queue.length > 0) {
    for (const next of graph.get(queue.shift()!) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push(next);
    }
  }
  return seen;
}

/**
 * The JS module that carries the self-seal / sidecar strip⇒fail checks.
 *
 * Those checks only run when the module is loaded, so the entry has to be a
 * file the program really executes. Order: the conventional `license.(cjs|js)`
 * gate module, then whatever `package.json` declares as `main` / `bin` /
 * `exports`, then a conventionally named start file, then the first candidate.
 * (Without the manifest step the pick was alphabetical — often a lazily-loaded
 * chunk whose checks never fire.)
 *
 * A package that is both a library and a CLI declares several entries, and the
 * check lives in one module. The one the others load wins (`bin` requires
 * `main` ⇒ host it in `main`, and both ways in are checked); a declared entry
 * that never loads the host is reported by `entriesNotLoadingHost`.
 */
function pickJsEntry<T extends { readonly relativePath: string; readonly inputPath: string }>(
  candidates: readonly T[],
  runtimeEntries: ReadonlySet<string>,
): T | undefined {
  const norm = (c: T): string => c.relativePath.replaceAll("\\", "/");
  // The check only runs when its host module loads, so prefer the file the
  // program starts from over whichever name sorts first (`lib.cjs` < `main.cjs`).
  const conventionalEntry = candidates
    .filter((c) =>
      /^(?:main|index|app|cli|server|start)\.[cm]?js$/i.test(norm(c).split("/").pop() ?? ""),
    )
    .sort((a, b) => norm(a).split("/").length - norm(b).split("/").length)[0];
  const declared = candidates.filter((c) => runtimeEntries.has(c.inputPath));
  let declaredEntry = declared[0];
  if (declared.length > 1) {
    const graph = relativeLoadGraph(candidates);
    const reach = declared.map((d) => loadedFrom(d.inputPath, graph));
    let best = -1;
    for (const candidate of declared) {
      const loadedBy = reach.filter((r) => r.has(candidate.inputPath)).length;
      if (loadedBy > best) {
        best = loadedBy;
        declaredEntry = candidate;
      }
    }
  }
  return (
    candidates.find((c) => /license\.(cjs|js)$/i.test(c.relativePath)) ??
    declaredEntry ??
    conventionalEntry ??
    candidates[0]
  );
}

/**
 * Declared `package.json` entry points among `candidates` that never load
 * `host` — starting the program through one of them runs no integrity check.
 */
function entriesNotLoadingHost<
  T extends { readonly relativePath: string; readonly inputPath: string },
>(host: T, candidates: readonly T[], runtimeEntries: ReadonlySet<string>): string[] {
  const declared = candidates.filter(
    (c) => runtimeEntries.has(c.inputPath) && c.inputPath !== host.inputPath,
  );
  if (declared.length === 0) return [];
  const graph = relativeLoadGraph(candidates);
  return declared
    .filter((d) => !loadedFrom(d.inputPath, graph).has(host.inputPath))
    .map((d) => d.relativePath.replaceAll("\\", "/"));
}

const posixRelativePath = (c: { readonly relativePath: string }): string =>
  c.relativePath.replaceAll("\\", "/");

/** The hardened file that is module `a.b.c` (`a/b/c.py` or `a/b/c/__init__.py`), if any. */
function resolvePythonModuleFile<T extends { readonly relativePath: string }>(
  module: string,
  candidates: readonly T[],
): T | undefined {
  const base = module.split(".").join("/");
  for (const wanted of [`${base}.py`, `${base}/__init__.py`]) {
    const exact = candidates.find((c) => posixRelativePath(c) === wanted);
    if (exact) return exact;
    // `src/` layouts put the package below the harden target …
    const below = candidates
      .filter((c) => posixRelativePath(c).endsWith(`/${wanted}`))
      .sort((a, b) => posixRelativePath(a).length - posixRelativePath(b).length)[0];
    if (below) return below;
    // … and a target inside the package sees only the tail of the module path.
    const tail = candidates
      .filter((c) => wanted.endsWith(`/${posixRelativePath(c)}`))
      .sort((a, b) => posixRelativePath(b).length - posixRelativePath(a).length)[0];
    if (tail) return tail;
  }
  return undefined;
}

/** Hardened files behind the console scripts the project declares, in declaration order. */
function resolvePythonDeclaredEntryFiles<T extends { readonly relativePath: string }>(
  absDir: string,
  candidates: readonly T[],
): T[] {
  let dir = absDir;
  try {
    if (!statSync(absDir).isDirectory()) dir = dirname(absDir);
  } catch {
    return [];
  }
  let modules = readPythonDeclaredEntryModules(dir);
  if (modules.length === 0) modules = readPythonDeclaredEntryModules(dirname(dir));
  const files: T[] = [];
  for (const module of modules) {
    const file = resolvePythonModuleFile(module, candidates);
    if (file !== undefined && !files.includes(file)) files.push(file);
  }
  return files;
}

/**
 * `__init__.py` of the outermost package that contains `file`, among the
 * hardened candidates. Python runs it before any module of the package, however
 * the program was started.
 */
function outermostPythonPackageInit<T extends { readonly relativePath: string }>(
  file: T,
  candidates: readonly T[],
): T | undefined {
  const byPath = new Map(candidates.map((c) => [posixRelativePath(c), c] as const));
  const segments = posixRelativePath(file).split("/").slice(0, -1);
  let found: T | undefined;
  for (let depth = segments.length; depth >= 0; depth--) {
    const init = byPath.get([...segments.slice(0, depth), "__init__.py"].join("/"));
    if (init === undefined) break;
    found = init;
  }
  return found;
}

/** Whether a Python source file declares a script entrypoint `if __name__ == "__main__":`. */
function pythonSourceHasMainGuard(path: string): boolean {
  try {
    if (statSync(path).size > 512 * 1024) return false;
    const text = readFileSync(path, "latin1");
    return /^[ \t]*if[ \t]+\(?[ \t]*__name__[ \t]*==[ \t]*["']__main__["'][ \t]*\)?[ \t]*:/m.test(text);
  } catch {
    return false;
  }
}

/**
 * The Python module that carries the load-time sibling check. It only runs
 * when that module is imported, so prefer one that always is: the conventional
 * `policy.py`; then, when the project declares console scripts, the package
 * those scripts import (an installed script never touches a `run.py` beside
 * the package); then a program entry point (`__main__.py`, `main`/`app`/`cli`/
 * `loader`/…, or a file with `if __name__ == "__main__":`), the shallowest
 * package `__init__.py`, and only then the first file by name.
 */
function pickPythonEntry<
  T extends { readonly relativePath: string; readonly inputPath?: string },
>(
  candidates: readonly T[],
  declaredEntryFiles: readonly T[] = [],
): T | undefined {
  const norm = posixRelativePath;
  const byBasename = (re: RegExp): T | undefined =>
    candidates
      .filter((c) => re.test(norm(c).split("/").pop() ?? ""))
      .sort((a, b) => norm(a).split("/").length - norm(b).split("/").length)[0];
  const byMainGuard = (): T | undefined =>
    candidates
      .filter((c) => typeof c.inputPath === "string" && pythonSourceHasMainGuard(c.inputPath))
      .sort((a, b) => norm(a).split("/").length - norm(b).split("/").length)[0];
  const declared = declaredEntryFiles[0];
  return (
    byBasename(/^policy\.py$/i) ??
    (declared !== undefined
      ? (outermostPythonPackageInit(declared, candidates) ?? declared)
      : undefined) ??
    byBasename(/^__main__\.py$/) ??
    byBasename(/^(?:main|app|cli|loader|manage|run|server|wsgi|asgi)\.py$/i) ??
    byMainGuard() ??
    byBasename(/^__init__\.py$/) ??
    candidates[0]
  );
}

/** Whether the Python source at `path` has an import statement naming module `name`. */
function pythonSourceImportsModule(path: string, name: string): boolean {
  let text: string;
  try {
    if (statSync(path).size > 512 * 1024) return false;
    text = readFileSync(path, "latin1");
  } catch {
    return false;
  }
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    String.raw`^[ \t]*(?:from[ \t]+[\w.]*\b${n}\b[\w.]*[ \t]+import\b|import[ \t]+[^#\n]*\b${n}\b|from[ \t]+[\w.]+[ \t]+import[ \t]+[^#\n]*\b${n}\b)`,
    "m",
  ).test(text);
}

/**
 * Declared console-script modules that start the program without running the
 * check in `host`: they are not `host`, not inside the package whose
 * `__init__.py` it is, and do not import it.
 */
function pythonEntriesNotLoadingHost<
  T extends { readonly relativePath: string; readonly inputPath: string },
>(host: T, declaredEntryFiles: readonly T[]): string[] {
  const hostRel = posixRelativePath(host);
  const hostSegments = hostRel.split("/");
  const hostFile = hostSegments[hostSegments.length - 1]!;
  const hostIsPackage = hostFile === "__init__.py";
  const hostDir = hostSegments.slice(0, -1).join("/");
  const hostModule = hostIsPackage
    ? (hostSegments[hostSegments.length - 2] ?? "")
    : hostFile.replace(/\.py$/i, "");
  return declaredEntryFiles
    .filter((d) => {
      const rel = posixRelativePath(d);
      if (rel === hostRel) return false;
      if (hostIsPackage && (hostDir.length === 0 || rel.startsWith(`${hostDir}/`))) return false;
      return hostModule.length === 0 || !pythonSourceImportsModule(d.inputPath, hostModule);
    })
    .map(posixRelativePath);
}

/** `package.json` runtime entries visible from a harden target (and its project root). */
function resolveRuntimeEntries(absDir: string): ReadonlySet<string> {
  const entries = new Set<string>();
  let dir = absDir;
  try {
    if (!statSync(absDir).isDirectory()) dir = dirname(absDir);
  } catch {
    return entries;
  }
  for (const entry of readPackageRuntimeEntries(dir)) entries.add(entry);
  if ((BLA_BUILD_OUTPUT_DIR_NAMES as readonly string[]).includes(basename(dir))) {
    for (const entry of readPackageRuntimeEntries(dirname(dir))) entries.add(entry);
  }
  return entries;
}

/**
 * One-sentence Counter-REA hardening: discover every protectable build artifact
 * under a project/build directory and run the full audit→defend→verify pipeline
 * with the bankrupt profile. Modelled on REA's `npx rea-agents setup` simplicity.
 *
 * Usage: `bla harden .` / MCP `bla_harden` with `{ "directory": "." }`
 */
export function hardenProject(
  rawOptions: HardenProjectOptions = {},
): HardenProjectReport {
  const absDir = resolve(rawOptions.directory ?? process.cwd());
  const stateDirectory = resolveApplyStateDirectory(absDir, rawOptions.applyStateRoot);
  const dryRun = rawOptions.dryRun === true;
  const relOfProject = (abs: string): string =>
    (relative(absDir, abs) || basename(abs)).split(sep).join("/");

  if (rawOptions.apply !== true) {
    // Build output that still holds the hardened bytes of an earlier `apply`
    // must not be fed to the hardener again: that hardens hardened code.
    const stillApplied = existsSync(absDir) ? listAppliedFiles(absDir, stateDirectory) : [];
    if (stillApplied.length > 0) {
      throw new Error(
        `${stillApplied.length} file(s) in ${absDir} are already hardened output promoted by an earlier apply run ` +
          `(${stillApplied.slice(0, 3).join(", ")}${stillApplied.length > 3 ? ", …" : ""}). ` +
          "Re-run with apply (bla harden --apply / bla_harden { apply: true }) to re-harden from the saved originals, " +
          "restore the originals first (bla harden --restore / bla_harden { restore: true }), or rebuild the project.",
      );
    }
    return withNextSteps(
      rememberHardenedOutputs(hardenProjectCore(rawOptions, {}), rawOptions.applyStateRoot),
      rawOptions,
      absDir,
    );
  }

  // ── apply: harden build output and promote it in place ──────────────────
  const stagingRoot = rawOptions.outputDirectory ?? join(stateDirectory, "staging");
  const coreOptions: HardenProjectOptions = { ...rawOptions, outputDirectory: stagingRoot };
  const refuse = (reason: string, sourceFiles?: readonly string[]): HardenProjectReport => {
    const preview = hardenProjectCore({ ...coreOptions, dryRun: true }, { buildOutputOnly: true });
    return withNextSteps(
      {
        ...preview,
        dryRun,
        overallSuccess: false,
        wouldOverwrite: [],
        apply: { status: "refused", reason, ...(sourceFiles ? { sourceFiles } : {}) },
      },
      rawOptions,
      absDir,
    );
  };
  if (!existsSync(absDir) || !statSync(absDir).isDirectory()) {
    throw new Error(
      `apply needs a project or build directory, not a single file: ${absDir}. Use bla protect --in-place for one file.`,
    );
  }

  // Originals first: discovery and the lints must see what the build produced,
  // not the hardened bytes of the previous promotion. `suspension.resume()`
  // puts those hardened bytes back if this run does not end in a promotion.
  const suspension = dryRun
    ? undefined
    : suspendAppliedOutputs(absDir, stateDirectory);
  let promoted = false;
  try {
    const applyExclude = mergedExcludeList(rawOptions, loadProjectConfigFor(absDir));
    const promotable = discoverHardenTargets(absDir, {
      ...(rawOptions.maxArtifacts !== undefined ? { maxArtifacts: rawOptions.maxArtifacts } : {}),
      outputDirectory: stagingRoot,
      buildOutputOnly: true,
      ...(rawOptions.applyStateRoot !== undefined ? { stateRoot: rawOptions.applyStateRoot } : {}),
      ...(applyExclude.length > 0 ? { exclude: applyExclude } : {}),
    });
    const outside = promotable.artifacts
      .map((a) => a.relativePath.split(sep).join("/"))
      .filter((rel) => !isInsideBuildOutput(rel, absDir, BLA_BUILD_OUTPUT_DIR_NAMES));
    if (promotable.artifacts.length === 0) {
      if (dryRun) {
        const previouslyApplied = listAppliedFiles(absDir, stateDirectory);
        if (previouslyApplied.length > 0) {
          const preview = hardenProjectCore({ ...coreOptions, dryRun: true }, { buildOutputOnly: true });
          const plannedArtifacts: HardenArtifactSummary[] = previouslyApplied.map((rel) => {
            const abs = join(absDir, rel);
            return {
              inputPath: abs,
              relativePath: rel,
              format: detectArtifactFormat(abs),
              outputPath: abs,
              success: false,
              defenseScore: 0,
              tokenAmplificationFactor: 0,
              costAmplificationFactor: 0,
              outputExisted: true,
            };
          });
          return withNextSteps(
            {
              ...preview,
              discoveredCount: plannedArtifacts.length,
              overallSuccess: false,
              hardenedCount: 0,
              failedCount: 0,
              artifacts: plannedArtifacts,
              wouldOverwrite: plannedArtifacts.map((a) => a.inputPath),
              apply: {
                status: "planned",
                applied: previouslyApplied,
              },
            },
            rawOptions,
            absDir,
          );
        }
      }
      return refuse(
        `No protectable build output found under ${absDir}. Build the project first (for example npm run build), then re-run with apply.`,
      );
    }
    if (outside.length > 0) {
      return refuse(
        `apply only overwrites build output, but ${absDir} has no build-output directory (${BLA_BUILD_OUTPUT_DIR_NAMES.slice(0, 4).join(", ")}, …): ` +
          `the ${outside.length} protectable file(s) found are source files, and overwriting them would replace your source code with hardened output. ` +
          "Build the project and re-run, or harden without apply and overlay the hardened mirror onto a staging copy of the project.",
        outside,
      );
    }
    const everything = discoverHardenTargets(absDir, {
      ...(rawOptions.maxArtifacts !== undefined ? { maxArtifacts: rawOptions.maxArtifacts } : {}),
      outputDirectory: stagingRoot,
      ...(rawOptions.applyStateRoot !== undefined ? { stateRoot: rawOptions.applyStateRoot } : {}),
      ...(applyExclude.length > 0 ? { exclude: applyExclude } : {}),
    });
    const promotableSet = new Set(promotable.artifacts.map((a) => a.path));
    const notPromoted = everything.artifacts
      .filter((a) => !promotableSet.has(a.path))
      .map((a) => a.relativePath.split(sep).join("/"));

    if (dryRun) {
      const preview = hardenProjectCore(coreOptions, { buildOutputOnly: true });
      return withNextSteps(
        {
          ...preview,
          // The staging tree is BLA-private state, not something of the user's.
          wouldOverwrite: preview.artifacts.map((a) => a.inputPath),
          apply: {
            status: "planned",
            applied: preview.artifacts.map((a) => relOfProject(a.inputPath)),
          },
          ...(notPromoted.length > 0 ? { notPromoted } : {}),
        },
        rawOptions,
        absDir,
      );
    }

    if (rawOptions.outputDirectory === undefined) {
      rmSync(stagingRoot, { recursive: true, force: true });
    }
    const startedAtMs = Date.now();
    const report = rememberHardenedOutputs(
      hardenProjectCore(coreOptions, { buildOutputOnly: true }),
      rawOptions.applyStateRoot,
    );
    const base = {
      ...report,
      wouldOverwrite: [] as readonly string[],
      ...(notPromoted.length > 0 ? { notPromoted } : {}),
    };
    if (!report.overallSuccess) {
      return withNextSteps(
        {
          ...base,
          apply: {
            status: "refused",
            reason:
              "Hardening did not fully succeed, so nothing was promoted" +
              (suspension?.active === true
                ? "; the build output still holds the hardened files of the previous apply run."
                : "; the build output is unchanged."),
          },
        },
        rawOptions,
        absDir,
      );
    }
    const applyReport = applyHardenedOutputs({
      projectDirectory: absDir,
      stateDirectory,
      runId: report.runId,
      buildDirNames: BLA_BUILD_OUTPUT_DIR_NAMES,
      candidates: collectApplyCandidates({
        projectDirectory: absDir,
        outputRoot: report.outputDirectory,
        artifactOutputPaths: report.artifacts.filter((a) => a.success).map((a) => a.outputPath),
        notBeforeMs: startedAtMs,
      }),
    });
    promoted = applyReport.status === "applied";
    return withNextSteps(
      { ...base, overallSuccess: promoted, apply: applyReport },
      rawOptions,
      absDir,
    );
  } finally {
    if (promoted) suspension?.discard();
    else suspension?.resume();
  }
}

/**
 * Record what a run wrote so later discovery / lint passes recognise it as
 * BLA output instead of hardening (or "fixing") it again.
 */
function rememberHardenedOutputs(
  report: HardenProjectReport,
  stateRoot: string | undefined,
): HardenProjectReport {
  if (report.dryRun) return report;
  for (const artifact of report.artifacts) {
    if (artifact.success) registerBlaOutput(artifact.outputPath, stateRoot);
  }
  return report;
}

/**
 * Undo `apply`: put the original build output back and drop the backups.
 * Files that changed since the promotion (a rebuild) are left alone.
 */
export function restoreHardenedProject(
  directory: string = process.cwd(),
  options: { readonly applyStateRoot?: string } = {},
): HardenApplyReport {
  const absDir = resolve(directory);
  return restoreAppliedOriginals(
    absDir,
    resolveApplyStateDirectory(absDir, options.applyStateRoot),
  );
}

/** One `.gitignore` pattern as a matcher for a single path (anchored) or path segment. */
function gitignorePatternToRegExp(pattern: string): RegExp {
  const body = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/\u0000/g, ".*");
  return new RegExp(`^${body}$`);
}

/**
 * `true` when `dir` sits in a git work tree and none of the ignore files on
 * the way down to it covers it — i.e. `git status` lists it as untracked.
 * Reads `.gitignore` files and `.git/info/exclude` only; a global ignore file
 * or a negated pattern is not consulted, so the answer errs towards "not
 * ignored" (one extra hint), never towards hiding the hint from a clean repo.
 */
function isUntrackedInGitWorkTree(dir: string): boolean {
  const abs = resolve(dir);
  let repoRoot: string | undefined;
  for (let cur = dirname(abs), depth = 0; depth < 64; cur = dirname(cur), depth++) {
    if (existsSync(join(cur, ".git"))) {
      repoRoot = cur;
      break;
    }
    if (dirname(cur) === cur) break;
  }
  if (repoRoot === undefined) return false;
  const segments = relative(repoRoot, abs).split(sep).filter((part) => part.length > 0);
  if (segments.length === 0 || segments[0] === "..") return false;

  const readLines = (file: string): string[] => {
    try {
      if (statSync(file).size > 512 * 1024) return [];
      return readFileSync(file, "utf8").split(/\r?\n/);
    } catch {
      return [];
    }
  };
  // Ignore files apply to paths below their own directory.
  const sources: { lines: string[]; below: string[] }[] = [
    { lines: readLines(join(repoRoot, ".git", "info", "exclude")), below: segments },
  ];
  for (let depth = 0; depth < segments.length; depth++) {
    sources.push({
      lines: readLines(join(repoRoot, ...segments.slice(0, depth), ".gitignore")),
      below: segments.slice(depth),
    });
  }
  for (const { lines, below } of sources) {
    for (const raw of lines) {
      const line = raw.trim();
      if (line.length === 0 || line.startsWith("#") || line.startsWith("!")) continue;
      let pattern = line.replace(/\/+$/, "");
      // A pattern with a slash names a path from the ignore file's directory;
      // one without (or behind `**/`) matches at any depth. Either way,
      // ignoring a directory ignores everything in it.
      const anyDepth = pattern.startsWith("**/") || !pattern.includes("/");
      pattern = pattern.replace(/^\*\*\//, "").replace(/^\//, "");
      if (pattern.length === 0) continue;
      const matcher = gitignorePatternToRegExp(pattern);
      for (let start = 0; start < (anyDepth ? below.length : 1); start++) {
        for (let end = start + 1; end <= below.length; end++) {
          if (matcher.test(below.slice(start, end).join("/"))) return false;
        }
      }
    }
  }
  return true;
}

/** Attach the caller's next actions to a finished report. */
function withNextSteps(
  report: HardenProjectReport,
  options: HardenProjectOptions,
  absDir: string,
): HardenProjectReport {
  const steps: string[] = [];
  const failed = report.artifacts.filter((a) => !a.success && a.error !== undefined);
  if (report.apply?.status === "refused" || report.apply?.status === "failed") {
    steps.push(`apply did not promote anything: ${report.apply.reason ?? "see apply.reason"}`);
  }
  if (report.agentWeaveGateBlocked === true) {
    steps.push(
      `Stage 2 is pending: edit [${(report.agentWeaveAssessment?.unwovenSourceFiles ?? []).join(", ")}] as agentWeaveAssessment.surgicalWorkorders and agentActions describe, confirm with bla_verify_weave, rebuild, then call bla_harden again.`,
    );
  } else if (report.discoveredCount === 0) {
    const already = report.skippedHardenedOutputs ?? [];
    steps.push(
      already.length > 0
        ? `Nothing new to harden under ${absDir}: the protectable file(s) found (${already.slice(0, 3).join(", ")}${already.length > 3 ? ", …" : ""}) are already BLA output from an earlier run, and hardened output is never hardened twice. Rebuild the project to produce fresh output, then run again.`
        : `Nothing protectable was found under ${absDir}. Build the project first, or point directory at the build output.`,
    );
  } else if (report.dryRun) {
    steps.push(
      report.apply?.status === "planned"
        ? `Preview only. Calling again without dry_run (and with confirm_overwrite: true over MCP) hardens and then overwrites ${report.apply.applied?.length ?? 0} build-output file(s); the originals are backed up outside the project.`
        : `Preview only — nothing was written. Call again without dry_run to harden ${report.discoveredCount} artifact(s).`,
    );
  } else if (failed.length > 0 || report.sidecarEntangleError !== undefined) {
    steps.push(
      `${failed.length} artifact(s) were not hardened — read artifacts[].error. Packaging refusals name the fix; bla_lint { "directory": "." } lists every gate with a remediation recipe.`,
    );
    if (report.hardenedCount > 0) {
      steps.push(
        "Do not ship a partially hardened build: fix the failures and re-run so every artifact is protected together.",
      );
    }
    steps.push(
      'A file the shield cannot process at all (a parse error, syntax it does not support) can be left out on purpose: repeat with it in "exclude". It then ships unprotected and is listed under excluded — never exclude a file just to get past a packaging refusal.',
    );
  } else if (report.apply?.status === "applied") {
    steps.push(
      `The build output now holds the hardened files (${(report.apply.applied ?? []).slice(0, 4).join(", ")}${(report.apply.applied?.length ?? 0) > 4 ? ", …" : ""}). Run the project's own tests or a smoke run against it before shipping — BLA checks structure, not your behaviour. If something breaks or a hot path is too slow: restore, then harden again at a lower intensity or with that one file in "exclude", and say so.`,
    );
    steps.push(
      "Every rebuild regenerates unprotected output: harden with apply again after each build (for example from the postbuild script).",
    );
    steps.push(
      'To undo: bla_harden { "directory": ".", "restore": true } (CLI: bla harden . --restore) puts the original build output back.',
    );
  } else if (report.overallSuccess) {
    const allInBuildOutput = report.artifacts.every((a) =>
      isInsideBuildOutput(a.relativePath.split(sep).join("/"), absDir, BLA_BUILD_OUTPUT_DIR_NAMES),
    );
    steps.push(
      `Not shipped yet: ${report.outputDirectory} is a partial mirror holding only the ${report.hardenedCount} hardened file(s). The build output is unchanged and still unprotected, and the mirror cannot run on its own (untouched assets are not copied into it).`,
    );
    steps.push(
      allInBuildOutput
        ? 'Promote it: call bla_harden again with "apply": true and "confirm_overwrite": true (CLI: bla harden . --apply). That overwrites the build output in place, keeps the originals outside the project, and is undone by "restore": true.'
        : "Some hardened files are source files, so apply will not overwrite them. Copy the project to a staging directory and overlay the mirror on top before packaging; never replace your source with hardened output.",
    );
    steps.push(
      allInBuildOutput
        ? "Then run the project's own tests or a smoke run against the promoted build before shipping — BLA checks structure, not your behaviour. If something breaks or a hot path is too slow: restore, then harden again at a lower intensity or with that one file in exclude, and say so."
        : "Then run the project's own tests or a smoke run against that staged copy before shipping — BLA checks structure, not your behaviour. If something breaks or a hot path is too slow: harden again at a lower intensity or with that one file in exclude, and say so.",
    );
  }
  const renamedWasm = report.artifacts.filter(
    (a) => a.success && a.wasmExportRenames !== undefined && a.wasmExportRenames.length > 0,
  );
  if (renamedWasm.length > 0) {
    const total = renamedWasm.reduce((n, a) => n + (a.wasmExportRenames?.length ?? 0), 0);
    steps.push(
      `${total} WASM export(s) were renamed in ${renamedWasm.map((a) => a.relativePath).join(", ")} — the old → new map is in artifacts[].wasmExportRenames. No file in this project calls them by the old name; a host outside it that does must be updated from the map, or keep the names with wasm_preserve_exports.`,
    );
  }
  const withSurvivors = report.artifacts.filter(
    (a) => a.success && a.plaintextSurvivors !== undefined,
  );
  if (withSurvivors.length > 0) {
    const total = withSurvivors.reduce((n, a) => n + (a.plaintextSurvivors?.count ?? 0), 0);
    const encodes = report.intensity === "maximum" || report.intensity === "bankrupt";
    steps.push(
      `${total} sensitive-looking literal(s) (digests, keys, tokens) are still readable in the hardened output of ${withSurvivors
        .slice(0, 3)
        .map((a) => a.relativePath)
        .join(", ")}${withSurvivors.length > 3 ? ", …" : ""} — artifacts[].plaintextSurvivors lists them with source lines. ` +
        (encodes
          ? "The shield splits string and template text of 3 to 256 characters, and a secret-looking value of up to 4,096 characters wherever it is written (string, template, object key, regular expression). It cannot reach HTML attributes, tagged templates, class member names, the keys and `as const` values of a TypeScript source, or anything longer: move the value into a plain string literal (or off the client) and rebuild."
          : `Intensity ${report.intensity} does not encode string literals: harden at maximum or bankrupt, or mask them first with bla_encrypt_strings.`),
    );
  }
  if (report.integrityBindingSkipped !== undefined && report.integrityBindingSkipped.length > 0) {
    const skipped = report.integrityBindingSkipped;
    steps.push(
      `The integrity binding (self_seal / sidecar_entangle) does not cover ${skipped.length} artifact(s) — ${skipped.slice(0, 3).map((b) => b.relativePath).join(", ")}${skipped.length > 3 ? ", …" : ""}; integrityBindingSkipped gives the reason for each. They are still hardened, but tampering with them is not detected at load time (for a web build use server-side checks and Subresource Integrity).`,
    );
  }
  if (report.outputSize !== undefined) {
    const { inputBytes, outputBytes, largestGrowth } = report.outputSize;
    const growth = outputBytes - inputBytes;
    // Worth a line only when it changes what the user ships: a megabyte or more.
    if (growth >= 1024 * 1024) {
      steps.push(
        `The hardened files are ${formatByteSize(growth)} larger than the originals (${formatByteSize(inputBytes)} → ${formatByteSize(outputBytes)}${
          largestGrowth !== undefined
            ? `; ${largestGrowth.relativePath} alone grew by ${formatByteSize(largestGrowth.growthBytes)}`
            : ""
        }). The decoys are the protection, so this is expected at ${report.intensity} — but if download or install size matters, harden at a lower intensity${
          report.intensity === "bankrupt" ? " (maximum keeps string encoding and export renaming at a fraction of the size)" : ""
        }, or leave the largest files out with "exclude".`,
      );
    }
  }
  if (report.excluded !== undefined && report.excluded.length > 0) {
    const excluded = report.excluded;
    steps.push(
      `${excluded.length} file(s) matched the exclude list and were left exactly as they are — unprotected (${excluded.slice(0, 4).join(", ")}${excluded.length > 4 ? ", …" : ""}). Tell the user; drop the pattern from exclude to protect a file again.`,
    );
  }
  if (report.integrityBindingEntry !== undefined) {
    const uncovered = report.integrityBindingUncoveredEntries ?? [];
    const one = uncovered.length === 1;
    steps.push(
      `${report.integrityBindingEntry} carries the cross-file integrity check (it pins its hardened siblings): the check runs whenever that module is loaded, and only then.` +
        (uncovered.length > 0
          ? ` ${uncovered.slice(0, 3).join(", ")}${uncovered.length > 3 ? ", …" : ""} ${one ? "is" : "are"} also declared in package.json but never load${one ? "s" : ""} it, so a replaced or removed sibling goes unnoticed when the program starts there — load ${report.integrityBindingEntry} from ${one ? "it" : "them"} and harden again.`
          : ""),
    );
  }
  if (report.selfSeal === true && report.hardenedCount > 0 && report.dryRun !== true) {
    steps.push(
      "self_seal pins exact file bytes: finish bundling, transpiling, or minifying (esbuild, terser, webpack, vite) BEFORE hardening, and do not edit, reformat, or append comments to the hardened files afterwards — any post-harden byte change triggers an integrity failure at runtime.",
    );
  }
  const sqliteHardened = report.artifacts.filter((a) => a.success && a.format === "sqlite");
  if (sqliteHardened.length > 0 && report.dryRun !== true) {
    const one = sqliteHardened.length === 1;
    steps.push(
      `${sqliteHardened
        .slice(0, 3)
        .map((a) => a.relativePath)
        .join(", ")}${sqliteHardened.length > 3 ? ", …" : ""} now ${one ? "holds" : "hold"} decoy tables beside the application's own tables, which are stored exactly as before: anyone who opens the file reads them. BLA does not encrypt a database — keep secrets out of a shipped database, or encrypt it (SQLCipher, application-layer encryption). The score for ${one ? "it" : "them"} is capped for that reason.`,
    );
  }
  if (report.sqliteEvalTrapArtifacts !== undefined && report.sqliteEvalTrapArtifacts.length > 0) {
    const dbs = report.sqliteEvalTrapArtifacts;
    steps.push(
      `${dbs.slice(0, 3).join(", ")}${dbs.length > 3 ? ", …" : ""} ${dbs.length === 1 ? "carries" : "carry"} evaluation-trap columns (sqlite_eval_trap). The application's own tables read as before, but on any connection that does not register enclave_unseal_payload() the honey tables cannot be read and PRAGMA integrity_check, PRAGMA quick_check, VACUUM and a dump/restore fail. Ship ${dbs.length === 1 ? "it" : "them"} only if the application never runs those on ${dbs.length === 1 ? "this database" : "these databases"} — or have the application register a deterministic one-argument SQL function named enclave_unseal_payload on its own connection; otherwise harden again without the option.`,
    );
  }
  if (report.pythonSidecarEntry !== undefined) {
    const uncovered = report.pythonSidecarUncoveredEntries ?? [];
    const one = uncovered.length === 1;
    steps.push(
      `${report.pythonSidecarEntry} now verifies the hardened files in its directory tree every time it is imported, and only then. Ship them exactly as hardened — loose files or a zipapp — and a changed or missing one stops it with "integrity binding mismatch". A bytecode-only tree (.pyc without .py) and PyInstaller / Nuitka / cx_Freeze bundles contain no sibling sources, so there the check lets the program start without verifying anything: the binding adds nothing to those targets.` +
        (uncovered.length > 0
          ? ` ${uncovered.slice(0, 3).join(", ")}${uncovered.length > 3 ? ", …" : ""} ${one ? "is" : "are"} declared as ${one ? "a console script" : "console scripts"} but never import${one ? "s" : ""} ${report.pythonSidecarEntry}, so started that way nothing is verified — import it from ${one ? "that module" : "those modules"} and harden again.`
          : ""),
    );
  }
  const pyHardened = report.artifacts.filter(
    (a) => a.success && a.format === "python-source",
  );
  if (pyHardened.length > 0 && report.dryRun !== true) {
    const stalePycacheDirs: string[] = [];
    const seenPyDirs = new Set<string>();
    for (const a of pyHardened) {
      const pyDir = dirname(a.inputPath);
      if (seenPyDirs.has(pyDir)) continue;
      seenPyDirs.add(pyDir);
      const cacheDir = join(pyDir, "__pycache__");
      try {
        if (
          existsSync(cacheDir) &&
          statSync(cacheDir).isDirectory() &&
          readdirSync(cacheDir).some((n) => /\.(?:pyc|pyo)$/i.test(n))
        ) {
          stalePycacheDirs.push(
            (relative(absDir, cacheDir) || "__pycache__").split(sep).join("/"),
          );
        }
      } catch {
        /* ignore */
      }
    }
    if (stalePycacheDirs.length > 0) {
      steps.push(
        `Unhardened Python bytecode remains in ${stalePycacheDirs.slice(0, 3).join(", ")}${stalePycacheDirs.length > 3 ? ", …" : ""} (__pycache__ is skipped during discovery). Delete those __pycache__ directories before packaging so unhardened .pyc files do not ship beside your hardened .py sources.`,
      );
    }
  }
  if (
    report.discoveredCount > 0 &&
    report.skippedHardenedOutputs !== undefined &&
    report.skippedHardenedOutputs.length > 0
  ) {
    const already = report.skippedHardenedOutputs;
    steps.push(
      `${already.length} file(s) were left alone because they are already BLA output from an earlier run (${already.slice(0, 3).join(", ")}${already.length > 3 ? ", …" : ""}); hardened output is never hardened twice. Do not edit or lint them — work on the files they were built from.`,
    );
  }
  if (report.notPromoted !== undefined && report.notPromoted.length > 0) {
    steps.push(
      `${report.notPromoted.length} protectable file(s) outside the build output were left alone (${report.notPromoted.slice(0, 3).join(", ")}). If they ship, harden them without apply and package the hardened copies.`,
    );
  }
  if (
    report.overallSuccess &&
    report.selfSealRecommended &&
    options.selfSeal !== true
  ) {
    steps.push(
      'Several artifacts ship together: add "self_seal": true (and "sidecar_entangle": true) so the entry module refuses to run when a sibling file is swapped or stripped.',
    );
  }
  if (
    report.dryRun !== true &&
    report.hardenedCount > 0 &&
    isUntrackedInGitWorkTree(report.outputDirectory)
  ) {
    const mirror = relative(absDir, report.outputDirectory).split(sep).join("/");
    steps.push(
      `${mirror.length > 0 && !mirror.startsWith("..") ? mirror : report.outputDirectory} is generated output and git does not ignore it: add it to .gitignore so hardened copies are not committed by accident.`,
    );
  }
  return steps.length > 0 ? { ...report, nextSteps: steps } : report;
}

/** The project config that applies to a harden target (its directory, or the project above a build dir). */
function loadProjectConfigFor(absDir: string): BlaProjectConfig | undefined {
  if (!existsSync(absDir)) return undefined;
  const configDir = statSync(absDir).isDirectory() ? absDir : dirname(absDir);
  const directLoaded = loadBlaConfig(configDir);
  if (directLoaded.sourcePath !== null) return directLoaded.config;
  if ((BLA_BUILD_OUTPUT_DIR_NAMES as readonly string[]).includes(basename(configDir))) {
    const parentLoaded = loadBlaConfig(dirname(configDir));
    if (parentLoaded.sourcePath !== null) return parentLoaded.config;
  }
  return undefined;
}

/** `exclude` from the project config and from this call, de-duplicated. */
function mergedExcludeList(
  rawOptions: HardenProjectOptions,
  projectCfg: BlaProjectConfig | undefined,
): string[] {
  return [...new Set([...(projectCfg?.exclude ?? []), ...(rawOptions.exclude ?? [])])];
}

function hardenProjectCore(
  rawOptions: HardenProjectOptions,
  internal: { readonly buildOutputOnly?: boolean },
): HardenProjectReport {
  const absDir = resolve(rawOptions.directory ?? process.cwd());
  const projectCfg = loadProjectConfigFor(absDir);
  const mergedExclude = mergedExcludeList(rawOptions, projectCfg);
  const resolvedSeed: string | number =
    rawOptions.seed !== undefined && String(rawOptions.seed).length > 0
      ? rawOptions.seed
      : projectCfg?.seed && projectCfg.seed.length > 0
        ? projectCfg.seed
        : generateProjectSeed();
  const mergedWasmPreserveExports = [
    ...new Set([
      ...(projectCfg?.wasmPreserveExports ?? []),
      ...(rawOptions.wasmPreserveExports ?? []),
    ]),
  ];
  const options: HardenProjectOptions = {
    ...rawOptions,
    seed: resolvedSeed,
    intensity: rawOptions.intensity ?? projectCfg?.intensity ?? "bankrupt",
    emitManifest: rawOptions.emitManifest ?? projectCfg?.emitManifest ?? false,
    ...(rawOptions.llmDirectives !== undefined || projectCfg?.llmDirectives !== undefined
      ? { llmDirectives: rawOptions.llmDirectives ?? projectCfg?.llmDirectives }
      : {}),
    ...(rawOptions.weaveDecoys !== undefined || projectCfg?.weaveDecoys !== undefined
      ? { weaveDecoys: rawOptions.weaveDecoys ?? projectCfg?.weaveDecoys }
      : {}),
    ...(rawOptions.selfSeal !== undefined || projectCfg?.selfSeal !== undefined
      ? { selfSeal: rawOptions.selfSeal ?? projectCfg?.selfSeal }
      : {}),
    ...(rawOptions.sidecarEntangle !== undefined || projectCfg?.sidecarEntangle !== undefined
      ? { sidecarEntangle: rawOptions.sidecarEntangle ?? projectCfg?.sidecarEntangle }
      : {}),
    ...(rawOptions.requireAgentWeave !== undefined || projectCfg?.requireAgentWeave !== undefined
      ? { requireAgentWeave: rawOptions.requireAgentWeave ?? projectCfg?.requireAgentWeave }
      : {}),
    ...((rawOptions.sqliteEvalTrap ?? projectCfg?.sqliteEvalTrap) === true
      ? { sqliteEvalTrap: true }
      : {}),
    ...(mergedExclude.length > 0 ? { exclude: mergedExclude } : {}),
    ...(mergedWasmPreserveExports.length > 0
      ? { wasmPreserveExports: mergedWasmPreserveExports }
      : {}),
    allowLaneIndependentGates:
      rawOptions.allowLaneIndependentGates ?? projectCfg?.allowLaneIndependentGates ?? false,
    allowPlaintextSeal:
      rawOptions.allowPlaintextSeal ?? projectCfg?.allowPlaintextSeal ?? false,
    allowWasmClearParamCarriers:
      rawOptions.allowWasmClearParamCarriers ?? projectCfg?.allowWasmClearParamCarriers ?? false,
    allowStablePanelDeriveAbi:
      rawOptions.allowStablePanelDeriveAbi ?? projectCfg?.allowStablePanelDeriveAbi ?? false,
    allowJsAesUnwrap:
      rawOptions.allowJsAesUnwrap ?? projectCfg?.allowJsAesUnwrap ?? false,
    allowJsWasmHydrateDump:
      rawOptions.allowJsWasmHydrateDump ?? projectCfg?.allowJsWasmHydrateDump ?? false,
    allowWasmXorMaskSidecar:
      rawOptions.allowWasmXorMaskSidecar ?? projectCfg?.allowWasmXorMaskSidecar ?? false,
    allowWasmSealXorKnownPlaintext:
      rawOptions.allowWasmSealXorKnownPlaintext ?? projectCfg?.allowWasmSealXorKnownPlaintext ?? false,
    allowPanelOfflineOracle:
      rawOptions.allowPanelOfflineOracle ?? projectCfg?.allowPanelOfflineOracle ?? false,
    allowReleaseHygieneLeak:
      rawOptions.allowReleaseHygieneLeak ?? projectCfg?.allowReleaseHygieneLeak ?? false,
  };
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";
  // Manifests are opt-in: do not ship `.bla-manifest.json` next to customer artifacts by default.
  const emitManifest = options.emitManifest === true;
  if (options.signManifest === true && emitManifest !== true) {
    throw new Error("signManifest requires emitManifest in hardenProject");
  }
  const maxArtifacts = options.maxArtifacts ?? MAX_DISCOVERED_ARTIFACTS;

  const outputRoot = resolve(
    options.outputDirectory ??
      (existsSync(absDir) && statSync(absDir).isDirectory()
        ? join(absDir, ".bla-hardened")
        : join(dirname(absDir), ".bla-hardened")),
  );

  if (options.outputDirectory) {
    if (existsSync(absDir)) {
      const physSrc = physicalPath(absDir);
      const physOut = physicalPath(outputRoot);
      if (physSrc === physOut) {
        throw new Error(
          "Output directory must not be the input directory; in-place project hardening is not supported.",
        );
      }
    }
    const relFromProject = relative(absDir, outputRoot);
    const checkSegments =
      !isAbsolute(relFromProject) && !relFromProject.startsWith("..")
        ? relFromProject.split(/[\\/]+/).filter(Boolean)
        : [basename(outputRoot)];
    for (const seg of checkSegments) {
      if (seg === ".git" || seg === "node_modules" || seg === ".hg" || seg === ".svn") {
        throw new Error(`Refusing to use protected directory as output: ${outputRoot}`);
      }
    }
  }

  const dryRun = options.dryRun === true;
  const discovery = discoverHardenTargets(absDir, {
    maxArtifacts,
    outputDirectory: outputRoot,
    ...(internal.buildOutputOnly === true ? { buildOutputOnly: true } : {}),
    ...(options.applyStateRoot !== undefined ? { stateRoot: options.applyStateRoot } : {}),
    ...(options.exclude !== undefined ? { exclude: options.exclude } : {}),
  });
  const discovered = discovery.artifacts;
  const runtimeEntries = resolveRuntimeEntries(absDir);

  const packagingBlocks = evaluateHardenProjectPackagingBlocks({
    directory: absDir,
    intensity,
    allowPlaintextSeal: options.allowPlaintextSeal,
    allowWasmClearParamCarriers: options.allowWasmClearParamCarriers,
    allowJsAesUnwrap: options.allowJsAesUnwrap,
    allowJsWasmHydrateDump: options.allowJsWasmHydrateDump,
    allowWasmXorMaskSidecar: options.allowWasmXorMaskSidecar,
    allowWasmSealXorKnownPlaintext: options.allowWasmSealXorKnownPlaintext,
    allowReleaseHygieneLeak: options.allowReleaseHygieneLeak,
  });
  const blockingSeals = packagingBlocks.blockingSeals;
  const blockingWasmParms = packagingBlocks.blockingWasmParms;
  const blockingJsAes = packagingBlocks.blockingJsAes;
  const blockingJsHydrateDump = packagingBlocks.blockingJsHydrateDump;
  const blockingWasmXorMask = packagingBlocks.blockingWasmXorMask;
  const blockingWasmSealXor = packagingBlocks.blockingWasmSealXor;
  const blockingReleaseHygiene = packagingBlocks.blockingReleaseHygiene;
  // Pre-flight lane-independence check across discovered JS/TS targets so a
  // refused gate blocks the whole harden run atomically instead of writing
  // sibling HTML/assets into `.bla-hardened` and omitting the refused script.
  const blockingLanes: Array<{
    readonly path: string;
    readonly format: ArtifactFormat;
    readonly report: LaneIndependenceReport;
  }> = [];
  if (options.allowLaneIndependentGates !== true) {
    for (const artifact of discovered) {
      if (!formatSupportsLaneIndependenceLint(artifact.format)) continue;
      try {
        const laneReport = lintLaneIndependence(readFileSync(artifact.path, "utf8"));
        if (laneReport.looksLaneIndependent) {
          blockingLanes.push({
            path: artifact.path,
            format: artifact.format,
            report: laneReport,
          });
        }
      } catch {
        /* unreadable artifacts surface in the per-artifact pass */
      }
    }
  }
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
  // The integrity bindings are Node programs; a front-end bundle cannot host
  // them (see browser-bundle.ts). Absolute input path → why it is one.
  const jsDiscovered = discovered.filter(
    (a) => a.format === "javascript" || a.format === "typescript",
  );
  const browserBundles = classifyBrowserBundles(jsDiscovered, absDir);
  const hasNodeJsHost = jsDiscovered.some((a) => !browserBundles.has(a.path));
  const integrityBindingRequested =
    options.selfSeal === true || options.sidecarEntangle === true;
  const integrityBindingSkipped: { relativePath: string; reason: string }[] = [];
  if (integrityBindingRequested) {
    for (const a of jsDiscovered) {
      if (!browserBundles.has(a.path)) continue;
      integrityBindingSkipped.push({
        relativePath: a.relativePath.split(sep).join("/"),
        reason: `browser bundle (${browserBundles.get(a.path)!}): the binding needs node:fs / node:crypto`,
      });
    }
    // (A tree of databases only has no code that could pin one.)
    const hasCodeHost = discovered.some((a) => !MUTABLE_DATA_FORMATS.has(a.format));
    for (const a of hasCodeHost ? discovered : []) {
      if (!MUTABLE_DATA_FORMATS.has(a.format)) continue;
      integrityBindingSkipped.push({
        relativePath: a.relativePath.split(sep).join("/"),
        reason:
          "mutable data: the application writes to this database, so a pinned hash would fail the integrity check after the first write",
      });
    }
  }
  const selfSealRecommended =
    intensity === "bankrupt" &&
    bindable.length >= 2 &&
    // Recommending a Node-only binding for a pure front-end build is bad advice.
    (jsDiscovered.length === 0 || hasNodeJsHost) &&
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

  const weaveFormats = new Set([
    "javascript",
    "typescript",
    "html-bundle",
    "python-source",
    "native-elf",
    "native-macho",
    "native-pe",
  ]);
  const weaveableDiscovered = discovered.filter((a) => weaveFormats.has(a.format));
  let agentWeaveAssessment: AgentWeaveAssessment | undefined;
  if (weaveableDiscovered.length > 0 || options.requireAgentWeave === true) {
    try {
      const weaveVerify = verifyWeaveTarget(absDir, { maxTargets: maxArtifacts });
      // Detect stale build outputs when Host Agent edited `src/` but forgot to rebuild `dist/`/`build/`/`out/`.
      let staleBuildMessage: string | undefined;
      if (options.requireAgentWeave === true) {
        const buildRelRe = /^(?:dist|build|out)(?:[\\/]|$)/i;
        const buildArtifacts = discovered.filter((a) => buildRelRe.test(a.relativePath));
        const srcRoot = join(absDir, "src");
        if (buildArtifacts.length > 0 && existsSync(srcRoot)) {
          let newestBuildMtime = 0;
          for (const ba of buildArtifacts) {
            try {
              const m = statSync(ba.path).mtimeMs;
              if (m > newestBuildMtime) newestBuildMtime = m;
            } catch {
              /* ignore */
            }
          }
          let newestSrcMtime = 0;
          let newestSrcRel = "";
          const srcStack = [srcRoot];
          while (srcStack.length > 0) {
            const cur = srcStack.pop()!;
            let ents;
            try {
              ents = readdirSync(cur, { withFileTypes: true });
            } catch {
              continue;
            }
            for (const ent of ents) {
              if (ent.name.startsWith(".")) continue;
              const full = join(cur, ent.name);
              if (ent.isDirectory()) {
                srcStack.push(full);
              } else if (ent.isFile() && /\.(?:[cm]?[jt]sx?|py|rs|go|c|cpp|cc)$/i.test(ent.name)) {
                try {
                  const m = statSync(full).mtimeMs;
                  if (m > newestSrcMtime) {
                    newestSrcMtime = m;
                    newestSrcRel = relative(absDir, full);
                  }
                } catch {
                  /* ignore */
                }
              }
            }
          }
          if (newestBuildMtime > 0 && newestSrcMtime > newestBuildMtime + 50) {
            staleBuildMessage = `Source file '${newestSrcRel}' is newer than build output in dist/build/out — rebuild your project (e.g. npm run build) after Stage-2 source surgery before running bla_harden.`;
          }
        }
      }

      if (weaveVerify.files.length > 0 || staleBuildMessage !== undefined) {
        // Only the files that decide the verdict are "unwoven"; a formatter or
        // a view component with no gate logic is advisory and never blocks.
        const unwovenSourceFiles = weaveVerify.files
          .filter((f) => !f.passed && f.scope !== "advisory")
          .map((f) => f.relativePath);
        // The workorders are the bulk of the payload. They are the agent's next
        // step only when this run was refused for a missing weave; any other
        // caller gets them from bla_weave_plan on demand.
        const workorderMap: Record<string, WeaveSurgicalWorkorder> = {};
        if (options.requireAgentWeave === true && unwovenSourceFiles.length > 0) {
          const unwovenSet = new Set(unwovenSourceFiles);
          const weavePlan = buildWeavePlan(absDir, { maxTargets: maxArtifacts });
          for (const target of weavePlan.targets) {
            if (target.surgicalWorkorder && unwovenSet.has(target.relativePath)) {
              workorderMap[target.relativePath] = target.surgicalWorkorder;
            }
          }
        }
        if (staleBuildMessage !== undefined && unwovenSourceFiles.length === 0) {
          unwovenSourceFiles.push("dist/ (stale build)");
        }
        const extraActions =
          staleBuildMessage !== undefined
            ? [
                {
                  priority: "high" as const,
                  file: "dist/",
                  checkId: "crown-jewel-entanglement" as const,
                  instruction: staleBuildMessage,
                  verifyTool: "bla_verify_weave" as const,
                },
              ]
            : [];
        // The per-check actions are the agent's work list only while the weave
        // gate is in force; an ungated run points at bla_verify_weave instead of
        // carrying a to-do list for an optional upgrade in every report.
        const combinedActions =
          options.requireAgentWeave === true
            ? [...extraActions, ...weaveVerify.agentActions]
            : [];
        const unwovenAreBuildOutput =
          unwovenSourceFiles.length > 0 &&
          unwovenSourceFiles.every((rel) =>
            isInsideBuildOutput(rel.split(sep).join("/"), absDir, BLA_BUILD_OUTPUT_DIR_NAMES),
          );
        const weaveVerified =
          weaveVerify.files.length > 0 &&
          weaveVerify.overallPassed &&
          staleBuildMessage === undefined;
        agentWeaveAssessment = {
          weaveVerified,
          weaveScore: staleBuildMessage !== undefined ? Math.min(weaveVerify.weaveScore, 50) : weaveVerify.weaveScore,
          weaveScope: weaveVerify.scope,
          unwovenSourceFiles,
          ...(weaveVerify.advisoryFiles.length > 0
            ? { advisorySourceFiles: weaveVerify.advisoryFiles }
            : {}),
          agentActions: combinedActions,
          surgicalWorkorders: workorderMap,
          agentPlaybookDirective: weaveVerified
            ? `All ${weaveVerify.requiredFiles.length} ${weaveVerify.scope === "crown-jewels" ? "crown-jewel " : ""}source file(s) passed Host-Agent structural weave verification (weaveScore=${weaveVerify.weaveScore}/100).`
            : staleBuildMessage ??
              (options.requireAgentWeave === true
                ? `Host-Agent source surgery pending on [${unwovenSourceFiles.join(", ")}] (weaveScore=${weaveVerify.weaveScore}/100). Follow surgicalWorkorders + agentActions using your file-editing tools, verify with bla_verify_weave, rebuild, then run bla_harden with weave_decoys:true and require_agent_weave:true.`
                : unwovenAreBuildOutput
                  ? `Optional Stage-2 upgrade: [${unwovenSourceFiles.join(", ")}] hold gate/entitlement logic that is not woven (weaveScore=${weaveVerify.weaveScore}/100). This run hardened mechanically. They are build output — never edit them; for patch-resistant gates weave the source modules they are built from (bla_weave_plan / bla_verify_weave on the source directory), rebuild, then re-run bla_harden.`
                  : `Optional Stage-2 upgrade: [${unwovenSourceFiles.join(", ")}] hold gate/entitlement logic that is not woven yet (weaveScore=${weaveVerify.weaveScore}/100). This run hardened mechanically. For patch-resistant gates, call bla_weave_plan for the surgicalWorkorders, edit the source, confirm with bla_verify_weave (it lists the exact actions), rebuild, then re-run bla_harden with weave_decoys:true and require_agent_weave:true.`),
        };
      } else if (options.requireAgentWeave === true) {
        agentWeaveAssessment = {
          weaveVerified: false,
          weaveScore: 0,
          unwovenSourceFiles: ["(no verifiable source files found)"],
          agentActions: [
            {
              priority: "high",
              file: ".",
              checkId: "customer-entry-edges",
              instruction:
                "require_agent_weave is enabled, but no verifiable JS/TS/HTML/Python/C/Rust/Go source files were found in the target directory. Point bla_verify_weave at your source directory before running bla_harden.",
              verifyTool: "bla_verify_weave",
            },
          ],
          surgicalWorkorders: {},
          agentPlaybookDirective:
            "require_agent_weave refused: no verifiable source files were found in the target directory.",
        };
      }
    } catch (err) {
      if (options.requireAgentWeave === true) {
        const msg = err instanceof Error ? err.message : String(err);
        agentWeaveAssessment = {
          weaveVerified: false,
          weaveScore: 0,
          unwovenSourceFiles: ["(weave verification error)"],
          agentActions: [
            {
              priority: "high",
              file: ".",
              checkId: "crown-jewel-entanglement",
              instruction: `verifyWeaveTarget failed (${msg}); fix source syntax/access issues and re-run bla_verify_weave before bla_harden.`,
              verifyTool: "bla_verify_weave",
            },
          ],
          surgicalWorkorders: {},
          agentPlaybookDirective: `require_agent_weave refused because weave verification threw an error: ${msg}`,
        };
      }
    }
  }

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
    ...(agentWeaveAssessment !== undefined
      ? { agentWeaveAssessment }
      : {}),
    dryRun,
    truncated: discovery.truncated,
    maxArtifacts: discovery.maxArtifacts,
    ...(integrityBindingSkipped.length > 0
      ? { integrityBindingSkipped: integrityBindingSkipped.slice() }
      : {}),
    ...(discovery.readErrors.length > 0
      ? { discoveryReadErrors: discovery.readErrors }
      : {}),
    ...(discovery.skippedDevTooling !== undefined
      ? { skippedDevTooling: discovery.skippedDevTooling }
      : {}),
    ...(discovery.skippedSourceFiles !== undefined
      ? { skippedSourceFiles: discovery.skippedSourceFiles }
      : {}),
    ...(discovery.skippedHardenedOutputs !== undefined
      ? { skippedHardenedOutputs: discovery.skippedHardenedOutputs }
      : {}),
    ...(discovery.excluded !== undefined ? { excluded: discovery.excluded } : {}),
    wouldOverwrite,
    runId,
  } as const;

  if (
    options.requireAgentWeave === true &&
    agentWeaveAssessment !== undefined &&
    !agentWeaveAssessment.weaveVerified
  ) {
    const unwovenSet = new Set(agentWeaveAssessment.unwovenSourceFiles);
    const actionsByFile = new Map<string, string[]>();
    for (const act of agentWeaveAssessment.agentActions) {
      const list = actionsByFile.get(act.file) ?? [];
      list.push(`[${act.checkId}] ${act.instruction}`);
      actionsByFile.set(act.file, list);
    }
    const planned = plannedOutputs.map(({ artifact, outputPath, outputExisted }) => {
      const rel = artifact.relativePath;
      const isUnwoven =
        unwovenSet.has(rel) || unwovenSet.has(basename(artifact.path));
      const fileActions =
        actionsByFile.get(rel) ?? actionsByFile.get(basename(artifact.path)) ?? [];
      return {
        inputPath: artifact.path,
        relativePath: rel,
        format: artifact.format,
        outputPath,
        success: false,
        defenseScore: 0,
        tokenAmplificationFactor: 0,
        costAmplificationFactor: 0,
        outputExisted,
        error: isUnwoven
          ? `refused by require_agent_weave (weaveScore=${agentWeaveAssessment.weaveScore}/100): Host Agent must perform Stage 2 source surgery on ${rel} first (${fileActions.join("; ") || "run bla_weave_plan and bla_verify_weave"})`
          : `skipped: run blocked by require_agent_weave on [${agentWeaveAssessment.unwovenSourceFiles.join(", ")}]`,
      };
    });
    return {
      ...reportBase,
      overallSuccess: false,
      agentWeaveGateBlocked: true,
      hardenedCount: 0,
      failedCount: planned.length,
      artifacts: planned,
    };
  }

  if (
    blockingLanes.length > 0 ||
    blockingSeals.length > 0 ||
    blockingWasmParms.length > 0 ||
    blockingJsAes.length > 0 ||
    blockingJsHydrateDump.length > 0 ||
    blockingWasmXorMask.length > 0 ||
    blockingWasmSealXor.length > 0 ||
    blockingReleaseHygiene.length > 0
  ) {
    const laneArtifacts = blockingLanes.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: r.format,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: laneIndependenceRefuseMessage(r.report, r.path),
    }));
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
    const releaseHygieneArtifacts = blockingReleaseHygiene.map((r) => ({
      inputPath: r.path,
      relativePath: (relative(absDir, r.path) || basename(r.path)).split(sep).join("/"),
      format: "unknown" as const,
      outputPath: r.path,
      success: false,
      defenseScore: 0,
      tokenAmplificationFactor: 0,
      costAmplificationFactor: 0,
      outputExisted: false,
      error: releaseHygieneRefuseMessage(r, r.path),
    }));
    const blockParts: string[] = [];
    if (blockingLanes.length > 0) blockParts.push("lane-independent JS gate");
    if (blockingSeals.length > 0) blockParts.push("plaintext/reversible seal sidecar");
    if (blockingWasmParms.length > 0) blockParts.push("clear WASM param carrier");
    if (blockingJsAes.length > 0) blockParts.push("JS AES wrap-key unwrap");
    if (blockingJsHydrateDump.length > 0) blockParts.push("JS WASM hydrate param-dump");
    if (blockingWasmXorMask.length > 0) blockParts.push("WASM XOR-mask sidecar");
    if (blockingWasmSealXor.length > 0) blockParts.push("WASM seal.revision XOR known-plaintext");
    if (blockingReleaseHygiene.length > 0) blockParts.push("leaked release environment artifact");
    const blockedExtras = [
      ...laneArtifacts,
      ...sealArtifacts,
      ...wasmArtifacts,
      ...jsAesArtifacts,
      ...jsHydrateDumpArtifacts,
      ...wasmXorMaskArtifacts,
      ...wasmSealXorArtifacts,
      ...releaseHygieneArtifacts,
    ];
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
    // A blocker that is itself a planned artifact already carries its refusal
    // above; listing it a second time made failedCount exceed discoveredCount.
    // Only blockers outside the plan (a seal.json, a leaked .env) are extra rows.
    const plannedPaths = new Set(planned.map((p) => resolve(p.inputPath)));
    const seenExtras = new Set<string>();
    const extraBlockers = blockedExtras.filter((artifact) => {
      const key = resolve(artifact.inputPath);
      if (plannedPaths.has(key) || seenExtras.has(key)) return false;
      seenExtras.add(key);
      return true;
    });
    return {
      ...reportBase,
      overallSuccess: false,
      hardenedCount: 0,
      failedCount: planned.length + extraBlockers.length,
      artifacts: [...planned, ...extraBlockers],
    };
  }

  if (dryRun) {
    // Preview only: never claim overallSuccess — nothing was hardened.
    return {
      ...reportBase,
      overallSuccess: false,
      hardenedCount: 0,
      failedCount: 0,
      artifacts: withArtifactSizes(
        plannedOutputs.map(({ artifact, outputPath, outputExisted }) => ({
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
        true,
      ),
    };
  }

  if (discovered.length > 0) {
    mkdirSync(outputRoot, { recursive: true });
  }

  const summaries: HardenArtifactSummary[] = [];
  const written: string[] = [];
  const total = plannedOutputs.length;
  // SHA-256 of each output as its own protect step left it; later post-passes
  // (sidecar entanglement) may rewrite the file.
  const outputShaAfterProtect = new Map<string, string>();
  let consumerIndex: WasmConsumerIndex | undefined;
  const referencedWasmExports = (
    wasmPath: string,
  ): { name: string; referencedBy: string }[] => {
    let exportNames: readonly string[];
    try {
      exportNames = inspectWasmBinary(readFileSync(wasmPath)).exportNames;
    } catch {
      return [];
    }
    if (exportNames.length === 0) return [];
    consumerIndex ??= buildWasmConsumerIndex(absDir, outputRoot);
    const found: { name: string; referencedBy: string }[] = [];
    for (const name of exportNames) {
      // `_start`, `memory`, … are never renamed whoever refers to them, so
      // they are not a keep-decision to report (or to advise renaming).
      if (isAbiMandatedWasmExport(name)) continue;
      const referencedBy = consumerIndex.findReference(name);
      if (referencedBy !== undefined) found.push({ name, referencedBy });
    }
    return found;
  };
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
  const jsPlanned = plannedOutputs.filter(
    ({ artifact }) =>
      /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(artifact.relativePath.replaceAll("\\", "/")) &&
      // A browser bundle cannot host the Node integrity binding.
      !browserBundles.has(artifact.path),
  );
  const designatedEntryOutput = pickJsEntry(
    jsPlanned.map((p) => ({
      relativePath: p.artifact.relativePath,
      inputPath: p.artifact.path,
      outputPath: p.outputPath,
    })),
    runtimeEntries,
  )?.outputPath;

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
    // A renamed export breaks every caller that still uses the old name, and
    // BLA cannot rewrite those callers. So names another project file refers
    // to are kept (on top of the explicit keep-list); only exports nothing in
    // the project mentions are renamed.
    const autoPreserved =
      artifact.format === "wasm" ? referencedWasmExports(artifact.path) : [];
    const artifactPreserveExports = [
      ...new Set([
        ...(options.wasmPreserveExports ?? []),
        ...autoPreserved.map((p) => p.name),
      ]),
    ];
    const explicitPreserve = new Set(options.wasmPreserveExports ?? []);
    const reportedAutoPreserved = autoPreserved.filter((p) => !explicitPreserve.has(p.name));
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
          ? { selfSeal: options.selfSeal && !browserBundles.has(artifact.path) }
          : {}),
        ...(options.sqliteEvalTrap === true && artifact.format === "sqlite"
          ? { sqliteEvalTrap: true }
          : {}),
        ...(artifactPreserveExports.length > 0
          ? { wasmPreserveExports: artifactPreserveExports }
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
          if (options.selfSeal !== true || browserBundles.has(artifact.path)) return {};
          if (designatedEntryOutput !== undefined && outputPath !== designatedEntryOutput) {
            return {};
          }
          // Include all non-mutable siblings in the mirror tree (same-dir first,
          // then upward-relative siblings like `../lib/core.cjs`) so multi-directory
          // builds like `dist/bin/cli.cjs` + `dist/lib/core.cjs` do not silently drop
          // cross-directory siblings when at least one same-dir sibling exists.
          const sameDir = plannedOutputs
            .filter(
              (p) =>
                p.outputPath !== outputPath &&
                isProtectableFormat(p.artifact.format) &&
                !MUTABLE_DATA_FORMATS.has(p.artifact.format),
            )
            .map((p) => relative(dirname(outputPath), p.outputPath).split(sep).join("/"))
            .filter((rel) => rel.length > 0 && !rel.startsWith(".."));
          const crossDir = plannedOutputs
            .filter(
              (p) =>
                p.outputPath !== outputPath &&
                isProtectableFormat(p.artifact.format) &&
                !MUTABLE_DATA_FORMATS.has(p.artifact.format),
            )
            .map((p) => relative(dirname(outputPath), p.outputPath).split(sep).join("/"))
            .filter((rel) => rel.length > 0 && rel.startsWith(".."));
          const list = [...sameDir, ...crossDir];
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
        ...(report.protection.wasmExportRenames !== undefined &&
        report.protection.wasmExportRenames.length > 0
          ? { wasmExportRenames: report.protection.wasmExportRenames }
          : {}),
        ...(reportedAutoPreserved.length > 0
          ? { wasmExportsAutoPreserved: reportedAutoPreserved }
          : {}),
        ...(() => {
          const survivors = report.overallSuccess
            ? findPlaintextSurvivors(artifact, report.outputPath)
            : undefined;
          return survivors !== undefined ? { plaintextSurvivors: survivors } : {};
        })(),
      });
      if (report.overallSuccess && existsSync(report.outputPath)) {
        written.push(report.outputPath);
        outputShaAfterProtect.set(report.outputPath, sha256File(report.outputPath));
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
      writeFileAtomicSync(
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
  // else Python, else WASM-only) with a strip⇒fail preamble / custom-section
  // note measured against FINAL sibling bytes (after all protects wrote).
  // Per-artifact protect skips inject when harden did not pass explicit
  // sidecarEntanglePaths (avoids partial/double prepend). Only one entry is
  // rewritten so sibling digests stay stable — except when a same-directory
  // Node CJS/ESM WASM loader is auto-wired: the WASM custom section is planted
  // first (excluding the JS entry, which is still rewritten later) and the
  // loader hook is prepended before the JS preamble, so both digests stay
  // consistent.
  // Outputs whose bytes the JS entry's sidecar binding really measures.
  const sidecarBoundOutputs = new Set<string>();
  // Python entry that received a load-time sibling check, if any, and the
  // declared console scripts that start the program without importing it.
  let pythonSidecarEntry: string | undefined;
  let pythonSidecarUncoveredEntries: readonly string[] = [];
  // JS module that hosts the load-time checks, and declared entries that skip it.
  let integrityBindingEntry: string | undefined;
  let integrityBindingUncoveredEntries: readonly string[] = [];
  let sidecarEntangleError: string | undefined;
  if (options.sidecarEntangle === true && !dryRun && summaries.some((s) => s.success)) {
    try {
      // Mutable data (a database the app writes to) is never part of a binding.
      const bindableSummaries = summaries.filter((s) => !MUTABLE_DATA_FORMATS.has(s.format));
      const jsLike = bindableSummaries.filter(
        (s) =>
          s.success &&
          !browserBundles.has(s.inputPath) &&
          /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const jsEntry = pickJsEntry(jsLike, runtimeEntries);
      const pyLike = bindableSummaries.filter(
        (s) =>
          s.success && /\.py$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const pyDeclaredEntries = !jsEntry ? resolvePythonDeclaredEntryFiles(absDir, pyLike) : [];
      const pyEntry = !jsEntry ? pickPythonEntry(pyLike, pyDeclaredEntries) : undefined;
      const wasmLike = bindableSummaries.filter(
        (s) =>
          s.success && /\.wasm$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const jsEntryAbs = jsEntry
        ? join(outputRoot, jsEntry.relativePath)
        : undefined;
      const pyEntryAbs = pyEntry
        ? join(outputRoot, pyEntry.relativePath)
        : undefined;

      let wasmSidecarLoaderHookApplied = false;
      let wasmSectionPlanted = false;
      const hookedLoaderAbs = new Set<string>();
      const wasmPlantTargets: typeof wasmLike = [];
      for (const wasmSum of wasmLike) {
        const wasmAbs = join(outputRoot, wasmSum.relativePath);
        if (!existsSync(wasmAbs)) continue;
        const wasmDir = dirname(wasmAbs);
        const siblingSidecars: { pathLabel: string; bytes: Buffer }[] = [];
        for (const s of bindableSummaries) {
          if (!s.success || s.relativePath === wasmSum.relativePath) continue;
          const abs = join(outputRoot, s.relativePath);
          if (jsEntryAbs && abs === jsEntryAbs) continue;
          if (pyEntryAbs && abs === pyEntryAbs) continue;
          const rel = relative(wasmDir, abs).split(sep).join("/");
          if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
          siblingSidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
        }
        // Predicate against the pre-protect input (shielded output is often
        // bloated / already self-sealed). Rewrite the output file.
        const loaderCandidates: {
          name: string;
          source: string;
          absPath: string;
        }[] = [];
        for (const s of jsLike) {
          const outAbs = join(outputRoot, s.relativePath);
          if (dirname(outAbs) !== wasmDir) continue;
          if (!isNodeWasmJsLoaderFilename(s.relativePath)) continue;
          let predicateSource: string | null = null;
          try {
            if (s.inputPath && existsSync(s.inputPath)) {
              predicateSource = readFileSync(s.inputPath, "utf8");
            }
          } catch {
            predicateSource = null;
          }
          if (predicateSource === null && existsSync(outAbs)) {
            try {
              predicateSource = readFileSync(outAbs, "utf8");
            } catch {
              predicateSource = null;
            }
          }
          if (predicateSource === null) continue;
          loaderCandidates.push({
            name: basename(outAbs),
            source: predicateSource,
            absPath: outAbs,
          });
        }
        const selectedName = selectNodeWasmJsLoader(
          basename(wasmAbs),
          loaderCandidates,
        );
        const found = selectedName
          ? loaderCandidates.find((c) => c.name === selectedName)
          : undefined;
        if (found) {
          const carrier = detectWasmJsLoaderCarrier(found.name, found.source);
          if (!carrier) {
            if (!jsEntry && !pyEntry) wasmPlantTargets.push(wasmSum);
            continue;
          }
          const otherPrimary =
            (jsEntryAbs !== undefined && found.absPath !== jsEntryAbs) ||
            (pyEntryAbs !== undefined && found.absPath !== pyEntryAbs);
          const alreadyNoted = inspectWasmBinary(readFileSync(wasmAbs)).customSectionNames.includes(
            WASM_SIDECAR_SECTION_NAME,
          );
          // A foreign JS/Python entry may already bake a digest of this
          // module. Hooking without a section would fail-closed at
          // instantiate; planting a new section would break that digest.
          if (otherPrimary && !alreadyNoted) {
            continue;
          }
          wasmPlantTargets.push(wasmSum);
          const wasmBytesForHook = readFileSync(wasmAbs);
          const identity = computeWasmSidecarCodeIdentity(wasmBytesForHook);
          const wasmExportsForHook = inspectWasmBinary(wasmBytesForHook).exportNames.filter(
            (name) => !name.startsWith("enclave_export_") && name !== "memory" && name !== "_start",
          );
          const existing = readFileSync(found.absPath, "utf8");
          const already = existing.includes(WASM_SIDECAR_LOADER_MARKER);
          const inject = already
            ? null
            : generateSidecarWasmLoaderSnippet({
                codeIdentityHex: identity,
                carrier,
                ...(wasmExportsForHook.length > 0
                  ? { protectedExportNames: wasmExportsForHook }
                  : {}),
              });
          const next = inject
            ? prependWasmSidecarLoaderHook(existing, inject.preamble)
            : existing;
          if (next !== existing) {
            writeFileAtomicSync(found.absPath, next, "utf8", {
              allowLinkWriteThrough: false,
            });
          }
          hookedLoaderAbs.add(found.absPath);
          wasmSidecarLoaderHookApplied = true;
        } else if (!jsEntry && !pyEntry) {
          wasmPlantTargets.push(wasmSum);
        }
      }
      // When a hook was auto-wired, plant the custom section now (before
      // the JS preamble rewrites jsEntry). Without a hook, keep the
      // historical one-primary-entry rule: only plant when no JS/Python
      // entry will be bound, and only the preferred core.wasm / first file.
      // Do not rewrite WASM bytes when some other JS/Python entry (e.g.
      // license.cjs) may already have baked a digest of the module — that
      // would fail-closed the protected program (red line). Plant a new
      // custom section only for wasm-only projects or when the only JS/Python
      // entry being bound is the dedicated auto-wired loader itself.
      const foreignJsOrPy =
        (jsEntryAbs !== undefined && !hookedLoaderAbs.has(jsEntryAbs)) ||
        (pyEntryAbs !== undefined && !hookedLoaderAbs.has(pyEntryAbs));
      const wasmToPlant = wasmSidecarLoaderHookApplied && !foreignJsOrPy
        ? wasmPlantTargets
        : !jsEntry && !pyEntry
          ? (wasmLike.find((s) => /core\.wasm$/i.test(s.relativePath)) ??
              wasmLike[0]
            ? [wasmLike.find((s) => /core\.wasm$/i.test(s.relativePath)) ?? wasmLike[0]!]
            : [])
          : [];
      for (const wasmSum of wasmToPlant) {
        const entryAbs = join(outputRoot, wasmSum.relativePath);
        if (!existsSync(entryAbs)) continue;
        const entryDir = dirname(entryAbs);
        const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
        for (const s of bindableSummaries) {
          if (!s.success || s.relativePath === wasmSum.relativePath) continue;
          const abs = join(outputRoot, s.relativePath);
          if (jsEntryAbs && abs === jsEntryAbs) continue;
          if (pyEntryAbs && abs === pyEntryAbs) continue;
          const rel = relative(entryDir, abs).split(sep).join("/");
          if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
          sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
        }
        if (sidecars.length === 0 && !wasmSidecarLoaderHookApplied) continue;
        const bound = entangleWasmEntryWithSidecars({
          entryPath: basename(entryAbs),
          entryBytes: readFileSync(entryAbs),
          sidecars,
          seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
          allowEmptySidecars: wasmSidecarLoaderHookApplied,
        });
        if (bound) {
          writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
            allowLinkWriteThrough: false,
          });
          wasmSectionPlanted = true;
        }
      }


      const pycPlantedAbs = new Set<string>();
      const pycLikeEarly = bindableSummaries.filter(
        (s) =>
          s.success && /\.pyc$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      for (const pycSum of pycLikeEarly) {
        const pycAbs = join(outputRoot, pycSum.relativePath);
        if (!existsSync(pycAbs)) continue;
        const pycDir = dirname(pycAbs);
        const searchDirs = [pycDir];
        if (basename(pycDir).toLowerCase() === "__pycache__") {
          searchDirs.push(dirname(pycDir));
        }
        const loaderCandidates: {
          name: string;
          source: string;
          absPath: string;
        }[] = [];
        for (const s of pyLike) {
          const outAbs = join(outputRoot, s.relativePath);
          if (!searchDirs.includes(dirname(outAbs))) continue;
          if (!isPythonPycLoaderFilename(s.relativePath)) continue;
          let predicateSource: string | null = null;
          try {
            if (s.inputPath && existsSync(s.inputPath)) {
              predicateSource = readFileSync(s.inputPath, "utf8");
            }
          } catch {
            predicateSource = null;
          }
          if (predicateSource === null && existsSync(outAbs)) {
            try {
              predicateSource = readFileSync(outAbs, "utf8");
            } catch {
              predicateSource = null;
            }
          }
          if (predicateSource === null) continue;
          loaderCandidates.push({
            name: basename(outAbs),
            source: predicateSource,
            absPath: outAbs,
          });
        }
        const selectedName = selectPythonPycLoader(
          basename(pycAbs),
          loaderCandidates,
        );
        const found = selectedName
          ? loaderCandidates.find((c) => c.name === selectedName)
          : undefined;
        if (!found) continue;
        const alreadyNoted =
          extractPycSidecarMarshalNote(readFileSync(pycAbs)) !== null;
        const otherPrimary =
          (jsEntryAbs !== undefined && found.absPath !== jsEntryAbs) ||
          (pyEntryAbs !== undefined && found.absPath !== pyEntryAbs);
        // A foreign JS/Python entry may already bake a digest of this
        // module. Hooking without a note would fail-closed at import;
        // planting a new trailer would break that digest.
        if (otherPrimary && !alreadyNoted) continue;

        if (!otherPrimary) {
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === pycSum.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            if (jsEntryAbs && abs === jsEntryAbs) continue;
            if (pyEntryAbs && abs === pyEntryAbs) continue;
            const rel = relative(pycDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          const bound = entanglePycEntryWithSidecars({
            entryPath: basename(pycAbs),
            entryBytes: readFileSync(pycAbs),
            sidecars,
            seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            allowEmptySidecars: true,
          });
          if (bound) {
            writeFileAtomicSync(pycAbs, bound.bytes, undefined, {
              allowLinkWriteThrough: false,
            });
            pycPlantedAbs.add(pycAbs);
          }
        }

        const identity = computePycSidecarCodeIdentity(readFileSync(pycAbs));
        const existing = readFileSync(found.absPath, "utf8");
        const already = existing.includes(PYC_SIDECAR_LOADER_MARKER);
        const pycRel = relativePycPathFromLoader(found.absPath, pycAbs);
        const inject = already
          ? null
          : generateSidecarPycLoaderSnippet({
              codeIdentityHex: identity,
              pycRelPaths: [pycRel],
            });
        const next = inject
          ? prependPycSidecarLoaderHook(existing, inject.preamble)
          : existing;
        if (next !== existing) {
          writeFileAtomicSync(found.absPath, next, "utf8", {
            allowLinkWriteThrough: false,
          });
        }
        // Hook presence is observed later by isPycSidecarLoaderHookWired /
        // protectTarget honesty; the loader rewrite above is the act.
      }

      const ggufPlantedAbs = new Set<string>();
      const ggufLikeEarly = bindableSummaries.filter(
        (s) =>
          s.success &&
          (s.format === "model-gguf" ||
            /\.gguf$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      for (const ggufSum of ggufLikeEarly) {
        const ggufAbs = join(outputRoot, ggufSum.relativePath);
        if (!existsSync(ggufAbs)) continue;
        const ggufDir = dirname(ggufAbs);
        const searchDirs = [ggufDir];
        const loaderCandidates: {
          name: string;
          source: string;
          absPath: string;
        }[] = [];
        for (const s of pyLike) {
          const outAbs = join(outputRoot, s.relativePath);
          if (!searchDirs.includes(dirname(outAbs))) continue;
          if (!isPythonPycLoaderFilename(s.relativePath)) continue;
          let predicateSource: string | null = null;
          try {
            if (s.inputPath && existsSync(s.inputPath)) {
              predicateSource = readFileSync(s.inputPath, "utf8");
            }
          } catch {
            predicateSource = null;
          }
          if (predicateSource === null && existsSync(outAbs)) {
            try {
              predicateSource = readFileSync(outAbs, "utf8");
            } catch {
              predicateSource = null;
            }
          }
          if (predicateSource === null) continue;
          loaderCandidates.push({
            name: basename(outAbs),
            source: predicateSource,
            absPath: outAbs,
          });
        }
        const selectedName = selectPythonGgufLoader(
          basename(ggufAbs),
          loaderCandidates,
        );
        const found = selectedName
          ? loaderCandidates.find((c) => c.name === selectedName)
          : undefined;
        if (!found) continue;
        const alreadyNoted =
          extractGgufSidecarMetadataNote(readFileSync(ggufAbs)) !== null;
        const otherPrimary =
          (jsEntryAbs !== undefined && found.absPath !== jsEntryAbs) ||
          (pyEntryAbs !== undefined && found.absPath !== pyEntryAbs);
        // A foreign JS/Python entry may already bake a digest of this
        // model. Hooking without a note would fail-closed at import;
        // planting a new metadata KV would break that digest.
        if (otherPrimary && !alreadyNoted) continue;

        if (!otherPrimary) {
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === ggufSum.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            if (jsEntryAbs && abs === jsEntryAbs) continue;
            if (pyEntryAbs && abs === pyEntryAbs) continue;
            if (abs === found.absPath) continue;
            const rel = relative(ggufDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          const bound = entangleGgufEntryWithSidecars({
            entryPath: basename(ggufAbs),
            entryBytes: readFileSync(ggufAbs),
            sidecars,
            seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            allowEmptySidecars: true,
          });
          if (bound) {
            writeFileAtomicSync(ggufAbs, bound.bytes, undefined, {
              allowLinkWriteThrough: false,
            });
            ggufPlantedAbs.add(ggufAbs);
          }
        }

        const identity = computeGgufSidecarCodeIdentity(readFileSync(ggufAbs));
        const existing = readFileSync(found.absPath, "utf8");
        const already = existing.includes(GGUF_SIDECAR_LOADER_MARKER);
        const ggufRel = relativeGgufPathFromLoader(found.absPath, ggufAbs);
        const inject = already
          ? null
          : generateSidecarGgufLoaderSnippet({
              codeIdentityHex: identity,
              ggufRelPaths: [ggufRel],
            });
        const next = inject
          ? prependGgufSidecarLoaderHook(existing, inject.preamble)
          : existing;
        if (next !== existing) {
          writeFileAtomicSync(found.absPath, next, "utf8", {
            allowLinkWriteThrough: false,
          });
        }
      }

      const safetensorsPlantedAbs = new Set<string>();
      const safetensorsLikeEarly = bindableSummaries.filter(
        (s) =>
          s.success &&
          (s.format === "model-safetensors" ||
            /\.safetensors$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      for (const stSum of safetensorsLikeEarly) {
        const stAbs = join(outputRoot, stSum.relativePath);
        if (!existsSync(stAbs)) continue;
        const stDir = dirname(stAbs);
        const searchDirs = [stDir];
        const loaderCandidates: {
          name: string;
          source: string;
          absPath: string;
        }[] = [];
        for (const s of pyLike) {
          const outAbs = join(outputRoot, s.relativePath);
          if (!searchDirs.includes(dirname(outAbs))) continue;
          if (!isPythonPycLoaderFilename(s.relativePath)) continue;
          let predicateSource: string | null = null;
          try {
            if (s.inputPath && existsSync(s.inputPath)) {
              predicateSource = readFileSync(s.inputPath, "utf8");
            }
          } catch {
            predicateSource = null;
          }
          if (predicateSource === null && existsSync(outAbs)) {
            try {
              predicateSource = readFileSync(outAbs, "utf8");
            } catch {
              predicateSource = null;
            }
          }
          if (predicateSource === null) continue;
          loaderCandidates.push({
            name: basename(outAbs),
            source: predicateSource,
            absPath: outAbs,
          });
        }
        const selectedName = selectPythonSafetensorsLoader(
          basename(stAbs),
          loaderCandidates,
        );
        const found = selectedName
          ? loaderCandidates.find((c) => c.name === selectedName)
          : undefined;
        if (!found) continue;
        const alreadyNoted =
          extractSafetensorsSidecarMetadataNote(readFileSync(stAbs)) !== null;
        const otherPrimary =
          (jsEntryAbs !== undefined && found.absPath !== jsEntryAbs) ||
          (pyEntryAbs !== undefined && found.absPath !== pyEntryAbs);
        // A foreign JS/Python entry may already bake a digest of this
        // model. Hooking without a note would fail-closed at import;
        // planting a new __metadata__ key would break that digest.
        if (otherPrimary && !alreadyNoted) continue;

        if (!otherPrimary) {
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === stSum.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            if (jsEntryAbs && abs === jsEntryAbs) continue;
            if (pyEntryAbs && abs === pyEntryAbs) continue;
            if (abs === found.absPath) continue;
            const rel = relative(stDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          const bound = entangleSafetensorsEntryWithSidecars({
            entryPath: basename(stAbs),
            entryBytes: readFileSync(stAbs),
            sidecars,
            seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            allowEmptySidecars: true,
          });
          if (bound) {
            writeFileAtomicSync(stAbs, bound.bytes, undefined, {
              allowLinkWriteThrough: false,
            });
            safetensorsPlantedAbs.add(stAbs);
          }
        }

        const identity = computeSafetensorsSidecarCodeIdentity(readFileSync(stAbs));
        const existing = readFileSync(found.absPath, "utf8");
        const already = existing.includes(SAFETENSORS_SIDECAR_LOADER_MARKER);
        const stRel = relativeSafetensorsPathFromLoader(found.absPath, stAbs);
        const inject = already
          ? null
          : generateSidecarSafetensorsLoaderSnippet({
              codeIdentityHex: identity,
              safetensorsRelPaths: [stRel],
            });
        const next = inject
          ? prependSafetensorsSidecarLoaderHook(existing, inject.preamble)
          : existing;
        if (next !== existing) {
          writeFileAtomicSync(found.absPath, next, "utf8", {
            allowLinkWriteThrough: false,
          });
        }
      }

      if (jsEntry) {
        const entryAbs = join(outputRoot, jsEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          const sidecarAbsPaths: string[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === jsEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
            sidecarAbsPaths.push(abs);
          }
          if (sidecars.length > 0) {
            const entrySource = readFileSync(entryAbs, "utf8");
            const bound = entangleJsEntryWithSidecars({
              entryPath: basename(entryAbs),
              entrySource,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
              carrier: refineJsCarrierForRuntimePaths(
                detectJsCarrierForSource(entrySource, entryAbs),
                [entryAbs, jsEntry.inputPath],
              ),
            });
            if (bound) {
              const finalized = finalizeSelfSealSelfDigest(bound.code);
              writeFileAtomicSync(entryAbs, finalized.content, "utf8", {
                allowLinkWriteThrough: false,
              });
              for (const abs of sidecarAbsPaths) sidecarBoundOutputs.add(abs);
              integrityBindingEntry = jsEntry.relativePath.split(sep).join("/");
              integrityBindingUncoveredEntries = entriesNotLoadingHost(
                jsEntry,
                jsLike,
                runtimeEntries,
              );
            }
          }
        }
      }

      // Python entry entanglement only when no JS entry was bound — rewriting
      // a Python sibling after the JS digest sealed would invalidate strip⇒fail.
      if (pyEntry) {
        const entryAbs = join(outputRoot, pyEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          const outsideEntryTree: string[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === pyEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || !existsSync(abs)) continue;
            if (rel.startsWith("..")) {
              outsideEntryTree.push(s.relativePath.split(sep).join("/"));
              continue;
            }
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entrySource = readFileSync(entryAbs, "utf8");
            const bound = entanglePythonEntryWithSidecars({
              entryPath: basename(entryAbs),
              entrySource,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.code, "utf8", {
                allowLinkWriteThrough: false,
              });
              pythonSidecarEntry = pyEntry.relativePath.split(sep).join("/");
              pythonSidecarUncoveredEntries = pythonEntriesNotLoadingHost(
                pyEntry,
                pyDeclaredEntries,
              );
              // The check reads files relative to its own module: whatever
              // lives above or beside that directory is pinned by nothing.
              for (const rel of outsideEntryTree) {
                if (integrityBindingSkipped.some((b) => b.relativePath === rel)) continue;
                integrityBindingSkipped.push({
                  relativePath: rel,
                  reason: `not bound: ${pythonSidecarEntry} only checks files in its own directory tree`,
                });
              }
            }
          }
        }
      }

      // WASM entry entanglement only when no JS/Python entry was bound —
      // custom-section note measured against FINAL sibling bytes. Skipped
      // when the auto-wire path already planted the section above.
      const wasmEntry =
        wasmSectionPlanted
          ? undefined
          : !jsEntry && !pyEntry
            ? wasmLike.find((s) => /core\.wasm$/i.test(s.relativePath)) ?? wasmLike[0]
            : undefined;
      if (wasmEntry) {
        const entryAbs = join(outputRoot, wasmEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === wasmEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entryBytes = readFileSync(entryAbs);
            const bound = entangleWasmEntryWithSidecars({
              entryPath: basename(entryAbs),
              entryBytes,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
                allowLinkWriteThrough: false,
              });
            }
          }
        }
      }

      // CPython .pyc marshal-note entanglement only when no JS/Python/WASM
      // entry was bound — TYPE_ASCII trailer measured against FINAL siblings;
      // importlib ignores the trailer (executed code object unchanged).
      const pycLike = bindableSummaries.filter(
        (s) =>
          s.success && /\.pyc$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const pycEntry =
        !jsEntry && !pyEntry && !wasmEntry
          ? pycLike.find((s) => /__main__\.pyc$/i.test(s.relativePath)) ??
            pycLike[0]
          : undefined;
      if (pycEntry) {
        const entryAbs = join(outputRoot, pycEntry.relativePath);
        if (existsSync(entryAbs) && !pycPlantedAbs.has(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === pycEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entryBytes = readFileSync(entryAbs);
            const bound = entanglePycEntryWithSidecars({
              entryPath: basename(entryAbs),
              entryBytes,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
                allowLinkWriteThrough: false,
              });
            }
          }
        }
      }

      // GGUF STRING-metadata entanglement only when no JS/Python/WASM/.pyc
      // entry was bound — bla.sidecar.v1 KV measured against FINAL siblings;
      // GGUF loaders ignore unknown STRING keys (tensor bytes stay bit-exact).
      const ggufLike = bindableSummaries.filter(
        (s) =>
          s.success &&
          (s.format === "model-gguf" ||
            /\.gguf$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      const ggufEntry =
        !jsEntry && !pyEntry && !wasmEntry && !pycEntry
          ? ggufLike[0]
          : undefined;
      if (ggufEntry) {
        const entryAbs = join(outputRoot, ggufEntry.relativePath);
        if (existsSync(entryAbs) && !ggufPlantedAbs.has(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === ggufEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entryBytes = readFileSync(entryAbs);
            const bound = entangleGgufEntryWithSidecars({
              entryPath: basename(entryAbs),
              entryBytes,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
                allowLinkWriteThrough: false,
              });
            }
          }
        }
      }

      // Safetensors __metadata__ entanglement only when no JS/Python/WASM/.pyc/GGUF
      // entry was bound — bla.sidecar.v1 __metadata__ key measured against FINAL
      // siblings; tensor bytes stay bit-exact.
      const safetensorsLike = bindableSummaries.filter(
        (s) =>
          s.success &&
          (s.format === "model-safetensors" ||
            /\.safetensors$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      const safetensorsEntry =
        !jsEntry && !pyEntry && !wasmEntry && !pycEntry && !ggufEntry
          ? safetensorsLike[0]
          : undefined;
      if (safetensorsEntry) {
        const entryAbs = join(outputRoot, safetensorsEntry.relativePath);
        if (existsSync(entryAbs) && !safetensorsPlantedAbs.has(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === safetensorsEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entryBytes = readFileSync(entryAbs);
            const bound = entangleSafetensorsEntryWithSidecars({
              entryPath: basename(entryAbs),
              entryBytes,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
                allowLinkWriteThrough: false,
              });
            }
          }
        }
      }


      // DEX string-pool entanglement only when no JS/Python/WASM/.pyc/GGUF/
      // Safetensors entry was bound — bla.sidecar.v1 sort-last pool string
      // measured against FINAL siblings; existing string indices + insn bytes
      // stay unchanged.
      const dexLike = bindableSummaries.filter(
        (s) =>
          s.success &&
          (s.format === "android-dex" ||
            /\.dex$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      const dexEntry =
        !jsEntry && !pyEntry && !wasmEntry && !pycEntry && !ggufEntry && !safetensorsEntry
          ? dexLike[0]
          : undefined;
      if (dexEntry) {
        const entryAbs = join(outputRoot, dexEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === dexEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entryBytes = readFileSync(entryAbs);
            const bound = entangleDexEntryWithSidecars({
              entryPath: basename(entryAbs),
              entryBytes,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
                allowLinkWriteThrough: false,
              });
            }
          }
        }
      }

      // SQLite schema-comment entanglement only when no JS/Python/WASM/.pyc/GGUF/
      // Safetensors/DEX entry was bound — reserved unused bla_sidecar_v1 VIEW
      // measured against FINAL siblings; user tables, rows, query results,
      // WAL/FK, and application_id/user_version stay unchanged.
      // (This note is offline evidence carried BY a database, not a load-time
      // check of one, so it works on the full list, databases included.)
      const sqliteLike = summaries.filter(
        (s) =>
          s.success &&
          (s.format === "sqlite" ||
            /\.(sqlite|sqlite3)$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      const sqliteEntry =
        !jsEntry &&
        !pyEntry &&
        !wasmEntry &&
        !pycEntry &&
        !ggufEntry &&
        !safetensorsEntry &&
        !dexEntry
          ? sqliteLike[0]
          : undefined;
      if (sqliteEntry) {
        const entryAbs = join(outputRoot, sqliteEntry.relativePath);
        if (existsSync(entryAbs)) {
          const entryDir = dirname(entryAbs);
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [];
          for (const s of summaries) {
            if (!s.success || s.relativePath === sqliteEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          if (sidecars.length > 0) {
            const entryBytes = readFileSync(entryAbs);
            const bound = entangleSqliteEntryWithSidecars({
              entryPath: basename(entryAbs),
              entryBytes,
              sidecars,
              seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
            });
            if (bound) {
              writeFileAtomicSync(entryAbs, bound.bytes, undefined, {
                allowLinkWriteThrough: false,
              });
            }
          }
        }
      }

      // Bun / EOF-preserved native companion note only when no JS/Python/WASM
      // entry was bound — binary stays byte-exact; `.bla-sidecar.v1.json`
      // binds the sibling `.bunfs-snapshot` planted by protect.
      // .pyc post-pass above runs first so Bun sidecar digests see final bytes.
      if (!jsEntry && !pyEntry && !wasmEntry) {
        const nativeLike = bindableSummaries.filter(
          (s) =>
            s.success &&
            (s.format === "native-elf" ||
              s.format === "native-macho" ||
              s.format === "native-pe"),
        );
        for (const nativeEntry of nativeLike) {
          const entryAbs = join(outputRoot, nativeEntry.relativePath);
          const snapshotAbs = `${entryAbs}.bunfs-snapshot`;
          if (!existsSync(entryAbs) || !existsSync(snapshotAbs)) continue;
          const entryLabel = basename(entryAbs);
          const snapshotLabel = `${entryLabel}.bunfs-snapshot`;
          const sidecars: { pathLabel: string; bytes: Buffer }[] = [
            { pathLabel: snapshotLabel, bytes: readFileSync(snapshotAbs) },
          ];
          const entryDir = dirname(entryAbs);
          for (const s of bindableSummaries) {
            if (!s.success || s.relativePath === nativeEntry.relativePath) continue;
            const abs = join(outputRoot, s.relativePath);
            const rel = relative(entryDir, abs).split(sep).join("/");
            if (rel.length === 0 || rel.startsWith("..") || !existsSync(abs)) continue;
            if (rel === snapshotLabel) continue;
            sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
          }
          const bound = entangleBunEntryWithSidecars({
            entryPath: entryLabel,
            entryBytes: readFileSync(entryAbs),
            sidecars,
            seedTag: derivePublicSidecarSeedTag(String(options.seed ?? runId)),
          });
          if (bound) {
            writeFileAtomicSync(
              `${entryAbs}${BUN_SIDECAR_COMPANION_SUFFIX}`,
              bound.noteBytes,
              "utf8",
              { allowLinkWriteThrough: false },
            );
          }
        }
      }

      // ASAR archive-note post-pass only when no JS/Python/WASM/Bun entry was
      // bound — plant `.bla/sidecar.v1.json` binding the decoy bridge member.
      const asarLike = bindableSummaries.filter(
        (s) =>
          s.success &&
          (s.format === "electron-asar" ||
            /\.asar$/i.test(s.relativePath.replaceAll("\\", "/"))),
      );
      if (!jsEntry && !pyEntry && !wasmEntry && asarLike.length > 0) {
        for (const asarEntry of asarLike) {
          const entryAbs = join(outputRoot, asarEntry.relativePath);
          if (!existsSync(entryAbs)) continue;
          const raw = readFileSync(entryAbs);
          let members;
          try {
            members = unpackAsarBuffer(raw);
          } catch {
            continue;
          }
          const bridge = members.find(
            (m) => m.relativePath === "enclave/hardware-tee-bridge.js",
          );
          if (!bridge) continue;
          const entryLabel = basename(entryAbs);
          const seedTag = derivePublicSidecarSeedTag(String(options.seed ?? runId));
          const hasNote = members.some(
            (m) => m.relativePath === ASAR_SIDECAR_ARCHIVE_NOTE_PATH,
          );
          let expectedHex: string | undefined;
          let working = members.map((m) => ({
            relativePath: m.relativePath,
            content: m.content,
            ...(m.executable ? { executable: true as const } : {}),
          }));
          if (!hasNote) {
            const bound = entangleAsarEntryWithSidecars({
              entryPath: entryLabel,
              entryBytes: raw,
              sidecars: [
                {
                  pathLabel: "enclave/hardware-tee-bridge.js",
                  bytes: bridge.content,
                },
              ],
              seedTag,
            });
            if (!bound) continue;
            expectedHex = bound.digest.hex;
            working = [
              ...working,
              {
                relativePath: ASAR_SIDECAR_ARCHIVE_NOTE_PATH,
                content: bound.noteBytes,
              },
            ];
          } else {
            const verified = verifyAsarSidecarArchiveNote({
              memberBytes: Object.fromEntries(
                working.map((m) => [m.relativePath, m.content]),
              ),
            });
            expectedHex = verified.expectedHex ?? verified.note?.digest;
          }
          if (!expectedHex) continue;
          const alreadyMain =
            working.some(
              (m) =>
                m.content.toString("utf8").includes(ASAR_SIDECAR_MAIN_JS_MARKER),
            );
          if (!alreadyMain) {
            const withMain = entangleAsarMainJsWithSidecars({
              members: working,
              entryPath: entryLabel,
              expectedHex,
              sidecarPaths: ["enclave/hardware-tee-bridge.js"],
              seedTag,
            });
            if (withMain) {
              working = withMain.members.map((m) => ({
                relativePath: m.relativePath,
                content: m.content,
                ...(m.executable ? { executable: true as const } : {}),
              }));
            }
          } else if (hasNote) {
            continue; // note + preamble already present
          }
          const repacked = packAsarBuffer(working);
          writeFileAtomicSync(entryAbs, repacked, undefined, {
            allowLinkWriteThrough: false,
          });
        }
      }
    } catch (err) {
      // Entanglement was explicitly requested, so a failure is not a harmless
      // no-op: the entry ships without the strip⇒fail binding. Record it so the
      // report can fail loudly instead of claiming success.
      sidecarEntangleError = err instanceof Error ? err.message : String(err);
    }
  }

  // Post-pass consistency. The sidecar pass above rewrites artifacts (WASM
  // custom section, loader hook, entry preamble) AFTER the self-seal entry
  // pinned its siblings' SHA-256 and AFTER each manifest recorded its
  // artifact's hash. Left alone, the untouched hardened tree fails its own
  // integrity check at startup and `verify-manifest --require-artifact`
  // rejects an artifact nobody modified. Re-pin and re-attest from final bytes.
  let postPassConsistencyError: string | undefined;
  if (!dryRun && summaries.some((s) => s.success)) {
    try {
      if (
        options.selfSeal === true &&
        designatedEntryOutput !== undefined &&
        existsSync(designatedEntryOutput)
      ) {
        let entryBytes: Buffer = readFileSync(designatedEntryOutput);
        let repinned = false;
        for (const s of summaries) {
          if (!s.success || s.outputPath === designatedEntryOutput) continue;
          const pinned = outputShaAfterProtect.get(s.outputPath);
          if (pinned === undefined || !existsSync(s.outputPath)) continue;
          const current = sha256File(s.outputPath);
          if (current === pinned) continue;
          const stale = Buffer.from(pinned, "latin1");
          const fresh = Buffer.from(current, "latin1");
          let at = entryBytes.indexOf(stale);
          if (at === -1) continue;
          let replacedHere = false;
          while (at !== -1) {
            // Only repin self-seal `expected = { "<rel>": "<sha256>" }` property
            // values (preceded by `:` + optional spaces + quote). Never clobber
            // WASM/PYC/GGUF loader hook code-identity arrays (`var __ids = ["<id>"]`),
            // which deliberately store the pre-custom-section code identity.
            let look = at - 1;
            const quote = look >= 0 ? entryBytes[look] : 0;
            if (quote === 0x22 || quote === 0x27) {
              look -= 1;
              while (look >= 0 && (entryBytes[look] === 0x20 || entryBytes[look] === 0x09)) {
                look -= 1;
              }
              if (look >= 0 && entryBytes[look] === 0x3a /* ':' */) {
                if (!replacedHere) entryBytes = Buffer.from(entryBytes);
                fresh.copy(entryBytes, at);
                replacedHere = true;
              }
            }
            at = entryBytes.indexOf(stale, at + stale.length);
          }
          if (replacedHere) repinned = true;
        }
        if (repinned) {
          const refinalized = finalizeSelfSealSelfDigest(entryBytes);
          writeFileAtomicSync(designatedEntryOutput, refinalized.content, undefined, {
            allowLinkWriteThrough: false,
          });
        }
      }
      if (emitManifest) {
        let signingKeyPem: string | undefined;
        for (const s of summaries) {
          if (!s.success || !existsSync(s.outputPath)) continue;
          const manifestPath = `${s.outputPath}.bla-manifest.json`;
          if (!existsSync(manifestPath)) continue;
          const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
          const current = sha256File(s.outputPath);
          if (manifest.protectedSha256 === current) continue;
          const { signature, ...unsigned } = manifest;
          const refreshed: Record<string, unknown> = { ...unsigned, protectedSha256: current };
          let toWrite = refreshed;
          if (signature !== undefined) {
            signingKeyPem ??= readManifestSigningKeyOrThrow(options.manifestSigningKeyPath ?? "");
            toWrite = signManifestPayload(refreshed, signingKeyPem);
          }
          writeFileAtomicSync(manifestPath, `${JSON.stringify(toWrite, null, 2)}\n`, "utf8");
        }
      }
    } catch (err) {
      postPassConsistencyError = err instanceof Error ? err.message : String(err);
    }
  }
  if (postPassConsistencyError !== undefined && sidecarEntangleError === undefined) {
    // Same contract as a failed entanglement: the tree is not self-consistent,
    // so the run must not report success.
    sidecarEntangleError = `post-pass integrity re-pin failed: ${postPassConsistencyError}`;
  }

  let integrityCoveragePath: string | undefined;
  let integrityCoverageSelfVerified: boolean | undefined;
  if (options.selfSeal === true && !dryRun && summaries.some((s) => s.success)) {
    try {
      const jsLike = summaries.filter(
        (s) =>
          s.success &&
          !browserBundles.has(s.inputPath) &&
          /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(s.relativePath.replaceAll("\\", "/")),
      );
      const entry = pickJsEntry(jsLike, runtimeEntries);
      if (entry) {
        const entryRel = entry.relativePath.replaceAll("\\", "/");
        const entryAbs = join(outputRoot, entryRel);
        const entryBytes = existsSync(entryAbs) ? readFileSync(entryAbs) : undefined;
        integrityCoverageSelfVerified =
          entryBytes !== undefined && verifySelfSealSelfDigest(entryBytes).verified;
        // The matrix is evidence, so it lists only what the hardened tree
        // enforces: the entry module is the one checker, and a file is covered
        // only when the entry pins its final SHA-256 (self-seal) or measures
        // its bytes (sidecar binding). Everything else is reported as unbound
        // instead of being drawn into a mesh nobody checks.
        const expectedSha256: Record<string, string> = {};
        if (entryBytes !== undefined) expectedSha256[entryRel] = sha256Hex(entryBytes);
        const coveredNodes: string[] = [];
        for (const s of summaries) {
          if (!s.success || s.relativePath === entry.relativePath) continue;
          const rel = s.relativePath.replaceAll("\\", "/");
          const abs = join(outputRoot, s.relativePath);
          if (!existsSync(abs)) continue;
          const digest = sha256File(abs);
          const pinned = entryBytes !== undefined && entryBytes.includes(digest);
          if (pinned || sidecarBoundOutputs.has(abs)) {
            coveredNodes.push(rel);
            expectedSha256[rel] = digest;
          } else if (!integrityBindingSkipped.some((b) => b.relativePath === rel)) {
            integrityBindingSkipped.push({
              relativePath: rel,
              reason: `not bound: ${entryRel} only checks files in its own directory tree that Node can read at load time`,
            });
          }
        }
        if (coveredNodes.length > 0 && integrityBindingEntry === undefined) {
          integrityBindingEntry = entryRel;
          integrityBindingUncoveredEntries = entriesNotLoadingHost(entry, jsLike, runtimeEntries);
        }
        const plannedMatrix = buildInterleavedCoverageMatrix({
          fileNodes: [entryRel, ...coveredNodes],
          checkerHosts: [entryRel],
          expectedSha256,
          colocatedSites: 2,
        });
        const matrix = integrityCoverageSelfVerified
          ? plannedMatrix
          : withoutHostSelfCoverage(plannedMatrix, entryRel);
        integrityCoveragePath = join(outputRoot, "integrity-coverage.json");
        writeFileAtomicSync(
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
  const sizedArtifacts = withArtifactSizes(summaries, dryRun);
  const outputSize = summarizeOutputSize(sizedArtifacts);
  const sqliteEvalTrapArtifacts =
    options.sqliteEvalTrap === true && !dryRun
      ? summaries.filter((s) => s.success && s.format === "sqlite").map((s) => s.relativePath)
      : [];
  return {
    ...reportBase,
    overallSuccess:
      !cancelled &&
      summaries.length > 0 &&
      failedCount === 0 &&
      sidecarEntangleError === undefined,
    hardenedCount,
    failedCount,
    artifacts: sizedArtifacts,
    ...(outputSize !== undefined ? { outputSize } : {}),
    ...(sqliteEvalTrapArtifacts.length > 0 ? { sqliteEvalTrapArtifacts } : {}),
    written: written.slice(),
    ...(cancelled ? { cancelled: true } : {}),
    ...(summaryPath !== undefined ? { summaryPath } : {}),
    ...(integrityCoveragePath !== undefined
      ? { integrityCoveragePath }
      : {}),
    ...(integrityCoverageSelfVerified !== undefined
      ? { integrityCoverageSelfVerified }
      : {}),
    ...(integrityBindingSkipped.length > 0 ? { integrityBindingSkipped } : {}),
    ...(pythonSidecarEntry !== undefined ? { pythonSidecarEntry } : {}),
    ...(pythonSidecarUncoveredEntries.length > 0
      ? { pythonSidecarUncoveredEntries: pythonSidecarUncoveredEntries.slice() }
      : {}),
    ...(integrityBindingEntry !== undefined ? { integrityBindingEntry } : {}),
    ...(integrityBindingUncoveredEntries.length > 0
      ? { integrityBindingUncoveredEntries: integrityBindingUncoveredEntries.slice() }
      : {}),
    ...(sidecarEntangleError !== undefined ? { sidecarEntangleError } : {}),
  };
}

function fileSizeOrUndefined(path: string): number | undefined {
  try {
    const stats = statSync(path);
    return stats.isFile() ? stats.size : undefined;
  } catch {
    return undefined;
  }
}

/** Attach on-disk sizes (after every post-pass) to each summary. */
function withArtifactSizes(
  summaries: readonly HardenArtifactSummary[],
  dryRun: boolean,
): HardenArtifactSummary[] {
  return summaries.map((summary) => {
    const inputBytes = fileSizeOrUndefined(summary.inputPath);
    const outputBytes =
      !dryRun && summary.success ? fileSizeOrUndefined(summary.outputPath) : undefined;
    return {
      ...summary,
      ...(inputBytes !== undefined ? { inputBytes } : {}),
      ...(outputBytes !== undefined ? { outputBytes } : {}),
    };
  });
}

function summarizeOutputSize(
  artifacts: readonly HardenArtifactSummary[],
): HardenProjectReport["outputSize"] {
  let inputBytes = 0;
  let outputBytes = 0;
  let largest: { relativePath: string; growthBytes: number } | undefined;
  let counted = 0;
  for (const artifact of artifacts) {
    if (artifact.inputBytes === undefined || artifact.outputBytes === undefined) continue;
    counted += 1;
    inputBytes += artifact.inputBytes;
    outputBytes += artifact.outputBytes;
    const growthBytes = artifact.outputBytes - artifact.inputBytes;
    if (largest === undefined || growthBytes > largest.growthBytes) {
      largest = { relativePath: artifact.relativePath.split(sep).join("/"), growthBytes };
    }
  }
  if (counted === 0) return undefined;
  return {
    inputBytes,
    outputBytes,
    ...(largest !== undefined && largest.growthBytes > 0 ? { largestGrowth: largest } : {}),
  };
}

/** `1536` → `1.5 KB`; binary units, one decimal below 10. */
export function formatByteSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 || value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export function formatHardenProjectReport(report: HardenProjectReport): string {
  // Artifact-derived strings (paths, errors, usage advice) pass through the
  // shared terminal sanitizer like every other formatter — a hostile name
  // must not carry OSC/CSI/C0 bytes into the operator's terminal.
  const safe = sanitizeTerminalText;
  const lines: string[] = [
    `BLA harden ${report.blaVersion} — ${safe(report.directory)}${report.dryRun ? " (dry-run: nothing written)" : ""}`,
    `Run: ${safe(report.runId)} (unsigned)`,
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
      lines.push(`    · written: ${safe(w)}`);
    }
  }
  if (report.selfSealRecommended) {
    lines.push(
      `  ⚠ self_seal recommended: ${report.selfSealRecommendation === undefined ? "multi-artifact tree — pass --self-seal / self_seal:true" : safe(report.selfSealRecommendation)}`,
    );
  }
  if (report.sidecarEntangleError !== undefined) {
    lines.push(
      `  ⚠ sidecar entanglement failed: ${safe(report.sidecarEntangleError)} — entry shipped WITHOUT the strip⇒fail binding`,
    );
  }
  for (const a of report.artifacts) {
    if (report.dryRun) {
      lines.push(
        `  • ${safe(a.relativePath)} [${a.format}] → ${safe(a.outputPath)}${a.outputExisted ? " (exists; would overwrite)" : ""}`,
      );
      continue;
    }
    lines.push(
      a.success
        ? `  ✓ ${safe(a.relativePath)} [${a.format}] score=${a.defenseScore} tokens×${a.tokenAmplificationFactor.toFixed(1)} → ${safe(a.outputPath)}`
        : `  ✗ ${safe(a.relativePath)} [${a.format}] ${a.error === undefined ? "failed" : safe(a.error)}`,
    );
    for (const rename of a.wasmExportRenames ?? []) {
      lines.push(`      export renamed: ${safe(rename.from)} → ${safe(rename.to)} (${rename.kind})`);
    }
    for (const kept of a.wasmExportsAutoPreserved ?? []) {
      lines.push(`      export kept: ${safe(kept.name)} (referenced by ${safe(kept.referencedBy)})`);
    }
    if (a.plaintextSurvivors !== undefined) {
      lines.push(
        `      ⚠ ${a.plaintextSurvivors.count} sensitive literal(s) still readable: ${a.plaintextSurvivors.samples
          .map((s) => `${safe(s.preview)}${s.line !== undefined ? ` (line ${s.line})` : ""}`)
          .join(", ")}`,
      );
    }
  }
  if (report.outputSize !== undefined) {
    const size = report.outputSize;
    lines.push(
      `Size: ${formatByteSize(size.inputBytes)} → ${formatByteSize(size.outputBytes)}${
        size.largestGrowth !== undefined
          ? ` (largest: ${safe(size.largestGrowth.relativePath)} +${formatByteSize(size.largestGrowth.growthBytes)})`
          : ""
      }`,
    );
  }
  if (report.truncated) {
    lines.push(
      `  ⚠ discovery truncated at ${report.maxArtifacts} artifacts; more targets exist (raise maxArtifacts or harden a narrower directory)`,
    );
  }
  if (report.discoveryReadErrors && report.discoveryReadErrors.length > 0) {
    lines.push(
      `  ⚠ discovery read errors (${report.discoveryReadErrors.length}) — inventory may be incomplete:`,
    );
    for (const entry of report.discoveryReadErrors.slice(0, 5)) {
      lines.push(`    - ${safe(entry)}`);
    }
    if (report.discoveryReadErrors.length > 5) {
      lines.push(`    … ${report.discoveryReadErrors.length - 5} more`);
    }
  }
  if (report.discoveredCount === 0) {
    lines.push(
      "  (no protectable artifacts found — put build outputs under dist/, build/, out/, or release/, or place .wasm/.sqlite/.safetensors/binaries at the project root)",
    );
  } else {
    lines.push(`Output: ${safe(report.outputDirectory)}`);
  }
  if (report.apply !== undefined) {
    const applied = report.apply.applied ?? [];
    if (report.apply.status === "applied") {
      lines.push(`Applied: ${applied.length} build-output file(s) now hold the hardened bytes`);
      for (const rel of applied) lines.push(`  ⇒ ${safe(rel)}`);
      for (const rel of report.apply.added ?? []) lines.push(`  + ${safe(rel)}`);
    } else if (report.apply.status === "planned") {
      lines.push(`Apply (dry-run): would overwrite ${applied.length} build-output file(s)`);
      for (const rel of applied) lines.push(`  ⇒ ${safe(rel)}`);
    } else {
      lines.push(`Apply ${report.apply.status.toUpperCase()}: ${safe(report.apply.reason ?? "")}`);
    }
  }
  if (report.nextSteps !== undefined && report.nextSteps.length > 0) {
    lines.push("Next:");
    report.nextSteps.forEach((step, idx) => lines.push(`  ${idx + 1}. ${safe(step)}`));
  }
  lines.push(`Tip: ${safe(report.oneSentenceUsage)}`);
  return lines.join("\n");
}
