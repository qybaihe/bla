import { BLA_IDENTITY } from "../identity.js";
import { initBlaConfig, loadBlaConfig } from "../core/config.js";
import { verifyManifestFile } from "../core/manifest-verify.js";
import { inspectReleaseExposure } from "../core/release-exposure.js";
import { registerBlaOutput } from "../core/output-registry.js";
import type { ProtectionIntensity } from "../core/types.js";
import { auditTarget } from "../engine/auditor.js";
import { protectTarget, resolveProtectOutputPath } from "../engine/protector.js";
import { verifyTarget, type VerifyTargetOptions } from "../engine/verifier.js";
import { defendTarget } from "../engine/defender.js";
import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join as joinPath, resolve as resolvePath } from "node:path";
import {
  discoverHardenTargets,
  hardenProject,
  restoreHardenedProject,
} from "../engine/harden.js";
import { BLA_BUILD_OUTPUT_DIR_NAMES, listAppliedFiles, resolveApplyStateDirectory } from "../engine/harden-apply.js";
import {
  lintLaneIndependence,
  type LaneIndependenceReport,
} from "../engine/lane-independence-lint.js";
import {
  lintSealCommitmentFile,
  type SealCommitmentReport,
} from "../engine/seal-commitment-lint.js";
import {
  lintWasmParamCarrierFile,
  type WasmParamCarrierReport,
} from "../engine/wasm-param-carrier-lint.js";
import {
  lintPanelDeriveAbiFile,
  type PanelDeriveAbiReport,
} from "../engine/panel-derive-abi-lint.js";
import {
  lintJsAesUnwrapFile,
  type JsAesUnwrapReport,
} from "../engine/js-aes-unwrap-lint.js";
import {
  lintJsWasmHydrateDumpFile,
  type JsWasmHydrateDumpReport,
} from "../engine/js-wasm-hydrate-dump-lint.js";
import {
  lintWasmXorMaskSidecarFile,
  type WasmXorMaskSidecarReport,
} from "../engine/wasm-xor-mask-sidecar-lint.js";
import {
  lintWasmSealXorKnownPlaintextFile,
  type WasmSealXorKnownPlaintextReport,
} from "../engine/wasm-seal-xor-known-plaintext-lint.js";
import {
  scanPackagingGates,
  type PackagingGatesReport,
} from "../engine/packaging-gates.js";
import {
  computeArtifactRunId,
  HARDEN_SUMMARY_FILE_NAME,
  readHardenRunSummary,
  sha256File,
} from "../engine/run-evidence.js";
import {
  getRedteamReport,
  runReaDriftCheck,
} from "../engine/rea-observability.js";
import {
  comparePolymorphArtifacts,
} from "../engine/polymorph-report.js";
import { encryptStrings } from "../engine/encrypt-strings.js";
import {
  discoverAndLintPlaintextSecrets,
  lintPlaintextSecretsFile,
} from "../engine/plaintext-secret-lint.js";
import {
  discoverAndLintIntegrityCoverage,
  evaluateCoverageMatrix,
  INTEGRITY_COVERAGE_SCHEMA,
  type CoverageMatrix,
} from "../engine/integrity-coverage.js";
import {
  applyBindScope,
  BIND_SCOPE_SCHEMA,
  discoverAndLintBindScope,
} from "../engine/bind-scope.js";
import { planSidecarEntanglement } from "../shields/runtime/sidecar-entangle.js";
import { runShowcaseBenchmark } from "../engine/benchmark.js";
import {
  emitCompileTimeNativeHeader,
  type NativeHeaderLanguage,
} from "../shields/formats/headers.js";
import { runDoctor } from "../setup/doctor.js";
import { resolveBundledSkillBundle } from "../setup/setup.js";
import {
  buildWeavePlan,
  getWeaveDirectivesMarkdown,
  verifyWeaveTarget,
  WEAVE_DECOY_DOC_PATH,
  WEAVE_DIRECTIVES_URI,
} from "../shields/weave/weave-decoy.js";

/** In-flight bla_harden AbortControllers keyed by JSON-RPC request id (issue #75). */
const activeHardenAborts = new Map<string | number, AbortController>();

function progressTokenOf(req: JsonRpcRequest): string | number | undefined {
  const params = req.params as { _meta?: { progressToken?: unknown } } | undefined;
  const token = params?._meta?.progressToken;
  if (typeof token === "string" || typeof token === "number") return token;
  return undefined;
}

function emitMcpProgress(
  token: string | number,
  progress: number,
  total: number,
  message: string,
): void {
  const note = {
    jsonrpc: "2.0" as const,
    method: "notifications/progress",
    params: {
      progressToken: token,
      progress,
      total,
      message,
    },
  };
  process.stdout.write(JSON.stringify(note) + "\n");
}

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: unknown;
}

export interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export interface McpPropertySchema {
  readonly type: "string" | "boolean" | "number" | "array";
  readonly description?: string;
  readonly enum?: readonly string[];
  /** Present when type is "array" (JSON Schema items). */
  readonly items?: { readonly type: "string" | "boolean" | "number" };
  /** Present when type is "array": upper bound on item count (JSON Schema `maxItems`). */
  readonly maxItems?: number;
  /** Present for count-like numbers: reject fractional values. */
  readonly integer?: boolean;
  /**
   * Optional per-property upper bound on string length (JSON Schema
   * `maxLength`). When absent, MAX_STRING_ARG_CHARS applies.
   */
  readonly maxLength?: number;
}

export interface McpToolAnnotations {
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly annotations?: McpToolAnnotations;
  readonly inputSchema: {
    readonly type: "object";
    readonly properties: Readonly<Record<string, McpPropertySchema | undefined>>;
    readonly required?: readonly string[];
    readonly additionalProperties?: boolean;
  };
}

export interface McpPromptArgumentDefinition {
  readonly name: string;
  readonly description: string;
  readonly required: boolean;
}

export interface McpPromptDefinition {
  readonly name: string;
  readonly description: string;
  readonly arguments: readonly McpPromptArgumentDefinition[];
}

export interface McpEngineHandlers {
  readonly hardenProject: typeof hardenProject;
  readonly defendTarget: typeof defendTarget;
  readonly auditTarget: typeof auditTarget;
  readonly protectTarget: typeof protectTarget;
  readonly verifyTarget: typeof verifyTarget;
  readonly runShowcaseBenchmark: typeof runShowcaseBenchmark;
  readonly emitCompileTimeNativeHeader: typeof emitCompileTimeNativeHeader;
  readonly runDoctor: typeof runDoctor;
  readonly inspectReleaseExposure: typeof inspectReleaseExposure;
  readonly initBlaConfig: typeof initBlaConfig;
}

const DEFAULT_ENGINE_HANDLERS: McpEngineHandlers = Object.freeze({
  hardenProject,
  defendTarget,
  auditTarget,
  protectTarget,
  verifyTarget,
  runShowcaseBenchmark,
  emitCompileTimeNativeHeader,
  runDoctor,
  inspectReleaseExposure,
  initBlaConfig,
});

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  "2024-11-05",
  "2025-03-26",
  "2025-06-18",
] as const);

/** Answer for a requested revision this server does not speak (MCP lifecycle: the latest it supports). */
const LATEST_MCP_PROTOCOL_VERSION =
  SUPPORTED_MCP_PROTOCOL_VERSIONS[SUPPORTED_MCP_PROTOCOL_VERSIONS.length - 1]!;
/** Answer for a client that sent no revision at all. */
const OLDEST_MCP_PROTOCOL_VERSION = SUPPORTED_MCP_PROTOCOL_VERSIONS[0];

/**
 * Server instructions returned from `initialize`. Hosts hand these to the
 * model, so an agent that has the MCP server but not the skill still walks the
 * whole path: harden → promote into the build output → test what ships.
 */
export const BLA_MCP_INSTRUCTIONS = [
  "BLA hardens a developer's own build artifacts against AI reverse-engineering agents. Defensive use only: never use it to analyse, unpack or bypass someone else's software.",
  "",
  "Hardening a project:",
  '1. Build the project, then call bla_harden { "directory": "." } (dry_run: true previews). It discovers the build output itself — do not ask which files to protect.',
  "2. Read nextSteps in every result and follow them. A plain run writes a partial mirror (.bla-hardened/) and ships nothing: the build output is still unprotected.",
  '3. Promote it: bla_harden { "directory": ".", "apply": true } replaces the build output in place (originals are backed up outside the project; restore: true undoes it). It answers confirmation_required first — ask the user, then repeat with confirm_overwrite: true.',
  "4. Run the project's own tests or a smoke run against the promoted build. BLA verifies structure, not behaviour.",
  "5. A test fails or a hot path is too slow? restore: true, then harden again with that one file in exclude (or at a lower intensity) and tell the user what ships unprotected.",
  "",
  "Rules:",
  "- isError: true means the call did not succeed. Read artifacts[].error, apply.reason and nextSteps; do not retry unchanged.",
  "- Never edit, lint or re-harden BLA's own output (it is decoys by design; discovery lists it under skippedHardenedOutputs). Change the source, rebuild, harden again.",
  "- Hardened code is unreadable: never write it over source files.",
  "- Report scores for what they are: structural checks and cost estimates, not measured attacker results.",
  "- Optional stage 2 for licence / entitlement checks: bla_weave_plan → edit the source as the workorder says → bla_verify_weave → rebuild → bla_harden with weave_decoys: true.",
  "- bla_lint lists packaging footguns before hardening; only findings with enforcedByHarden: true make bla_harden refuse.",
  "- No BLA skill in your client? The full guide is the resource bla://skill/SKILL.md; per-format notes are under bla://skill/references/.",
].join("\n");

const MUTATING_MCP_TOOLS: ReadonlySet<string> = new Set([
  "bla_harden",
  "bla_defend",
  "bla_protect",
  "bla_init",
  "bla_encrypt_strings",
  "bla_bind_scope",
  "bla_redteam_report",
]);

function withToolAnnotations(tool: McpToolDefinition): McpToolDefinition {
  const isMutating = MUTATING_MCP_TOOLS.has(tool.name);
  return {
    ...tool,
    annotations: {
      readOnlyHint: !isMutating,
      // Mutating tools write or overwrite files, so clients that honor the
      // hint can prompt the operator before executing them.
      destructiveHint: isMutating,
      idempotentHint: !isMutating || tool.name === "bla_redteam_report",
      openWorldHint: false,
    },
  };
}

/**
 * Upper bound for string-array tool arguments. Every array argument is a short
 * user-authored list (WASM export names, allowed hostnames, glob patterns), so
 * the cap is far above real use while still refusing an unbounded or buggy
 * client the ability to push one call into unbounded work.
 */
export const MAX_STRING_ARRAY_ITEMS = 1024;

/**
 * Default upper bound for a single string tool argument (paths, seeds, key
 * paths, hex digests — all short operator-authored values). Far above real
 * use; bounds the hashing/copy work a buggy or hostile client can trigger
 * with one call. A property schema may declare a tighter `maxLength`.
 */
export const MAX_STRING_ARG_CHARS = 65_536;

/**
 * Upper bound for numeric tool arguments (counts, offsets, thresholds). Every
 * real value is far smaller; the cap keeps a huge magnitude from flowing into
 * engine loops or report math as a plausible input.
 */
export const MAX_NUMERIC_ARG = 1_000_000_000;

const RAW_BLA_MCP_TOOLS: readonly McpToolDefinition[] = [
  {
    name: "bla_harden",
    description:
      "Counter-REA project hardening engine (Stage 3 of the 4-Stage Agent-First Closed Loop). IMPORTANT FOR HOST AGENTS: When source code is present, YOU (the Host Agent) are the primary hardening engine — before calling bla_harden, run (1) bla_lint + bla_weave_plan to obtain surgicalWorkorder & crownJewelCandidates, (2) edit source files to eliminate single-point boolean gates and weave shared-state shadow business logic, and (3) verify with bla_verify_weave. Pass require_agent_weave:true (plus weave_decoys:true, self_seal:true, sidecar_entangle:true) to enforce the pre-flight Agent weave gate. Also supports one-sentence fast-path hardening on pre-built directories (dist/, build/, out/, release/, .asar, .wasm, .py/.pyc, native binaries).",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Project or build directory to harden (default: current working directory)",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Protection intensity preset (default: bankrupt)",
        },
        emit_manifest: {
          type: "boolean",
          description: "Opt-in: emit a .bla-manifest.json attestation per artifact (unsigned unless sign_manifest is true). Default false.",
        },
        sign_manifest: {
          type: "boolean",
          description: "Opt-in: ed25519-sign each emitted manifest (implies emit_manifest). Requires manifest_key_path. Default false.",
        },
        manifest_key_path: {
          type: "string",
          description: "Path to an ed25519 private key PEM file used when sign_manifest is true.",
        },
        llm_directives: {
          type: "boolean",
          description: "Opt-in risky LLM directive layers (fake COPPA/medical notices, dual-use imitation, AI chat markers). Default false.",
        },
        weave_decoys: {
          type: "boolean",
          description:
            "Opt-in weave-decoy entanglement: JS AST weave (always) + Python .py customer-def weave + .pyc co_consts TYPE_CODE weave. When false, Python stays warm-init/trailer-only. See bla://directives/weave-decoy. Default false.",
        },
        self_seal: {
          type: "boolean",
          description:
            "Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5). Injects a self-integrity preamble and entangles the opaque-predicate seed. For multi-artifact entitlement trees, bankrupt harden sets selfSealRecommended when this is false; enabling it auto-binds sibling JS/WASM/HTML paths. Default false — never auto-enabled for single-file trees.",
        },
        sqlite_eval_trap: {
          type: "boolean",
          description:
            "SQLite only, opt-in. Honey-table columns call a function no stock connection has: an inspector's row read of those tables fails — and so do PRAGMA integrity_check, VACUUM and a dump/restore in the application itself. Use only for a database the application just queries. Default false: decoy columns every SQLite build evaluates.",
        },
        sidecar_entangle: {
          type: "boolean",
          description:
            "Opt-in sidecar/entry entanglement for JS/Python/ASAR + WASM/Bun/.pyc/GGUF/Safetensors notes (issue #40). When true, harden/protect binds sibling sidecar bytes into the entry via a strip⇒fail preamble (CommonJS require or ESM createRequire + import.meta.url) — removing or altering a sidecar fail-closes the entry body. ESM static import/export-from bindings still evaluate before that hook (defenseScore gap esm-import-hoist-before-hooks). OFF by default.",
        },
        require_agent_weave: {
          type: "boolean",
          description:
            "Agent-First Closed-Loop gate: when true, refuses mechanical hardening until the crown-jewel source files — the ones holding gate / auth / license / entitlement logic — have passed Host-Agent structural weave verification (bla_verify_weave), returning agentWeaveAssessment (weaveScope, unwovenSourceFiles, surgicalWorkorders + agentActions) so the Host Agent edits the source code first. Files without gate logic are advisory and never block; when nothing is named like a gate, at least one source file of your choosing must pass. Default false.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
          maxItems: MAX_STRING_ARRAY_ITEMS,
          description:
            "WASM export names to keep as the public ABI. At maximum/bankrupt every other export is renamed by default — pass explicitly to keep mix/seal-style names (issue #40.3 / red-blue round-1).",
        },
        allow_lane_independent: {
          type: "boolean",
          description:
            "Allow harden/defend/protect of JS/TS that looks lane-independent (per-byte oracles). Default false — refuse (issue #40.1 / red-blue round-1).",
        },
        allow_plaintext_seal: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite plaintext or reversible seal/entitlement JSON sidecars. Default false — refuse (red-blue round-2).",
        },
        allow_wasm_clear_params: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite clear WASM param/cipher ASCII carriers (R3PARM/R3CIPH/R2SEAL-class). Default false — refuse (red-blue round-3). Full data-section encryption is a follow-up.",
        },
        allow_stable_panel_derive: {
          type: "boolean",
          description:
            "Keep stable __vaultPanelDerive_* / deriveLocal ABI (skip rewrite). Default false — maximum/bankrupt rewrite to seed-stable _blaPd_* / _blaPdLocal_* (red-blue round-3/4).",
        },
        allow_js_aes_unwrap: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite JS AES wrap-key + create*iv + fixed sealed-hdr unwrap footguns. Default false — refuse (red-blue round-4). Gate only — not white-box AES.",
        },
        allow_panel_offline_oracle: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite deriveLocal + plaintext panelTokenSha256 offline-oracle packaging. Default false — refuse (red-blue round-4).",
        },
        allow_js_wasm_hydrate_dump: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite JS←WASM hydrate memory dumps of salt/rounds/cipher. Default false — refuse (red-blue round-5). Prefer in-WASM ARX+certify; gate only.",
        },
        allow_wasm_xor_mask_sidecar: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite WASM data-section XOR-mask-beside-blob entitlement packs. Default false — refuse (red-blue round-6). Prefer key-dependent unmask + one-way commitments.",
        },
        allow_wasm_seal_xor_known_plaintext: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite WASM seal.revision XOR known-plaintext entitlement packs. Default false — refuse (red-blue round-7). Prefer one-way mask KDFs; keep public digests out of masked plaintext.",
        },
        allow_release_hygiene_leak: {
          type: "boolean",
          description:
            "Lab escape: allow bankrupt/maximum harden despite leaked SOLUTION/writeup notes, populated .env secrets, SSH/PEM private keys, or unstripped .pdb/.dSYM/.dwp debug databases. Default false — refuse.",
        },
        seed: {
          type: "string",
          description: "Optional deterministic seed; when omitted, BLA uses/persists a per-project random seed in .blarc",
        },
        dry_run: {
          type: "boolean",
          description:
            "Preview only: return discovered targets, planned output paths, wouldOverwrite and truncation without writing a single byte. Default false.",
        },
        max_artifacts: {
          type: "number",
          integer: true,
          description: "Optional cap on discovered artifacts (default 64); the report sets truncated=true when more exist.",
        },
        confirm_overwrite: {
          type: "boolean",
          description:
            "Explicit write-confirmation boundary. Required (true) when this call would overwrite an existing output file; without it the call is refused with a confirmation_required receipt listing the paths. Default false.",
        },
        output_directory: {
          type: "string",
          description:
            "Optional root directory for hardened outputs (same as CLI `harden -o`). Default: <directory>/.bla-hardened.",
        },
        exclude: {
          type: "array",
          items: { type: "string" },
          description:
            "Project-relative paths or globs to leave out — for the one file that breaks or slows the program when hardened, so everything else is still protected. A pattern with a slash is anchored at the project root and covers everything beneath a matching directory (dist/vendor, dist/chunks/heavy-*.js); one without matches any path segment (vendor, *.min.js). Excluded files ship unprotected and are listed in the result's excluded. Merged with the project config's exclude.",
        },
        apply: {
          type: "boolean",
          description:
            "Ship it: after hardening, overwrite the build output with the hardened files so the tree that gets packaged is the protected one (CLI --apply). Only files inside a build-output directory (dist/, build/, out/, release/, …) are overwritten — never source files. The originals are backed up outside the project, restore:true puts them back, and re-running re-hardens from those originals instead of hardening twice. Always needs confirm_overwrite:true. Default false: hardened copies go to output_directory (a partial mirror) and the build output stays unprotected.",
        },
        restore: {
          type: "boolean",
          description:
            "Undo a previous apply: put the original build output back and harden nothing (CLI --restore). Files that changed since the apply (for example after a rebuild) are left alone. Needs confirm_overwrite:true.",
        },
        clear_stale_lock: {
          type: "boolean",
          description:
            "Apply/restore only: remove a transaction lock left by an exited BLA process when its recorded PID is no longer running. A live owner or a lock without an owner record is never cleared. Default false.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_discover",
    description:
      "Read-only inventory of protectable artifacts under a project/build directory using the exact discovery bla_harden uses (format per file, truncated flag when the cap is hit). For 64+ trees: pass offset from a prior nextOffset to page without losing the tail. Writes nothing. Use it to scope work before bla_harden / bla_defend.",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Project or build directory to inventory (default: current working directory)",
        },
        max_artifacts: {
          type: "number",
          integer: true,
          description: "Optional page size / cap (default 64); truncated=true when more exist beyond this page.",
        },
        offset: {
          type: "number",
          integer: true,
          description: "Zero-based offset into the stable discovery order (use prior nextOffset to page). Default 0.",
        },
        exclude: {
          type: "array",
          items: { type: "string" },
          description:
            "Project-relative paths or globs to leave out, with the same syntax as bla_harden's exclude. Matching files are listed in excluded instead of artifacts.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_defend",
    description:
      "One-click Counter-REA full defense hardening pipeline. Runs release source-map exposure inspection, multi-vector REA vulnerability audit, Resource-Exhaustion + Model-Misjudgment shield injection (default: bankrupt preset), and mathematical invariant verification in a single call.",
    inputSchema: {
      type: "object",
      properties: {
        input_path: {
          type: "string",
          description: "Path to the artifact or directory to harden against REA",
        },
        output_path: {
          type: "string",
          description: "Optional output path for the hardened artifact",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Protection intensity preset (default: bankrupt)",
        },
        emit_manifest: {
          type: "boolean",
          description: "Opt-in: emit a .bla-manifest.json attestation next to the hardened artifact (unsigned unless sign_manifest is true). Default false.",
        },
        sign_manifest: {
          type: "boolean",
          description: "Opt-in: ed25519-sign the emitted manifest (implies emit_manifest). Requires manifest_key_path. Default false.",
        },
        manifest_key_path: {
          type: "string",
          description: "Path to an ed25519 private key PEM file used when sign_manifest is true.",
        },
        llm_directives: {
          type: "boolean",
          description: "Opt-in risky LLM directive layers (fake COPPA/medical notices, dual-use imitation, AI chat markers). Default false.",
        },
        weave_decoys: {
          type: "boolean",
          description:
            "Opt-in weave-decoy entanglement (shared-state / entry-reachable decoys into customer paths; not dismissible noise). Python .py structural weave + .pyc co_consts CODE weave when true. Default false.",
        },
        self_seal: {
          type: "boolean",
          description:
            "Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5). Injects a self-integrity preamble and entangles the opaque-predicate seed. For multi-artifact entitlement trees, bankrupt harden sets selfSealRecommended when this is false; enabling it auto-binds sibling JS/WASM/HTML paths. Default false — never auto-enabled for single-file trees.",
        },
        sqlite_eval_trap: {
          type: "boolean",
          description:
            "SQLite only, opt-in. Honey-table columns call a function no stock connection has: an inspector's row read of those tables fails — and so do PRAGMA integrity_check, VACUUM and a dump/restore in the application itself. Use only for a database the application just queries. Default false: decoy columns every SQLite build evaluates.",
        },
        sidecar_entangle: {
          type: "boolean",
          description:
            "Opt-in sidecar/entry entanglement for JS/Python/ASAR + WASM/Bun/.pyc/GGUF/Safetensors notes (issue #40). When true, harden/protect binds sibling sidecar bytes into the entry via a strip⇒fail preamble (CommonJS require or ESM createRequire + import.meta.url) — removing or altering a sidecar fail-closes the entry body. ESM static import/export-from bindings still evaluate before that hook (defenseScore gap esm-import-hoist-before-hooks). OFF by default.",
        },
        require_agent_weave: {
          type: "boolean",
          description:
            "Agent-First Closed-Loop gate: when true, refuses mechanical defense if the target source file has not yet passed Host-Agent structural weave verification (bla_verify_weave). Default false.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
          maxItems: MAX_STRING_ARRAY_ITEMS,
          description:
            "WASM export names to keep as the public ABI. At maximum/bankrupt every other export is renamed by default — pass explicitly to keep mix/seal-style names (issue #40.3 / red-blue round-1).",
        },
        allow_lane_independent: {
          type: "boolean",
          description:
            "Allow harden/defend/protect of JS/TS that looks lane-independent (per-byte oracles). Default false — refuse (issue #40.1 / red-blue round-1).",
        },
        allow_plaintext_seal: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite plaintext or reversible seal/entitlement JSON sidecars. Default false — refuse (red-blue round-2).",
        },
        allow_wasm_clear_params: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite clear WASM param/cipher ASCII carriers (R3PARM/R3CIPH/R2SEAL-class). Default false — refuse (red-blue round-3). Full data-section encryption is a follow-up.",
        },
        allow_stable_panel_derive: {
          type: "boolean",
          description:
            "Keep stable __vaultPanelDerive_* / deriveLocal ABI (skip rewrite). Default false — maximum/bankrupt rewrite to seed-stable _blaPd_* / _blaPdLocal_* (red-blue round-3/4).",
        },
        allow_js_aes_unwrap: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite JS AES wrap-key + create*iv + fixed sealed-hdr unwrap footguns. Default false — refuse (red-blue round-4). Gate only — not white-box AES.",
        },
        allow_panel_offline_oracle: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite deriveLocal + plaintext panelTokenSha256 offline-oracle packaging. Default false — refuse (red-blue round-4).",
        },
        allow_js_wasm_hydrate_dump: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite JS←WASM hydrate memory dumps of salt/rounds/cipher. Default false — refuse (red-blue round-5). Prefer in-WASM ARX+certify; gate only.",
        },
        allow_wasm_xor_mask_sidecar: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite WASM data-section XOR-mask-beside-blob entitlement packs. Default false — refuse (red-blue round-6). Prefer key-dependent unmask + one-way commitments.",
        },
        allow_wasm_seal_xor_known_plaintext: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite WASM seal.revision XOR known-plaintext entitlement packs. Default false — refuse (red-blue round-7). Prefer one-way mask KDFs; keep public digests out of masked plaintext.",
        },
        allow_release_hygiene_leak: {
          type: "boolean",
          description:
            "Lab escape: allow bankrupt/maximum defend despite leaked SOLUTION/writeup notes, populated .env secrets, SSH/PEM private keys, or unstripped .pdb/.dSYM/.dwp debug databases. Default false — refuse.",
        },
        seed: {
          type: "string",
          description: "Optional deterministic seed; when omitted, BLA uses/persists a per-project random seed in .blarc",
        },
        in_place: {
          type: "boolean",
          description:
            "Overwrite the input path in place (same as CLI --in-place). When the planned output already exists — including the input itself — confirm_overwrite:true is required; otherwise the call is refused and nothing is written. Default false.",
        },
        confirm_overwrite: {
          type: "boolean",
          description:
            "Explicit write-confirmation boundary. Required (true) when this call would overwrite an existing output file; without it the call is refused with a confirmation_required receipt listing the paths. Default false.",
        },
      },
      required: ["input_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_audit",
    description:
      "Pre-flight REA exposure and vulnerability audit. Simulates REA static/semantic passes on a target file or directory (JS/TS, Electron .asar, WASM, Python .py/.pyc, Native ELF/Mach-O/PE, ZIP/APK) and estimates attacker Claude/GPT token and dollar cost.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the artifact or directory to audit",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_protect",
    description:
      "Injects BLA's multi-layer adversarial defense shield (Algorithmic Tarpit, REA Semantic Budget Breakers, Electron IPC Ambiguity, Honey Source Maps, and Architectural Chaff) into a target artifact.",
    inputSchema: {
      type: "object",
      properties: {
        input_path: {
          type: "string",
          description: "Path to the input artifact or directory",
        },
        output_path: {
          type: "string",
          description: "Optional output path for the protected artifact",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Protection intensity preset (default: balanced)",
        },
        weave_decoys: {
          type: "boolean",
          description:
            "Opt-in weave-decoy entanglement (shared-state / entry-reachable decoys into customer paths; not dismissible noise). Python .py structural weave + .pyc co_consts CODE weave when true. Default false.",
        },
        self_seal: {
          type: "boolean",
          description:
            "Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5). Injects a self-integrity preamble and entangles the opaque-predicate seed. For multi-artifact entitlement trees, bankrupt harden sets selfSealRecommended when this is false; enabling it auto-binds sibling JS/WASM/HTML paths. Default false — never auto-enabled for single-file trees.",
        },
        sqlite_eval_trap: {
          type: "boolean",
          description:
            "SQLite only, opt-in. Honey-table columns call a function no stock connection has: an inspector's row read of those tables fails — and so do PRAGMA integrity_check, VACUUM and a dump/restore in the application itself. Use only for a database the application just queries. Default false: decoy columns every SQLite build evaluates.",
        },
        sidecar_entangle: {
          type: "boolean",
          description:
            "Opt-in sidecar/entry entanglement for JS/Python/ASAR + WASM/Bun/.pyc/GGUF/Safetensors notes (issue #40). When true, harden/protect binds sibling sidecar bytes into the entry via a strip⇒fail preamble (CommonJS require or ESM createRequire + import.meta.url) — removing or altering a sidecar fail-closes the entry body. ESM static import/export-from bindings still evaluate before that hook (defenseScore gap esm-import-hoist-before-hooks). OFF by default.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
          maxItems: MAX_STRING_ARRAY_ITEMS,
          description:
            "WASM export names to keep as the public ABI. At maximum/bankrupt every other export is renamed by default — pass explicitly to keep mix/seal-style names (issue #40.3 / red-blue round-1).",
        },
        allow_lane_independent: {
          type: "boolean",
          description:
            "Allow harden/defend/protect of JS/TS that looks lane-independent (per-byte oracles). Default false — refuse (issue #40.1 / red-blue round-1).",
        },
        allow_plaintext_seal: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite plaintext or reversible seal/entitlement JSON sidecars. Default false — refuse (red-blue round-2).",
        },
        allow_wasm_clear_params: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite clear WASM param/cipher ASCII carriers (R3PARM/R3CIPH/R2SEAL-class). Default false — refuse (red-blue round-3). Full data-section encryption is a follow-up.",
        },
        allow_stable_panel_derive: {
          type: "boolean",
          description:
            "Keep stable __vaultPanelDerive_* / deriveLocal ABI (skip rewrite). Default false — maximum/bankrupt rewrite to seed-stable _blaPd_* / _blaPdLocal_* (red-blue round-3/4).",
        },
        allow_js_aes_unwrap: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite JS AES wrap-key + create*iv + fixed sealed-hdr unwrap footguns. Default false — refuse (red-blue round-4). Gate only — not white-box AES.",
        },
        allow_panel_offline_oracle: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite deriveLocal + plaintext panelTokenSha256 offline-oracle packaging. Default false — refuse (red-blue round-4).",
        },
        allow_js_wasm_hydrate_dump: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite JS←WASM hydrate memory dumps of salt/rounds/cipher. Default false — refuse (red-blue round-5). Prefer in-WASM ARX+certify; gate only.",
        },
        allow_wasm_xor_mask_sidecar: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite WASM data-section XOR-mask-beside-blob entitlement packs. Default false — refuse (red-blue round-6). Prefer key-dependent unmask + one-way commitments.",
        },
        allow_wasm_seal_xor_known_plaintext: {
          type: "boolean",
          description:
            "Allow bankrupt harden/protect despite WASM seal.revision XOR known-plaintext entitlement packs. Default false — refuse (red-blue round-7). Prefer one-way mask KDFs; keep public digests out of masked plaintext.",
        },
        allow_release_hygiene_leak: {
          type: "boolean",
          description:
            "Lab escape: allow bankrupt/maximum harden despite leaked SOLUTION/writeup notes, populated .env secrets, SSH/PEM private keys, or unstripped .pdb/.dSYM/.dwp debug databases. Default false — refuse.",
        },
        seed: {
          type: "string",
          description: "Optional deterministic seed; when omitted, BLA mints an ephemeral random seed (prefer project .blarc via CLI)",
        },
        llm_directives: {
          type: "boolean",
          description: "Opt-in risky LLM directive layers. Default false.",
        },
        in_place: {
          type: "boolean",
          description:
            "Overwrite the input path in place (same as CLI --in-place). When the planned output already exists — including the input itself — confirm_overwrite:true is required; otherwise the call is refused and nothing is written. Default false.",
        },
        honey_source_maps: {
          type: "boolean",
          description:
            "Emit honey/decoy source maps with the shield (same as CLI default; pass false for --no-honey-maps). Default true.",
        },
        confirm_overwrite: {
          type: "boolean",
          description:
            "Explicit write-confirmation boundary. Required (true) when this call would overwrite an existing output file; without it the call is refused with a confirmation_required receipt listing the paths. Default false.",
        },
      },
      required: ["input_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_verify",
    description:
      "Verifies a BLA-protected artifact against REA's static/semantic resource limits, call-graph tarpit expansion, and token bankruptcy amplification. Pass protection-side honesty metadata (self_seal_enabled / sidecar_entangle_enabled / wasm_export_rename_applied) so defenseScore soft-caps reflect what actually ran — same fields defend/harden already forward from ProtectionResult. Optional run_id / summary_path correlate this verify with a prior harden summary (unsigned).",
    inputSchema: {
      type: "object",
      properties: {
        target_path: {
          type: "string",
          description: "Path to the protected artifact to verify",
        },
        original_path: {
          type: "string",
          description: "Optional path to the unprotected original for amplification comparison",
        },
        self_seal_enabled: {
          type: "boolean",
          description:
            "Honesty metadata: true when protect/defend ran with self-seal. Omitting it soft-caps JS-like scores with self-seal-not-enabled (issue #40.6).",
        },
        sidecar_entangle_enabled: {
          type: "boolean",
          description:
            "Honesty metadata: true when protect/defend/harden ran with sidecarEntangle. Omitting it soft-caps formats that support strip⇒fail entanglement with sidecar-entangle-not-enabled (issue #40 / DESIGN).",
        },
        wasm_export_rename_applied: {
          type: "boolean",
          description:
            "Honesty metadata: true when WASM export rename actually rewrote non-ABI exports. Omitting it soft-caps WASM scores with wasm-export-rename-pending (issue #40.6).",
        },
        numeric_template_leak_known: {
          type: "boolean",
          description:
            "Honesty metadata: true when known BLA-injected numeric template golden constants still leak (issue #40.6).",
        },
        summary_path: {
          type: "string",
          description:
            "Optional path to bla-harden-summary.json (or its output directory) to correlate this verify with a prior harden run (unsigned).",
        },
        run_id: {
          type: "string",
          description:
            "Optional harden run_id; when paired with summary_path, must match the summary or the tool errors.",
        },
        manifest_path: {
          type: "string",
          description:
            "Optional path to a .bla-manifest.json attestation file to cryptographically verify alongside the artifact.",
        },
        public_key_path: {
          type: "string",
          description:
            "Optional path to a pinned Ed25519 public key PEM file used when verifying manifest_path.",
        },
        require_pinned_key: {
          type: "boolean",
          description:
            "When true with manifest_path, fails verification unless a pinned public_key_path is supplied and matches.",
        },
      },
      required: ["target_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_benchmark",
    description:
      "Runs the Counter-REA Showcase Benchmark suite and returns Before vs. After metrics.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "bla_emit_headers",
    description:
      "Emits compile-time native defense headers for C/C++ (bla_shield.h), Rust (bla_shield.rs), or Go (bla_shield.go) to defeat Ghidra/Hopper/IDA and REA native binary analyzers.",
    inputSchema: {
      type: "object",
      properties: {
        language: {
          type: "string",
          enum: ["c", "rust", "go"],
          description: "Target native language (c, rust, or go)",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
        },
      },
      required: ["language"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_doctor",
    description:
      "Checks readiness of all BLA protection engines and agent MCP registrations: which clients have the server registered, whether each pins this release (versionSkew), and what to run to repair them (nextSteps). Also reads the project's own MCP configs (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, …) into projectRegistrations. Clients that are not installed are only named in clientsNotDetected.",
    inputSchema: {
      type: "object",
      properties: {
        home_dir: {
          type: "string",
          description: "Optional home directory path to inspect",
        },
        directory: {
          type: "string",
          description:
            "Project whose own MCP config files are checked for a BLA entry (default: the server's working directory).",
        },
        verify_handshake: {
          type: "boolean",
          description:
            "Self-test the installed BLA CLI with an MCP initialize request. Registration launchers are inspected from disk.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_inspect_release",
    description:
      "Read-only local source-map and symbol exposure scan for build directories and release artifacts.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the build directory or artifact to inspect",
        },
        max_files: {
          type: "number",
          integer: true,
          description: "Optional maximum number of files to scan",
        },
        max_total_bytes: {
          type: "number",
          integer: true,
          description: "Optional maximum total bytes to scan",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_init",
    description:
      "Creates a starter bla.config.json in a project directory for zero-argument `bla defend` workflows.",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Target project directory (pass '.' explicitly for current directory)",
        },
        overwrite: {
          type: "boolean",
          description: "Overwrite an existing bla.config.json if present",
        },
      },
      required: ["directory"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_weave_plan",
    description:
      "Read-only weave-decoy planner: analyze a project or artifact, return bla-weave-plan/v1 JSON (principles, forbidden patterns, checklist, per-file maturity, plus AST surgicalWorkorder with entryFunctions, sharedStateSlots, branchCandidates, and agentRewriteRecipe). Defensive only — no crack/RE steps. Prefer before Agent source surgery and bla_harden with weave_decoys:true.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Project directory or single artifact to analyze",
        },
        max_targets: {
          type: "number",
          integer: true,
          description: "Optional cap on files to classify (default 48)",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_verify_weave",
    description:
      "Read-only structural weave verifier (bla-weave-verify/v1): validates Agent-authored source weave edits and hardened outputs against all 7 WEAVE_ACCEPTANCE_TESTS (no forbidden banners, mixed mundane/security stems, shared-state mutation across functions, customer entry call-graph reachability, opaque-true entanglement, filter resistance, and crown-jewel entanglement). For a directory, overallPassed depends only on the crown-jewel files (requiredFiles: gate / auth / license / entitlement logic); files without gate logic are listed in advisoryFiles and never block, so you never have to weave a formatter or a view. Returns weaveScore, scope, and actionable agentActions (required files only) for autonomous self-repair.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the source file, artifact, or directory to verify",
        },
        max_targets: {
          type: "number",
          integer: true,
          description: "Optional cap on files to verify (default 48)",
        },
        scope: {
          type: "string",
          enum: ["auto", "all"],
          description:
            "Which files decide overallPassed for a directory. 'auto' (default): only crown-jewel files — those holding gate / auth / license / entitlement logic — must pass; every other source file is advisory. When nothing is named like a gate, at least one file you choose must pass. 'all': every verified source file must pass. A single-file path is always verified strictly.",
        },
        verbose: {
          type: "boolean",
          description:
            "Include the full per-check reports of advisory files too (default false: advisory files are only listed by path in advisoryFiles).",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint",
    description:
      "DEFAULT packaging-footgun gate scan for a project directory (or file). Runs every R1–R7 bankrupt refuse lint plus lane-independence and panel-derive discovery in one call — same engines as the individual bla_lint_* tools / `bla lint`. Returns bla-packaging-gates/v1 with findings, blocking, and honestyNote. Writes nothing. Prefer this over calling eight separate lints when reviewing an entitlement tree before harden.",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Project directory or file to scan (default: cwd)",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Intensity used to decide refuse (default: bankrupt)",
        },
        allow_plaintext_seal: {
          type: "boolean",
          description: "Treat plaintext/reversible seal as non-blocking (lab only)",
        },
        allow_wasm_clear_params: {
          type: "boolean",
          description: "Treat clear WASM param carriers as non-blocking (lab only)",
        },
        allow_js_aes_unwrap: {
          type: "boolean",
          description: "Treat JS AES unwrap footgun as non-blocking (lab only)",
        },
        allow_js_wasm_hydrate_dump: {
          type: "boolean",
          description: "Treat JS←WASM hydrate dump as non-blocking (lab only)",
        },
        allow_wasm_xor_mask_sidecar: {
          type: "boolean",
          description: "Treat WASM XOR-mask sidecar as non-blocking (lab only)",
        },
        allow_wasm_seal_xor_known_plaintext: {
          type: "boolean",
          description: "Treat seal.revision XOR KP as non-blocking (lab only)",
        },
        allow_lane_independent: {
          type: "boolean",
          description: "Treat lane-independent gates as non-blocking (lab only)",
        },
        allow_stable_panel_derive: {
          type: "boolean",
          description: "Keep stable __vaultPanelDerive_* / deriveLocal ABI without rewrite warning (lab only)",
        },
        allow_panel_offline_oracle: {
          type: "boolean",
          description: "Treat panel offline oracle as non-blocking (lab only)",
        },
        allow_plaintext_string: {
          type: "boolean",
          description: "Treat cleartext sensitive literals as non-blocking (lab only)",
        },
        allow_single_point_integrity: {
          type: "boolean",
          description: "Treat single-point integrity coverage as non-blocking (lab only)",
        },
        allow_missing_bind_runtime: {
          type: "boolean",
          description: "Treat missing/narrow bind runtime scope as non-blocking (lab only)",
        },
        allow_release_hygiene_leak: {
          type: "boolean",
          description:
            "Treat leaked SOLUTION/writeup notes, populated .env secrets, private keys, or .pdb/.dSYM/.dwp debug symbols as non-blocking (lab only)",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_lanes",
    description:
      "Read-only heuristic lane-independence footgun lint (same engine as CLI `bla lint-lanes`). Returns severity-error findings when gate/activation source looks like independent per-lane checks. Harden refuses such gates unless allow_lane_independent. Prefer whole-key chained mixing. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a UTF-8 source file to lint (JS/TS/Python-like)",
        },
        allow_lane_independent: {
          type: "boolean",
          description: "Lab escape: report findings without refusing",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_seal",
    description:
      "Read-only seal-commitment lint (same engine as CLI `bla lint-seal`). Flags plaintext seal/entitlement JSON sidecars and reversible public commitments (scheduleSalt+rounds+revision without a one-way algorithm). Bankrupt harden refuses error findings unless allow_plaintext_seal. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a seal.json / *.seal.json (or seal-shaped JSON) file to lint",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_wasm_params",
    description:
      "Read-only WASM param/cipher carrier lint (same engine as CLI `bla lint-wasm-params`). Flags clear ASCII magics such as R3PARM/R3CIPH/R2SEAL with adjacent binary blobs. Bankrupt harden refuses unless allow_wasm_clear_params. Does not encrypt WASM data sections. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a .wasm (or WASM-shaped) file to lint",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_panel_derive",
    description:
      "Read-only panel-derive ABI lint (same engine as CLI `bla lint-panel-derive`). Flags stable __vaultPanelDerive_* / deriveLocal, classic FNV primes, and deriveLocal+panelTokenSha256 offline-oracle packaging. Maximum/bankrupt rewrites ABI unless allow_stable_panel_derive; bankrupt refuses oracle combo unless allow_panel_offline_oracle. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a JS/TS/HTML file to lint",
        },
        allow_stable_panel_derive: {
          type: "boolean",
          description: "Lab escape: allow stable __vaultPanelDerive_* / deriveLocal ABI",
        },
        allow_panel_offline_oracle: {
          type: "boolean",
          description: "Lab escape: allow deriveLocal + panelTokenSha256 offline oracle combo",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_js_aes_unwrap",
    description:
      "Read-only JS AES wrap-key unwrap lint (same engine as CLI `bla lint-js-aes-unwrap`). Flags hex/base64 wrap-key material + createDecipheriv/createCipheriv + fixed sealed hdr (e.g. d17ea004). Bankrupt harden refuses unless allow_js_aes_unwrap. Gate only — not white-box AES. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a JS/TS/HTML file to lint",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_js_wasm_hydrate_dump",
    description:
      "Read-only JS←WASM hydrate param-dump lint (same engine as CLI `bla lint-js-wasm-hydrate-dump`). Flags memory.buffer reads + salt/rounds/cipher layout decode after hydrate/instantiate. Bankrupt harden refuses unless allow_js_wasm_hydrate_dump. Prefer keep ARX+certify inside WASM. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a JS/TS/HTML file to lint",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_wasm_xor_mask_sidecar",
    description:
      "Read-only WASM XOR-mask sidecar lint (same engine as CLI `bla lint-wasm-xor-mask-sidecar`). Flags masked entitlement packs stored beside a plaintext 32-byte XOR mask in WASM data. Bankrupt harden refuses unless allow_wasm_xor_mask_sidecar. Prefer key-dependent unmask + one-way commitments. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a .wasm file to lint",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_wasm_seal_xor_known_plaintext",
    description:
      "Read-only WASM+seal.revision XOR known-plaintext lint (same engine as CLI `bla lint-wasm-seal-xor-known-plaintext`). Flags entitlement packs where public seal.revision sits under a repeating XOR mask in WASM data — recovers the mask with no key (red-blue round-7). Looks for sibling seal.json. Bankrupt harden refuses unless allow_wasm_seal_xor_known_plaintext. Prefer one-way mask KDFs and keep public digests out of masked plaintext. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to a .wasm file (sibling seal.json used when seal_path omitted)",
        },
        seal_path: {
          type: "string",
          description: "Optional explicit seal.json path",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_integrity_coverage",
    description:
      "Read-only integrity coverage matrix lint (Direction-3). Evaluates bla-integrity-coverage/v1 JSON (path to file or directory discovering integrity-coverage.json). Refuses when full coverage / anti-single-point / hashes / connectivity fail. Hash-only — no guessing. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to integrity-coverage.json or a project directory containing one",
        },
        allow_single_point_integrity: {
          type: "boolean",
          description: "Lab escape: report findings without bankrupt refuse semantics",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_run_lookup",
    description:
      "Read-only correlation of a prior harden run: load bla-harden-summary.json by path or output directory, optionally asserting a run_id. Unsigned summaries only — never treats absence as success.",
    inputSchema: {
      type: "object",
      properties: {
        summary_path: {
          type: "string",
          description:
            "Path to bla-harden-summary.json, or the harden output directory that contains it",
        },
        run_id: {
          type: "string",
          description: "Optional expected run_id; mismatch or missing id is an error",
        },
      },
      required: ["summary_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_rea_drift",
    description:
      "Run the REA constant-drift harness (scripts/verify-rea-constants.mjs). This is NOT red-team evidence. Absent sibling REA → status unverified (never a silent pass).",
    inputSchema: {
      type: "object",
      properties: {
        rea_root: {
          type: "string",
          description: "Optional path to a local REA checkout (defaults to REA_ROOT or ../rea)",
        },
      },
      additionalProperties: false,
    },
  },

  {
    name: "bla_polymorph_report",
    description:
      "Compare two hardened artifact directories and report objective structural drift (export-name Jaccard, export-order Kendall-tau, byte-diff ratio, identifier overlap, aggregate driftScore). Honesty: drift ≠ cracking resistance — prove equivalence with bla_verify / REA. expect=same refuses when driftScore is not near zero; expect=different refuses when drift is too low.",
    inputSchema: {
      type: "object",
      properties: {
        dir_a: {
          type: "string",
          description: "First artifact directory (e.g. harden output with seed A)",
        },
        dir_b: {
          type: "string",
          description: "Second artifact directory (e.g. harden output with seed B or a re-run of A)",
        },
        expect: {
          type: "string",
          enum: ["same", "different", "report"],
          description:
            "same → fail unless near-byte-identical; different → fail unless driftScore ≥ threshold; report (default) → metrics only",
        },
        same_threshold: {
          type: "number",
          description: "driftScore upper bound for expect=same (default 0.01)",
        },
        different_threshold: {
          type: "number",
          description: "driftScore lower bound for expect=different (default 0.25)",
        },
      },
      required: ["dir_a", "dir_b"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_encrypt_strings",
    description:
      "Encrypt sensitive string literals in panel.html / license.cjs with a seed-derived XOR keystream and inject a runtime decrypt stub. Reuses SeededPrng.derive(\"string.encrypt\") — never JS AES wrap-key (that footgun is refused by bla_lint_js_aes_unwrap). Honesty: raises static grep cost only; prove equivalence with verify / CrackMe / REA. Writes outputs (or dry_run); an in-place run refuses until confirm_overwrite: true.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "File or directory containing panel.html / license.cjs",
        },
        seed: {
          type: "string",
          description: "Project seed for reproducible XOR keystream",
        },
        out_dir: {
          type: "string",
          description: "Optional output directory (default: in-place)",
        },
        include_urls: {
          type: "boolean",
          description: "Also encrypt http(s) URL literals (default true)",
        },
        dry_run: {
          type: "boolean",
          description: "Report only; write nothing",
        },
        confirm_overwrite: {
          type: "boolean",
          description:
            "Required when the run would rewrite an existing file in place. Re-run with true to confirm.",
        },
      },
      required: ["path", "seed"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_plaintext_secrets",
    description:
      "Read-only lint for cleartext sensitive literals (FLAG{…}, high-entropy tokens, PEM headers, long hex/base64, derive key-name strings) in panel.html / license.cjs. Bankrupt packaging gates refuse error findings unless allow_plaintext_string. URLs are warning-class. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "File or directory to scan",
        },
        allow_plaintext_string: {
          type: "boolean",
          description: "Treat error-class cleartext secrets as non-blocking (lab only)",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_bind_scope",
    description:
      "Optional honest code-lock: write a PUBLIC bind-scope.json (domains + validity window) and inject a deterministic runtime check into license.cjs/entry. Default OFF. Never a covert backdoor — public:true is mandatory; hidden fields refuse. Host for Node comes from BLA_BIND_HOST (or location.hostname in browsers). In-place runs refuse until confirm_overwrite: true.",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Project/artifact directory containing license.cjs (or pass entry_path)",
        },
        domains: {
          type: "array",
          items: { type: "string" },
          maxItems: MAX_STRING_ARRAY_ITEMS,
          description: "Allowed hostnames or *.suffix globs (public)",
        },
        valid_from: {
          type: "string",
          description: "Inclusive ISO 8601 start",
        },
        valid_until: {
          type: "string",
          description: "Inclusive ISO 8601 end",
        },
        entry_path: {
          type: "string",
          description: "Optional entry JS/CJS to inject BLA_BIND_SCOPE_CHECK into",
        },
        out_dir: {
          type: "string",
          description: "Optional output directory (default: in-place)",
        },
        dry_run: {
          type: "boolean",
          description: "Report only; write nothing",
        },
        confirm_overwrite: {
          type: "boolean",
          description:
            "Required when the run would rewrite an existing entry or contract. Re-run with true to confirm.",
        },
      },
      required: ["directory"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_lint_bind_scope",
    description:
      "Read-only lint for bla-bind-scope/v1. Refuses when public≠true, constraints empty, dates/domains invalid, hidden fields present, or bind-scope.json exists without BLA_BIND_SCOPE_CHECK in the entry. Writes nothing.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to bind-scope.json or a project directory",
        },
        allow_missing_bind_runtime: {
          type: "boolean",
          description: "Lab escape: do not refuse missing runtime check / non-public fields",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_redteam_report",
    description:
      "Read (or optionally re-run) the empirical REA red-team report at docs/redteam/empirical-rea-validation.json. On-disk read without execute → status available (not a live REA verdict). execute:true → pass/fail from the harness. Missing report, unready REA, or a harness that could not call this REA checkout for a probe → status unverified (nothing measured; not a verdict on a shield). Live execution requires a trusted absolute REA_ROOT configured by the MCP server operator.",
    inputSchema: {
      type: "object",
      properties: {
        execute: {
          type: "boolean",
          description:
            "Run the local harness against the built REA checkout configured by the server operator. Default false.",
        },
        rea_root: {
          type: "string",
          description: "Optional checkout location for read-mode diagnostics. Live mode uses the operator-configured REA_ROOT.",
        },
        report_path: {
          type: "string",
          description: "Read mode only. Path to a bla-redteam-rea/v1 JSON report under the workspace, BLA package, or BLA state directory.",
        },
      },
      additionalProperties: false,
    },
  },
];

export const BLA_MCP_TOOLS: readonly McpToolDefinition[] = Object.freeze(
  RAW_BLA_MCP_TOOLS.map(withToolAnnotations),
);


export interface McpResourceDefinition {
  readonly uri: string;
  readonly name: string;
  readonly description: string;
  readonly mimeType: string;
}

export const BLA_MCP_RESOURCES: readonly McpResourceDefinition[] = Object.freeze([
  {
    uri: WEAVE_DIRECTIVES_URI,
    name: "weave-decoy-directives",
    description:
      "Chinese-friendly weave-decoy theory + executor checklist for Counter-REA agents (defensive only).",
    mimeType: "text/markdown",
  },
  {
    uri: "bla://docs/weave-decoy-mcp",
    name: "weave-decoy-doc",
    description: `Pointer to repository theory pack ${WEAVE_DECOY_DOC_PATH}`,
    mimeType: "text/markdown",
  },
]);

/** URI prefix of the agent guide (the skill bundle), served so an MCP-only agent can read it. */
export const BLA_SKILL_RESOURCE_PREFIX = "bla://skill/" as const;

function skillResourceDescription(relativePath: string): string {
  if (relativePath === "SKILL.md") {
    return "The full BLA agent guide (the skill): stages, decision tree, how to read a harden report, how to recover. Read this when the skill is not installed in your client.";
  }
  const base = relativePath.replace(/^references\//, "").replace(/\.md$/, "");
  const format = /^format-(.+)$/.exec(base);
  return format
    ? `Skill appendix: what hardening does to ${format[1]} artifacts and what callers can still rely on.`
    : `Skill appendix: ${base}.`;
}

let skillResourceCache:
  | { readonly definitions: readonly McpResourceDefinition[]; readonly bodies: ReadonlyMap<string, string> }
  | undefined;

/**
 * The bundled skill as MCP resources (`bla://skill/SKILL.md`,
 * `bla://skill/references/…`). A client that only registered the server — a
 * checked-in `.mcp.json`, say — has the tools and the short `instructions`,
 * but not the guide; this is how it gets the rest. Bodies are looked up by
 * exact URI, never by joining a path from the request.
 */
function skillResources(): NonNullable<typeof skillResourceCache> {
  if (skillResourceCache !== undefined) return skillResourceCache;
  const definitions: McpResourceDefinition[] = [];
  const bodies = new Map<string, string>();
  let files: ReturnType<typeof resolveBundledSkillBundle> = [];
  try {
    files = resolveBundledSkillBundle();
  } catch {
    files = [];
  }
  for (const file of files) {
    if (!file.relativePath.endsWith(".md")) continue;
    const uri = `${BLA_SKILL_RESOURCE_PREFIX}${file.relativePath}`;
    definitions.push({
      uri,
      name:
        file.relativePath === "SKILL.md"
          ? "bla-skill-guide"
          : `bla-skill-${file.relativePath.replace(/^references\//, "").replace(/\.md$/, "")}`,
      description: skillResourceDescription(file.relativePath),
      mimeType: "text/markdown",
    });
    bodies.set(uri, file.content);
  }
  skillResourceCache = { definitions, bodies };
  return skillResourceCache;
}

/** Every resource the server lists: the weave directives plus the skill bundle. */
export function listBlaMcpResources(): readonly McpResourceDefinition[] {
  return [...BLA_MCP_RESOURCES, ...skillResources().definitions];
}

export const BLA_MCP_PROMPTS: readonly McpPromptDefinition[] = Object.freeze([
  {
    name: "bla-harden-project",
    description:
      "One-sentence Counter-REA hardening: discover every protectable build artifact under a project directory and run bla_harden (audit→defend→verify, bankrupt profile).",
    arguments: [
      {
        name: "directory",
        description: "Project or build directory (default: .)",
        required: false,
      },
    ],
  },
  {
    name: "shield-against-rea",
    description:
      "Audit a build artifact for REA exposure, apply BLA's adversarial shield, and verify the token bankruptcy factor.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the build artifact or directory",
        required: true,
      },
    ],
  },
  {
    name: "bla-hardening-workflow",
    description:
      "Step-by-step release hardening checklist using bla_inspect_release, bla_audit, bla_protect, and bla_verify.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the build artifact or directory",
        required: true,
      },
    ],
  },
  {
    name: "bla-counter-rea",
    description:
      "Evaluate REA reverse-engineering exposure and plan defensive hardening for a software artifact.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the build artifact or directory",
        required: true,
      },
    ],
  },
  {
    name: "bla-weave-decoy",
    description:
      "Plan weave-decoy hardening: read bla://directives/weave-decoy, call bla_weave_plan, then bla_harden with weave_decoys:true. Defensive only.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the project or artifact",
        required: true,
      },
    ],
  },
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Write-confirmation boundary for destructive MCP calls. Returns the existing
 * paths a call would overwrite; the caller refuses unless confirm_overwrite.
 */
function existingPaths(paths: readonly string[]): string[] {
  return paths.filter((p) => existsSync(p));
}

function planHardenOverwrites(
  preview: ReturnType<typeof hardenProject>,
  args: Record<string, unknown>,
  apply: boolean,
  customOutput: boolean,
): string[] {
  const planned = new Set(preview.wouldOverwrite);
  if (preview.artifacts.length === 0) return [...planned];

  let emitManifests = args.sign_manifest === true || args.emit_manifest === true;
  if (!emitManifests && args.emit_manifest === undefined) {
    const configDir = statSync(preview.directory).isDirectory()
      ? preview.directory
      : dirname(preview.directory);
    let loaded = loadBlaConfig(configDir);
    if (!loaded.sourcePath && (BLA_BUILD_OUTPUT_DIR_NAMES as readonly string[]).includes(basename(configDir))) {
      loaded = loadBlaConfig(dirname(configDir));
    }
    emitManifests = loaded.config.emitManifest === true;
  }
  const shadowPaths = preview.artifacts.map((artifact) =>
    joinPath(preview.outputDirectory, artifact.relativePath),
  );
  const skippedBindings = new Set(preview.integrityBindingSkipped?.map((item) => item.relativePath));
  const canWriteCoverage = preview.selfSeal && preview.artifacts.some((artifact) =>
    /\.(mjs|cjs|js|ts|tsx|jsx)$/i.test(artifact.relativePath) &&
    !skippedBindings.has(artifact.relativePath.replaceAll("\\", "/")),
  );
  const auxiliary = [
    joinPath(preview.outputDirectory, HARDEN_SUMMARY_FILE_NAME),
    ...(canWriteCoverage ? [joinPath(preview.outputDirectory, "integrity-coverage.json")] : []),
    ...(emitManifests ? shadowPaths.map((path) => `${path}.bla-manifest.json`) : []),
  ];
  const writes = !apply || customOutput ? [...shadowPaths, ...auxiliary] : [];
  if (apply && emitManifests) {
    writes.push(...preview.artifacts.map((artifact) => `${artifact.inputPath}.bla-manifest.json`));
  }
  for (const path of writes) {
    if (lstatSync(path, { throwIfNoEntry: false })) planned.add(path);
  }
  return [...planned];
}

function confirmationRequiredPayload(
  tool: string,
  wouldOverwrite: readonly string[],
  action?: "apply" | "restore",
): Record<string, unknown> {
  const n = wouldOverwrite.length;
  // Say what the overwrite is: "choose a new output path" is no way out of an
  // apply or a restore, and the user is being asked about their build output.
  const what =
    action === "restore"
      ? `${tool} restore would put the original file(s) back over ${n} hardened file(s) in the build output`
      : action === "apply"
        ? `${tool} apply would replace ${n} build-output file(s) with their hardened versions (the originals are kept outside the project; restore: true brings them back)`
        : `${tool} would overwrite ${n} existing file(s)`;
  return {
    status: "confirmation_required",
    tool,
    wrote: [],
    wouldOverwrite,
    message: `${what}; nothing was written. Confirm with the user, then retry with confirm_overwrite: true${action === undefined ? " (or choose a new output path)" : ""}.`,
  };
}

function writeReceipt(
  outputs: readonly string[],
  overwritten: readonly string[],
  confirmed: boolean,
): Record<string, unknown> {
  return { status: "written", wrote: outputs, overwrote: overwritten, confirmed };
}

/**
 * Planned write targets for `bla_bind_scope`, resolved with a zero-write
 * dry run so the overwrite gate can name the exact files before anything is
 * mutated. An invalid contract returns `[]` here so the real run surfaces the
 * contract error instead of a misleading confirmation request.
 */
function plannedBindScopeWrites(
  options: Parameters<typeof applyBindScope>[0],
): string[] {
  const preview = applyBindScope({ ...options, dryRun: true });
  if (preview.status === "error") return [];
  return [preview.contractPath, preview.entryPath].filter(
    (p): p is string => typeof p === "string" && p.length > 0,
  );
}

function attachArtifactRunEvidence(
  tool: string,
  inputPath: string,
  report: Record<string, unknown>,
): Record<string, unknown> {
  const outputPath =
    typeof report.outputPath === "string" ? report.outputPath : undefined;
  if (outputPath === undefined || !existsSync(outputPath)) {
    return {
      ...report,
      runEvidence: {
        signature: "unsigned",
        status: "unverified",
        reason: "Protected output path missing; cannot content-address this run",
      },
    };
  }
  const outputSha256 = sha256File(outputPath);
  const runId = computeArtifactRunId({
    tool,
    inputPath,
    outputPath,
    outputSha256,
  });
  return {
    ...report,
    runId,
    runEvidence: {
      schema: "bla-artifact-run/v1",
      signature: "unsigned",
      runId,
      outputPath,
      outputSha256,
    },
  };
}


function optionalCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : undefined;
}

function optionalOffset(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.floor(value)
    : undefined;
}

function stringListArg(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const list = value.filter((x): x is string => typeof x === "string" && x.length > 0);
  return list.length > 0 ? list : undefined;
}

/**
 * Tool results land in the calling agent's context window, so they must stay
 * small. An audit lists every exposed item; after hardening that list is the
 * injected decoys themselves — megabytes for one WASM module (a single
 * `bla_defend` returned 6 MB, with 12 KB decoy export names). Keep the head of
 * each list plus its true count, clip oversized names, and state the coverage
 * contract once instead of once per nested audit. The CLI (`--json`) still
 * prints everything.
 */
const MAX_EXPOSED_ITEMS_BEFORE = 40;
const MAX_EXPOSED_ITEMS_AFTER = 8;
const MAX_EXPOSED_ITEM_TEXT = 160;

function clipExposedItemText(item: unknown): unknown {
  if (typeof item !== "object" || item === null) return item;
  let clipped: Record<string, unknown> | undefined;
  for (const [key, value] of Object.entries(item as Record<string, unknown>)) {
    if (typeof value !== "string" || value.length <= MAX_EXPOSED_ITEM_TEXT) continue;
    clipped ??= { ...(item as Record<string, unknown>) };
    clipped[key] =
      `${value.slice(0, MAX_EXPOSED_ITEM_TEXT)}…[+${value.length - MAX_EXPOSED_ITEM_TEXT} chars]`;
  }
  return clipped ?? item;
}

function compactAudit(audit: unknown, maxItems: number): unknown {
  if (typeof audit !== "object" || audit === null) return audit;
  const record = { ...(audit as Record<string, unknown>) };
  const items = record.exposedItems;
  if (Array.isArray(items)) {
    record.exposedItems = items.slice(0, maxItems).map(clipExposedItemText);
    if (items.length > maxItems) {
      record.exposedItemsTotal = items.length;
      record.exposedItemsTruncated = true;
    }
  }
  // "Fix now: bla-agents protect <file>" is advice for an exposed artifact;
  // on one that is already shielded it would have the agent protect it twice.
  if (record.protectionStatus === "BLA_PROTECTED") delete record.recommendedCommand;
  return record;
}

function withoutCoverageContract(value: unknown): unknown {
  if (typeof value !== "object" || value === null) return value;
  const { coverageContract: _dropped, ...rest } = value as Record<string, unknown>;
  return rest;
}

function compactArtifactReport(report: unknown): unknown {
  if (typeof report !== "object" || report === null) return report;
  let out = { ...(report as Record<string, unknown>) };
  // `bla_audit`: the report is the audit itself.
  if ("exposedItems" in out) {
    return compactAudit(out, MAX_EXPOSED_ITEMS_BEFORE);
  }
  if ("beforeAudit" in out) out.beforeAudit = compactAudit(out.beforeAudit, MAX_EXPOSED_ITEMS_BEFORE);
  if ("afterAudit" in out) out.afterAudit = compactAudit(out.afterAudit, MAX_EXPOSED_ITEMS_AFTER);
  const protection = out.protection;
  if (typeof protection === "object" && protection !== null) {
    const { beforeAudit: nestedBefore, ...rest } = protection as Record<string, unknown>;
    out.protection = {
      ...rest,
      // The defend report already carries the same audit at the top level.
      ...("beforeAudit" in out || nestedBefore === undefined
        ? {}
        : { beforeAudit: compactAudit(nestedBefore, MAX_EXPOSED_ITEMS_BEFORE) }),
      ...("afterAudit" in rest
        ? { afterAudit: compactAudit(rest.afterAudit, MAX_EXPOSED_ITEMS_AFTER) }
        : {}),
    };
  }

  // One coverage contract for the whole result — the one describing the final
  // artifact — instead of an identical 1.7 KB block under every nested report.
  const nestedProtection = out.protection as Record<string, unknown> | undefined;
  const contractHolders: unknown[] = [
    out.verification,
    nestedProtection?.afterAudit,
    out.afterAudit,
    nestedProtection?.beforeAudit,
    out.beforeAudit,
  ];
  const contract = contractHolders
    .map((holder) =>
      typeof holder === "object" && holder !== null
        ? (holder as Record<string, unknown>).coverageContract
        : undefined,
    )
    .find((candidate) => candidate !== undefined);
  if (contract !== undefined) {
    if ("verification" in out) out.verification = withoutCoverageContract(out.verification);
    if ("beforeAudit" in out) out.beforeAudit = withoutCoverageContract(out.beforeAudit);
    if ("afterAudit" in out) out.afterAudit = withoutCoverageContract(out.afterAudit);
    if (nestedProtection !== undefined) {
      out.protection = {
        ...nestedProtection,
        ...("afterAudit" in nestedProtection
          ? { afterAudit: withoutCoverageContract(nestedProtection.afterAudit) }
          : {}),
        ...("beforeAudit" in nestedProtection
          ? { beforeAudit: withoutCoverageContract(nestedProtection.beforeAudit) }
          : {}),
      };
    }
    out = { ...out, coverageContract: contract };
  }
  return out;
}

function runDefend(handlers: McpEngineHandlers, args: Record<string, unknown>): unknown {
  const wasmPreserveExports = stringListArg(args.wasm_preserve_exports);
  return handlers.defendTarget({
    inputPath: args.input_path as string,
    ...(typeof args.output_path === "string"
      ? { outputPath: args.output_path }
      : {}),
    ...(args.in_place === true ? { inPlace: true } : {}),
    intensity:
      typeof args.intensity === "string"
        ? (args.intensity as ProtectionIntensity)
        : "bankrupt",
    emitManifest: Boolean(args.emit_manifest) || args.sign_manifest === true,
    ...(args.sign_manifest === true
      ? {
          signManifest: true,
          manifestSigningKeyPath:
            typeof args.manifest_key_path === "string" ? args.manifest_key_path : "",
        }
      : {}),
    llmDirectives: Boolean(args.llm_directives),
    weaveDecoys: Boolean(args.weave_decoys),
    selfSeal: Boolean(args.self_seal),
    sidecarEntangle: Boolean(args.sidecar_entangle),
    ...(args.sqlite_eval_trap === true ? { sqliteEvalTrap: true } : {}),
    ...(args.require_agent_weave === true ? { requireAgentWeave: true } : {}),
    ...(wasmPreserveExports !== undefined ? { wasmPreserveExports } : {}),
    ...(args.allow_lane_independent === true
      ? { allowLaneIndependentGates: true }
      : {}),
    ...(args.allow_plaintext_seal === true ? { allowPlaintextSeal: true } : {}),
    ...(args.allow_wasm_clear_params === true
      ? { allowWasmClearParamCarriers: true }
      : {}),
    ...(args.allow_stable_panel_derive === true
      ? { allowStablePanelDeriveAbi: true }
      : {}),
    ...(args.allow_js_aes_unwrap === true ? { allowJsAesUnwrap: true } : {}),
    ...(args.allow_panel_offline_oracle === true
      ? { allowPanelOfflineOracle: true }
      : {}),
    ...(args.allow_js_wasm_hydrate_dump === true
      ? { allowJsWasmHydrateDump: true }
      : {}),
    ...(args.allow_wasm_xor_mask_sidecar === true
      ? { allowWasmXorMaskSidecar: true }
      : {}),
    ...(args.allow_wasm_seal_xor_known_plaintext === true
      ? { allowWasmSealXorKnownPlaintext: true }
      : {}),
    ...(args.allow_release_hygiene_leak === true
      ? { allowReleaseHygieneLeak: true }
      : {}),
    ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
  });
}

function runProtect(handlers: McpEngineHandlers, args: Record<string, unknown>): unknown {
  const wasmPreserveExports = stringListArg(args.wasm_preserve_exports);
  return handlers.protectTarget({
    inputPath: args.input_path as string,
    ...(typeof args.output_path === "string" ? { outputPath: args.output_path } : {}),
    ...(args.in_place === true ? { inPlace: true } : {}),
    ...(typeof args.intensity === "string"
      ? { intensity: args.intensity as ProtectionIntensity }
      : {}),
    ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
    llmDirectives: Boolean(args.llm_directives),
    weaveDecoys: Boolean(args.weave_decoys),
    selfSeal: Boolean(args.self_seal),
    sidecarEntangle: Boolean(args.sidecar_entangle),
    ...(args.sqlite_eval_trap === true ? { sqliteEvalTrap: true } : {}),
    ...(typeof args.honey_source_maps === "boolean"
      ? { honeySourceMaps: args.honey_source_maps }
      : {}),
    ...(wasmPreserveExports !== undefined ? { wasmPreserveExports } : {}),
    ...(args.allow_lane_independent === true
      ? { allowLaneIndependentGates: true }
      : {}),
    ...(args.allow_plaintext_seal === true ? { allowPlaintextSeal: true } : {}),
    ...(args.allow_wasm_clear_params === true
      ? { allowWasmClearParamCarriers: true }
      : {}),
    ...(args.allow_stable_panel_derive === true
      ? { allowStablePanelDeriveAbi: true }
      : {}),
    ...(args.allow_js_aes_unwrap === true ? { allowJsAesUnwrap: true } : {}),
    ...(args.allow_panel_offline_oracle === true
      ? { allowPanelOfflineOracle: true }
      : {}),
    ...(args.allow_js_wasm_hydrate_dump === true
      ? { allowJsWasmHydrateDump: true }
      : {}),
    ...(args.allow_wasm_xor_mask_sidecar === true
      ? { allowWasmXorMaskSidecar: true }
      : {}),
    ...(args.allow_wasm_seal_xor_known_plaintext === true
      ? { allowWasmSealXorKnownPlaintext: true }
      : {}),
    ...(args.allow_release_hygiene_leak === true
      ? { allowReleaseHygieneLeak: true }
      : {}),
  });
}

function verifyHonestyOptions(args: Record<string, unknown>): VerifyTargetOptions {
  return {
    ...(typeof args.self_seal_enabled === "boolean"
      ? { selfSealEnabled: args.self_seal_enabled }
      : {}),
    ...(typeof args.sidecar_entangle_enabled === "boolean"
      ? { sidecarEntangleEnabled: args.sidecar_entangle_enabled }
      : {}),
    ...(typeof args.wasm_export_rename_applied === "boolean"
      ? { wasmExportRenameApplied: args.wasm_export_rename_applied }
      : {}),
    ...(typeof args.numeric_template_leak_known === "boolean"
      ? { numericTemplateLeakKnown: args.numeric_template_leak_known }
      : {}),
  };
}

function runPackagingGatesLint(args: Record<string, unknown>): PackagingGatesReport {
  const directory =
    typeof args.directory === "string" && args.directory.length > 0
      ? resolvePath(args.directory)
      : process.cwd();
  const intensity =
    args.intensity === "stealth" ||
    args.intensity === "balanced" ||
    args.intensity === "maximum" ||
    args.intensity === "bankrupt"
      ? args.intensity
      : "bankrupt";
  return scanPackagingGates({
    directory,
    intensity,
    includeProtectTimeGates: true,
    ...(args.allow_plaintext_seal === true ? { allowPlaintextSeal: true } : {}),
    ...(args.allow_wasm_clear_params === true
      ? { allowWasmClearParamCarriers: true }
      : {}),
    ...(args.allow_js_aes_unwrap === true ? { allowJsAesUnwrap: true } : {}),
    ...(args.allow_js_wasm_hydrate_dump === true
      ? { allowJsWasmHydrateDump: true }
      : {}),
    ...(args.allow_wasm_xor_mask_sidecar === true
      ? { allowWasmXorMaskSidecar: true }
      : {}),
    ...(args.allow_wasm_seal_xor_known_plaintext === true
      ? { allowWasmSealXorKnownPlaintext: true }
      : {}),
    ...(args.allow_lane_independent === true
      ? { allowLaneIndependentGates: true }
      : {}),
    ...(args.allow_stable_panel_derive === true
      ? { allowStablePanelDeriveAbi: true }
      : {}),
    ...(args.allow_panel_offline_oracle === true
      ? { allowPanelOfflineOracle: true }
      : {}),
    ...(args.allow_plaintext_string === true
      ? { allowPlaintextString: true }
      : {}),
    ...(args.allow_single_point_integrity === true
      ? { allowSinglePointIntegrity: true }
      : {}),
    ...(args.allow_missing_bind_runtime === true
      ? { allowMissingBindRuntime: true }
      : {}),
    ...(args.allow_release_hygiene_leak === true
      ? { allowReleaseHygieneLeak: true }
      : {}),
  });
}

function runLintLanes(args: Record<string, unknown>): LaneIndependenceReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-lanes target not found: ${abs}`);
  }
  const source = readFileSync(abs, "utf8");
  return lintLaneIndependence(source);
}

function runLintSeal(args: Record<string, unknown>): SealCommitmentReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-seal target not found: ${abs}`);
  }
  return lintSealCommitmentFile(abs);
}

function runLintWasmParams(args: Record<string, unknown>): WasmParamCarrierReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-wasm-params target not found: ${abs}`);
  }
  return lintWasmParamCarrierFile(abs);
}

function runLintPanelDerive(args: Record<string, unknown>): PanelDeriveAbiReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-panel-derive target not found: ${abs}`);
  }
  return lintPanelDeriveAbiFile(abs);
}

function runLintJsAesUnwrap(args: Record<string, unknown>): JsAesUnwrapReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-js-aes-unwrap target not found: ${abs}`);
  }
  return lintJsAesUnwrapFile(abs);
}

function runLintJsWasmHydrateDump(args: Record<string, unknown>): JsWasmHydrateDumpReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-js-wasm-hydrate-dump target not found: ${abs}`);
  }
  return lintJsWasmHydrateDumpFile(abs);
}

function runLintWasmXorMaskSidecar(args: Record<string, unknown>): WasmXorMaskSidecarReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-wasm-xor-mask-sidecar target not found: ${abs}`);
  }
  return lintWasmXorMaskSidecarFile(abs);
}

function runLintWasmSealXorKnownPlaintext(args: Record<string, unknown>): WasmSealXorKnownPlaintextReport {
  const abs = resolvePath(args.path as string);
  if (!existsSync(abs)) {
    throw new Error(`lint-wasm-seal-xor-known-plaintext target not found: ${abs}`);
  }
  const seal =
    typeof args.seal_path === "string" && args.seal_path.trim().length > 0
      ? resolvePath(args.seal_path as string)
      : undefined;
  return lintWasmSealXorKnownPlaintextFile(abs, seal);
}

export function validateMcpToolCall(
  params: unknown,
):
  | {
      readonly ok: true;
      readonly tool: McpToolDefinition;
      readonly args: Record<string, unknown>;
    }
  | {
      readonly ok: false;
      readonly code: -32601 | -32602;
      readonly message: string;
    } {
  if (!isPlainObject(params)) {
    return {
      ok: false,
      code: -32602,
      message: "Invalid params: tool call params must be a JSON object",
    };
  }

  if (typeof params.name !== "string" || params.name.trim().length === 0) {
    return {
      ok: false,
      code: -32602,
      message: "Invalid params: tool 'name' must be a non-empty string",
    };
  }

  const tool = BLA_MCP_TOOLS.find((t) => t.name === params.name);
  if (!tool) {
    return {
      ok: false,
      code: -32602,
      message: `Invalid params: unknown BLA MCP tool '${params.name}'`,
    };
  }

  const rawArgs = params.arguments;
  const requiredFields = tool.inputSchema.required ?? [];

  if (rawArgs === undefined) {
    if (requiredFields.length > 0) {
      return {
        ok: false,
        code: -32602,
        message: `Invalid params for '${tool.name}': missing required arguments (${requiredFields.join(", ")})`,
      };
    }
    return { ok: true, tool, args: {} };
  }

  if (!isPlainObject(rawArgs)) {
    return {
      ok: false,
      code: -32602,
      message: `Invalid params for '${tool.name}': 'arguments' must be a JSON object`,
    };
  }

  // Reject unexpected properties when additionalProperties is false
  const allowedProps = tool.inputSchema.properties;
  for (const key of Object.keys(rawArgs)) {
    if (!(key in allowedProps)) {
      return {
        ok: false,
        code: -32602,
        message: `Invalid params for '${tool.name}': unknown argument '${key}'`,
      };
    }
  }

  // Validate required properties
  for (const reqKey of requiredFields) {
    if (!(reqKey in rawArgs) || rawArgs[reqKey] === undefined || rawArgs[reqKey] === null) {
      return {
        ok: false,
        code: -32602,
        message: `Invalid params for '${tool.name}': missing required argument '${reqKey}'`,
      };
    }
  }

  // Validate types, non-empty strings, numbers, booleans, and enums
  for (const [key, val] of Object.entries(rawArgs)) {
    if (val === undefined) continue;
    const propSchema = allowedProps[key];
    if (!propSchema) continue;

    if (propSchema.type === "string") {
      if (typeof val !== "string") {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a string, received ${val === null ? "null" : typeof val}`,
        };
      }
      if (val.trim().length === 0) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a non-empty string`,
        };
      }
      const maxLen = propSchema.maxLength ?? MAX_STRING_ARG_CHARS;
      if (val.length > maxLen) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' exceeds the ${maxLen}-character limit (received ${val.length})`,
        };
      }
      if (propSchema.enum && !propSchema.enum.includes(val)) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be one of [${propSchema.enum.join(", ")}], received '${val}'`,
        };
      }
    } else if (propSchema.type === "boolean") {
      if (typeof val !== "boolean") {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a boolean`,
        };
      }
    } else if (propSchema.type === "number") {
      const allowZero =
        key === "offset" || key.endsWith("_threshold") || key === "fail_under";
      const integerOnly = propSchema.integer === true;
      if (
        typeof val !== "number" ||
        !Number.isFinite(val) ||
        (integerOnly && !Number.isInteger(val)) ||
        (allowZero ? val < 0 : val <= 0)
      ) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a ${allowZero ? "non-negative" : "positive"} ${
            integerOnly ? "integer" : "finite number"
          }`,
        };
      }
      if (val > MAX_NUMERIC_ARG) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' exceeds the ${MAX_NUMERIC_ARG} magnitude limit (received ${val})`,
        };
      }
    } else if (propSchema.type === "array") {
      if (!Array.isArray(val)) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be an array, received ${val === null ? "null" : typeof val}`,
        };
      }
      const maxItems = propSchema.maxItems ?? MAX_STRING_ARRAY_ITEMS;
      if (val.length > maxItems) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must hold at most ${maxItems} items, received ${val.length}`,
        };
      }
      if (propSchema.items?.type === "string") {
        for (let i = 0; i < val.length; i++) {
          if (typeof val[i] !== "string" || (val[i] as string).trim().length === 0) {
            return {
              ok: false,
              code: -32602,
              message: `Invalid params for '${tool.name}': item ${i} in '${key}' must be a non-empty string`,
            };
          }
        }
      }
    }
  }

  return { ok: true, tool, args: rawArgs };
}

function isRequestId(value: unknown): value is string | number {
  return typeof value === "string" || (typeof value === "number" && Number.isFinite(value));
}

function isJsonRpcRequest(value: unknown): value is JsonRpcRequest {
  return isPlainObject(value) && value.jsonrpc === "2.0" && typeof value.method === "string" &&
    (value.id === undefined || value.id === null || isRequestId(value.id)) &&
    (value.params === undefined || isPlainObject(value.params) || Array.isArray(value.params));
}

function invalidRequest(value: unknown): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id: isPlainObject(value) && isRequestId(value.id) ? value.id : null,
    error: { code: -32600, message: "Invalid Request: expected JSON-RPC 2.0 request object" },
  };
}

function cancellationOf(req: JsonRpcRequest): { requestId: string | number; reason: string } | undefined {
  if (req.id !== undefined || !isPlainObject(req.params)) return undefined;
  const { requestId, reason } = req.params;
  if (!isRequestId(requestId) || (reason !== undefined && typeof reason !== "string")) return undefined;
  return { requestId, reason: reason ?? "cancelled" };
}

export async function handleMcpRequest(
  req: unknown,
  handlers: McpEngineHandlers = DEFAULT_ENGINE_HANDLERS,
): Promise<JsonRpcResponse | null> {
  if (!isJsonRpcRequest(req)) return invalidRequest(req);

  if (req.method === "notifications/cancelled") {
    const cancellation = cancellationOf(req);
    if (cancellation) activeHardenAborts.get(cancellation.requestId)?.abort(cancellation.reason);
    if (req.id !== undefined) {
      return {
        jsonrpc: "2.0", id: req.id,
        error: { code: -32600, message: "Cancellation must be sent as a notification without an id" },
      };
    }
    return null;
  }

  // Notifications without an `id` do not produce a response
  if (req.id === undefined) {
    return null;
  }

  try {
    switch (req.method) {
      case "initialize": {
        if (req.params !== undefined && !isPlainObject(req.params)) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: initialize params must be an object",
            },
          };
        }
        const requestedVersion = req.params?.protocolVersion;
        if (requestedVersion !== undefined && typeof requestedVersion !== "string") {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: protocolVersion must be a string",
            },
          };
        }
        const negotiatedVersion =
          typeof requestedVersion !== "string"
            ? OLDEST_MCP_PROTOCOL_VERSION
            : (SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]).includes(requestedVersion)
              ? requestedVersion
              : LATEST_MCP_PROTOCOL_VERSION;

        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            protocolVersion: negotiatedVersion,
            capabilities: {
              tools: {},
              prompts: {},
              resources: {},
            },
            serverInfo: {
              name: BLA_IDENTITY.mcpServerName,
              version: BLA_IDENTITY.version,
            },
            instructions: BLA_MCP_INSTRUCTIONS,
          },
        };
      }

      case "ping":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {},
        };

      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            tools: BLA_MCP_TOOLS,
          },
        };

      case "resources/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            resources: listBlaMcpResources(),
          },
        };

      case "resources/read": {
        if (!isPlainObject(req.params) || typeof req.params.uri !== "string") {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: resources/read requires a string 'uri'",
            },
          };
        }
        const uri = req.params.uri;
        const skillBody = skillResources().bodies.get(uri);
        const known = BLA_MCP_RESOURCES.find((r) => r.uri === uri);
        if (!known && skillBody === undefined) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: unknown resource URI '${uri}'`,
            },
          };
        }
        // The doc resource is a pointer: returning the directives a second
        // time under another URI only spends the reader's context twice.
        const markdown =
          skillBody !== undefined
            ? skillBody
            : uri === WEAVE_DIRECTIVES_URI
              ? getWeaveDirectivesMarkdown()
              : `# Weave-decoy theory pack\n\nThe executable checklist is the resource \`${WEAVE_DIRECTIVES_URI}\` — read that one. The longer theory pack lives in the BLA repository at \`${WEAVE_DECOY_DOC_PATH}\` and is not shipped in the npm package.\n`;
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            contents: [
              {
                uri,
                mimeType: "text/markdown",
                text: markdown,
              },
            ],
          },
        };
      }

      case "prompts/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            prompts: BLA_MCP_PROMPTS,
          },
        };

      case "prompts/get": {
        if (!isPlainObject(req.params) || typeof req.params.name !== "string") {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: prompts/get requires a string 'name'",
            },
          };
        }
        const promptName = req.params.name;
        const promptDef = BLA_MCP_PROMPTS.find((p) => p.name === promptName);
        if (!promptDef) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: unknown prompt '${req.params.name}'`,
            },
          };
        }
        // Arguments may be omitted when the prompt has no required arguments
        // (e.g. bla-harden-project); only a present-but-malformed value errors.
        if (req.params.arguments !== undefined && !isPlainObject(req.params.arguments)) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: prompt '${promptDef.name}' requires an 'arguments' object`,
            },
          };
        }
        const promptArgs: Record<string, unknown> = isPlainObject(req.params.arguments)
          ? req.params.arguments
          : {};
        for (const argSpec of promptDef.arguments) {
          if (argSpec.required) {
            const val = promptArgs[argSpec.name];
            if (typeof val !== "string" || val.trim().length === 0) {
              return {
                jsonrpc: "2.0",
                id: req.id,
                error: {
                  code: -32602,
                  message: `Invalid params: prompt '${promptDef.name}' requires non-empty string argument '${argSpec.name}'`,
                },
              };
            }
          }
        }
        let promptText: string;
        if (promptDef.name === "bla-harden-project") {
          const directory =
            typeof promptArgs.directory === "string" && promptArgs.directory.trim().length > 0
              ? String(promptArgs.directory)
              : ".";
          promptText =
            `Harden my software against REA: call bla_harden with { "directory": ${JSON.stringify(directory)} }. ` +
            `It auto-discovers build outputs, runs audit→defend→verify with the bankrupt profile on every artifact, and returns a per-artifact summary. ` +
            `Do not ask which files to protect — discover them. ` +
            `To preview without writing, pass dry_run: true. If the tool returns confirmation_required, ask the user before retrying with confirm_overwrite: true. ` +
            `Then follow the result's nextSteps: the run writes a partial mirror that is not shipped yet, so promote it into the build output with apply: true (the originals are backed up; restore: true undoes it) and run the project's own tests against the promoted build before calling it done. ` +
            `isError: true means the run did not succeed — read artifacts[].error and nextSteps instead of retrying unchanged.`;
        } else if (promptDef.name === "bla-weave-decoy") {
          const targetPath =
            typeof promptArgs.target_path === "string" && promptArgs.target_path.trim().length > 0
              ? String(promptArgs.target_path)
              : ".";
          promptText =
            `Defensive weave-decoy only (no crack/RE): read resource ${WEAVE_DIRECTIVES_URI}, call bla_weave_plan with { "path": ${JSON.stringify(targetPath)} } to inspect surgicalWorkorder, weave domain-plausible helpers sharing state slots, verify with bla_verify_weave, then call bla_harden with { "directory": ${JSON.stringify(targetPath)}, "weave_decoys": true }. Do not add dismissible honeypot noise layers.`;
        } else {
          const targetPath = JSON.stringify(String(promptArgs.target_path ?? "."));
          const shared =
            `Defensive only; use existing bla_* tools, never invent new ones. ` +
            `Writes that would overwrite existing outputs return confirmation_required — ask the user before retrying with confirm_overwrite: true.`;
          if (promptDef.name === "shield-against-rea") {
            promptText =
              `Shield ${targetPath} against REA: audit it (bla_audit), apply one shield (bla_protect, or bla_defend for the full pipeline), then report bla_verify checks and defenseScore. ${shared}`;
          } else if (promptDef.name === "bla-hardening-workflow") {
            promptText =
              `Release-hardening for ${targetPath}: check leaks with bla_inspect_release, audit with bla_audit, review findings with the user, then protect/defend and verify. For a whole project directory prefer bla_harden (dry_run: true to preview). ${shared}`;
          } else {
            promptText =
              `Evaluate REA exposure for ${targetPath} with bla_audit and propose a hardening plan (intensity, output location, opt-in layers) before applying anything; keep audit estimates distinct from measured redteam evidence. ${shared}`;
          }
        }
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            description: promptDef.description,
            messages: [
              {
                role: "user",
                content: {
                  type: "text",
                  text: promptText,
                },
              },
            ],
          },
        };
      }

      case "tools/call": {
        const validated = validateMcpToolCall(req.params);
        if (!validated.ok) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: validated.code,
              message: validated.message,
            },
          };
        }

        const { tool, args } = validated;
        const name = tool.name;
        let payload: unknown;

        let refused = false;
        const confirmed = args.confirm_overwrite === true;
        if (name === "bla_discover") {
          const offset = optionalOffset(args.offset);
          payload = discoverHardenTargets(
            typeof args.directory === "string" && args.directory.trim().length > 0
              ? args.directory
              : process.cwd(),
            {
              ...(optionalCount(args.max_artifacts) !== undefined
                ? { maxArtifacts: optionalCount(args.max_artifacts)! }
                : {}),
              ...(offset !== undefined ? { offset } : {}),
              ...(stringListArg(args.exclude) !== undefined
                ? { exclude: stringListArg(args.exclude)! }
                : {}),
            },
          );
        } else if (name === "bla_harden") {
          const hardenDir =
            typeof args.directory === "string" && args.directory.trim().length > 0
              ? (args.directory as string)
              : process.cwd();
          const maxArtifacts = optionalCount(args.max_artifacts);
          const dryRun = args.dry_run === true;
          const outputDirectory =
            typeof args.output_directory === "string" &&
            args.output_directory.trim().length > 0
              ? (args.output_directory as string)
              : undefined;
          const applyMode = args.apply === true;
          const exclude = stringListArg(args.exclude);
          let preOverwrite: readonly string[] = [];
          if (args.restore === true) {
            if (applyMode) {
              throw new Error("apply and restore cannot be combined");
            }
            const hardenRoot = resolvePath(hardenDir);
            const pending = listAppliedFiles(
              hardenRoot,
              resolveApplyStateDirectory(hardenRoot),
            ).map((rel) => joinPath(hardenRoot, rel));
            if (pending.length > 0 && !confirmed && !dryRun) {
              refused = true;
              payload = confirmationRequiredPayload(name, pending, "restore");
            } else if (dryRun) {
              payload = { status: "planned", restored: pending };
            } else {
              const restored = restoreHardenedProject(hardenRoot, {
                clearStaleLock: args.clear_stale_lock === true,
              });
              refused = restored.status === "failed";
              payload = restored;
            }
          } else {
          if (!dryRun && existsSync(hardenDir)) {
            // Zero-write preview with the real engine to find clobbered outputs
            // (with apply: the build-output files that would be replaced).
            const preview = hardenProject({
              directory: hardenDir,
              dryRun: true,
              ...(applyMode ? { apply: true } : {}),
              ...(maxArtifacts !== undefined ? { maxArtifacts } : {}),
              ...(outputDirectory !== undefined ? { outputDirectory } : {}),
              ...(exclude !== undefined ? { exclude } : {}),
              ...(typeof args.self_seal === "boolean" ? { selfSeal: args.self_seal } : {}),
              ...(args.clear_stale_lock === true ? { clearStaleLock: true } : {}),
            });
            preOverwrite = planHardenOverwrites(preview, args, applyMode, outputDirectory !== undefined);
          }
          if (!dryRun && preOverwrite.length > 0 && !confirmed) {
            refused = true;
            payload = confirmationRequiredPayload(
              name,
              preOverwrite,
              applyMode ? "apply" : undefined,
            );
          } else {
            const wasmPreserveExports = stringListArg(args.wasm_preserve_exports);
            const preAborted =
              typeof req.id === "string" || typeof req.id === "number"
                ? preAbortedHardenRequests.get(req.id)
                : undefined;
            const abortCtl = preAborted ?? new AbortController();
            if (typeof req.id === "string" || typeof req.id === "number") {
              preAbortedHardenRequests.delete(req.id);
              activeHardenAborts.set(req.id, abortCtl);
            }
            const progressToken = progressTokenOf(req);
            let report;
            try {
              report = handlers.hardenProject({
                directory: hardenDir,
                dryRun,
                ...(applyMode ? { apply: true } : {}),
                ...(maxArtifacts !== undefined ? { maxArtifacts } : {}),
                ...(outputDirectory !== undefined ? { outputDirectory } : {}),
                ...(exclude !== undefined ? { exclude } : {}),
                ...(typeof args.intensity === "string"
                  ? { intensity: args.intensity as ProtectionIntensity }
                  : {}),
                ...(typeof args.emit_manifest === "boolean" || args.sign_manifest === true
                  ? { emitManifest: Boolean(args.emit_manifest) || args.sign_manifest === true }
                  : {}),
                ...(args.sign_manifest === true
                  ? {
                      signManifest: true,
                      manifestSigningKeyPath:
                        typeof args.manifest_key_path === "string" ? args.manifest_key_path : "",
                    }
                  : {}),
                ...(typeof args.llm_directives === "boolean"
                  ? { llmDirectives: args.llm_directives }
                  : {}),
                ...(typeof args.weave_decoys === "boolean"
                  ? { weaveDecoys: args.weave_decoys }
                  : {}),
                ...(typeof args.self_seal === "boolean"
                  ? { selfSeal: args.self_seal }
                  : {}),
                ...(args.clear_stale_lock === true ? { clearStaleLock: true } : {}),
                ...(typeof args.sidecar_entangle === "boolean"
                  ? { sidecarEntangle: args.sidecar_entangle }
                  : {}),
                ...(args.sqlite_eval_trap === true ? { sqliteEvalTrap: true } : {}),
                ...(typeof args.require_agent_weave === "boolean"
                  ? { requireAgentWeave: args.require_agent_weave }
                  : {}),
                ...(wasmPreserveExports !== undefined ? { wasmPreserveExports } : {}),
                ...(args.allow_lane_independent === true
                  ? { allowLaneIndependentGates: true }
                  : {}),
                ...(args.allow_plaintext_seal === true ? { allowPlaintextSeal: true } : {}),
                ...(args.allow_wasm_clear_params === true
                  ? { allowWasmClearParamCarriers: true }
                  : {}),
                ...(args.allow_stable_panel_derive === true
                  ? { allowStablePanelDeriveAbi: true }
                  : {}),
                ...(args.allow_js_aes_unwrap === true ? { allowJsAesUnwrap: true } : {}),
                ...(args.allow_panel_offline_oracle === true
                  ? { allowPanelOfflineOracle: true }
                  : {}),
                ...(args.allow_js_wasm_hydrate_dump === true
                  ? { allowJsWasmHydrateDump: true }
                  : {}),
                ...(args.allow_wasm_xor_mask_sidecar === true
                  ? { allowWasmXorMaskSidecar: true }
                  : {}),
                ...(args.allow_wasm_seal_xor_known_plaintext === true
                  ? { allowWasmSealXorKnownPlaintext: true }
                  : {}),
                ...(args.allow_release_hygiene_leak === true
                  ? { allowReleaseHygieneLeak: true }
                  : {}),
                ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
                signal: abortCtl.signal,
                onProgress: (ev) => {
                  if (progressToken === undefined) return;
                  if (ev.phase === "artifact") {
                    emitMcpProgress(
                      progressToken,
                      ev.index + 1,
                      ev.total,
                      ev.relativePath ?? `artifact ${ev.index + 1}/${ev.total}`,
                    );
                  } else if (ev.phase === "cancelled") {
                    emitMcpProgress(
                      progressToken,
                      ev.written.length,
                      ev.total,
                      `cancelled after ${ev.written.length} written`,
                    );
                  } else if (ev.phase === "done") {
                    emitMcpProgress(
                      progressToken,
                      ev.total,
                      ev.total,
                      "done",
                    );
                  }
                },
              });
            } finally {
              if (typeof req.id === "string" || typeof req.id === "number") {
                activeHardenAborts.delete(req.id);
              }
            }
            // Dry-run / confirmation_required / agentWeaveGateBlocked leave no write receipt; real writes do.
            if (report.agentWeaveGateBlocked === true) {
              refused = true;
              payload = report;
            } else if (!dryRun) {
              const wrote = (report.written ?? report.artifacts
                .filter((a) => a.success)
                .map((a) => a.outputPath)).slice();
              if (report.summaryPath !== undefined) {
                wrote.push(report.summaryPath);
              }
              if (report.integrityCoveragePath !== undefined) {
                wrote.push(report.integrityCoveragePath);
              }
              for (const path of preOverwrite) {
                if (path.endsWith(".bla-manifest.json") && report.artifacts.some(
                  (artifact) => artifact.success && `${artifact.outputPath}.bla-manifest.json` === path,
                )) {
                  wrote.push(path);
                }
              }
              if (report.apply?.status === "applied") {
                const hardenRoot = resolvePath(hardenDir);
                for (const rel of [...(report.apply.applied ?? []), ...(report.apply.added ?? [])]) {
                  wrote.push(joinPath(hardenRoot, rel));
                }
              }
              payload = {
                ...report,
                wouldOverwrite: preOverwrite,
                writeReceipt: writeReceipt(wrote, preOverwrite.filter((path) => wrote.includes(path)), confirmed),
              };
              // A run that hardened nothing, failed an artifact, or could not
              // promote is not a success the agent may build on.
              if (!report.overallSuccess) refused = true;
            } else {
              payload = { ...report, wouldOverwrite: planHardenOverwrites(report, args, applyMode, outputDirectory !== undefined) };
            }
          }
          }
        } else if (name === "bla_defend" || name === "bla_protect") {
          const inPlace = args.in_place === true;
          const out = resolveProtectOutputPath(
            args.input_path as string,
            typeof args.output_path === "string" ? args.output_path : undefined,
            inPlace,
          );
          const planned =
            name === "bla_defend" &&
            (args.emit_manifest === true || args.sign_manifest === true)
              ? [out, `${out}.bla-manifest.json`]
              : [out];
          const clobbered = existingPaths(planned);
          if (clobbered.length > 0 && !confirmed) {
            refused = true;
            payload = confirmationRequiredPayload(name, clobbered);
          } else {
            const report = compactArtifactReport(
              name === "bla_defend" ? runDefend(handlers, args) : runProtect(handlers, args),
            ) as Record<string, unknown>;
            if (name === "bla_defend" && report.overallSuccess === false) refused = true;
            // A later bla_harden / bla_lint must recognise this file as hardened
            // output, not as a fresh artifact full of plaintext "secrets".
            if (typeof report.outputPath === "string") registerBlaOutput(report.outputPath);
            const withRun = attachArtifactRunEvidence(
              name,
              args.input_path as string,
              report,
            );
            payload = {
              ...withRun,
              writeReceipt: writeReceipt(
                existingPaths(planned),
                clobbered,
                confirmed,
              ),
            };
          }
        } else if (name === "bla_audit") {
          payload = compactArtifactReport(handlers.auditTarget(args.path as string));
        } else if (name === "bla_verify") {
          const verification = handlers.verifyTarget(
            args.target_path as string,
            typeof args.original_path === "string" ? args.original_path : undefined,
            verifyHonestyOptions(args),
          );
          refused = verification.overallPassed === false;
          let verifyPayload: Record<string, unknown> = { ...verification };
          if (typeof args.summary_path === "string" && args.summary_path.trim().length > 0) {
            const lookup = readHardenRunSummary(
              args.summary_path as string,
              typeof args.run_id === "string" && args.run_id.trim().length > 0
                ? (args.run_id as string)
                : undefined,
            );
            verifyPayload = {
              ...verifyPayload,
              runCorrelation: {
                schema: "bla-run-correlation/v1",
                signature: "unsigned",
                runId: lookup.runId,
                summaryPath: lookup.summaryPath,
                runIdMatches: lookup.runIdMatches,
              },
            };
          } else if (typeof args.run_id === "string" && args.run_id.trim().length > 0) {
            throw new Error(
              "bla_verify: run_id requires summary_path so the id can be correlated against an on-disk harden summary",
            );
          }
          const manifestPath = typeof args.manifest_path === "string" && args.manifest_path.trim()
            ? args.manifest_path : undefined;
          const publicKeyPath = typeof args.public_key_path === "string" && args.public_key_path.trim()
            ? args.public_key_path : undefined;
          if (args.require_pinned_key === true && (!manifestPath || !publicKeyPath)) {
            verifyPayload.manifestVerification = {
              ok: false, signed: false, pinned: false, artifactVerified: false,
              reason: "require_pinned_key requires both manifest_path and public_key_path.",
            };
            refused = true;
          } else if (manifestPath) {
            const manifestVerification = verifyManifestFile(
              manifestPath, publicKeyPath, args.target_path as string,
              { requirePinnedKey: args.require_pinned_key === true },
            );
            verifyPayload.manifestVerification = manifestVerification;
            if (!manifestVerification.ok) refused = true;
          }
          payload = verifyPayload;
        } else if (name === "bla_benchmark") {
          const benchmark = await handlers.runShowcaseBenchmark();
          payload = benchmark;
          refused = benchmark.cases.some((entry) => entry.functionalCheckPassed === false);
        } else if (name === "bla_emit_headers") {
          payload = handlers.emitCompileTimeNativeHeader(
            args.language as NativeHeaderLanguage,
            {
              ...(typeof args.intensity === "string"
                ? { intensity: args.intensity as ProtectionIntensity }
                : {}),
            },
          );
        } else if (name === "bla_doctor") {
          const doctor = handlers.runDoctor({
            ...(typeof args.home_dir === "string" ? { homeDir: args.home_dir } : {}),
            ...(args.verify_handshake === true ? { verifyHandshake: true } : {}),
            projectDirectory:
              typeof args.directory === "string" && args.directory.trim().length > 0
                ? args.directory
                : process.cwd(),
          });
          // Agent-facing shape: one client list (not the `clients` alias too),
          // absent clients as names only, and no 4 KB table of REA constants.
          const {
            clients: _clientsAlias,
            reaLimitsTargeted,
            agentClients,
            ...doctorRest
          } = doctor;
          const present = (agentClients ?? []).filter(
            (c) => c.detected || c.configured || c.skillInstalled,
          );
          payload = {
            ...doctorRest,
            agentClients: present,
            clientsNotDetected: (agentClients ?? [])
              .filter((c) => !present.includes(c))
              .map((c) => c.id),
            reaLimitsTargetedCount: Object.keys(reaLimitsTargeted ?? {}).length,
          };
        } else if (name === "bla_inspect_release") {
          const maxFiles = optionalCount(args.max_files);
          const maxTotalBytes = optionalCount(args.max_total_bytes);
          payload = handlers.inspectReleaseExposure(args.path as string, {
            ...(maxFiles !== undefined ? { maxFiles } : {}),
            ...(maxTotalBytes !== undefined ? { maxTotalBytes } : {}),
          });
        } else if (name === "bla_init") {
          payload = handlers.initBlaConfig(
            args.directory as string,
            Boolean(args.overwrite),
          );
        } else if (name === "bla_weave_plan") {
          payload = buildWeavePlan(args.path as string, {
            ...(typeof args.max_targets === "number"
              ? { maxTargets: args.max_targets }
              : {}),
          });
        } else if (name === "bla_verify_weave") {
          const verifyReport = verifyWeaveTarget(args.path as string, {
            ...(typeof args.max_targets === "number"
              ? { maxTargets: args.max_targets }
              : {}),
            ...(args.scope === "all" ? { scope: "all" as const } : {}),
          });
          // Advisory files never block the verdict; their per-check detail is
          // noise for the agent unless it asks for it.
          payload =
            args.verbose === true
              ? verifyReport
              : {
                  ...verifyReport,
                  files: verifyReport.files.filter((f) => f.scope !== "advisory"),
                };
          refused = !verifyReport.overallPassed;
        } else if (name === "bla_lint") {
          const full = runPackagingGatesLint(args);
          const { details, ...compact } = full;
          payload = {
            ...compact,
            detailCounts: {
              seals: details.seals.length,
              wasmParams: details.wasmParams.length,
              jsAes: details.jsAes.length,
              jsHydrateDump: details.jsHydrateDump.length,
              wasmXorMask: details.wasmXorMask.length,
              wasmSealXor: details.wasmSealXor.length,
              lanes: details.lanes.length,
              panelDerive: details.panelDerive.length,
              plaintextSecrets: details.plaintextSecrets.length,
              integrityCoverage: details.integrityCoverage.length,
              bindScope: details.bindScope.length,
              releaseHygiene: details.releaseHygiene.length,
            },
          };
          refused = full.shouldRefuseBankrupt;
        } else if (name === "bla_lint_lanes") {
          payload = runLintLanes(args);
          refused =
            args.allow_lane_independent === true
              ? false
              : (payload as LaneIndependenceReport).looksLaneIndependent;
        } else if (name === "bla_lint_seal") {
          payload = runLintSeal(args);
          refused = (payload as SealCommitmentReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_wasm_params") {
          payload = runLintWasmParams(args);
          refused = (payload as WasmParamCarrierReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_panel_derive") {
          payload = runLintPanelDerive(args);
          const panelRep = payload as PanelDeriveAbiReport;
          refused =
            (panelRep.shouldRefuseBankrupt && args.allow_panel_offline_oracle !== true) ||
            (panelRep.shouldRewriteOrRefuse && args.allow_stable_panel_derive !== true);
        } else if (name === "bla_lint_js_aes_unwrap") {
          payload = runLintJsAesUnwrap(args);
          refused = (payload as JsAesUnwrapReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_js_wasm_hydrate_dump") {
          payload = runLintJsWasmHydrateDump(args);
          refused = (payload as JsWasmHydrateDumpReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_wasm_xor_mask_sidecar") {
          payload = runLintWasmXorMaskSidecar(args);
          refused = (payload as WasmXorMaskSidecarReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_wasm_seal_xor_known_plaintext") {
          payload = runLintWasmSealXorKnownPlaintext(args);
          refused = (payload as WasmSealXorKnownPlaintextReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_integrity_coverage") {
          const target = String(args.path ?? "");
          const allow = args.allow_single_point_integrity === true;
          const reports = discoverAndLintIntegrityCoverage(target);
          const anyRefuse = reports.some((r) => r.shouldRefuseBankrupt);
          payload = {
            schema: INTEGRITY_COVERAGE_SCHEMA,
            path: target,
            reports,
            shouldRefuseBankrupt: allow ? false : anyRefuse,
            oneLineAdvice: anyRefuse
              ? "ERROR: Integrity coverage matrix failed — fix interleaved checkers or allow_single_point_integrity (lab only)."
              : reports.length === 0
                ? "No integrity-coverage.json found (not an error — emit via harden --self-seal)."
                : "Integrity coverage matrix OK.",
          };
          refused = allow ? false : anyRefuse;
        } else if (name === "bla_run_lookup") {
          payload = readHardenRunSummary(
            args.summary_path as string,
            typeof args.run_id === "string" && args.run_id.trim().length > 0
              ? (args.run_id as string)
              : undefined,
          );
        } else if (name === "bla_rea_drift") {
          payload = runReaDriftCheck({
            ...(typeof args.rea_root === "string" && args.rea_root.trim().length > 0
              ? { reaRoot: args.rea_root as string }
              : {}),
          });
          {
            const status = (payload as { status: string }).status;
            refused = status === "unverified" || status === "fail";
          }
        
        } else if (name === "bla_polymorph_report") {
          const expectArg = typeof args.expect === "string" ? args.expect : "report";
          const expectMode =
            expectArg === "same" || expectArg === "different" || expectArg === "report"
              ? expectArg
              : "report";
          payload = comparePolymorphArtifacts({
            dirA: args.dir_a as string,
            dirB: args.dir_b as string,
            expect: expectMode,
            ...(typeof args.same_threshold === "number"
              ? { sameThreshold: args.same_threshold as number }
              : {}),
            ...(typeof args.different_threshold === "number"
              ? { differentThreshold: args.different_threshold as number }
              : {}),
          });
          {
            const status = (payload as { status: string }).status;
            refused = status === "fail" || status === "error";
          }
        } else if (name === "bla_encrypt_strings") {
          const encryptArgs = {
            path: args.path as string,
            seed: args.seed as string,
            ...(typeof args.out_dir === "string" && args.out_dir.trim().length > 0
              ? { outDir: args.out_dir as string }
              : {}),
            ...(typeof args.include_urls === "boolean"
              ? { includeUrls: args.include_urls as boolean }
              : {}),
          };
          const dryRun = args.dry_run === true;
          const clobbered = dryRun
            ? []
            : existingPaths(
                encryptStrings({ ...encryptArgs, dryRun: true })
                  .files.filter((f) => f.encryptedCount > 0)
                  .map((f) => f.outPath),
              );
          if (clobbered.length > 0 && !confirmed) {
            refused = true;
            payload = confirmationRequiredPayload(name, clobbered);
          } else {
            const report = encryptStrings({ ...encryptArgs, dryRun });
            const written = report.files
              .filter((f) => f.written)
              .map((f) => f.outPath);
            payload =
              written.length > 0
                ? { ...report, writeReceipt: writeReceipt(written, clobbered, confirmed) }
                : report;
            refused = report.status === "error";
          }
        } else if (name === "bla_lint_plaintext_secrets") {
          const allow = args.allow_plaintext_string === true;
          const target = args.path as string;
          const reports = discoverAndLintPlaintextSecrets(target, {
            allowPlaintextString: allow,
          });
          const shouldRefuse = reports.some((r) => r.shouldRefuseBankrupt);
          payload = {
            schema: "bla-plaintext-secret-lint/v1",
            path: target,
            reports,
            shouldRefuseBankrupt: shouldRefuse,
            oneLineAdvice: shouldRefuse
              ? "ERROR: Cleartext sensitive literals — run bla_encrypt_strings or allow_plaintext_string (lab only)."
              : reports.some((r) => r.looksExposed)
                ? "WARNING: Non-refusing sensitive literals remain."
                : "No cleartext sensitive-literal findings (heuristic).",
          };
          refused = shouldRefuse;
        } else if (name === "bla_bind_scope") {
          const domains = Array.isArray(args.domains)
            ? args.domains.filter((d) => typeof d === "string")
            : undefined;
          const bindArgs = {
            directory: args.directory as string,
            ...(domains && domains.length > 0 ? { domains } : {}),
            ...(typeof args.valid_from === "string" && args.valid_from.trim()
              ? { validFrom: args.valid_from as string }
              : {}),
            ...(typeof args.valid_until === "string" && args.valid_until.trim()
              ? { validUntil: args.valid_until as string }
              : {}),
            ...(typeof args.entry_path === "string" && args.entry_path.trim()
              ? { entryPath: args.entry_path as string }
              : {}),
            ...(typeof args.out_dir === "string" && args.out_dir.trim()
              ? { outDir: args.out_dir as string }
              : {}),
          };
          const dryRun = args.dry_run === true;
          const clobbered = dryRun
            ? []
            : existingPaths(plannedBindScopeWrites(bindArgs));
          if (clobbered.length > 0 && !confirmed) {
            refused = true;
            payload = confirmationRequiredPayload(name, clobbered);
          } else {
            const report = applyBindScope({ ...bindArgs, dryRun });
            const written = report.written
              ? [report.contractPath, ...(report.entryPath ? [report.entryPath] : [])]
              : [];
            payload =
              written.length > 0
                ? { ...report, writeReceipt: writeReceipt(written, clobbered, confirmed) }
                : report;
            refused = report.status === "error";
          }
        } else if (name === "bla_lint_bind_scope") {
          const allow = args.allow_missing_bind_runtime === true;
          const target = args.path as string;
          const reports = discoverAndLintBindScope(target);
          const anyRefuse = reports.some((r) => r.shouldRefuseBankrupt);
          payload = {
            schema: BIND_SCOPE_SCHEMA,
            path: target,
            reports,
            shouldRefuseBankrupt: allow ? false : anyRefuse,
            oneLineAdvice: anyRefuse
              ? "ERROR: Bind-scope contract failed honesty/runtime checks — fix or allow_missing_bind_runtime (lab only)."
              : reports.length === 0
                ? "No bind-scope.json found (OK — bind-scope is opt-in / default OFF)."
                : "Bind-scope contract OK.",
          };
          refused = allow ? false : anyRefuse;
        } else if (name === "bla_redteam_report") {
          const execute = args.execute === true;
          const requestedRoot = typeof args.rea_root === "string" ? args.rea_root.trim() : "";
          const reportPath = typeof args.report_path === "string" ? args.report_path.trim() : "";
          const operatorRoot = process.env.REA_ROOT?.trim() ?? "";
          if (execute && (!isAbsolute(operatorRoot) ||
            (requestedRoot && resolvePath(requestedRoot) !== resolvePath(operatorRoot)))) {
            throw new Error("Live red-team execution requires an absolute REA_ROOT configured by the MCP server operator. Set it before starting BLA.");
          }
          const result = getRedteamReport({
            execute,
            ...(execute ? { reaRoot: operatorRoot } : requestedRoot ? { reaRoot: requestedRoot } : {}),
            ...(!execute && reportPath ? { reportPath } : {}),
          });
          payload = result;
          refused = result.status === "unverified" || result.status === "fail";
        }

        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify(payload, null, 2),
              },
            ],
            structuredContent: payload,
            // A refused write is a tool-level error the agent must act on.
            isError: refused,
          },
        };
      }

      default:
        return {
          jsonrpc: "2.0",
          id: req.id,
          error: {
            code: -32601,
            message: `Method not found: ${req.method}`,
          },
        };
    }
  } catch (err) {
    return {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        content: [
          {
            type: "text",
            text: redactAbsolutePaths(err instanceof Error ? err.message : String(err)),
          },
        ],
        isError: true,
      },
    };
  }
}

/**
 * Roots whose absolute spellings must never reach an MCP client: engine error
 * messages embed resolved paths, and the client is untrusted relative to the
 * operator's filesystem. Relative fragments stay readable for debugging.
 */
const ERROR_PATH_REDACT_ROOTS: ReadonlySet<string> = new Set(
  [process.cwd(), tmpdir(), homedir()]
    .filter((root): root is string => typeof root === "string")
    .map((root) => resolvePath(root).toLowerCase()),
);

function redactAbsolutePaths(text: string): string {
  let out = text;
  for (const root of ERROR_PATH_REDACT_ROOTS) {
    let searchIndex = out.toLowerCase().indexOf(root);
    while (searchIndex >= 0) {
      out = out.slice(0, searchIndex) + "<path>" + out.slice(searchIndex + root.length);
      searchIndex = out.toLowerCase().indexOf(root, searchIndex + "<path>".length);
    }
  }
  // Windows drive-letter absolute paths outside the known roots (POSIX
  // absolute paths under the known roots are already covered above).
  out = out.replace(/[A-Za-z]:[\\/][^\s"'`,;)\]}]*/g, "<path>");
  return out;
}

/** Queued bla_harden requests cancelled before their serial turn started. */
const preAbortedHardenRequests = new Map<string | number, AbortController>();

/**
 * Largest single stdio line accepted before the client is treated as
 * misbehaving. Measured in UTF-16 code units (`String.length`, matching what
 * JavaScript reports as a string's "characters"), not bytes.
 */
export const MAX_STDIO_LINE_CHARS = 1_048_576;

export interface StdioLineProcessorHooks {
  readonly onLine: (line: string) => void;
  readonly onOversizedLine?: () => void;
}

export interface StdioLineProcessor {
  readonly push: (chunk: string) => void;
}

/**
 * Dual-mode stdio frame splitter supporting both newline-delimited JSON-RPC 2.0
 * and LSP/MCP `Content-Length: <bytes>\r\n\r\n<body>` byte-counted frames with
 * a hard per-message size cap.
 */
export function createStdioLineProcessor(hooks: StdioLineProcessorHooks): StdioLineProcessor {
  let buffer = "";
  let discarding = false;
  let pendingContentBytes: number | null = null;
  let awaitingHeaderBlankLine = false;
  return {
    push(chunk: string): void {
      if (discarding) {
        const nl = chunk.indexOf("\n");
        if (nl < 0) return;
        discarding = false;
        buffer = chunk.slice(nl + 1);
      } else {
        buffer += chunk;
      }

      while (buffer.length > 0 || (!awaitingHeaderBlankLine && pendingContentBytes === 0)) {
        if (!awaitingHeaderBlankLine && pendingContentBytes !== null) {
          const byteLen = Buffer.byteLength(buffer, "utf8");
          if (byteLen >= pendingContentBytes) {
            const rawBuf = Buffer.from(buffer, "utf8");
            const body = rawBuf.subarray(0, pendingContentBytes).toString("utf8");
            buffer = rawBuf.subarray(pendingContentBytes).toString("utf8");
            pendingContentBytes = null;
            if (body.length > MAX_STDIO_LINE_CHARS) {
              hooks.onOversizedLine?.();
              continue;
            }
            hooks.onLine(body);
            continue;
          }
          // A framed JSON body can contain newlines before the rest arrives.
          break;
        }

        const newlineIdx = buffer.indexOf("\n");
        if (newlineIdx < 0) break;
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);

        if (awaitingHeaderBlankLine) {
          if (line === "") {
            awaitingHeaderBlankLine = false;
          }
          continue;
        }

        if (!line) continue;
        const clMatch = /^Content-Length:\s*(\d+)$/i.exec(line);
        if (clMatch) {
          const parsedBytes = Number.parseInt(clMatch[1]!, 10);
          if (!Number.isFinite(parsedBytes) || parsedBytes > MAX_STDIO_LINE_CHARS * 4) {
            pendingContentBytes = null;
            awaitingHeaderBlankLine = false;
            buffer = "";
            discarding = true;
            hooks.onOversizedLine?.();
            return;
          }
          pendingContentBytes = parsedBytes;
          awaitingHeaderBlankLine = true;
          continue;
        }
        if (line.startsWith("Content-Type:")) continue;

        if (line.length > MAX_STDIO_LINE_CHARS) {
          hooks.onOversizedLine?.();
          continue;
        }
        hooks.onLine(line);
      }

      if ((pendingContentBytes === null || awaitingHeaderBlankLine) && buffer.length > MAX_STDIO_LINE_CHARS) {
        buffer = "";
        pendingContentBytes = null;
        awaitingHeaderBlankLine = false;
        discarding = true;
        hooks.onOversizedLine?.();
      }
    },
  };
}

/**
 * Starts the BLA MCP server over stdio (supporting newline-delimited and Content-Length JSON-RPC 2.0).
 */
export function startMcpStdioServer(): void {
  let processingQueue = Promise.resolve();
  const queuedRequests = new Map<string | number, { cancelled: boolean; reason?: string }>();
  const processor = createStdioLineProcessor({
    onLine: (line: string) => {
      // Parse first so cancel can abort an in-flight or queued harden without waiting
      // for the serial request queue (issue #75).
      let req: unknown;
      try {
        req = JSON.parse(line);
      } catch {
        const parseErr: JsonRpcResponse = {
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32700,
            message: "Parse error",
          },
        };
        process.stdout.write(JSON.stringify(parseErr) + "\n");
        return;
      }
      if (!isJsonRpcRequest(req)) {
        process.stdout.write(JSON.stringify(invalidRequest(req)) + "\n");
        return;
      }
      if (req.method === "notifications/cancelled" && req.id === undefined) {
        const cancellation = cancellationOf(req);
        if (cancellation) {
          const entry = queuedRequests.get(cancellation.requestId);
          if (entry) {
            entry.cancelled = true;
            entry.reason = cancellation.reason;
          }
          activeHardenAborts.get(cancellation.requestId)?.abort(cancellation.reason);
        }
        return;
      }
      const reqId = req.method === "tools/call" && isPlainObject(req.params) &&
        req.params.name === "bla_harden" && isRequestId(req.id) ? req.id : undefined;
      if (reqId !== undefined) {
        queuedRequests.set(reqId, { cancelled: false });
      }
      processingQueue = processingQueue.then(async () => {
        const queuedState = reqId !== undefined ? queuedRequests.get(reqId) : undefined;
        if (reqId !== undefined) {
          queuedRequests.delete(reqId);
          if (queuedState?.cancelled) {
            const ctl = new AbortController();
            ctl.abort(queuedState.reason ?? "cancelled");
            preAbortedHardenRequests.set(reqId, ctl);
          }
        }
        try {
          const res = await handleMcpRequest(req);
          if (res !== null) {
            process.stdout.write(JSON.stringify(res) + "\n");
          }
        } catch {
          const parseErr: JsonRpcResponse = {
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: "Parse error",
            },
          };
          process.stdout.write(JSON.stringify(parseErr) + "\n");
        } finally {
          if (reqId !== undefined) {
            preAbortedHardenRequests.delete(reqId);
          }
        }
      });
    },
    onOversizedLine: () => {
      const parseErr: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: `Parse error: line exceeds ${MAX_STDIO_LINE_CHARS} character limit`,
        },
      };
      process.stdout.write(JSON.stringify(parseErr) + "\n");
    },
  });
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => processor.push(chunk));
}
