import { BLA_IDENTITY } from "../identity.js";
import { initBlaConfig } from "../core/config.js";
import { inspectReleaseExposure } from "../core/release-exposure.js";
import type { ProtectionIntensity } from "../core/types.js";
import { auditTarget } from "../engine/auditor.js";
import { protectTarget, resolveProtectOutputPath } from "../engine/protector.js";
import { verifyTarget, type VerifyTargetOptions } from "../engine/verifier.js";
import { defendTarget } from "../engine/defender.js";
import { existsSync, readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { discoverHardenTargets, hardenProject } from "../engine/harden.js";
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
  readonly params?: Record<string, unknown>;
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
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
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
] as const);

export const BLA_MCP_TOOLS: readonly McpToolDefinition[] = Object.freeze([
  {
    name: "bla_harden",
    description:
      "DEFAULT one-sentence Counter-REA hardening. Auto-discovers build outputs (dist/, build/, out/, release/, .asar, native binaries, .wasm, .py/.pyc, .sqlite, .safetensors/.gguf, .dex, .class, etc.), detects each artifact's format, and runs the full audit→defend→verify pipeline with the bankrupt profile. Pass just a project or build directory (default: cwd). Prefer this over bla_defend when the user says 'harden my software' without naming a specific file.",
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
        sidecar_entangle: {
          type: "boolean",
          description:
            "Opt-in sidecar/entry entanglement for JS/Python (issue #40). When true, harden/protect binds sibling sidecar bytes into the entry via a strip⇒fail preamble — removing or altering a sidecar fails closed. OFF by default.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
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
          description: "Optional page size / cap (default 64); truncated=true when more exist beyond this page.",
        },
        offset: {
          type: "number",
          description: "Zero-based offset into the stable discovery order (use prior nextOffset to page). Default 0.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_defend",
    description:
      "One-click Counter-REA full defense hardening pipeline. Runs release source-map exposure inspection, 16-vector REA vulnerability audit, Resource-Exhaustion + Model-Misjudgment shield injection (default: bankrupt preset), and mathematical invariant verification in a single call.",
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
        sidecar_entangle: {
          type: "boolean",
          description:
            "Opt-in sidecar/entry entanglement for JS/Python (issue #40). When true, harden/protect binds sibling sidecar bytes into the entry via a strip⇒fail preamble — removing or altering a sidecar fails closed. OFF by default.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
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
        sidecar_entangle: {
          type: "boolean",
          description:
            "Opt-in sidecar/entry entanglement for JS/Python (issue #40). When true, harden/protect binds sibling sidecar bytes into the entry via a strip⇒fail preamble — removing or altering a sidecar fails closed. OFF by default.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
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
      "Verifies a BLA-protected artifact against REA's static/semantic resource limits, call-graph tarpit expansion, and token bankruptcy amplification. Pass protection-side honesty metadata (self_seal_enabled / wasm_export_rename_applied) so defenseScore soft-caps reflect what actually ran — same fields defend/harden already forward from ProtectionResult. Optional run_id / summary_path correlate this verify with a prior harden summary (unsigned).",
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
      "Checks readiness of all BLA protection engines and agent MCP registrations.",
    inputSchema: {
      type: "object",
      properties: {
        home_dir: {
          type: "string",
          description: "Optional home directory path to inspect",
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
          description: "Optional maximum number of files to scan",
        },
        max_total_bytes: {
          type: "number",
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
      "Read-only structural weave verifier (bla-weave-verify/v1): validates Agent-authored source weave edits and hardened outputs against WEAVE_ACCEPTANCE_TESTS (no forbidden banners, mixed mundane/security stems, shared-state mutation across functions, customer entry call-graph reachability, opaque-true entanglement, and filter resistance). Returns weaveScore and actionable agentActions for autonomous self-repair.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the source file, artifact, or directory to verify",
        },
        max_targets: {
          type: "number",
          description: "Optional cap on files to verify (default 48)",
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
        allow_panel_offline_oracle: {
          type: "boolean",
          description: "Treat panel offline oracle as non-blocking (lab only)",
        },
        allow_plaintext_string: {
          type: "boolean",
          description: "Treat cleartext sensitive literals as non-blocking (lab only)",
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
      "Encrypt sensitive string literals in panel.html / license.cjs with a seed-derived XOR keystream and inject a runtime decrypt stub. Reuses SeededPrng.derive(\"string.encrypt\") — never JS AES wrap-key (that footgun is refused by bla_lint_js_aes_unwrap). Honesty: raises static grep cost only; prove equivalence with verify / CrackMe / REA. Writes outputs (or dry_run).",
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
      "Optional honest code-lock: write a PUBLIC bind-scope.json (domains + validity window) and inject a deterministic runtime check into license.cjs/entry. Default OFF. Never a covert backdoor — public:true is mandatory; hidden fields refuse. Host for Node comes from BLA_BIND_HOST (or location.hostname in browsers).",
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
      "Read (or optionally re-run) the empirical REA red-team report at docs/redteam/empirical-rea-validation.json. On-disk read without execute → status available (not a live REA verdict). execute:true → pass/fail from the harness. Missing report and unready REA → status unverified. Pass execute:true only when sibling REA dist is built.",
    inputSchema: {
      type: "object",
      properties: {
        execute: {
          type: "boolean",
          description:
            "When true, spawn npm redteam:rea (requires sibling REA dist). Default false: read the on-disk report only.",
        },
        rea_root: {
          type: "string",
          description: "Optional path to a local REA checkout (defaults to REA_ROOT or ../rea)",
        },
        report_path: {
          type: "string",
          description: "Optional override path for the empirical JSON report",
        },
      },
      additionalProperties: false,
    },
  },
]);


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

function confirmationRequiredPayload(
  tool: string,
  wouldOverwrite: readonly string[],
): Record<string, unknown> {
  return {
    status: "confirmation_required",
    tool,
    wrote: [],
    wouldOverwrite,
    message: `${tool} would overwrite ${wouldOverwrite.length} existing file(s); nothing was written. Confirm with the user, then retry with confirm_overwrite: true (or choose a new output path).`,
  };
}

function writeReceipt(
  outputs: readonly string[],
  overwritten: readonly string[],
  confirmed: boolean,
): Record<string, unknown> {
  return { status: "written", wrote: outputs, overwrote: overwritten, confirmed };
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

function stringListArg(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const list = value.filter((x): x is string => typeof x === "string" && x.length > 0);
  return list.length > 0 ? list : undefined;
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
  });
}

function verifyHonestyOptions(args: Record<string, unknown>): VerifyTargetOptions {
  return {
    ...(typeof args.self_seal_enabled === "boolean"
      ? { selfSealEnabled: args.self_seal_enabled }
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
    ...(args.allow_panel_offline_oracle === true
      ? { allowPanelOfflineOracle: true }
      : {}),
    ...(args.allow_plaintext_string === true
      ? { allowPlaintextString: true }
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
      if (typeof val !== "number" || !Number.isFinite(val) || val <= 0) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a positive finite number`,
        };
      }
    }
  }

  return { ok: true, tool, args: rawArgs };
}

export async function handleMcpRequest(
  req: JsonRpcRequest,
  handlers: McpEngineHandlers = DEFAULT_ENGINE_HANDLERS,
): Promise<JsonRpcResponse | null> {
  if (!isPlainObject(req) || req.jsonrpc !== "2.0" || typeof req.method !== "string") {
    return {
      jsonrpc: "2.0",
      id: isPlainObject(req) && (typeof req.id === "string" || typeof req.id === "number") ? req.id : null,
      error: {
        code: -32600,
        message: "Invalid Request: expected JSON-RPC 2.0 request object",
      },
    };
  }

  // Cancel must be honored even when the notification has no `id` (MCP spec)
  // and must not wait behind a serial harden call (issue #75).
  if (req.method === "notifications/cancelled") {
    const params = (req.params ?? {}) as {
      requestId?: string | number;
      reason?: string;
    };
    const rid = params.requestId;
    if (rid !== undefined && rid !== null) {
      const ctl = activeHardenAborts.get(rid);
      if (ctl) ctl.abort(params.reason ?? "cancelled");
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
          typeof requestedVersion === "string" &&
          (SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]).includes(requestedVersion)
            ? requestedVersion
            : "2024-11-05";

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
            resources: BLA_MCP_RESOURCES,
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
        const known = BLA_MCP_RESOURCES.find((r) => r.uri === uri);
        if (!known) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: unknown resource URI '${uri}'`,
            },
          };
        }
        const markdown = getWeaveDirectivesMarkdown();
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
        const promptDef = BLA_MCP_PROMPTS.find((p) => p.name === req.params!.name);
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
            `Harden my software against REA in one step: call bla_harden with { "directory": ${JSON.stringify(directory)} }. ` +
            `It auto-discovers build outputs, runs audit→defend→verify with the bankrupt profile on every artifact, and returns a per-artifact summary. ` +
            `Do not ask which files to protect — discover them. ` +
            `To preview without writing, pass dry_run: true. If the tool returns confirmation_required, ask the user before retrying with confirm_overwrite: true.`;
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
          const offset = optionalCount(args.offset);
          payload = discoverHardenTargets(
            typeof args.directory === "string" && args.directory.trim().length > 0
              ? args.directory
              : process.cwd(),
            {
              ...(optionalCount(args.max_artifacts) !== undefined
                ? { maxArtifacts: optionalCount(args.max_artifacts)! }
                : {}),
              ...(offset !== undefined ? { offset } : {}),
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
          let preOverwrite: readonly string[] = [];
          if (!dryRun && existsSync(hardenDir)) {
            // Zero-write preview with the real engine to find clobbered outputs.
            preOverwrite = hardenProject({
              directory: hardenDir,
              dryRun: true,
              ...(maxArtifacts !== undefined ? { maxArtifacts } : {}),
              ...(outputDirectory !== undefined ? { outputDirectory } : {}),
            }).wouldOverwrite;
          }
          if (!dryRun && preOverwrite.length > 0 && !confirmed) {
            refused = true;
            payload = confirmationRequiredPayload(name, preOverwrite);
          } else {
            const wasmPreserveExports = stringListArg(args.wasm_preserve_exports);
            const abortCtl = new AbortController();
            if (typeof req.id === "string" || typeof req.id === "number") {
              activeHardenAborts.set(req.id, abortCtl);
            }
            const progressToken = progressTokenOf(req);
            let report;
            try {
              report = handlers.hardenProject({
                directory: hardenDir,
                dryRun,
                ...(maxArtifacts !== undefined ? { maxArtifacts } : {}),
                ...(outputDirectory !== undefined ? { outputDirectory } : {}),
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
            // Dry-run / confirmation_required leave no write receipt; real writes do.
            if (!dryRun) {
              const wrote = (report.written ?? report.artifacts
                .filter((a) => a.success)
                .map((a) => a.outputPath)).slice();
              if (report.summaryPath !== undefined) {
                wrote.push(report.summaryPath);
              }
              payload = {
                ...report,
                writeReceipt: writeReceipt(wrote, preOverwrite, confirmed),
              };
            } else {
              payload = report;
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
            const report = (name === "bla_defend"
              ? runDefend(handlers, args)
              : runProtect(handlers, args)) as Record<string, unknown>;
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
          payload = handlers.auditTarget(args.path as string);
        } else if (name === "bla_verify") {
          const verification = handlers.verifyTarget(
            args.target_path as string,
            typeof args.original_path === "string" ? args.original_path : undefined,
            verifyHonestyOptions(args),
          );
          if (typeof args.summary_path === "string" && args.summary_path.trim().length > 0) {
            const lookup = readHardenRunSummary(
              args.summary_path as string,
              typeof args.run_id === "string" && args.run_id.trim().length > 0
                ? (args.run_id as string)
                : undefined,
            );
            payload = {
              ...verification,
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
          } else {
            payload = verification;
          }
        } else if (name === "bla_benchmark") {
          payload = await handlers.runShowcaseBenchmark();
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
          payload = handlers.runDoctor(
            typeof args.home_dir === "string" ? args.home_dir : undefined,
          );
        } else if (name === "bla_inspect_release") {
          payload = handlers.inspectReleaseExposure(args.path as string);
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
          });
          payload = verifyReport;
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
            },
          };
          refused = full.shouldRefuseBankrupt;
        } else if (name === "bla_lint_lanes") {
          payload = runLintLanes(args);
        } else if (name === "bla_lint_seal") {
          payload = runLintSeal(args);
          refused = (payload as SealCommitmentReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_wasm_params") {
          payload = runLintWasmParams(args);
          refused = (payload as WasmParamCarrierReport).shouldRefuseBankrupt;
        } else if (name === "bla_lint_panel_derive") {
          payload = runLintPanelDerive(args);
          refused =
            (payload as PanelDeriveAbiReport).shouldRefuseBankrupt ||
            (payload as PanelDeriveAbiReport).shouldRewriteOrRefuse;
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
          payload = encryptStrings({
            path: args.path as string,
            seed: args.seed as string,
            ...(typeof args.out_dir === "string" && args.out_dir.trim().length > 0
              ? { outDir: args.out_dir as string }
              : {}),
            ...(typeof args.include_urls === "boolean"
              ? { includeUrls: args.include_urls as boolean }
              : {}),
            dryRun: args.dry_run === true,
          });
          {
            const status = (payload as { status: string }).status;
            refused = status === "error";
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
          payload = applyBindScope({
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
            dryRun: args.dry_run === true,
          });
          {
            const status = (payload as { status: string }).status;
            refused = status === "error";
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
          payload = getRedteamReport({
            execute: args.execute === true,
            ...(typeof args.rea_root === "string" && args.rea_root.trim().length > 0
              ? { reaRoot: args.rea_root as string }
              : {}),
            ...(typeof args.report_path === "string" && args.report_path.trim().length > 0
              ? { reportPath: args.report_path as string }
              : {}),
          });
          {
            const status = (payload as { status: string }).status;
            refused = status === "unverified" || status === "fail";
          }
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
            text: err instanceof Error ? err.message : String(err),
          },
        ],
        isError: true,
      },
    };
  }
}

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
 * Newline-delimited stdio line splitter with a hard per-line size cap so a
 * client that streams an unterminated giant line cannot grow the buffer without
 * bound. Blank lines and `Content-Length:` framing lines are skipped, matching
 * the previous server behavior.
 */
export function createStdioLineProcessor(hooks: StdioLineProcessorHooks): StdioLineProcessor {
  let buffer = "";
  let discarding = false;
  return {
    push(chunk: string): void {
      if (discarding) {
        // The remainder of an oversized line is still in flight; resume at its newline.
        const nl = chunk.indexOf("\n");
        if (nl < 0) return;
        discarding = false;
        buffer = chunk.slice(nl + 1);
      } else {
        buffer += chunk;
      }
      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        if (!line || line.startsWith("Content-Length:")) continue;
        if (line.length > MAX_STDIO_LINE_CHARS) {
          hooks.onOversizedLine?.();
          continue;
        }
        hooks.onLine(line);
      }
      if (buffer.length > MAX_STDIO_LINE_CHARS) {
        buffer = "";
        discarding = true;
        hooks.onOversizedLine?.();
      }
    },
  };
}

/**
 * Starts the BLA MCP server over stdio (supporting newline-delimited JSON-RPC 2.0).
 */
export function startMcpStdioServer(): void {
  let processingQueue = Promise.resolve();
  const processor = createStdioLineProcessor({
    onLine: (line: string) => {
      // Parse first so cancel can abort an in-flight harden without waiting
      // for the serial request queue (issue #75).
      let req: JsonRpcRequest;
      try {
        req = JSON.parse(line) as JsonRpcRequest;
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
      if (req.method === "notifications/cancelled") {
        void handleMcpRequest(req);
        return;
      }
      processingQueue = processingQueue.then(async () => {
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
