/**
 * Unified packaging-footgun gate pipeline (red-blue R1–R12 → BLA 2.0).
 *
 * Aggregates every bankrupt refuse lint that harden already runs at project
 * level, plus advisory lane / panel-derive discovery (protect still refuses
 * those per-file). Agents call this via `bla lint` / MCP `bla_lint` instead of
 * eight separate tools.
 *
 * Honesty: gates close *packaging* footguns. They do **not** claim white-box
 * secrecy against full WASM RE / online guessing / SMT (R8–R12 residual).
 */

import { basename, relative, resolve, sep } from "node:path";
import { listKnownBlaOutputs } from "../core/output-registry.js";
import { BLA_BUILD_OUTPUT_DIR_NAMES, isInsideBuildOutput } from "./harden-apply.js";
import { sanitizeTerminalText } from "../core/terminal-text.js";
import type { ProtectionIntensity } from "../core/types.js";
import {
  discoverAndLintSealSidecars,
  intensityEnforcesSealRefusal,
  sealCommitmentRefuseMessage,
  type SealCommitmentReport,
} from "./seal-commitment-lint.js";
import {
  discoverAndLintWasmParamCarriers,
  intensityEnforcesWasmParamRefusal,
  wasmParamCarrierRefuseMessage,
  type WasmParamCarrierReport,
} from "./wasm-param-carrier-lint.js";
import {
  discoverAndLintJsAesUnwrap,
  intensityEnforcesJsAesUnwrapRefusal,
  jsAesUnwrapRefuseMessage,
  type JsAesUnwrapReport,
} from "./js-aes-unwrap-lint.js";
import {
  discoverAndLintJsWasmHydrateDump,
  intensityEnforcesJsWasmHydrateDumpRefusal,
  jsWasmHydrateDumpRefuseMessage,
  type JsWasmHydrateDumpReport,
} from "./js-wasm-hydrate-dump-lint.js";
import {
  discoverAndLintWasmXorMaskSidecars,
  intensityEnforcesWasmXorMaskSidecarRefusal,
  wasmXorMaskSidecarRefuseMessage,
  type WasmXorMaskSidecarReport,
} from "./wasm-xor-mask-sidecar-lint.js";
import {
  discoverAndLintWasmSealXorKnownPlaintext,
  intensityEnforcesWasmSealXorKnownPlaintextRefusal,
  wasmSealXorKnownPlaintextRefuseMessage,
  type WasmSealXorKnownPlaintextReport,
} from "./wasm-seal-xor-known-plaintext-lint.js";
import {
  discoverAndLintLaneIndependence,
  laneIndependenceRefuseMessage,
  type LaneIndependenceReport,
} from "./lane-independence-lint.js";
import {
  discoverAndLintPanelDerive,
  intensityEnforcesPanelOracleRefusal,
  panelDeriveRefuseMessage,
  type PanelDeriveAbiReport,
} from "./panel-derive-abi-lint.js";
import {
  discoverAndLintPlaintextSecrets,
  intensityEnforcesPlaintextSecretRefusal,
  plaintextSecretRefuseMessage,
  type PlaintextSecretReport,
} from "./plaintext-secret-lint.js";
import {
  discoverAndLintIntegrityCoverage,
  integrityCoverageRefuseMessage,
  type IntegrityCoverageFileReport,
} from "./integrity-coverage.js";
import {
  bindScopeRefuseMessage,
  discoverAndLintBindScope,
  intensityEnforcesBindScopeRefusal,
  type BindScopeLintReport,
} from "./bind-scope.js";
import {
  discoverAndLintReleaseHygiene,
  intensityEnforcesReleaseHygieneRefusal,
  releaseHygieneRefuseMessage,
  type ReleaseHygieneFileReport,
} from "./release-hygiene-lint.js";
import { BLA_IDENTITY } from "../identity.js";
import type { SarifLog } from "../core/sarif.js";

export const PACKAGING_GATES_SCHEMA = "bla-packaging-gates/v1" as const;

export type PackagingGateId =
  | "seal-commitment"
  | "wasm-param-carrier"
  | "js-aes-unwrap"
  | "js-wasm-hydrate-dump"
  | "wasm-xor-mask-sidecar"
  | "wasm-seal-xor-known-plaintext"
  | "lane-independence"
  | "panel-derive"
  | "plaintext-secret"
  | "integrity-coverage"
  | "bind-scope"
  | "release-hygiene";

/** One concrete hit behind a gate finding — what was matched and where. */
export interface PackagingGateEvidence {
  /** Sub-finding id from the underlying lint (e.g. `plaintext-flag-literal`). */
  readonly id: string;
  /** `warning` hits never refuse on their own. Absent when the lint has no severity. */
  readonly severity?: "warning" | "error";
  /** Short excerpt or description of what was matched. */
  readonly detail?: string;
  /** 1-based source line, when the lint could place the hit. */
  readonly line?: number;
}

/** Upper bound on evidence rows per gate finding (the rest is counted in `findingCount`). */
export const MAX_GATE_EVIDENCE = 5;

export interface PackagingGateFinding {
  readonly gate: PackagingGateId;
  readonly path: string;
  readonly relativePath: string;
  readonly shouldRefuseBankrupt: boolean;
  readonly refuseMessage?: string;
  readonly oneLineAdvice: string;
  readonly findingCount: number;
  /**
   * Up to `MAX_GATE_EVIDENCE` concrete hits, errors first, so an agent can act
   * on the finding without a second per-file lint call.
   */
  readonly evidence?: readonly PackagingGateEvidence[];
  readonly remediationRecipe?: string;
  readonly recommendedMcpTool?: string;
  /**
   * Whether `bla_harden` itself refuses the run because of this finding.
   * `false` is either advisory (a warning that blocks nothing) or a lint-only
   * hygiene gate: this scan fails on it, but a harden run still goes ahead.
   */
  readonly enforcedByHarden?: boolean;
  /**
   * Source files (project-relative) that carry this same finding because this
   * build-output file was made from them. They are not listed as findings of
   * their own: fix the value there and rebuild — never rewrite the source
   * file with a masking tool.
   */
  readonly sameFindingInSource?: readonly string[];
}

/**
 * Gates `bla_harden` does not enforce — `bla lint` is the only place they
 * fail. Everything else is refused by harden at project level or by the
 * per-file protect step.
 */
const LINT_ONLY_GATES: ReadonlySet<PackagingGateId> = new Set<PackagingGateId>([
  "plaintext-secret",
  "integrity-coverage",
  "bind-scope",
]);

export interface PackagingGateRemediation {
  readonly gate: PackagingGateId;
  readonly path: string;
  readonly relativePath: string;
  /** `low` = advisory the engine already handles; no source change required. */
  readonly priority: "critical" | "high" | "medium" | "low";
  readonly owner: "agent-source-refactor" | "mcp-tool-call";
  readonly recommendedMcpTool?: string;
  readonly sourceRefactorRecipe: string;
  readonly verifyCommand: string;
}

export interface PackagingGatesAllowOptions {
  readonly allowPlaintextSeal?: boolean;
  readonly allowWasmClearParamCarriers?: boolean;
  readonly allowJsAesUnwrap?: boolean;
  readonly allowJsWasmHydrateDump?: boolean;
  readonly allowWasmXorMaskSidecar?: boolean;
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  readonly allowLaneIndependentGates?: boolean;
  readonly allowPanelOfflineOracle?: boolean;
  readonly allowStablePanelDeriveAbi?: boolean;
  readonly allowPlaintextString?: boolean;
  /** Lab escape: allow bankrupt despite failing integrity coverage matrix. */
  readonly allowSinglePointIntegrity?: boolean;
  /** Lab escape: allow bind-scope contract without runtime check / non-public fields. */
  readonly allowMissingBindRuntime?: boolean;
  /** Lab escape: allow leaked SOLUTION/dotenv/private-key/debug-symbol files in release tree. */
  readonly allowReleaseHygieneLeak?: boolean;
}

export interface PackagingGatesScanOptions extends PackagingGatesAllowOptions {
  readonly directory: string;
  /** Intensity used to decide which findings refuse bankrupt (default bankrupt). */
  readonly intensity?: ProtectionIntensity;
  /**
   * When true (default), also scan JS/HTML for lane-independence + panel-derive.
   * Harden project-level refuse historically used the six carrier/JS/WASM gates
   * only — lanes/panel stay protect-time unless includeProtectTimeGates.
   */
  readonly includeProtectTimeGates?: boolean;
}

export interface PackagingGatesReport {
  readonly schema: typeof PACKAGING_GATES_SCHEMA;
  readonly directory: string;
  readonly intensity: ProtectionIntensity;
  readonly findings: readonly PackagingGateFinding[];
  /** Findings that would refuse bankrupt/maximum under current allow flags. */
  readonly blocking: readonly PackagingGateFinding[];
  /** Structured Agent remediation plan for autonomous source refactoring before harden. */
  readonly remediationPlan: readonly PackagingGateRemediation[];
  readonly shouldRefuseBankrupt: boolean;
  readonly gateCounts: Readonly<Record<PackagingGateId, number>>;
  readonly oneLineAdvice: string;
  readonly honestyNote: string;
  /**
   * Files this scan left out because they are BLA's own hardened output
   * (project-relative, capped). Their decoys are bait, not findings — lint the
   * files they were built from. Present only when non-empty.
   */
  readonly skippedHardenedOutputs?: readonly string[];
  /** Raw per-gate reports for agents that need detail. */
  readonly details: {
    readonly seals: readonly SealCommitmentReport[];
    readonly wasmParams: readonly WasmParamCarrierReport[];
    readonly jsAes: readonly JsAesUnwrapReport[];
    readonly jsHydrateDump: readonly JsWasmHydrateDumpReport[];
    readonly wasmXorMask: readonly WasmXorMaskSidecarReport[];
    readonly wasmSealXor: readonly WasmSealXorKnownPlaintextReport[];
    readonly lanes: ReadonlyArray<LaneIndependenceReport & { readonly path: string }>;
    readonly panelDerive: readonly PanelDeriveAbiReport[];
    readonly plaintextSecrets: readonly PlaintextSecretReport[];
    readonly integrityCoverage: readonly IntegrityCoverageFileReport[];
    readonly bindScope: readonly BindScopeLintReport[];
    readonly releaseHygiene: readonly ReleaseHygieneFileReport[];
  };
}

const HONESTY_NOTE =
  "Packaging gates close shipping footguns (R1–R7 refuse + R8–R12 engine hygiene). " +
  "They do not claim white-box secrecy against full WASM RE / online guessing / SMT.";

function relPath(absDir: string, filePath: string): string {
  return (relative(absDir, filePath) || basename(filePath)).split(sep).join("/");
}

/** JS / TS / HTML: the files a build copies, transpiles or bundles into its output. */
const BUILD_INPUT_EXT_RE = /\.(?:[cm]?[jt]sx?|html?)$/i;

/**
 * A copy or transpile build leaves the same finding twice: on
 * `dist/license.cjs`, which ships, and on the `src/license.cjs` it was made
 * from. Listed as two findings, the remediation plan sends an agent to run a
 * rewriting tool on a source file. The build output keeps the finding and
 * names its source (`sameFindingInSource`); the source is not listed again.
 *
 * Two findings are the same when gate, file stem and evidence agree — line
 * numbers do not have to, a transpiler moves them. Only this presentation is
 * folded: `details` keeps every file, and that is what `bla_harden` refuses on.
 */
function foldBuildInputTwins(
  findings: readonly PackagingGateFinding[],
  absDir: string,
  counts: Record<PackagingGateId, number>,
): PackagingGateFinding[] {
  const shipped = (f: PackagingGateFinding): boolean =>
    isInsideBuildOutput(f.relativePath, absDir, BLA_BUILD_OUTPUT_DIR_NAMES);
  const keyOf = (f: PackagingGateFinding): string =>
    JSON.stringify([
      f.gate,
      (basename(f.relativePath).split(".")[0] ?? "").toLowerCase(),
      f.shouldRefuseBankrupt,
      f.findingCount,
      (f.evidence ?? []).map((e) => [e.id, e.severity ?? "", e.detail ?? ""]),
    ]);
  const outputByKey = new Map<string, number>();
  findings.forEach((f, index) => {
    if (!BUILD_INPUT_EXT_RE.test(f.relativePath) || !shipped(f)) return;
    const key = keyOf(f);
    if (!outputByKey.has(key)) outputByKey.set(key, index);
  });
  if (outputByKey.size === 0) return [...findings];

  const sourcesOf = new Map<number, string[]>();
  const folded = new Set<number>();
  findings.forEach((f, index) => {
    if (!BUILD_INPUT_EXT_RE.test(f.relativePath) || shipped(f)) return;
    const target = outputByKey.get(keyOf(f));
    if (target === undefined) return;
    sourcesOf.set(target, [...(sourcesOf.get(target) ?? []), f.relativePath]);
    folded.add(index);
    counts[f.gate] -= 1;
  });
  return findings.flatMap((f, index) => {
    if (folded.has(index)) return [];
    const sources = sourcesOf.get(index);
    return [sources !== undefined ? { ...f, sameFindingInSource: sources } : f];
  });
}

/** What a recipe adds for a finding that also sits in the file's source. */
function sourceTwinNote(f: PackagingGateFinding): string {
  const sources = f.sameFindingInSource;
  if (sources === undefined || sources.length === 0) return "";
  return ` Also in ${sources.map((s) => `\`${s}\``).join(", ")} — the source this file is built from, not listed as a finding of its own. A fix made there needs a rebuild; a fix made only in the build output lasts until the next build. Tools that rewrite a file (\`bla_encrypt_strings\`, \`bla_harden\`) belong on the build output, never on the source.`;
}

function emptyCounts(): Record<PackagingGateId, number> {
  return {
    "seal-commitment": 0,
    "wasm-param-carrier": 0,
    "js-aes-unwrap": 0,
    "js-wasm-hydrate-dump": 0,
    "wasm-xor-mask-sidecar": 0,
    "wasm-seal-xor-known-plaintext": 0,
    "lane-independence": 0,
    "panel-derive": 0,
    "plaintext-secret": 0,
    "integrity-coverage": 0,
    "bind-scope": 0,
    "release-hygiene": 0,
  };
}

/**
 * Project the heterogeneous per-lint finding shapes onto compact evidence rows.
 * Errors sort first so the cap never hides the reason a gate refuses.
 */
function summarizeEvidence(
  findings: ReadonlyArray<unknown>,
): readonly PackagingGateEvidence[] | undefined {
  const rows: PackagingGateEvidence[] = [];
  for (const raw of findings) {
    if (typeof raw === "string") {
      rows.push({ id: "reason", detail: sanitizeTerminalText(raw).slice(0, 160) });
      continue;
    }
    if (typeof raw !== "object" || raw === null) continue;
    const f = raw as Record<string, unknown>;
    const id =
      typeof f.id === "string" ? f.id : typeof f.kind === "string" ? f.kind : "finding";
    const detailSource =
      typeof f.evidence === "string" && f.evidence.length > 0
        ? f.evidence
        : typeof f.summary === "string"
          ? f.summary
          : undefined;
    rows.push({
      id,
      ...(f.severity === "warning" || f.severity === "error"
        ? { severity: f.severity }
        : {}),
      ...(detailSource !== undefined
        ? { detail: sanitizeTerminalText(detailSource).replace(/\s+/g, " ").slice(0, 160) }
        : {}),
      ...(typeof f.line === "number" ? { line: f.line } : {}),
    });
  }
  if (rows.length === 0) return undefined;
  rows.sort(
    (a, b) => Number(b.severity === "error") - Number(a.severity === "error"),
  );
  return rows.slice(0, MAX_GATE_EVIDENCE);
}

function buildGateRemediationMeta(
  gate: PackagingGateId,
  rel: string,
  evidenceIds: ReadonlySet<string> = new Set(),
): {
  readonly owner: "agent-source-refactor" | "mcp-tool-call";
  readonly recommendedMcpTool?: string;
  readonly sourceRefactorRecipe: string;
  /** True when the finding needs no source change (the engine already covers it). */
  readonly advisoryOnly?: boolean;
} {
  switch (gate) {
    case "lane-independence":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, replace per-byte / per-segment independent comparisons (e.g. \`key[i] === ...\` or \`parts[0] === ...\`) with a single whole-key chained ARX/FNV/SHA-256 accumulator so no byte can be solved in isolation, or move unlock verification into WASM.`,
      };
    case "seal-commitment":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove plaintext keys/flags/seeds and replace reversible \`(scheduleSalt + rounds + revision)\` fields with a one-way \`SHA-256\` commitment (\`certificateSha256\`), keeping the materialization \`seed\` private.`,
      };
    case "wasm-param-carrier":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove clear ASCII magic headers (\`R3PARM\`/\`R3CIPH\`/\`R2SEAL\`) from WASM data segments and derive mask keys via one-way \`SHA-256(key)\` inside WASM.`,
      };
    case "js-aes-unwrap":
      return {
        owner: "agent-source-refactor",
        recommendedMcpTool: "bla_encrypt_strings",
        sourceRefactorRecipe: `In \`${rel}\`, remove hardcoded AES wrap-key material + \`createDecipheriv\` from JS; move payload unlocking inside WASM or use \`bla_encrypt_strings\` (seed-derived XOR stream) for non-cryptographic literal masking.`,
      };
    case "js-wasm-hydrate-dump":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, stop reading \`memory.buffer\` salt/rounds/cipher layouts in JS after WASM instantiation; keep the entire ARX/KDF + certificate check inside WASM \`unlock(keyPtr, keyLen) -> outLen\`.`,
      };
    case "wasm-xor-mask-sidecar":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, do not store a static 32-byte XOR mask beside the masked blob in WASM linear memory; derive the keystream from user key bytes via one-way KDF at runtime.`,
      };
    case "wasm-seal-xor-known-plaintext":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`, remove public \`seal.revision\` digests from the XOR-masked WASM payload (known-plaintext recovers the repeating XOR mask without a key); store public commitments in a separate unmasked segment.`,
      };
    case "panel-derive": {
      const onlyFnvConstants =
        evidenceIds.size > 0 &&
        [...evidenceIds].every((id) => id === "classic-fnv-prime-literal");
      if (onlyFnvConstants) {
        // A readable FNV-1a prime is not an oracle; do not send the agent hunting
        // for a `deriveLocal` / `panelTokenSha256` pair that is not in the file.
        return {
          owner: "mcp-tool-call",
          recommendedMcpTool: "bla_harden",
          advisoryOnly: true,
          sourceRefactorRecipe: `Advisory only — no source change needed. \`${rel}\` contains readable FNV-1a constants (0x811c9dc5 / 0x01000193); \`bla_harden\` at \`maximum\`/\`bankrupt\` rewrites integer literals into opaque expressions, so they do not survive in the hardened output.`,
        };
      }
      const parts: string[] = [];
      if (evidenceIds.has("panel-token-sha-oracle")) {
        parts.push(
          "stop shipping a callable local derive next to the plaintext `panelTokenSha256` it can be checked against (move the derive behind the server or into WASM, or drop the digest from the shipped tree)",
        );
      }
      if (
        evidenceIds.has("stable-panel-derive-global") ||
        evidenceIds.has("stable-local-derive") ||
        parts.length === 0
      ) {
        parts.push(
          "let `bla_harden` at `bankrupt` intensity rewrite the stable `__vaultPanelDerive_*` / `deriveLocal` symbols to seed-stable identifiers (do not pass `allow_stable_panel_derive` outside a lab)",
        );
      }
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `In \`${rel}\`: ${parts.join("; ")}.`,
      };
    }
    case "plaintext-secret":
      return {
        owner: "mcp-tool-call",
        recommendedMcpTool: "bla_encrypt_strings",
        sourceRefactorRecipe: `Call MCP \`bla_encrypt_strings\` on \`${rel}\` with your project seed to XOR-mask the cleartext literals listed in \`evidence\`, then re-run \`bla_lint\`. It replaces whole string literals and \`\`…\`\` templates without \`\${}\`; a secret inside an interpolated template, a regular expression or an HTML attribute must be moved into a plain string literal (or out of the shipped file) by hand first. This gate is lint-only: \`bla_harden\` does not refuse on it. At \`maximum\`/\`bankrupt\` it splits string and template text of 3–256 characters itself, and a secret-looking value of up to 4,096 characters wherever it is written (string, template, object key, regular expression); whatever it could not reach (HTML attributes, tagged templates, class member names, TypeScript object keys and \`as const\` values, longer values) is listed in \`artifacts[].plaintextSurvivors\`.`,
      };
    case "integrity-coverage":
      return {
        owner: "mcp-tool-call",
        recommendedMcpTool: "bla_harden",
        sourceRefactorRecipe: `Ensure \`${rel}\` forms a strongly-connected interleaved verification graph where each node checks >=1 sibling and no single node is a single point of failure, or re-run \`bla_harden\` with \`self_seal: true\`.`,
      };
    case "bind-scope":
      return {
        owner: "mcp-tool-call",
        recommendedMcpTool: "bla_bind_scope",
        sourceRefactorRecipe: `Ensure \`${rel}\` sets \`"public": true\`, valid ISO dates / domain globs, and inject \`BLA_BIND_SCOPE_CHECK\` into the entry module via MCP \`bla_bind_scope\`.`,
      };
    case "release-hygiene":
      return {
        owner: "agent-source-refactor",
        sourceRefactorRecipe: `Delete or exclude leaked environment artifact \`${rel}\` (SOLUTION/writeup notes, populated \`.env\`, SSH/PEM private keys, or \`.pdb\`/\`.dSYM\`/\`.dwp\` debug databases) from the release directory before hardening.`,
      };
  }
}

/**
 * Scan a project (or file) for every packaging footgun lint.
 * Read-only — never writes.
 */
export function scanPackagingGates(
  options: PackagingGatesScanOptions,
): PackagingGatesReport {
  const absDir = resolve(options.directory);
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";
  const includeProtectTime = options.includeProtectTimeGates !== false;

  const seals = discoverAndLintSealSidecars(absDir);
  const wasmParams = discoverAndLintWasmParamCarriers(absDir);
  const jsAes = discoverAndLintJsAesUnwrap(absDir);
  const jsHydrateDump = discoverAndLintJsWasmHydrateDump(absDir);
  const wasmXorMask = discoverAndLintWasmXorMaskSidecars(absDir);
  const wasmSealXor = discoverAndLintWasmSealXorKnownPlaintext(absDir);
  const lanes = includeProtectTime
    ? discoverAndLintLaneIndependence(absDir)
    : [];
  const panelDerive = includeProtectTime
    ? discoverAndLintPanelDerive(absDir)
    : [];
  const plaintextSecrets = discoverAndLintPlaintextSecrets(absDir, {
    allowPlaintextString: options.allowPlaintextString,
  });
  const integrityCoverage = discoverAndLintIntegrityCoverage(absDir);
  const bindScope = discoverAndLintBindScope(absDir);
  const releaseHygiene = discoverAndLintReleaseHygiene(absDir);

  const findings: PackagingGateFinding[] = [];
  const counts = emptyCounts();

  for (const r of seals) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["seal-commitment"] += 1;
    findings.push({
      gate: "seal-commitment",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? sealCommitmentRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of wasmParams) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["wasm-param-carrier"] += 1;
    findings.push({
      gate: "wasm-param-carrier",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? wasmParamCarrierRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of jsAes) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["js-aes-unwrap"] += 1;
    findings.push({
      gate: "js-aes-unwrap",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? jsAesUnwrapRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of jsHydrateDump) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["js-wasm-hydrate-dump"] += 1;
    findings.push({
      gate: "js-wasm-hydrate-dump",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? jsWasmHydrateDumpRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of wasmXorMask) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["wasm-xor-mask-sidecar"] += 1;
    findings.push({
      gate: "wasm-xor-mask-sidecar",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? wasmXorMaskSidecarRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of wasmSealXor) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["wasm-seal-xor-known-plaintext"] += 1;
    findings.push({
      gate: "wasm-seal-xor-known-plaintext",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? wasmSealXorKnownPlaintextRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of lanes) {
    if (!r.looksLaneIndependent) continue;
    counts["lane-independence"] += 1;
    findings.push({
      gate: "lane-independence",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: true,
      refuseMessage: laneIndependenceRefuseMessage(r, r.path),
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of panelDerive) {
    const refuse =
      r.shouldRefuseBankrupt ||
      (r.stableSymbols.length > 0 || r.localDeriveSymbols.length > 0);
    if (r.findings.length === 0 && !refuse) continue;
    counts["panel-derive"] += 1;
    findings.push({
      gate: "panel-derive",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: refuse ? panelDeriveRefuseMessage(r, r.path) : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of plaintextSecrets) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["plaintext-secret"] += 1;
    findings.push({
      gate: "plaintext-secret",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? plaintextSecretRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of integrityCoverage) {
    if (r.ok && !r.shouldRefuseBankrupt) continue;
    counts["integrity-coverage"] += 1;
    findings.push({
      gate: "integrity-coverage",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? integrityCoverageRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.reasons.length,
      ...(() => {
        const evidence = summarizeEvidence(r.reasons);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of bindScope) {
    if (r.ok && !r.shouldRefuseBankrupt) continue;
    counts["bind-scope"] += 1;
    findings.push({
      gate: "bind-scope",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? bindScopeRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.reasons.length,
      ...(() => {
        const evidence = summarizeEvidence(r.reasons);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }
  for (const r of releaseHygiene) {
    if (r.findings.length === 0 && !r.shouldRefuseBankrupt) continue;
    counts["release-hygiene"] += 1;
    findings.push({
      gate: "release-hygiene",
      path: r.path,
      relativePath: relPath(absDir, r.path),
      shouldRefuseBankrupt: r.shouldRefuseBankrupt,
      refuseMessage: r.shouldRefuseBankrupt
        ? releaseHygieneRefuseMessage(r, r.path)
        : undefined,
      oneLineAdvice: r.oneLineAdvice,
      findingCount: r.findings.length,
      ...(() => {
        const evidence = summarizeEvidence(r.findings);
        return evidence !== undefined ? { evidence } : {};
      })(),
    });
  }

  // Recipes are chosen from the sub-findings actually present, so guidance
  // never names a construct that is not in the file.
  const evidenceIdsOf = (f: PackagingGateFinding): ReadonlySet<string> => {
    const raw =
      f.gate === "panel-derive"
        ? panelDerive.find((r) => r.path === f.path)?.findings
        : undefined;
    return new Set((raw ?? f.evidence ?? []).map((e) => e.id));
  };

  const listedFindings = foldBuildInputTwins(findings, absDir, counts);
  const enrichedFindings: PackagingGateFinding[] = listedFindings.map((f) => {
    const meta = buildGateRemediationMeta(f.gate, f.relativePath, evidenceIdsOf(f));
    return {
      ...f,
      remediationRecipe: `${meta.sourceRefactorRecipe}${sourceTwinNote(f)}`,
      ...(meta.recommendedMcpTool !== undefined
        ? { recommendedMcpTool: meta.recommendedMcpTool }
        : {}),
      enforcedByHarden: !LINT_ONLY_GATES.has(f.gate),
    };
  });

  const blockingUnmarked = filterBlockingFindings(enrichedFindings, intensity, options);
  // A warning blocks nothing, so it is not "enforced" either — only a finding
  // that fails this scan can be one harden refuses on.
  const blockingRefs = new Set<PackagingGateFinding>(blockingUnmarked);
  for (let i = 0; i < enrichedFindings.length; i++) {
    const f = enrichedFindings[i]!;
    if (f.enforcedByHarden === true && !blockingRefs.has(f)) {
      enrichedFindings[i] = { ...f, enforcedByHarden: false };
    }
  }
  const blocking = filterBlockingFindings(enrichedFindings, intensity, options);

  const remediationPlan: PackagingGateRemediation[] = enrichedFindings.map((f) => {
    const meta = buildGateRemediationMeta(f.gate, f.relativePath, evidenceIdsOf(f));
    const isBlocking = blocking.some(
      (b) => b.gate === f.gate && b.path === f.path,
    );
    return {
      gate: f.gate,
      path: f.path,
      relativePath: f.relativePath,
      priority: isBlocking
        ? "critical"
        : f.shouldRefuseBankrupt
          ? "high"
          : meta.advisoryOnly === true
            ? "low"
            : "medium",
      owner: meta.owner,
      ...(meta.recommendedMcpTool !== undefined
        ? { recommendedMcpTool: meta.recommendedMcpTool }
        : {}),
      sourceRefactorRecipe: `${meta.sourceRefactorRecipe}${sourceTwinNote(f)}`,
      verifyCommand: "bla_lint",
    };
  });

  const skippedHardenedOutputs = listKnownBlaOutputs(absDir);
  const foldedSources = enrichedFindings.reduce(
    (n, f) => n + (f.sameFindingInSource?.length ?? 0),
    0,
  );
  const skippedNote =
    (skippedHardenedOutputs.length > 0
      ? ` ${skippedHardenedOutputs.length} BLA-hardened output file(s) were not linted (see skippedHardenedOutputs) — lint the files they were built from.`
      : "") +
    (foldedSources > 0
      ? ` ${foldedSources} finding(s) repeat in the source a build-output file was made from; they are listed once, on the file that ships (sameFindingInSource).`
      : "");
  // Say which failures actually stop `bla_harden`: an agent told "harden would
  // refuse" about a lint-only gate goes off fixing something that blocks nothing.
  const hardenRefusing = blocking.filter((f) => f.enforcedByHarden !== false).length;
  const lintOnly = blocking.length - hardenRefusing;
  const blockingAdvice =
    hardenRefusing === 0
      ? `ERROR: ${blocking.length} packaging gate finding(s) fail this lint at ${intensity}. bla_harden does not refuse on them (enforcedByHarden: false) — it will still run; fix them per remediationPlan or pass the matching --allow-* / allow_* flag (lab only).`
      : `ERROR: ${hardenRefusing} packaging gate(s) would refuse ${intensity} harden${lintOnly > 0 ? `, and ${lintOnly} more fail this lint only (enforcedByHarden: false)` : ""}. Follow remediationPlan to refactor source or pass the matching --allow-* / allow_* flag (lab only).`;
  const oneLineAdvice =
    (blocking.length === 0
      ? enrichedFindings.length === 0
        ? "No packaging footgun findings (heuristic). Gates ≠ white-box secrecy."
        : `Packaging scan: ${enrichedFindings.length} finding(s), none refuse under current intensity/allows.`
      : blockingAdvice) + skippedNote;

  return {
    schema: PACKAGING_GATES_SCHEMA,
    directory: absDir,
    intensity,
    findings: enrichedFindings,
    blocking,
    remediationPlan,
    shouldRefuseBankrupt: blocking.length > 0,
    gateCounts: counts,
    oneLineAdvice,
    honestyNote: HONESTY_NOTE,
    ...(skippedHardenedOutputs.length > 0 ? { skippedHardenedOutputs } : {}),
    details: {
      seals,
      wasmParams,
      jsAes,
      jsHydrateDump,
      wasmXorMask,
      wasmSealXor,
      lanes,
      panelDerive,
      plaintextSecrets,
      integrityCoverage,
      bindScope,
      releaseHygiene,
    },
  };
}

export function filterBlockingFindings(
  findings: readonly PackagingGateFinding[],
  intensity: ProtectionIntensity,
  allow: PackagingGatesAllowOptions,
): PackagingGateFinding[] {
  return findings.filter((f) => {
    if (!f.shouldRefuseBankrupt && f.gate !== "lane-independence") {
      // panel stable-ABI rewrite is not a harden project-level refuse today
      return false;
    }
    switch (f.gate) {
      case "seal-commitment":
        return intensityEnforcesSealRefusal(intensity) && allow.allowPlaintextSeal !== true;
      case "wasm-param-carrier":
        return (
          intensityEnforcesWasmParamRefusal(intensity) &&
          allow.allowWasmClearParamCarriers !== true
        );
      case "js-aes-unwrap":
        return (
          intensityEnforcesJsAesUnwrapRefusal(intensity) &&
          allow.allowJsAesUnwrap !== true
        );
      case "js-wasm-hydrate-dump":
        return (
          intensityEnforcesJsWasmHydrateDumpRefusal(intensity) &&
          allow.allowJsWasmHydrateDump !== true
        );
      case "wasm-xor-mask-sidecar":
        return (
          intensityEnforcesWasmXorMaskSidecarRefusal(intensity) &&
          allow.allowWasmXorMaskSidecar !== true
        );
      case "wasm-seal-xor-known-plaintext":
        return (
          intensityEnforcesWasmSealXorKnownPlaintextRefusal(intensity) &&
          allow.allowWasmSealXorKnownPlaintext !== true
        );
      case "lane-independence":
        // Project-level lint reports lanes; harden project refuse historically
        // left lanes to protect-time. Blocking list for `bla lint` treats them
        // as refuse-worthy so agents see the same footgun before harden.
        return allow.allowLaneIndependentGates !== true && f.shouldRefuseBankrupt;
      case "panel-derive":
        return (
          intensityEnforcesPanelOracleRefusal(intensity) &&
          allow.allowPanelOfflineOracle !== true &&
          f.shouldRefuseBankrupt
        );
      case "plaintext-secret":
        return (
          intensityEnforcesPlaintextSecretRefusal(intensity) &&
          allow.allowPlaintextString !== true &&
          f.shouldRefuseBankrupt
        );
      case "integrity-coverage":
        return (
          intensity === "bankrupt" &&
          allow.allowSinglePointIntegrity !== true &&
          f.shouldRefuseBankrupt
        );
      case "bind-scope":
        return (
          intensityEnforcesBindScopeRefusal(intensity) &&
          allow.allowMissingBindRuntime !== true &&
          f.shouldRefuseBankrupt
        );
      case "release-hygiene":
        return (
          intensityEnforcesReleaseHygieneRefusal(intensity) &&
          allow.allowReleaseHygieneLeak !== true &&
          f.shouldRefuseBankrupt
        );
      default: {
        // Fail closed: a gate id added to `PackagingGateId` without a refusal
        // decision here must not silently become advisory-only.
        const unhandled: never = f.gate;
        throw new Error(`Unhandled packaging gate: ${String(unhandled)}`);
      }
    }
  });
}

/**
 * Subset of packaging gates that hardenProject historically refuses at
 * project scope (excludes lane/panel — those remain protect-time).
 */
export function evaluateHardenProjectPackagingBlocks(
  options: PackagingGatesScanOptions,
): {
  readonly report: PackagingGatesReport;
  readonly blockingSeals: readonly SealCommitmentReport[];
  readonly blockingWasmParms: readonly WasmParamCarrierReport[];
  readonly blockingJsAes: readonly JsAesUnwrapReport[];
  readonly blockingJsHydrateDump: readonly JsWasmHydrateDumpReport[];
  readonly blockingWasmXorMask: readonly WasmXorMaskSidecarReport[];
  readonly blockingWasmSealXor: readonly WasmSealXorKnownPlaintextReport[];
  readonly blockingReleaseHygiene: readonly ReleaseHygieneFileReport[];
} {
  // Harden project-level: do not include protect-time gates in the scan used
  // for the early refuse path (preserves prior semantics).
  const report = scanPackagingGates({
    ...options,
    includeProtectTimeGates: false,
  });
  const intensity: ProtectionIntensity = options.intensity ?? "bankrupt";
  const blockingSeals =
    intensityEnforcesSealRefusal(intensity) && options.allowPlaintextSeal !== true
      ? report.details.seals.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingWasmParms =
    intensityEnforcesWasmParamRefusal(intensity) &&
    options.allowWasmClearParamCarriers !== true
      ? report.details.wasmParams.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingJsAes =
    intensityEnforcesJsAesUnwrapRefusal(intensity) &&
    options.allowJsAesUnwrap !== true
      ? report.details.jsAes.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingJsHydrateDump =
    intensityEnforcesJsWasmHydrateDumpRefusal(intensity) &&
    options.allowJsWasmHydrateDump !== true
      ? report.details.jsHydrateDump.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingWasmXorMask =
    intensityEnforcesWasmXorMaskSidecarRefusal(intensity) &&
    options.allowWasmXorMaskSidecar !== true
      ? report.details.wasmXorMask.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingWasmSealXor =
    intensityEnforcesWasmSealXorKnownPlaintextRefusal(intensity) &&
    options.allowWasmSealXorKnownPlaintext !== true
      ? report.details.wasmSealXor.filter((r) => r.shouldRefuseBankrupt)
      : [];
  const blockingReleaseHygiene =
    intensityEnforcesReleaseHygieneRefusal(intensity) &&
    options.allowReleaseHygieneLeak !== true
      ? report.details.releaseHygiene.filter((r) => r.shouldRefuseBankrupt)
      : [];
  return {
    report,
    blockingSeals,
    blockingWasmParms,
    blockingJsAes,
    blockingJsHydrateDump,
    blockingWasmXorMask,
    blockingWasmSealXor,
    blockingReleaseHygiene,
  };
}

/** Human-readable CLI/MCP text for a packaging-gates report. */
export function formatPackagingGatesReport(report: PackagingGatesReport): string {
  const lines: string[] = [
    `BLA packaging gates — ${sanitizeTerminalText(report.directory)}`,
    report.oneLineAdvice,
    report.honestyNote,
  ];
  if (report.findings.length === 0) {
    lines.push("  (no findings)");
    return lines.join("\n");
  }
  for (const f of report.findings) {
    const tag = f.shouldRefuseBankrupt ? "refuse" : "info";
    lines.push(
      `  [${tag}] ${f.gate} · ${sanitizeTerminalText(f.relativePath)} · ${f.findingCount} finding(s)`,
    );
    lines.push(`    ${sanitizeTerminalText(f.oneLineAdvice)}`);
    if (f.sameFindingInSource !== undefined && f.sameFindingInSource.length > 0) {
      lines.push(
        `    same finding in its source: ${f.sameFindingInSource.map((s) => sanitizeTerminalText(s)).join(", ")}`,
      );
    }
  }
  if (report.blocking.length > 0) {
    lines.push(`blocking (${report.blocking.length}):`);
    for (const b of report.blocking) {
      lines.push(`  - ${b.gate} · ${sanitizeTerminalText(b.relativePath)}`);
      if (b.remediationRecipe) {
        lines.push(`    recipe: ${sanitizeTerminalText(b.remediationRecipe)}`);
      }
    }
  }
  return lines.join("\n");
}

/**
 * SARIF 2.1.0 projection of a packaging-gates report for CI code scanning
 * (`github/codeql-action/upload-sarif`), the same way `buildSarifReport` covers
 * audit findings. Each gate becomes one rule, refusing findings become `error`,
 * informational findings become `note`, and paths are emitted with forward
 * slashes so GitHub can match them to repository files.
 */
export function buildPackagingGatesSarif(report: PackagingGatesReport): SarifLog {
  const rulesMap = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      defaultConfiguration: { level: "error" | "warning" | "note" };
    }
  >();
  const results: SarifLog["runs"][0]["results"][number][] = [];

  for (const f of report.findings) {
    const ruleId = `BLA-LINT-${f.gate.toUpperCase().replace(/[^A-Z0-9]+/g, "-")}`;
    const level: "error" | "warning" | "note" = f.shouldRefuseBankrupt
      ? "error"
      : "note";
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: `PackagingGate_${f.gate}`,
        shortDescription: {
          text: `BLA packaging gate '${f.gate}' (${f.shouldRefuseBankrupt ? "bankrupt refusal" : "informational"})`,
        },
        defaultConfiguration: { level },
      });
    }
    results.push({
      ruleId,
      level,
      message: {
        text: `${f.gate}: ${f.findingCount} finding(s) — ${sanitizeTerminalText(f.oneLineAdvice)}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: sanitizeTerminalText(f.relativePath.replace(/\\/g, "/")) },
          },
        },
      ],
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: BLA_IDENTITY.packageName,
            fullName: BLA_IDENTITY.fullName,
            version: BLA_IDENTITY.version,
            informationUri: "https://bla.tools",
            rules: [...rulesMap.values()],
          },
        },
        results,
      },
    ],
  };
}
