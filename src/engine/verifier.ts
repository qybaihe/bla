import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import type {
  VerificationAgentAction,
  VerificationCheck,
  VerificationReport,
} from "../core/types.js";
import { auditTarget } from "./auditor.js";
import { buildDefenseCoverageContract } from "../core/coverage-contract.js";
import {
  applyDefenseScoreHonesty,
  DEFENSE_SCORE_DISCLAIMER,
} from "./defense-score-honesty.js";
import { inspectNativeBinary } from "../shields/formats/native.js";
import { inspectSqliteBuffer } from "../shields/formats/sqlite.js";
import { inspectWasmBinary, readWasmCustomSectionContent } from "../shields/formats/wasm.js";
import { canonicalSelfDigest } from "../shields/runtime/self-seal.js";
import { jsModuleHasHoistedDependencyGraph } from "../shields/javascript/ast-shield.js";
import {
  BUN_SIDECAR_COMPANION_SUFFIX,
  WASM_SIDECAR_SECTION_NAME,
  extractDexSidecarStringPoolNote,
  extractGgufSidecarMetadataNote,
  extractPycSidecarMarshalNote,
  extractSafetensorsSidecarMetadataNote,
  extractSqliteSidecarSchemaComment,
  isGgufSidecarLoaderHookWired,
  isPycSidecarLoaderHookWired,
  isSafetensorsSidecarLoaderHookWired,
  isSqliteSidecarLoaderHookWired,
  isWasmSidecarLoaderHookWired,
} from "../shields/runtime/sidecar-entangle.js";

export interface VerifyTargetOptions {
  readonly selfSealEnabled?: boolean;
  readonly sidecarEntangleEnabled?: boolean;
  readonly wasmExportRenameApplied?: boolean;
  readonly numericTemplateLeakKnown?: boolean;
  /**
   * When true (default for CLI `bla verify`), auto-detect verified on-disk
   * self-seal, sidecar-entangle bindings, and WASM export renames without
   * requiring caller metadata flags.
   */
  readonly autoDetectBindings?: boolean;
}

/**
 * Verifies a protected artifact against REA's analysis invariants (`bla verify`).
 * `defenseScore` is soft-capped when known product gaps still apply (issue #40.6).
 */
/**
 * Cap on an auto-detected `integrity-coverage.json`. It is a JSON coverage
 * matrix used only to decide whether a sibling pins this artifact, not an
 * artifact itself, so an implausibly large or symlinked file is ignored rather
 * than read into memory.
 */
const MAX_AUTODETECT_COVERAGE_BYTES = 8 * 1024 * 1024;

export function verifyTarget(
  targetPath: string,
  originalPath?: string,
  options: VerifyTargetOptions = {},
): VerificationReport {
  const absTarget = resolve(targetPath);
  const afterAudit = auditTarget(absTarget);
  const beforeAudit = originalPath ? auditTarget(resolve(originalPath)) : undefined;

  const sim = afterAudit.reaSimulation;
  const checks: VerificationCheck[] = [];

  // Check 1: REA Examination Status degraded to "limited"
  checks.push({
    id: "rea-examination-limited",
    name: "REA Static/Semantic Examination Degraded to Limited",
    targetReaComponent: "javascriptStaticAnalysis.ts / RustBinaryProvider / WabtWat.ts",
    passed: sim.examinationStatus === "limited" && sim.triggeredResourceLimits.length > 0,
    details:
      sim.triggeredResourceLimits.length > 0
        ? `Triggered resource limits: ${sim.triggeredResourceLimits.join(", ")}`
        : "No REA semantic resource limits triggered",
  });

  // Check 2: Algorithmic Tarpit & Obligation Graph Expansion
  checks.push({
    id: "obligation-graph-tarpit",
    name: "Algorithmic Tarpit & Call-Graph Labyrinth Active",
    targetReaComponent: "trace_application_feature / build_reconstruction_obligation_ledger",
    passed: sim.decoyFunctionsDetectedAsReal >= 5 && sim.obligationLedgerNodes >= 15,
    details: `Injected ${sim.decoyFunctionsDetectedAsReal} decoy tarpit nodes (${sim.obligationLedgerNodes} total obligation ledger nodes)`,
  });

  // Check 3: Architectural Chaff & Enclave Delegation Mirage
  checks.push({
    id: "architectural-chaff-mirage",
    name: "Defensive Architectural Chaff & Honey-Context Embedded",
    targetReaComponent: "Context Window / Evidence Dossier Summarizer",
    passed: sim.architecturalChaffPayloads >= 2,
    details: `${sim.architecturalChaffPayloads} enclave delegation & honey-contract payloads active`,
  });

  // Check 4: Electron IPC / Route / Binary Specific Invariant
  if (
    afterAudit.detectedFormat === "javascript" ||
    afterAudit.detectedFormat === "typescript" ||
    afterAudit.detectedFormat === "electron-asar" ||
    afterAudit.detectedFormat === "directory"
  ) {
    checks.push({
      id: "ipc-and-route-shield",
      name: "Electron IPC Pairing Ambiguity & Route Mirage",
      targetReaComponent: "electronStaticAnalysisIpc.ts / JavaScriptRouteScan.ts",
      passed:
        sim.ipcChannelsPairedUniquely === 0 &&
        (sim.ipcChannelsAmbiguousOrDynamic > 0 || sim.decoyRoutesHarvested > 0),
      details: `Uniquely paired IPC channels: ${sim.ipcChannelsPairedUniquely}; Ambiguous/Dynamic IPC sites: ${sim.ipcChannelsAmbiguousOrDynamic}; Decoy routes: ${sim.decoyRoutesHarvested}`,
    });
  } else {
    checks.push({
      id: "binary-container-shield",
      name: "Binary Container & Custom Section Shield",
      targetReaComponent: `inspect_${afterAudit.detectedFormat.replace("-", "_")}`,
      passed: afterAudit.protectionStatus === "BLA_PROTECTED",
      details: `Container status: ${afterAudit.protectionStatus} (Exposure score: ${afterAudit.exposureScore}/100)`,
    });
  }

  // Check 5: Token & Cost Bankruptcy Amplification
  const afterEst = afterAudit.agentEstimates[0]!;
  const baselineSource: "measured" | "assumed" = beforeAudit ? "measured" : "assumed";
  const beforeTokens = beforeAudit ? beforeAudit.agentEstimates[0]!.estimatedInputTokens : 3_200;
  const beforeCost = beforeAudit ? beforeAudit.agentEstimates[0]!.estimatedCostUsd : 0.12;
  const beforeNodes = beforeAudit ? Math.max(1, beforeAudit.reaSimulation.obligationLedgerNodes) : 3;

  const tokenAmp = Number((afterEst.estimatedInputTokens / Math.max(1, beforeTokens)).toFixed(1));
  const costAmp = Number((afterEst.estimatedCostUsd / Math.max(0.01, beforeCost)).toFixed(1));
  const graphAmp = Number((sim.obligationLedgerNodes / beforeNodes).toFixed(1));

  checks.push({
    id: "token-bankruptcy-amplification",
    name: "Agent Token & Cost Bankruptcy Amplification (>= 10x)",
    targetReaComponent: "MCP Context Window & Retained Evidence Paging",
    passed: tokenAmp >= 10 || afterEst.estimatedInputTokens >= 80_000,
    details:
      baselineSource === "measured"
        ? `Token amplification: ${tokenAmp}x (${afterEst.estimatedInputTokens.toLocaleString()} tokens, ~$${afterEst.estimatedCostUsd.toFixed(2)})`
        : `Token amplification: ${tokenAmp}x against an assumed baseline of 3,200 input tokens (${afterEst.estimatedInputTokens.toLocaleString()} tokens, ~$${afterEst.estimatedCostUsd.toFixed(2)}); pass the original artifact (bla verify <target> <original>) for a measured ratio`,
    baselineSource,
  });

  let targetBytes: Buffer | undefined;
  try {
    targetBytes = readFileSync(absTarget);
  } catch {
    targetBytes = undefined;
  }

  const autoDetect = options.autoDetectBindings === true;
  const sealRequired = options.selfSealEnabled === true;
  const sealSupported = afterAudit.detectedFormat === "javascript" ||
    afterAudit.detectedFormat === "typescript" || afterAudit.detectedFormat === "python-source";
  const sealText = sealSupported && (sealRequired || (autoDetect && options.selfSealEnabled !== false))
    ? targetBytes?.toString("latin1")
    : undefined;
  // A selfExpected variable in application code is not a binding. Match the
  // emitted digest assignment and the adjacent placeholder guard together.
  const sealMarkers = sealText === undefined ? [] : [
    ...sealText.matchAll(/(?:\bvar\s+selfExpected|\bself_expected)\s*=\s*(["'])([^"'\r\n]*)\1;?\s*(?:var\s+)?_ph\s*=\s*["']~self-digest-["']\s*\+\s*["']pending-finalize["']/g),
  ];
  const sealDigests = new Set(sealMarkers.map((marker) => marker[2]!));
  const effectiveSelfSealEnabled = targetBytes !== undefined &&
    sealDigests.size === 1 &&
    [...sealDigests].every((digest) =>
      /^[a-f0-9]{64}$/.test(digest) && canonicalSelfDigest(targetBytes, digest) === digest);
  if ((sealRequired || sealMarkers.length > 0) && !effectiveSelfSealEnabled) {
    checks.push({
      id: "self-seal-digest-integrity",
      name: "Self-Seal Canonical Self-Digest Integrity",
      targetReaComponent: "runtime/self-seal.ts",
      passed: false,
      details: sealMarkers.length === 0
        ? "Required self-seal binding is absent or unsupported for this artifact"
        : "Embedded canonical SHA-256 digest failed offline verification (file tampered or unfinalized after self-seal)",
    });
  }

  const passedCount = checks.filter((c) => c.passed).length;
  // Raw score = Counter-REA gate pass-rate + exposure drop only.
  // Soft-capped below when known gaps still apply (issue #40.6).
  const rawDefenseScore = Math.min(
    100,
    Math.round(
      (passedCount / checks.length) * 70 + Math.max(0, (100 - afterAudit.exposureScore) * 0.3),
    ),
  );
  const isNativeFormat =
    afterAudit.detectedFormat === "native-elf" ||
    afterAudit.detectedFormat === "native-macho" ||
    afterAudit.detectedFormat === "native-pe";
  let nativeMappedSectionInjected: boolean | undefined;
  if (isNativeFormat) {
    try {
      nativeMappedSectionInjected = Boolean(
        inspectNativeBinary(targetBytes ?? readFileSync(absTarget)).nativeMappedSectionInjected,
      );
    } catch {
      nativeMappedSectionInjected = false;
    }
  }

  let wasmSidecarLoaderHookApplied = false;
  if (afterAudit.detectedFormat === "wasm") {
    try {
      wasmSidecarLoaderHookApplied = isWasmSidecarLoaderHookWired({
        wasmBytes: targetBytes ?? readFileSync(absTarget),
        wasmPath: absTarget,
      });
    } catch {
      wasmSidecarLoaderHookApplied = false;
    }
  }

  let pycSidecarLoaderHookApplied = false;
  if (afterAudit.detectedFormat === "python-pyc") {
    try {
      pycSidecarLoaderHookApplied = isPycSidecarLoaderHookWired({
        pycBytes: targetBytes ?? readFileSync(absTarget),
        pycPath: absTarget,
      });
    } catch {
      pycSidecarLoaderHookApplied = false;
    }
  }

  let ggufSidecarLoaderHookApplied = false;
  if (afterAudit.detectedFormat === "model-gguf") {
    try {
      ggufSidecarLoaderHookApplied = isGgufSidecarLoaderHookWired({
        ggufBytes: targetBytes ?? readFileSync(absTarget),
        ggufPath: absTarget,
      });
    } catch {
      ggufSidecarLoaderHookApplied = false;
    }
  }

  let safetensorsSidecarLoaderHookApplied = false;
  if (afterAudit.detectedFormat === "model-safetensors") {
    try {
      safetensorsSidecarLoaderHookApplied = isSafetensorsSidecarLoaderHookWired({
        safetensorsBytes: targetBytes ?? readFileSync(absTarget),
        safetensorsPath: absTarget,
      });
    } catch {
      safetensorsSidecarLoaderHookApplied = false;
    }
  }

  let sqliteSidecarLoaderHookApplied = false;
  if (afterAudit.detectedFormat === "sqlite") {
    try {
      sqliteSidecarLoaderHookApplied = isSqliteSidecarLoaderHookWired({
        sqliteBytes: targetBytes ?? readFileSync(absTarget),
        sqlitePath: absTarget,
      });
    } catch {
      sqliteSidecarLoaderHookApplied = false;
    }
  }

  // Auto-detect on-disk sidecar entanglement when `autoDetectBindings` is set
  // (CLI `bla verify <protected> <original>`) and caller did not override.
  let effectiveSidecarEntangleEnabled = options.sidecarEntangleEnabled === true;
  if (autoDetect && options.sidecarEntangleEnabled === undefined && targetBytes) {
    try {
      const fmt = afterAudit.detectedFormat;
      if (fmt === "javascript" || fmt === "typescript") {
        const text = targetBytes.toString("latin1");
        if (
          /_verifySiblingDigest_[0-9a-f]{8}/.test(text) &&
          text.includes("integrity binding mismatch")
        ) {
          effectiveSidecarEntangleEnabled = true;
        }
      } else if (fmt === "python-source") {
        const text = targetBytes.toString("latin1");
        if (
          /_verify_sibling_digest_[0-9a-f]{8}/.test(text) &&
          text.includes("integrity binding mismatch")
        ) {
          effectiveSidecarEntangleEnabled = true;
        }
      } else if (fmt === "wasm") {
        effectiveSidecarEntangleEnabled =
          wasmSidecarLoaderHookApplied ||
          readWasmCustomSectionContent(targetBytes, WASM_SIDECAR_SECTION_NAME) !== null;
      } else if (fmt === "python-pyc") {
        effectiveSidecarEntangleEnabled =
          pycSidecarLoaderHookApplied || extractPycSidecarMarshalNote(targetBytes) !== null;
      } else if (fmt === "model-gguf") {
        effectiveSidecarEntangleEnabled =
          ggufSidecarLoaderHookApplied || extractGgufSidecarMetadataNote(targetBytes) !== null;
      } else if (fmt === "model-safetensors") {
        effectiveSidecarEntangleEnabled =
          safetensorsSidecarLoaderHookApplied ||
          extractSafetensorsSidecarMetadataNote(targetBytes) !== null;
      } else if (fmt === "android-dex") {
        effectiveSidecarEntangleEnabled = extractDexSidecarStringPoolNote(targetBytes) !== null;
      } else if (fmt === "sqlite") {
        effectiveSidecarEntangleEnabled =
          sqliteSidecarLoaderHookApplied ||
          extractSqliteSidecarSchemaComment(targetBytes) !== null;
      } else if (fmt === "native-elf" || fmt === "native-macho" || fmt === "native-pe") {
        effectiveSidecarEntangleEnabled = existsSync(`${absTarget}${BUN_SIDECAR_COMPANION_SUFFIX}`);
      }
      // Also check whether a sibling/parent `integrity-coverage.json` from
      // `bla harden --self-seal --sidecar-entangle` pins this artifact's exact SHA-256.
      if (!effectiveSidecarEntangleEnabled) {
        let dir = dirname(absTarget);
        for (let depth = 0; depth < 3; depth++) {
          const covPath = join(dir, "integrity-coverage.json");
          const covStat = lstatSync(covPath, { throwIfNoEntry: false });
          // `lstatSync` reports a symlink as itself, so a linked matrix is not
          // followed out of the tree, and the size cap bounds the read.
          if (covStat?.isFile() && covStat.size <= MAX_AUTODETECT_COVERAGE_BYTES) {
            const cov = JSON.parse(readFileSync(covPath, "utf8")) as {
              readonly expectedSha256?: Record<string, string>;
              readonly checks?: readonly { readonly target?: string; readonly expectedSha256?: string }[];
            };
            const targetSha = afterAudit.sha256.toLowerCase();
            const pinned =
              Object.values(cov.expectedSha256 ?? {}).some(
                (v) => typeof v === "string" && v.toLowerCase() === targetSha,
              ) ||
              (cov.checks ?? []).some(
                (c) => typeof c.expectedSha256 === "string" && c.expectedSha256.toLowerCase() === targetSha,
              );
            if (pinned) effectiveSidecarEntangleEnabled = true;
            break;
          }
          const parent = dirname(dir);
          if (parent === dir) break;
          dir = parent;
        }
      }
      // Also check whether a sibling Python entry in the same directory binds
      // this artifact in its `_sc_sidecars_<8hex> = [...]` list.
      if (!effectiveSidecarEntangleEnabled) {
        const selfBase = basename(absTarget);
        const selfDir = dirname(absTarget);
        const pySiblings = readdirSync(selfDir)
          .filter((n) => n.endsWith(".py") && n !== selfBase)
          .slice(0, 16);
        for (const pyName of pySiblings) {
          const pyPath = join(selfDir, pyName);
          try {
            if (statSync(pyPath).size > 1024 * 1024) continue;
            const pyText = readFileSync(pyPath, "latin1");
            const sidecarMatch = pyText.match(/_sc_sidecars_[0-9a-f]{8}\s*=\s*(\[[^\n]+\])/);
            if (!sidecarMatch || !pyText.includes("integrity binding mismatch")) continue;
            const list = JSON.parse(sidecarMatch[1]!) as unknown;
            if (Array.isArray(list) && list.includes(selfBase)) {
              effectiveSidecarEntangleEnabled = true;
              break;
            }
          } catch {
            /* ignore unreadable sibling */
          }
        }
      }
    } catch {
      /* ignore auto-detect read/parse error */
    }
  }

  let effectiveWasmExportRenameApplied = options.wasmExportRenameApplied === true;
  if (
    autoDetect &&
    options.wasmExportRenameApplied === undefined &&
    afterAudit.detectedFormat === "wasm" &&
    targetBytes &&
    originalPath
  ) {
    try {
      const origExports = new Set(inspectWasmBinary(readFileSync(resolve(originalPath))).exportNames);
      const targetExports = inspectWasmBinary(targetBytes).exportNames.filter(
        (n) => !n.startsWith("enclave_export_"),
      );
      if (targetExports.some((n) => !origExports.has(n))) {
        effectiveWasmExportRenameApplied = true;
      }
    } catch {
      /* ignore */
    }
  }

  let esmImportHoistBeforeHooks = false;
  if (
    afterAudit.detectedFormat === "javascript" ||
    afterAudit.detectedFormat === "typescript"
  ) {
    try {
      esmImportHoistBeforeHooks = jsModuleHasHoistedDependencyGraph(
        targetBytes ? targetBytes.toString("utf8") : readFileSync(absTarget, "utf8"),
        absTarget,
      );
    } catch {
      esmImportHoistBeforeHooks = false;
    }
  }

  let sqliteTrapMode: "none" | "stock" | "eval" | undefined;
  if (afterAudit.detectedFormat === "sqlite") {
    try {
      sqliteTrapMode = inspectSqliteBuffer(targetBytes ?? readFileSync(absTarget)).trapMode;
    } catch {
      sqliteTrapMode = undefined;
    }
  }

  const honesty = applyDefenseScoreHonesty(rawDefenseScore, {
    detectedFormat: afterAudit.detectedFormat,
    ...(sqliteTrapMode !== undefined ? { sqliteTrapMode } : {}),
    selfSealEnabled: effectiveSelfSealEnabled,
    sidecarEntangleEnabled: effectiveSidecarEntangleEnabled,
    wasmExportRenameApplied: effectiveWasmExportRenameApplied,
    numericTemplateLeakKnown: options.numericTemplateLeakKnown === true,
    ...(nativeMappedSectionInjected !== undefined
      ? { nativeMappedSectionInjected }
      : {}),
    ...(esmImportHoistBeforeHooks ? { esmImportHoistBeforeHooks: true } : {}),
    ...(wasmSidecarLoaderHookApplied ? { wasmSidecarLoaderHookApplied: true } : {}),
    ...(pycSidecarLoaderHookApplied ? { pycSidecarLoaderHookApplied: true } : {}),
    ...(ggufSidecarLoaderHookApplied ? { ggufSidecarLoaderHookApplied: true } : {}),
    ...(safetensorsSidecarLoaderHookApplied ? { safetensorsSidecarLoaderHookApplied: true } : {}),
    ...(sqliteSidecarLoaderHookApplied ? { sqliteSidecarLoaderHookApplied: true } : {}),
  });

  const agentActions: VerificationAgentAction[] = [];
  if (
    beforeAudit &&
    beforeAudit.protectionStatus === "BLA_PROTECTED" &&
    afterAudit.protectionStatus !== "BLA_PROTECTED"
  ) {
    agentActions.push({
      id: "reversed-verify-arguments",
      priority: "high",
      reason:
        "Arguments appear reversed: targetPath is unprotected while originalPath is already BLA_PROTECTED.",
      instruction: `Swap the two paths — usage is \`bla verify <protected-target> <original>\` (try \`bla verify ${resolve(originalPath!)} ${absTarget}\`).`,
      recommendedMcpTool: "bla_verify",
      recommendedArgs: {
        target_path: resolve(originalPath!),
        original_path: absTarget,
      },
    });
  }
  for (const check of checks) {
    if (!check.passed) {
      agentActions.push({
        id: `fix-check-${check.id}`,
        priority: "high",
        reason: `Verification check '${check.id}' failed (${check.details}).`,
        instruction:
          `Re-run hardening at 'bankrupt' intensity with weave_decoys:true on ${absTarget}, then re-verify.`,
        recommendedMcpTool: "bla_defend",
        recommendedArgs: {
          input_path: originalPath ? resolve(originalPath) : absTarget,
          intensity: "bankrupt",
          weave_decoys: true,
          self_seal: true,
        },
      });
    }
  }

  for (const gap of honesty.gaps) {
    if (gap.id === "self-seal-not-enabled") {
      agentActions.push({
        id: "enable-self-seal",
        priority: "medium",
        reason: gap.summary,
        instruction:
          "Enable self_seal: true (and sidecar_entangle: true for multi-file trees) during bla_harden / bla_defend, and pass self_seal_enabled: true when calling bla_verify directly.",
        recommendedMcpTool: "bla_defend",
        recommendedArgs: {
          input_path: originalPath ? resolve(originalPath) : absTarget,
          intensity: "bankrupt",
          self_seal: true,
          sidecar_entangle: true,
          weave_decoys: true,
        },
      });
    } else if (gap.id === "wasm-export-rename-pending") {
      agentActions.push({
        id: "enable-wasm-export-rename",
        priority: "medium",
        reason: gap.summary,
        instruction:
          "Protect the WASM artifact at maximum/bankrupt intensity (specifying only public ABI exports in wasm_preserve_exports) and pass wasm_export_rename_applied: true to bla_verify.",
        recommendedMcpTool: "bla_defend",
        recommendedArgs: {
          input_path: originalPath ? resolve(originalPath) : absTarget,
          intensity: "bankrupt",
        },
      });
    } else if (gap.id === "native-postlink-cfg-untouched") {
      agentActions.push({
        id: "compile-with-bla-headers",
        priority: "medium",
        reason: gap.summary,
        instruction:
          "Generate compile-time C/C++/Rust/Go defense headers via bla_emit_headers and include them before compiling/linking the native binary so decoy tarpit functions and xrefs live inside .text.",
        recommendedMcpTool: "bla_emit_headers",
        recommendedArgs: {
          language: "c",
          intensity: "bankrupt",
        },
      });
    }
  }

  return {
    targetPath: absTarget,
    ...(originalPath ? { originalPath: resolve(originalPath) } : {}),
    detectedFormat: afterAudit.detectedFormat,
    overallPassed: passedCount === checks.length,
    verificationScope: "counter-rea-structural",
    runtimeEquivalence: {
      status: "not-tested",
      reason: "No original-versus-protected programme execution or equivalence oracle was run.",
    },
    defenseScore: honesty.cappedScore,
    defenseScoreRaw: honesty.rawScore,
    defenseScoreGaps: honesty.gaps.map((g) => ({
      id: g.id,
      summary: g.summary,
      scoreCap: g.scoreCap,
    })),
    defenseScoreDisclaimer: DEFENSE_SCORE_DISCLAIMER,
    agentActions,
    checks,
    tokenAmplificationFactor: tokenAmp,
    costAmplificationFactor: costAmp,
    obligationGraphExpansionFactor: graphAmp,
    // Static parsing alone cannot establish executable functional equivalence.
    functionalIntegrityVerified: false,
    coverageContract: buildDefenseCoverageContract({
      clientProtected: afterAudit.protectionStatus === "BLA_PROTECTED",
    }),
  };
}
