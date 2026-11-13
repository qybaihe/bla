import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, type Stats } from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";
import { detectArtifactFormat } from "../core/detector.js";
import { buildDefenseCoverageContract } from "../core/coverage-contract.js";
import { estimateAgentReverseEngineeringCosts } from "../core/token-estimator.js";
import type {
  ArtifactFormat,
  AuditReport,
  ExposedSymbolOrModule,
  ReaAttackVectorId,
  ReaSemanticSimulationResult,
} from "../core/types.js";
import { unpackAsarBuffer } from "../shields/formats/asar.js";
import { inspectWasmBinary } from "../shields/formats/wasm.js";
import { lintWasmParamCarrierBuffer } from "./wasm-param-carrier-lint.js";
import { lintPanelDeriveAbiSource } from "./panel-derive-abi-lint.js";
import { lintJsAesUnwrapSource } from "./js-aes-unwrap-lint.js";
import { lintJsWasmHydrateDumpSource } from "./js-wasm-hydrate-dump-lint.js";
import { lintWasmXorMaskSidecarBuffer } from "./wasm-xor-mask-sidecar-lint.js";
import { inspectPythonPyc } from "../shields/formats/python.js";
import { inspectNativeBinary } from "../shields/formats/native.js";
import { detectBunStandaloneGraph } from "../shields/formats/bun-standalone.js";
import { readZipEntries } from "../shields/formats/archive.js";
import { inspectSqliteBuffer } from "../shields/formats/sqlite.js";
import { inspectModelBuffer } from "../shields/formats/model.js";
import { inspectAndroidDex } from "../shields/formats/mobile-game.js";
import { inspectErlangBeam } from "../shields/formats/erlang-beam.js";
import { inspectEvmBytecode } from "../shields/formats/evm-bytecode.js";
import { inspectPcapCapture } from "../shields/formats/pcap-capture.js";
import { inspectGpuPtx } from "../shields/formats/gpu-ptx.js";
import { inspectUf2Firmware } from "../shields/formats/firmware-uf2.js";
import { REA_INTERNAL_LIMITS } from "../identity.js";

type UnwrapDefault<T> = T extends { readonly default: infer D } ? D : T;
type TraverseFn = UnwrapDefault<typeof _traverse>;
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : (_traverse as unknown as { readonly default: TraverseFn }).default;

function isExecutableHtmlScriptAttrs(attrs: string): boolean {
  if (/\bsrc\s*=/i.test(attrs)) return false;
  const typeMatch = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
  if (!typeMatch) return true;
  const rawType = (typeMatch[1] ?? typeMatch[2] ?? typeMatch[3] ?? "")
    .trim()
    .toLowerCase();
  return (
    rawType === "" ||
    rawType === "module" ||
    rawType === "text/javascript" ||
    rawType === "application/javascript" ||
    rawType === "text/ecmascript" ||
    rawType === "application/ecmascript" ||
    rawType === "javascript"
  );
}

function extractExecutableHtmlInlineScripts(htmlText: string): readonly string[] {
  const scripts: string[] = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(htmlText)) !== null) {
    const attrs = m[1] ?? "";
    const body = m[2] ?? "";
    if (!body.trim()) continue;
    if (!isExecutableHtmlScriptAttrs(attrs)) continue;
    scripts.push(body);
  }
  return scripts;
}

function analyzeJsSourceForAudit(
  source: string,
  fileLabel: string,
): {
  sim: ReaSemanticSimulationResult;
  exposed: ExposedSymbolOrModule[];
  vectors: Set<ReaAttackVectorId>;
} {
  const exposed: ExposedSymbolOrModule[] = [];
  const vectors = new Set<ReaAttackVectorId>(["js-static-semantics"]);

  let visitedAstNodes = 0;
  let totalFunctions = 0;
  let decoyFunctionsDetectedAsReal = 0;
  let staticStringsResolved = 0;
  let staticStringsOpaque = 0;
  let ipcChannelsTotal = 0;
  const ipcLiteralCounts = new Map<string, number>();
  let ipcDynamicCount = 0;
  let routesDiscovered = 0;
  let decoyRoutesHarvested = 0;
  let architecturalChaffPayloads = 0;

  const triggeredLimits = new Set<string>();
  const uncertainties = new Set<string>();

  const chaffMatches = source.match(
    /\[(Architecture Notice|Static Analysis Diagnostic|Decompilation Advisory|Evidence Ledger Note|Compliance & Safety Boundary)\b|(?:EVIDENCE_CONTRACT_SUMMARY|ANALYSIS_VIEW_PROJECTION|RECONSTRUCTION_LEDGER_STATE|NATIVE_DISPATCH_TABLE_NOTE|SYMBOL_OFFSET_MANIFEST_[0-9A-F]+|FSM_SPEC_V3|QUORUM_PROTOCOL_DESCRIPTOR|IPC_BRIDGE_TOPOLOGY|HSM_ATTESTATION_DESCRIPTOR_[0-9a-f]+):/g,
  );
  if (chaffMatches) {
    architecturalChaffPayloads += chaffMatches.length;
  }

  let parseStatus: "complete" | "recovered" | "failed" = "complete";
  const pendingCustomerFunctions: Array<{ name: string; line: number }> = [];
  const pendingCustomerClasses: Array<{ name: string; line: number }> = [];
  let aliasOptionChainCount = 0;
  let combinatorialPlusChains = 0;
  let stringDoublingDecls = 0;
  let getterMethodsCount = 0;
  let hasRecursiveGrowGetter = false;
  let hasProtoExposure = false;
  let hasCursorWhileLoop = false;

  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      plugins: [
        "typescript",
        "jsx",
        "decorators-legacy",
      ],
      errorRecovery: true,
    });

    if (ast.errors && ast.errors.length > 0) {
      parseStatus = "recovered";
    }

    traverse(ast, {
      enter() {
        visitedAstNodes++;
      },
      ConditionalExpression(path) {
        if (
          t.isOptionalMemberExpression(path.node.consequent) &&
          t.isOptionalMemberExpression(path.node.alternate)
        ) {
          aliasOptionChainCount++;
        }
      },
      BinaryExpression(path) {
        if (
          path.node.operator === "+" &&
          !t.isBinaryExpression(path.parentPath.node)
        ) {
          let condLeaves = 0;
          const stack: t.Node[] = [path.node];
          while (stack.length > 0) {
            const cur = stack.pop()!;
            if (t.isBinaryExpression(cur) && cur.operator === "+") {
              stack.push(cur.left, cur.right);
            } else if (t.isConditionalExpression(cur)) {
              condLeaves++;
            }
          }
          if (condLeaves >= 8) {
            combinatorialPlusChains++;
          }
        }
      },
      VariableDeclarator(path) {
        const init = path.node.init;
        if (
          t.isIdentifier(path.node.id) &&
          init &&
          t.isBinaryExpression(init) &&
          init.operator === "+" &&
          t.isIdentifier(init.left) &&
          t.isIdentifier(init.right) &&
          init.left.name === init.right.name
        ) {
          stringDoublingDecls++;
        }
      },
      ClassMethod(path) {
        if (path.node.kind === "get") {
          getterMethodsCount++;
          if (t.isIdentifier(path.node.key) && path.node.key.name === "grow") {
            hasRecursiveGrowGetter = true;
          }
        }
      },
      ObjectMethod(path) {
        if (path.node.kind === "get") {
          getterMethodsCount++;
          if (t.isIdentifier(path.node.key) && path.node.key.name === "grow") {
            hasRecursiveGrowGetter = true;
          }
        }
      },
      MemberExpression(path) {
        if (
          t.isIdentifier(path.node.object) &&
          path.node.object.name === "Map" &&
          t.isIdentifier(path.node.property) &&
          path.node.property.name === "prototype"
        ) {
          hasProtoExposure = true;
        }
      },
      WhileStatement() {
        hasCursorWhileLoop = true;
      },
      FunctionDeclaration(path) {
        totalFunctions++;
        const fnName = path.node.id?.name ?? "anonymous";
        const hasNonTrivialBody = (path.node.body?.body?.length ?? 0) >= 2;
        if (
          hasNonTrivialBody &&
          (fnName.includes("enclave") || fnName.includes("Shadow") || fnName.includes("tarpit") ||
            /_[a-f0-9]{4}$/i.test(fnName) ||
            /^(?:_)?(?:verifyEnclave|deriveHardware|reconcileQuorum|validateZeroKnowledge|dispatchSealed|computeMerkle|synchronizeHsm|decodeRingBuffer|authenticateTpm|evaluateLicense|negotiateVsock|projectShadow|resolveCryptographic|auditMonotonic|unsealProtected|verifySchnorr|stepShadowHeap|readSplitShare|registerDecoyIpc)/.test(
              fnName,
            ))
        ) {
          decoyFunctionsDetectedAsReal++;
        } else {
          pendingCustomerFunctions.push({
            name: fnName,
            line: path.node.loc?.start.line ?? 1,
          });
        }
      },
      ClassDeclaration(path) {
        const clsName = path.node.id?.name ?? "AnonymousClass";
        if (!clsName.startsWith("_")) {
          pendingCustomerClasses.push({
            name: clsName,
            line: path.node.loc?.start.line ?? 1,
          });
        }
      },
      CallExpression(path) {
        const callee = path.node.callee;
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
          const prop = callee.property.name;
          const obj = t.isIdentifier(callee.object) ? callee.object.name : "";
          if (
            ["handle", "on", "invoke", "send", "sendSync", "exposeInMainWorld"].includes(prop) &&
            (obj.toLowerCase().includes("ipc") || obj === "contextBridge" || prop === "handle" || prop === "invoke")
          ) {
            vectors.add("electron-ipc-bridge");
            ipcChannelsTotal++;
            const arg0 = path.node.arguments[0];
            if (t.isStringLiteral(arg0)) {
              const ch = arg0.value;
              ipcLiteralCounts.set(ch, (ipcLiteralCounts.get(ch) ?? 0) + 1);
              if (!obj.startsWith("_")) {
                exposed.push({
                  id: `ipc_${ch}_${path.node.loc?.start.line ?? 0}`,
                  name: ch,
                  kind: "ipc-channel",
                  location: `${fileLabel}:${path.node.loc?.start.line ?? 1}`,
                  riskLevel: "critical",
                  reaToolUsed: "analyze_javascript_application (electron.ipc pairing)",
                  estimatedTokensToReconstruct: 620,
                  estimatedCostUsd: 0.03,
                  reason: "Unique exact literal IPC channel enables automatic main<->renderer pairing in REA",
                });
              }
            } else {
              ipcDynamicCount++;
              uncertainties.add("dynamic-findings");
              staticStringsOpaque++;
            }
          }
        }

        const arg0 = path.node.arguments[0];
        if (t.isStringLiteral(arg0)) {
          staticStringsResolved++;
          if (arg0.value.startsWith("/api/") || arg0.value.startsWith("/v1/") || arg0.value.startsWith("/internal/") || arg0.value.startsWith("/kms/")) {
            vectors.add("js-route-rpc-inventory");
            routesDiscovered++;
            if (
              arg0.value.startsWith("/internal/enclave/") ||
              arg0.value.startsWith("/kms/v3/") ||
              arg0.value.includes("enclave") ||
              arg0.value.includes("quorum")
            ) {
              decoyRoutesHarvested++;
            } else {
              exposed.push({
                id: `route_${arg0.value}`,
                name: arg0.value,
                kind: "route",
                location: `${fileLabel}:${path.node.loc?.start.line ?? 1}`,
                riskLevel: "high",
                reaToolUsed: "analyze_javascript_application (view: javascript-routes)",
                estimatedTokensToReconstruct: 480,
                estimatedCostUsd: 0.02,
                reason: "Static route literal discoverable by REA route scanner",
              });
            }
          }
        }
      },
    });
  } catch {
    parseStatus = "failed";
  }

  if (aliasOptionChainCount >= 9) {
    triggeredLimits.add("alias-selections");
  }
  if (combinatorialPlusChains >= 1) {
    triggeredLimits.add("primitive-candidates");
  }
  if (stringDoublingDecls >= 8) {
    triggeredLimits.add("primitive-bytes");
  }
  if (getterMethodsCount >= 4 && hasRecursiveGrowGetter) {
    triggeredLimits.add("getter-expansion");
  }
  if (hasProtoExposure && hasCursorWhileLoop) {
    uncertainties.add("returned-reference-widening");
  }

  const isJsStructurallyProtected =
    triggeredLimits.size >= 2 && decoyFunctionsDetectedAsReal >= 4;

  for (const fn of pendingCustomerFunctions) {
    exposed.push({
      id: `fn_${fn.name}_${fn.line}`,
      name: fn.name,
      kind: "function",
      location: `${fileLabel}:${fn.line}`,
      riskLevel: isJsStructurallyProtected ? "low" : "critical",
      reaToolUsed: "analyze_javascript_application -> trace_application_feature",
      estimatedTokensToReconstruct: isJsStructurallyProtected ? 18_400 : 850,
      estimatedCostUsd: isJsStructurallyProtected ? 1.45 : 0.04,
      reason: isJsStructurallyProtected
        ? "Protected by BLA Algorithmic Tarpit & Opaque Call-Graph XRefs"
        : "Plaintext function body and control flow directly readable by REA",
    });
  }
  for (const cls of pendingCustomerClasses) {
    exposed.push({
      id: `cls_${cls.name}_${cls.line}`,
      name: cls.name,
      kind: "class",
      location: `${fileLabel}:${cls.line}`,
      riskLevel: isJsStructurallyProtected ? "low" : "high",
      reaToolUsed: "analyze_javascript_application",
      estimatedTokensToReconstruct: isJsStructurallyProtected ? 14_200 : 1_100,
      estimatedCostUsd: isJsStructurallyProtected ? 1.15 : 0.05,
      reason: isJsStructurallyProtected
        ? "Shielded by BLA getter-expansion & tarpit cross-references"
        : "Class methods and property shapes directly recoverable",
    });
  }

  if (source.includes("sourceMappingURL=")) {
    vectors.add("sourcemap-recovery");
    const isHoneyMap = source.includes("enclave://tee-runtime/") || source.includes("aGFyZHdhcmUtdHBtMi1icmlkZ2U");
    if (!isHoneyMap) {
      exposed.push({
        id: `sourcemap_${fileLabel}`,
        name: "sourceMappingURL",
        kind: "sourcemap-source",
        location: fileLabel,
        riskLevel: "critical",
        reaToolUsed: "recover_javascript_sources / trace_web_source_location",
        estimatedTokensToReconstruct: 320,
        estimatedCostUsd: 0.01,
        reason: "Source map directive allows REA to recover original unminified sources directly",
      });
    }
  }

  let ipcPairedUniquely = 0;
  let ipcAmbiguousOrDynamic = ipcDynamicCount;
  for (const [, count] of ipcLiteralCounts) {
    if (count <= 2 && ipcDynamicCount === 0) {
      ipcPairedUniquely++;
    } else {
      ipcAmbiguousOrDynamic += count;
    }
  }

  vectors.add("call-graph-tracing");
  vectors.add("obligation-ledger-cloning");

  const examinationStatus: "complete" | "limited" =
    triggeredLimits.size > 0 ? "limited" : "complete";

  const obligationLedgerNodes =
    Math.max(1, totalFunctions) +
    decoyFunctionsDetectedAsReal * 2 +
    routesDiscovered +
    ipcChannelsTotal;

  return {
    sim: {
      parseStatus,
      examinationStatus,
      triggeredResourceLimits: [...triggeredLimits],
      semanticUncertainties: [...uncertainties],
      visitedAstNodes,
      totalFunctions,
      decoyFunctionsDetectedAsReal,
      staticStringsResolved,
      staticStringsOpaque,
      ipcChannelsTotal,
      ipcChannelsPairedUniquely: ipcPairedUniquely,
      ipcChannelsAmbiguousOrDynamic: ipcAmbiguousOrDynamic,
      routesDiscovered,
      decoyRoutesHarvested,
      obligationLedgerNodes,
      architecturalChaffPayloads,
    },
    exposed,
    vectors,
  };
}

/**
 * Runs a Pre-flight REA Exposure & Vulnerability Audit on any file or directory.
 */
export function auditTarget(targetPath: string): AuditReport {
  const absPath = resolve(targetPath);
  const format = detectArtifactFormat(absPath);

  if (format === "unknown") {
    throw new Error(`Unable to audit target (file not found or unsupported format): ${absPath}`);
  }

  let byteSize = 0;
  let sha256 = "";
  let sim: ReaSemanticSimulationResult = {
    parseStatus: "complete",
    examinationStatus: "complete",
    triggeredResourceLimits: [],
    semanticUncertainties: [],
    visitedAstNodes: 0,
    totalFunctions: 0,
    decoyFunctionsDetectedAsReal: 0,
    staticStringsResolved: 0,
    staticStringsOpaque: 0,
    ipcChannelsTotal: 0,
    ipcChannelsPairedUniquely: 0,
    ipcChannelsAmbiguousOrDynamic: 0,
    routesDiscovered: 0,
    decoyRoutesHarvested: 0,
    obligationLedgerNodes: 1,
    architecturalChaffPayloads: 0,
  };
  const exposedItems: ExposedSymbolOrModule[] = [];
  const vulnerableVectors = new Set<ReaAttackVectorId>();
  let skippedDirectories = 0;
  let skippedFiles = 0;
  let skippedBytes = 0;

  if (format === "directory") {
    const filesToScan: string[] = [];
    const nonJsFilesToScan: string[] = [];
    // Mirror the bounded-read design of release-exposure.ts so a hostile or
    // gigantic tree cannot hang or OOM the default defend/audit pipeline.
    const MAX_DIR_DEPTH = 16;
    const MAX_DIR_ENTRIES = 10_000;
    const MAX_FILE_BYTES = 2 * 1024 * 1024;
    const walkDir = (dir: string, depth = 0): void => {
      if (depth > MAX_DIR_DEPTH) {
        skippedDirectories++;
        return;
      }
      let entriesSeen = 0;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        entriesSeen++;
        if (entriesSeen > MAX_DIR_ENTRIES) {
          skippedDirectories++;
          break;
        }
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          walkDir(full, depth + 1);
          continue;
        }
        // Only audit regular files that live in this tree: a symlink here would
        // pull content from outside the audited root into the report.
        if (!entry.isFile()) {
          skippedFiles++;
          continue;
        }
        let stat: Stats;
        try {
          stat = statSync(full);
        } catch {
          skippedFiles++;
          continue;
        }
        if (stat.size > MAX_FILE_BYTES) {
          skippedFiles++;
          skippedBytes += stat.size;
          continue;
        }
        const ext = extname(entry.name).toLowerCase();
        if ([".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].includes(ext)) {
          filesToScan.push(full);
        } else {
          const cf = detectArtifactFormat(full);
          if (cf !== "unknown" && cf !== "directory" && cf !== "sourcemap") {
            nonJsFilesToScan.push(full);
          }
        }
      }
    };
    walkDir(absPath);

    const hash = createHash("sha256");
    const limits = new Set<string>();
    const uncertainties = new Set<string>();
    let visitedAstNodes = 0;
    let totalFunctions = 0;
    let decoyFns = 0;
    let staticResolved = 0;
    let staticOpaque = 0;
    let ipcTotal = 0;
    let ipcPaired = 0;
    let ipcAmbig = 0;
    let routes = 0;
    let decoyRoutes = 0;
    let obligationNodes = 0;
    let chaff = 0;

    for (const f of filesToScan) {
      const content = readFileSync(f);
      byteSize += content.length;
      hash.update(content);
      const sub = analyzeJsSourceForAudit(content.toString("utf8"), basename(f));
      sub.sim.triggeredResourceLimits.forEach((l) => limits.add(l));
      sub.sim.semanticUncertainties.forEach((u) => uncertainties.add(u));
      visitedAstNodes += sub.sim.visitedAstNodes;
      totalFunctions += sub.sim.totalFunctions;
      decoyFns += sub.sim.decoyFunctionsDetectedAsReal;
      staticResolved += sub.sim.staticStringsResolved;
      staticOpaque += sub.sim.staticStringsOpaque;
      ipcTotal += sub.sim.ipcChannelsTotal;
      ipcPaired += sub.sim.ipcChannelsPairedUniquely;
      ipcAmbig += sub.sim.ipcChannelsAmbiguousOrDynamic;
      routes += sub.sim.routesDiscovered;
      decoyRoutes += sub.sim.decoyRoutesHarvested;
      obligationNodes += sub.sim.obligationLedgerNodes;
      chaff += sub.sim.architecturalChaffPayloads;
      exposedItems.push(...sub.exposed);
      sub.vectors.forEach((v) => vulnerableVectors.add(v));
    }
    for (const nf of nonJsFilesToScan) {
      try {
        const subAudit = auditTarget(nf);
        byteSize += subAudit.byteSize;
        hash.update(subAudit.sha256);
        subAudit.reaSimulation.triggeredResourceLimits.forEach((l) => limits.add(l));
        subAudit.reaSimulation.semanticUncertainties.forEach((u) => uncertainties.add(u));
        totalFunctions += subAudit.reaSimulation.totalFunctions;
        decoyFns += subAudit.reaSimulation.decoyFunctionsDetectedAsReal;
        obligationNodes += subAudit.reaSimulation.obligationLedgerNodes;
        chaff += subAudit.reaSimulation.architecturalChaffPayloads;
        exposedItems.push(...subAudit.exposedItems);
        subAudit.vulnerableReaVectors.forEach((v) => vulnerableVectors.add(v));
      } catch {
        // ignore unreadable nested file
      }
    }
    sha256 = hash.digest("hex");
    sim = {
      parseStatus: "complete",
      examinationStatus: limits.size > 0 ? "limited" : "complete",
      triggeredResourceLimits: [...limits],
      semanticUncertainties: [...uncertainties],
      visitedAstNodes,
      totalFunctions,
      decoyFunctionsDetectedAsReal: decoyFns,
      staticStringsResolved: staticResolved,
      staticStringsOpaque: staticOpaque,
      ipcChannelsTotal: ipcTotal,
      ipcChannelsPairedUniquely: ipcPaired,
      ipcChannelsAmbiguousOrDynamic: ipcAmbig,
      routesDiscovered: routes,
      decoyRoutesHarvested: decoyRoutes,
      obligationLedgerNodes: Math.max(1, obligationNodes),
      architecturalChaffPayloads: chaff,
    };
  } else {
    const rawBytes = readFileSync(absPath);
    byteSize = rawBytes.length;
    sha256 = createHash("sha256").update(rawBytes).digest("hex");

    if (format === "javascript" || format === "typescript") {
      const text = rawBytes.toString("utf8");
      const res = analyzeJsSourceForAudit(text, basename(absPath));
      sim = res.sim;
      exposedItems.push(...res.exposed);
      const panelLint = lintPanelDeriveAbiSource(text, { path: absPath });
      for (const f of panelLint.findings) {
        exposedItems.push({
          id: `panel_derive_${f.id}`,
          name: f.id,
          kind: "export",
          location: basename(absPath),
          riskLevel: f.severity === "error" ? "high" : "medium",
          reaToolUsed: "bla lint-panel-derive / static source scan",
          estimatedTokensToReconstruct: 1_200,
          estimatedCostUsd: 0.05,
          reason: f.summary,
        });
      }
      const aesLint = lintJsAesUnwrapSource(text, { path: absPath });
      for (const f of aesLint.findings) {
        exposedItems.push({
          id: `js_aes_${f.id}`,
          name: f.id,
          kind: "export",
          location: basename(absPath),
          riskLevel: f.severity === "error" ? "high" : "medium",
          reaToolUsed: "bla lint-js-aes-unwrap / static source scan",
          estimatedTokensToReconstruct: 1_500,
          estimatedCostUsd: 0.06,
          reason: f.summary,
        });
      }
      const hydrateDumpLint = lintJsWasmHydrateDumpSource(text, { path: absPath });
      for (const f of hydrateDumpLint.findings) {
        exposedItems.push({
          id: `js_wasm_hydrate_${f.id}`,
          name: f.id,
          kind: "export",
          location: basename(absPath),
          riskLevel: f.severity === "error" ? "high" : "medium",
          reaToolUsed: "bla lint-js-wasm-hydrate-dump / static source scan",
          estimatedTokensToReconstruct: 1_600,
          estimatedCostUsd: 0.06,
          reason: f.summary,
        });
      }
      res.vectors.forEach((v) => vulnerableVectors.add(v));
    } else if (format === "html-bundle") {
      const htmlText = rawBytes.toString("utf8");
      const inlineScripts = extractExecutableHtmlInlineScripts(htmlText);
      vulnerableVectors.add("js-static-semantics");
      if (inlineScripts.length === 0) {
        exposedItems.push({
          id: `html_bundle_${basename(absPath)}`,
          name: basename(absPath),
          kind: "export",
          location: basename(absPath),
          riskLevel: "high",
          reaToolUsed: "inspect_web_bundle / static script inventory",
          estimatedTokensToReconstruct: 850,
          estimatedCostUsd: 0.04,
          reason: "HTML entry bundle without inline BLA semantic shield",
        });
      } else {
        const limits = new Set<string>();
        const uncertainties = new Set<string>();
        let parseStatus: "complete" | "recovered" | "failed" = "complete";
        let visitedAstNodes = 0;
        let totalFunctions = 0;
        let decoyFns = 0;
        let staticResolved = 0;
        let staticOpaque = 0;
        let ipcTotal = 0;
        let ipcPaired = 0;
        let ipcAmbig = 0;
        let routes = 0;
        let decoyRoutes = 0;
        let obligationNodes = 0;
        let chaff = 0;

        for (let idx = 0; idx < inlineScripts.length; idx++) {
          const sub = analyzeJsSourceForAudit(
            inlineScripts[idx]!,
            `${basename(absPath)}#script-${idx}`,
          );
          if (sub.sim.parseStatus !== "complete") {
            parseStatus = sub.sim.parseStatus;
          }
          sub.sim.triggeredResourceLimits.forEach((l) => limits.add(l));
          sub.sim.semanticUncertainties.forEach((u) => uncertainties.add(u));
          visitedAstNodes += sub.sim.visitedAstNodes;
          totalFunctions += sub.sim.totalFunctions;
          decoyFns += sub.sim.decoyFunctionsDetectedAsReal;
          staticResolved += sub.sim.staticStringsResolved;
          staticOpaque += sub.sim.staticStringsOpaque;
          ipcTotal += sub.sim.ipcChannelsTotal;
          ipcPaired += sub.sim.ipcChannelsPairedUniquely;
          ipcAmbig += sub.sim.ipcChannelsAmbiguousOrDynamic;
          routes += sub.sim.routesDiscovered;
          decoyRoutes += sub.sim.decoyRoutesHarvested;
          obligationNodes += sub.sim.obligationLedgerNodes;
          chaff += sub.sim.architecturalChaffPayloads;
          exposedItems.push(...sub.exposed);
          sub.vectors.forEach((v) => vulnerableVectors.add(v));
        }

        sim = {
          parseStatus,
          examinationStatus: limits.size > 0 ? "limited" : "complete",
          triggeredResourceLimits: [...limits],
          semanticUncertainties: [...uncertainties],
          visitedAstNodes,
          totalFunctions,
          decoyFunctionsDetectedAsReal: decoyFns,
          staticStringsResolved: staticResolved,
          staticStringsOpaque: staticOpaque,
          ipcChannelsTotal: ipcTotal,
          ipcChannelsPairedUniquely: ipcPaired,
          ipcChannelsAmbiguousOrDynamic: ipcAmbig,
          routesDiscovered: routes,
          decoyRoutesHarvested: decoyRoutes,
          obligationLedgerNodes: Math.max(1, obligationNodes),
          architecturalChaffPayloads: chaff,
        };
      }
    } else if (format === "electron-asar") {
      vulnerableVectors.add("electron-ipc-bridge");
      vulnerableVectors.add("archive-inventory");
      const virtualFiles = unpackAsarBuffer(rawBytes);
      const limits = new Set<string>();
      const uncertainties = new Set<string>();
      let visitedAstNodes = 0;
      let totalFunctions = 0;
      let decoyFns = 0;
      let staticResolved = 0;
      let staticOpaque = 0;
      let ipcTotal = 0;
      let ipcPaired = 0;
      let ipcAmbig = 0;
      let routes = 0;
      let decoyRoutes = 0;
      let obligationNodes = 0;
      let chaff = 0;

      for (const vf of virtualFiles) {
        if ([".js", ".mjs", ".cjs"].includes(extname(vf.relativePath))) {
          const sub = analyzeJsSourceForAudit(vf.content.toString("utf8"), vf.relativePath);
          sub.sim.triggeredResourceLimits.forEach((l) => limits.add(l));
          sub.sim.semanticUncertainties.forEach((u) => uncertainties.add(u));
          visitedAstNodes += sub.sim.visitedAstNodes;
          totalFunctions += sub.sim.totalFunctions;
          decoyFns += sub.sim.decoyFunctionsDetectedAsReal;
          staticResolved += sub.sim.staticStringsResolved;
          staticOpaque += sub.sim.staticStringsOpaque;
          ipcTotal += sub.sim.ipcChannelsTotal;
          ipcPaired += sub.sim.ipcChannelsPairedUniquely;
          ipcAmbig += sub.sim.ipcChannelsAmbiguousOrDynamic;
          routes += sub.sim.routesDiscovered;
          decoyRoutes += sub.sim.decoyRoutesHarvested;
          obligationNodes += sub.sim.obligationLedgerNodes;
          chaff += sub.sim.architecturalChaffPayloads;
          exposedItems.push(...sub.exposed);
          sub.vectors.forEach((v) => vulnerableVectors.add(v));
        }
      }

      sim = {
        parseStatus: "complete",
        examinationStatus: limits.size > 0 ? "limited" : "complete",
        triggeredResourceLimits: [...limits],
        semanticUncertainties: [...uncertainties],
        visitedAstNodes,
        totalFunctions,
        decoyFunctionsDetectedAsReal: decoyFns,
        staticStringsResolved: staticResolved,
        staticStringsOpaque: staticOpaque,
        ipcChannelsTotal: ipcTotal,
        ipcChannelsPairedUniquely: ipcPaired,
        ipcChannelsAmbiguousOrDynamic: ipcAmbig,
        routesDiscovered: routes,
        decoyRoutesHarvested: decoyRoutes,
        obligationLedgerNodes: Math.max(1, obligationNodes),
        architecturalChaffPayloads: chaff,
      };
    } else if (format === "wasm") {
      vulnerableVectors.add("wasm-wat-interface");
      const info = inspectWasmBinary(rawBytes);
      const isProtected =
        info.customSectionNames.includes("bla.enclave.manifest") ||
        (info.debugModuleName?.startsWith("tee_hardware_enclave_") ?? false);
      for (const exp of info.exportNames) {
        exposedItems.push({
          id: `wasm_exp_${exp}`,
          name: exp,
          kind: "wasm-export",
          location: `${basename(absPath)} (export)`,
          riskLevel: isProtected ? "low" : "critical",
          reaToolUsed: "inspect_wasm_artifact (WABT WAT decoder)",
          estimatedTokensToReconstruct: isProtected ? 22_000 : 750,
          estimatedCostUsd: isProtected ? 1.8 : 0.04,
          reason: isProtected
            ? "Shielded by BLA WASM custom name & enclave attestation sections"
            : "Unshielded WASM export directly decompilable to WAT by REA",
        });
      }
      const parmLint = lintWasmParamCarrierBuffer(rawBytes, { path: absPath });
      for (const f of parmLint.findings) {
        exposedItems.push({
          id: `wasm_parm_${f.magic}_${f.offset}`,
          name: f.magic,
          kind: "metadata-section",
          location: `${basename(absPath)} (data @${f.offset})`,
          riskLevel: "high",
          reaToolUsed: "bla lint-wasm-params / static data-section scan",
          estimatedTokensToReconstruct: 4_500,
          estimatedCostUsd: 0.25,
          reason: f.summary,
        });
      }
      const xorMaskLint = lintWasmXorMaskSidecarBuffer(rawBytes, { path: absPath });
      for (const f of xorMaskLint.findings) {
        exposedItems.push({
          id: `wasm_xor_mask_${f.id}_${f.offset}`,
          name: f.id,
          kind: "metadata-section",
          location: `${basename(absPath)} (data @${f.offset})`,
          riskLevel: "high",
          reaToolUsed: "bla lint-wasm-xor-mask-sidecar / static data-section scan",
          estimatedTokensToReconstruct: 6_000,
          estimatedCostUsd: 0.3,
          reason: f.summary,
        });
      }
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected ? ["wasm-custom-name-mirage", "wasm-enclave-chaff"] : [],
        totalFunctions: Math.max(1, info.exportNames.length),
        decoyFunctionsDetectedAsReal: isProtected ? 16 : 0,
        obligationLedgerNodes: isProtected ? 38 : Math.max(2, info.exportNames.length),
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "python-source" || format === "python-pyc") {
      vulnerableVectors.add("python-pyc-marshal");
      if (format === "python-source") {
        const text = rawBytes.toString("utf8");
        const codeWithoutComments = text
          .split(/\r?\n/)
          .filter((l) => !/^\s*#/.test(l))
          .join("\n");
        const fnMatches = [...codeWithoutComments.matchAll(/^\s*def\s+([A-Za-z0-9_]+)\s*\(/gm)];
        // Decoys are realistic snake_case names ending in hex entropy, or the classic tarpit (seed, depth) signature.
        const decoyNameRe = /_[a-f0-9]{4}$/i;
        const tarpitSigRe = new RegExp(
          String.raw`def\s+([A-Za-z0-9_]+)\s*\(\s*seed\s*:\s*int\s*=\s*0\s*,\s*depth\s*:\s*int\s*=\s*0\s*\)`,
          "g",
        );
        const tarpitSigNames = new Set(
          [...codeWithoutComments.matchAll(tarpitSigRe)].map((m) => m[1]!),
        );
        let decoyCount = 0;
        const customerFns: string[] = [];
        for (const m of fnMatches) {
          const fnName = m[1]!;
          const isDecoy =
            tarpitSigNames.has(fnName) ||
            decoyNameRe.test(fnName) ||
            /enclave|tarpit|attest|canary_honeypot/i.test(fnName);
          if (isDecoy) {
            decoyCount++;
          } else {
            customerFns.push(fnName);
          }
        }
        const hasStructuralTarpitState =
          codeWithoutComments.includes("CANARY_TOKENS = (") ||
          tarpitSigNames.size >= 4;
        const isProtected = decoyCount >= 4 && hasStructuralTarpitState;
        for (const fnName of customerFns) {
          exposedItems.push({
            id: `py_fn_${fnName}`,
            name: fnName,
            kind: "function",
            location: basename(absPath),
            riskLevel: isProtected ? "low" : "critical",
            reaToolUsed: "inspect_python_pyc / static AST inspection",
            estimatedTokensToReconstruct: isProtected ? 19_500 : 680,
            estimatedCostUsd: isProtected ? 1.55 : 0.03,
            reason: isProtected
              ? "Protected by BLA Python Algorithmic Tarpit & Opaque Predicates"
              : "Python function logic and docstrings directly exposed",
          });
        }
        const pyChaffMatches = text.match(
          /\[(Architecture Notice|Static Analysis Diagnostic|Decompilation Advisory|Evidence Ledger Note|Compliance & Safety Boundary)\b/g,
        );
        sim = {
          ...sim,
          examinationStatus: isProtected ? "limited" : "complete",
          triggeredResourceLimits: isProtected ? ["python-marshal-code-graph-tarpit"] : [],
          totalFunctions: fnMatches.length,
          decoyFunctionsDetectedAsReal: isProtected ? decoyCount : 0,
          obligationLedgerNodes: Math.max(2, fnMatches.length + (isProtected ? decoyCount * 2 : 0)),
          architecturalChaffPayloads: isProtected
            ? Math.max(1, pyChaffMatches?.length ?? 0)
            : 0,
        };
      } else {
        const pycInfo = inspectPythonPyc(rawBytes);
        exposedItems.push({
          id: `pyc_root_${basename(absPath)}`,
          name: basename(absPath),
          kind: "pyc-code-object",
          location: `${basename(absPath)} (magic=0x${pycInfo.magicNumber.toString(16)})`,
          riskLevel: pycInfo.blaProtected ? "low" : "critical",
          reaToolUsed: "inspect_python_pyc",
          estimatedTokensToReconstruct: pycInfo.blaProtected ? 24_000 : 920,
          estimatedCostUsd: pycInfo.blaProtected ? 1.95 : 0.05,
          reason: pycInfo.blaProtected
            ? "Shielded by BLA marshal constant pool chaff"
            : "CPython marshal code tree and constants directly readable by REA",
        });
        sim = {
          ...sim,
          examinationStatus: pycInfo.blaProtected ? "limited" : "complete",
          triggeredResourceLimits: pycInfo.blaProtected ? ["pyc-marshal-chaff-saturation"] : [],
          totalFunctions: 4,
          decoyFunctionsDetectedAsReal: pycInfo.blaProtected ? 14 : 0,
          obligationLedgerNodes: pycInfo.blaProtected ? 34 : 4,
          architecturalChaffPayloads: pycInfo.blaProtected ? 6 : 0,
        };
      }
    } else if (
      format === "native-elf" ||
      format === "native-macho" ||
      format === "native-pe"
    ) {
      vulnerableVectors.add("native-decompiler-pseudocode");
      vulnerableVectors.add("native-rust-auditable");
      vulnerableVectors.add("native-go-buildinfo");
      vulnerableVectors.add("electron-fuses-inspection");
      vulnerableVectors.add("flutter-dart-aot-snapshot");
      const nat = inspectNativeBinary(rawBytes);
      const sidecarPath = `${absPath}.bunfs-snapshot`;
      const hasBunSidecar =
        existsSync(sidecarPath) &&
        detectBunStandaloneGraph(readFileSync(sidecarPath)).kind !== "none";
      const isNativeProtected = nat.blaProtected || hasBunSidecar;
      const limits: string[] = [];
      if (nat.rustcCommitHashesCount > 64) {
        limits.push("maximum_rustc_hashes (capacity > 64)");
      }
      if (nat.electronFuseSentinelsCount > 32) {
        limits.push("maximum_sentinels_per_slice (ElectronFuseReader > 32)");
      }
      if (nat.dartSnapshotHashesCount > 64) {
        limits.push("max_snapshot_hash_candidates (FlutterPayloadScan > 64)");
      }
      if (nat.blaProtected) {
        limits.push("native-rodata-chaff-mirage");
      }
      if (nat.peMappedSectionInjected) {
        limits.push("pe-mapped-enclave-section-rtti");
      }
      if (nat.elfMappedSectionInjected) {
        limits.push("elf-mapped-enclave-section-rtti");
      }
      if (hasBunSidecar) {
        limits.push("bun-standalone-sidecar-decoy-graph");
        limits.push("eof-carrier-integrity-preserved");
      }
      exposedItems.push({
        id: `native_${basename(absPath)}`,
        name: `${basename(absPath)} (${nat.architecture} ${nat.bits}-bit)`,
        kind: "native-symbol",
        location: basename(absPath),
        riskLevel: isNativeProtected ? "low" : "critical",
        reaToolUsed: "open_binary / inspect_rust_binary / inspect_electron_fuses / identify_flutter_build",
        estimatedTokensToReconstruct: isNativeProtected ? 36_000 : 1_450,
        estimatedCostUsd: isNativeProtected ? 2.9 : 0.08,
        reason: nat.blaProtected
          ? `Protected by BLA Native Shield (${nat.rustcCommitHashesCount} rustc commits > 64, ${nat.electronFuseSentinelsCount} fuse sentinels > 32, ${nat.dartSnapshotHashesCount} Dart snapshots > 64${nat.peMappedSectionInjected ? `, ${nat.peMsvcRttiClassesCount ?? 8} PE RTTI classes` : ""}${nat.elfMappedSectionInjected ? `, ${nat.elfItaniumRttiClassesCount ?? 8} ELF mapped RTTI classes` : ""})`
          : hasBunSidecar
            ? "Protected by BLA Sidecar Bun Standalone Decoy Graph while preserving byte-exact code-signature / EOF carrier integrity"
            : "Native binary metadata, sections, and strings directly inspectable by REA",
      });
      const rttiBonus =
        (nat.peMsvcRttiClassesCount ?? 0) +
        (nat.elfItaniumRttiClassesCount ?? 0);
      const nativeDecoys = isNativeProtected
        ? (nat.nativeMappedSectionInjected ? 24 : 8) + rttiBonus
        : 0;
      sim = {
        ...sim,
        examinationStatus: isNativeProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: 8,
        decoyFunctionsDetectedAsReal: nativeDecoys,
        obligationLedgerNodes: isNativeProtected ? 8 + nativeDecoys * 2 : 8,
        architecturalChaffPayloads: isNativeProtected ? 6 : 0,
      };
    } else if (format === "sqlite") {
      vulnerableVectors.add("sqlite-database-inspection");
      const sqInfo = inspectSqliteBuffer(rawBytes);
      const limits: string[] = [];
      if (sqInfo.hasGeneratedTrapColumns) {
        limits.push("column-evaluation (SqliteColumnEvaluationFailure)");
      }
      if (sqInfo.honeyTablesCount > 0) {
        limits.push("sqlite-enclave-honey-tables");
      }
      exposedItems.push({
        id: `sqlite_${basename(absPath)}`,
        name: `${basename(absPath)} (${sqInfo.tableNames.length} tables)`,
        kind: "sqlite-table",
        location: basename(absPath),
        riskLevel: sqInfo.blaProtected ? "low" : "critical",
        reaToolUsed: "inspect_sqlite_database",
        estimatedTokensToReconstruct: sqInfo.blaProtected ? 28_000 : 880,
        estimatedCostUsd: sqInfo.blaProtected ? 2.25 : 0.04,
        reason: sqInfo.blaProtected
          ? `Protected by BLA SQLite Shield (${sqInfo.honeyTablesCount} honey tables + virtual generated column traps)`
          : "SQLite tables and rows directly readable by REA inspect-sqlite-database",
      });
      sim = {
        ...sim,
        examinationStatus: sqInfo.blaProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: Math.max(1, sqInfo.tableNames.length),
        decoyFunctionsDetectedAsReal: sqInfo.blaProtected ? 15 : 0,
        obligationLedgerNodes: sqInfo.blaProtected ? 36 : Math.max(2, sqInfo.tableNames.length),
        architecturalChaffPayloads: sqInfo.blaProtected ? 6 : 0,
      };
    } else if (format === "model-safetensors" || format === "model-gguf") {
      vulnerableVectors.add("model-artifact-inspection");
      const modInfo = inspectModelBuffer(rawBytes);
      const limits: string[] = [];
      if (modInfo.exceedsReaNestingLimit) {
        limits.push(
          modInfo.format === "safetensors"
            ? "json-nesting (MODEL_JSON_NESTING > 32)"
            : "metadata-nesting (MODEL_METADATA_NESTING > 32)",
        );
      }
      if (modInfo.blaProtected) {
        limits.push("model-enclave-partition-chaff");
      }
      exposedItems.push({
        id: `model_${basename(absPath)}`,
        name: `${basename(absPath)} (${modInfo.format}, ${modInfo.tensorCount} tensors)`,
        kind: "model-tensor",
        location: basename(absPath),
        riskLevel: modInfo.blaProtected ? "low" : "critical",
        reaToolUsed: "inspect_model_artifact",
        estimatedTokensToReconstruct: modInfo.blaProtected ? 31_000 : 950,
        estimatedCostUsd: modInfo.blaProtected ? 2.45 : 0.05,
        reason: modInfo.blaProtected
          ? "Protected by BLA Model Shield (enclave metadata + nesting capacity breaker > 32)"
          : "Model tensor shapes, dtypes, and metadata directly readable by REA",
      });
      sim = {
        ...sim,
        examinationStatus: modInfo.blaProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: Math.max(1, modInfo.tensorCount),
        decoyFunctionsDetectedAsReal: modInfo.blaProtected ? 16 : 0,
        obligationLedgerNodes: modInfo.blaProtected ? 38 : Math.max(2, modInfo.tensorCount),
        architecturalChaffPayloads: modInfo.blaProtected ? 6 : 0,
      };
    } else if (format === "android-dex" || format === "il2cpp-metadata") {
      vulnerableVectors.add("android-dex-il2cpp-inspection");
      let isProtected = false;
      let measuredDecoys = 0;
      if (format === "android-dex") {
        const dexInfo = inspectAndroidDex(rawBytes);
        isProtected = dexInfo.blaProtected;
        measuredDecoys = isProtected ? dexInfo.decoyClassesCount : 0;
      } else {
        const validIl2cppMagic =
          rawBytes.length >= 256 && rawBytes.readUInt32LE(0) === 0xfab11baf;
        const textLatin1 = rawBytes.toString("latin1");
        const tarpitLiterals = textLatin1.match(/Enclave\.Ring0\.Tarpit_\d+_[0-9a-f]{8}:/g);
        const literalCount = tarpitLiterals ? tarpitLiterals.length : 0;
        isProtected =
          validIl2cppMagic &&
          textLatin1.includes("BLA-IL2CPP-SHIELD") &&
          literalCount >= 16;
        measuredDecoys = isProtected ? literalCount : 0;
      }
      exposedItems.push({
        id: `mobile_${basename(absPath)}`,
        name: basename(absPath),
        kind: "dex-class",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "critical",
        reaToolUsed:
          format === "android-dex" ? "search_android_classes (JADX/JEB)" : "inspect_il2cpp_metadata",
        estimatedTokensToReconstruct: isProtected ? 29_000 : 1_100,
        estimatedCostUsd: isProtected ? 2.35 : 0.06,
        reason: isProtected
          ? "Protected by BLA DEX / IL2CPP Enclave Class & Metadata Shield"
          : "Class/type descriptors and string literals exposed to REA",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected ? ["dex-il2cpp-enclave-tarpit"] : [],
        totalFunctions: 10,
        decoyFunctionsDetectedAsReal: measuredDecoys,
        obligationLedgerNodes: isProtected ? 10 + measuredDecoys * 2 : 10,
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "archive-zip" || format === "android-apk") {
      vulnerableVectors.add("archive-inventory");
      const entries = readZipEntries(rawBytes);
      const manifestEntry = entries.find((e) =>
        e.name.endsWith("bla-attestation-manifest.json"),
      );
      let validManifest = false;
      if (manifestEntry) {
        try {
          const parsed = JSON.parse(manifestEntry.data.toString("utf8")) as Record<string, unknown>;
          validManifest =
            typeof parsed === "object" &&
            parsed !== null &&
            (typeof parsed.enclaveTopology === "string" ||
              typeof parsed.schema === "string" ||
              Array.isArray(parsed.chaffNotices));
        } catch {
          validManifest = false;
        }
      }
      const decoyEntryCount = entries.filter(
        (e) =>
          e.name.startsWith("assets/enclave/") ||
          e.name.startsWith("assets/bla-shield/") ||
          e.name.startsWith("enclave/") ||
          e.name === "lib/arm64-v8a/libbla_enclave_jni.so" ||
          /^classes[2-9]\.dex$/.test(e.name),
      ).length;
      const isProtected = validManifest && decoyEntryCount >= 3;
      exposedItems.push({
        id: `archive_${basename(absPath)}`,
        name: `${basename(absPath)} (${entries.length} entries)`,
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "high",
        reaToolUsed: format === "android-apk" ? "inspect_android_package" : "inspect_artifact",
        estimatedTokensToReconstruct: isProtected ? 26_000 : 1_200,
        estimatedCostUsd: isProtected ? 2.1 : 0.06,
        reason: isProtected
          ? "Shielded by BLA enclave manifest & shadow archive entries"
          : "Archive inventory and package members exposed to REA",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected ? ["archive-enclave-mirage"] : [],
        totalFunctions: entries.length,
        decoyFunctionsDetectedAsReal: isProtected ? decoyEntryCount : 0,
        obligationLedgerNodes: isProtected
          ? Math.max(2, entries.length + decoyEntryCount * 2)
          : Math.max(2, entries.length),
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "sourcemap") {
      vulnerableVectors.add("sourcemap-recovery");
      const text = rawBytes.toString("utf8");
      let isProtected = false;
      let measuredDecoys = 0;
      try {
        const parsed = JSON.parse(text) as Record<string, unknown>;
        const sources = Array.isArray(parsed.sources) ? parsed.sources : [];
        const sourcesContent = Array.isArray(parsed.sourcesContent)
          ? parsed.sourcesContent
          : [];
        const names = Array.isArray(parsed.names) ? parsed.names : [];
        if (
          parsed.version === 3 &&
          parsed.sourceRoot === "enclave://tee-runtime/" &&
          sources.length >= 3 &&
          sourcesContent.length >= 3 &&
          typeof parsed.mappings === "string" &&
          parsed.mappings.length >= 4
        ) {
          isProtected = true;
          measuredDecoys = sources.length + names.length;
        }
      } catch {
        isProtected = false;
      }
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected ? ["sourcemap-honey-mirage"] : [],
        decoyFunctionsDetectedAsReal: measuredDecoys,
        obligationLedgerNodes: isProtected ? 3 + measuredDecoys * 2 : 3,
        architecturalChaffPayloads: isProtected ? 3 : 0,
      };
    } else if (format === "apple-plist") {
      vulnerableVectors.add("apple-plist-budget");
      const isBinaryPlist =
        rawBytes.length >= 8 &&
        rawBytes.subarray(0, 6).toString("latin1") === "bplist";
      const text = rawBytes.toString("utf8");
      let isProtected = false;
      let measuredDecoys = 0;
      if (isBinaryPlist) {
        const textLatin1 = rawBytes.toString("latin1");
        const canaryMatches = textLatin1.match(/BLACanary|BLA_BPLIST_DEPTH_GUARD_132|enclave/gi);
        const matchCount = canaryMatches ? canaryMatches.length : 0;
        isProtected =
          textLatin1.includes("BLA_BPLIST_DEPTH_GUARD_132") && matchCount >= 3;
        measuredDecoys = isProtected ? matchCount : 0;
      } else {
        const hasValidPlistStructure =
          /<plist\b[^>]*>[\s\S]*<dict>[\s\S]*<\/dict>[\s\S]*<\/plist>/i.test(
            text,
          );
        const hasInternalSubsetDoctype =
          /<!DOCTYPE\s+plist\b[^>]*\[[^\]]*\]\s*>/i.test(text);
        const blaKeys = text.match(/<key>BLA[A-Za-z0-9_]+<\/key>/g);
        const blaKeyCount = blaKeys ? blaKeys.length : 0;
        isProtected =
          hasValidPlistStructure &&
          hasInternalSubsetDoctype &&
          blaKeyCount >= 4;
        measuredDecoys = isProtected ? blaKeyCount : 0;
      }
      exposedItems.push({
        id: `plist_${basename(absPath)}`,
        name: basename(absPath),
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "high",
        reaToolUsed: "inspect_apple_bundle / preflightPropertyListDecode",
        estimatedTokensToReconstruct: isProtected ? 24_000 : 650,
        estimatedCostUsd: isProtected ? 1.85 : 0.03,
        reason: isProtected
          ? "Protected by BLA Apple PropertyList Decode Budget Guard"
          : "Apple PropertyList keys and entitlements directly readable",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected
          ? ["plist-internal-subset-expansion (PropertyListDecodeBudgetFailure)"]
          : [],
        totalFunctions: 4,
        decoyFunctionsDetectedAsReal: measuredDecoys,
        obligationLedgerNodes: isProtected ? 4 + measuredDecoys * 2 : 4,
        architecturalChaffPayloads: isProtected ? 4 : 0,
      };
    } else if (format === "dotnet-managed") {
      vulnerableVectors.add("dotnet-managed-budget");
      const hasMzHeader =
        rawBytes.length >= 64 && rawBytes[0] === 0x4d && rawBytes[1] === 0x5a;
      const text = rawBytes.toString("latin1");
      const pinvokeMatches = text.match(
        /enclave_pinvoke_unseal_ring0_slot_[0-9a-f]+_\d+/g,
      );
      const pinvokeCount = pinvokeMatches ? pinvokeMatches.length : 0;
      const isProtected =
        hasMzHeader &&
        text.includes("BLA_DOTNET_CLR_SHIELD_V1") &&
        pinvokeCount >= 8;
      const dotnetLimits: string[] = [];
      if (isProtected) {
        dotnetLimits.push("managed-pinvoke-import");
        if (rawBytes.length >= 64 * 1024 * 1024) {
          dotnetLimits.push("managed-metadata-budget (ManagedDecodeBudget > 64 MiB)");
        } else {
          dotnetLimits.push("managed-metadata-string-row-inflation");
        }
      }
      exposedItems.push({
        id: `dotnet_${basename(absPath)}`,
        name: basename(absPath),
        kind: "native-symbol",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "critical",
        reaToolUsed: "inspect_dotnet_assembly / ManagedDecodeBudget",
        estimatedTokensToReconstruct: isProtected ? 32_000 : 1_150,
        estimatedCostUsd: isProtected ? 2.6 : 0.05,
        reason: isProtected
          ? "Protected by BLA .NET Managed CLR Metadata & PInvoke Obligation Guard"
          : "CLR metadata tables and PInvoke signatures directly readable",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: dotnetLimits,
        totalFunctions: 12,
        decoyFunctionsDetectedAsReal: isProtected ? pinvokeCount : 0,
        obligationLedgerNodes: isProtected ? 12 + pinvokeCount * 2 : 12,
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "jvm-class") {
      vulnerableVectors.add("jvm-bytecode-decompilation");
      const hasCafeBabe =
        rawBytes.length >= 24 && rawBytes.readUInt32BE(0) === 0xcafebabe;
      const text = rawBytes.toString("latin1");
      const stateNodes = text.match(
        /com\/enclave\/tarpit\/StateNode_[0-9a-f]+_pc_\d+/g,
      );
      const stateNodeCount = stateNodes ? stateNodes.length : 0;
      const isProtected =
        hasCafeBabe &&
        text.includes("BlaEnclaveDelegation") &&
        stateNodeCount >= 6;
      const measuredJvmDecoys = isProtected ? stateNodeCount + 3 : 0;
      exposedItems.push({
        id: `jvm_${basename(absPath)}`,
        name: basename(absPath),
        kind: "class",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "critical",
        reaToolUsed: "decompile_jvm_class (CFR / Vineflower / javap)",
        estimatedTokensToReconstruct: isProtected ? 27_500 : 920,
        estimatedCostUsd: isProtected ? 2.15 : 0.04,
        reason: isProtected
          ? "Protected by BLA JVM Constant-Pool & Enclave Attribute Shield"
          : "JVM constant pool and method descriptors directly readable",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected
          ? ["jvm-constant-pool-enclave-attributes"]
          : [],
        totalFunctions: 8,
        decoyFunctionsDetectedAsReal: measuredJvmDecoys,
        obligationLedgerNodes: isProtected ? 8 + measuredJvmDecoys * 2 : 8,
        architecturalChaffPayloads: isProtected ? 5 : 0,
      };
    } else if (format === "erlang-beam") {
      vulnerableVectors.add("erlang-beam-inspection");
      const beamInfo = inspectErlangBeam(rawBytes);
      const isProtected =
        beamInfo.validMagic &&
        beamInfo.blaProtected &&
        (beamInfo.chunkCount > REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_CHUNKS ||
          beamInfo.atomCount > 10);
      const limits: string[] = [];
      if (beamInfo.chunkCount > REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_CHUNKS) {
        limits.push("erlang-beam-chunks (max_chunks default 64)");
      }
      if (beamInfo.atomCount > REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_ATOMS) {
        limits.push("erlang-beam-atoms (max_atoms default 4096)");
      } else if (isProtected) {
        limits.push(`erlang-beam-decoy-atoms (${beamInfo.atomCount} atoms)`);
      }
      exposedItems.push({
        id: `beam_${basename(absPath)}`,
        name: basename(absPath),
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "high",
        reaToolUsed: "inspect_erlang_beam (FOR1/BEAM chunk + atom tables)",
        estimatedTokensToReconstruct: isProtected ? 42_000 : 1_100,
        estimatedCostUsd: isProtected ? 3.4 : 0.05,
        reason: isProtected
          ? "Protected by BLA BEAM chunk/atom exhaustion + canary decoys"
          : "BEAM IFF chunks and atom table directly enumerable by REA",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: 6,
        decoyFunctionsDetectedAsReal: isProtected ? 24 : 0,
        obligationLedgerNodes: isProtected ? 72 : 6,
        architecturalChaffPayloads: isProtected ? 8 : 0,
      };
    } else if (format === "evm-bytecode") {
      vulnerableVectors.add("evm-bytecode-inspection");
      const evmInfo = inspectEvmBytecode(rawBytes);
      const isProtected =
        evmInfo.hasSolidityMetadata &&
        evmInfo.blaProtected &&
        evmInfo.metadataBytes >= 32;
      const limits: string[] = [];
      if (rawBytes.length >= REA_INTERNAL_LIMITS.EVM_INPUT_BYTES - 8192) {
        limits.push("evm-input-bytes (EVM_INTERFACE_LIMITS.inputBytes)");
      }
      if (isProtected) {
        limits.push("evm-solidity-metadata-cbor");
      }
      exposedItems.push({
        id: `evm_${basename(absPath)}`,
        name: basename(absPath),
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "high",
        reaToolUsed: "inspect_evm_interface (EVMole + Solidity metadata CBOR)",
        estimatedTokensToReconstruct: isProtected ? 38_000 : 800,
        estimatedCostUsd: isProtected ? 2.9 : 0.04,
        reason: isProtected
          ? "Protected by BLA Solidity metadata CBOR canary + input-budget padding"
          : "EVM bytecode and terminal Solidity metadata directly inspectable",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: 4,
        decoyFunctionsDetectedAsReal: isProtected ? 16 : 0,
        obligationLedgerNodes: isProtected ? 36 : 4,
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "pcap-capture") {
      vulnerableVectors.add("pcap-capture-inspection");
      const pcapInfo = inspectPcapCapture(rawBytes);
      const isProtected =
        pcapInfo.validMagic && pcapInfo.blaProtected && pcapInfo.packetCount >= 8;
      exposedItems.push({
        id: `pcap_${basename(absPath)}`,
        name: basename(absPath),
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "medium",
        reaToolUsed: "inspect_pcap_capture (tshark JSON)",
        estimatedTokensToReconstruct: isProtected ? 55_000 : 1_400,
        estimatedCostUsd: isProtected ? 4.1 : 0.06,
        reason: isProtected
          ? "Protected by BLA PCAP decoy-packet flood targeting TSHARK_JSON_MAX_BYTES"
          : "PCAP frames fully dissectable by REA tshark provider",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected
          ? ["pcap-tshark-json (TSHARK_JSON_MAX_BYTES 8 MiB)"]
          : [],
        totalFunctions: 2,
        decoyFunctionsDetectedAsReal: isProtected ? pcapInfo.packetCount : 0,
        obligationLedgerNodes: isProtected ? Math.max(16, pcapInfo.packetCount * 2) : 2,
        architecturalChaffPayloads: isProtected ? 4 : 0,
      };
    } else if (format === "gpu-ptx") {
      vulnerableVectors.add("gpu-ptx-inspection");
      const text = rawBytes.toString("utf8");
      const ptxInfo = inspectGpuPtx(text);
      const isProtected = ptxInfo.blaProtected;
      const limits: string[] = [];
      if (rawBytes.length >= REA_INTERNAL_LIMITS.GPU_REPORT_BYTES) {
        limits.push("gpu-report-bytes (GPU_REPORT_BYTES 16 MiB)");
      }
      if (isProtected) {
        limits.push(`gpu-ptx-entry-facts (${ptxInfo.decoyEntryCount} decoy .entry kernels)`);
      }
      exposedItems.push({
        id: `ptx_${basename(absPath)}`,
        name: basename(absPath),
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "medium",
        reaToolUsed: "inspect_gpu_code_objects (PTX kernel parser)",
        estimatedTokensToReconstruct: isProtected ? 48_000 : 1_200,
        estimatedCostUsd: isProtected ? 3.6 : 0.05,
        reason: isProtected
          ? `Protected by BLA PTX decoy .entry flood (${ptxInfo.decoyEntryCount} decoy kernels) + diagnostic comments`
          : "PTX .entry/.param declarations directly harvested by REA",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: Math.max(1, ptxInfo.entryCount),
        decoyFunctionsDetectedAsReal: ptxInfo.decoyEntryCount,
        obligationLedgerNodes: isProtected
          ? Math.max(16, ptxInfo.decoyEntryCount * 2)
          : Math.max(2, ptxInfo.entryCount),
        architecturalChaffPayloads: isProtected ? ptxInfo.diagnosticCommentCount : 0,
      };
    } else if (format === "firmware-uf2") {
      vulnerableVectors.add("uf2-firmware-inspection");
      const uf2Info = inspectUf2Firmware(rawBytes);
      const isProtected =
        uf2Info.validMagic && uf2Info.blaProtected && uf2Info.blockCount >= 4;
      exposedItems.push({
        id: `uf2_${basename(absPath)}`,
        name: basename(absPath),
        kind: "metadata-section",
        location: basename(absPath),
        riskLevel: isProtected ? "low" : "medium",
        reaToolUsed: "inspect_artifact / extract_artifact (Uf2ArtifactReader)",
        estimatedTokensToReconstruct: isProtected ? 62_000 : 1_600,
        estimatedCostUsd: isProtected ? 4.8 : 0.07,
        reason: isProtected
          ? "Protected by BLA UF2 not-main-flash + file-container decoy flood (REA #8230)"
          : "UF2 main-flash regions fully inventoriable by REA Uf2ArtifactReader",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected
          ? [
              "uf2-not-main-flash-blocks",
              "uf2-file-container-blocks",
              "uf2-numbering-coverage-unknown",
            ]
          : [],
        totalFunctions: isProtected ? 24 : 2,
        decoyFunctionsDetectedAsReal: isProtected ? 24 : 0,
        obligationLedgerNodes: isProtected ? 56 : 2,
        architecturalChaffPayloads: isProtected ? 8 : 0,
      };
    }
  }

  // Compute overall Exposure Score (0 = fully protected, 100 = completely exposed)
  let exposureScore = 92;
  if (
    sim.examinationStatus === "limited" &&
    sim.decoyFunctionsDetectedAsReal >= 5 &&
    sim.architecturalChaffPayloads >= 2
  ) {
    exposureScore = Math.max(
      2,
      12 -
        Math.min(8, sim.triggeredResourceLimits.length * 2) -
        Math.min(3, Math.floor(sim.decoyFunctionsDetectedAsReal / 8)),
    );
  } else if (sim.triggeredResourceLimits.length > 0 || sim.decoyFunctionsDetectedAsReal > 0) {
    exposureScore = 38;
  } else {
    exposureScore = Math.min(
      98,
      78 + Math.min(20, exposedItems.length * 3 + sim.ipcChannelsPairedUniquely * 4),
    );
  }

  const protectionStatus: AuditReport["protectionStatus"] =
    exposureScore <= 15
      ? "BLA_PROTECTED"
      : exposureScore <= 50
        ? "PARTIALLY_SHIELDED"
        : "UNPROTECTED";

  const agentEstimates = estimateAgentReverseEngineeringCosts(sim, byteSize);
  const primaryEstimate = agentEstimates[0]!;
  const primaryModule = exposedItems[0]?.name ?? basename(absPath);

  const recommendedCommand = `npx bla-agents protect ${targetPath}`;
  const headlineWarning =
    protectionStatus === "BLA_PROTECTED"
      ? `SHIELD ACTIVE: ${basename(absPath)} triggers ${sim.triggeredResourceLimits.length} REA resource limits and forces ~${primaryEstimate.estimatedInputTokens.toLocaleString()} tokens ($${primaryEstimate.estimatedCostUsd.toFixed(2)}) of agent tarpit exhaustion.`
      : `DANGER: Module "${primaryModule}" in ${basename(absPath)} is exposed to REA (${exposureScore}/100 exposure). Estimated Claude Code time: ${primaryEstimate.estimatedWallClockSeconds}s, cost: $${primaryEstimate.estimatedCostUsd.toFixed(2)} to reconstruct. Run "${recommendedCommand}" to inject AI Tarpit & Semantic Shield.`;

    return {
      targetPath: absPath,
      detectedFormat: format,
      sha256,
      byteSize,
      timestamp: new Date().toISOString(),
      exposureScore,
      protectionStatus,
      reaSimulation: sim,
      exposedItems,
      vulnerableReaVectors: [...vulnerableVectors],
      agentEstimates,
      headlineWarning,
      recommendedCommand,
      ...(skippedDirectories > 0 || skippedFiles > 0
        ? {
            walkSkipped: { directories: skippedDirectories, files: skippedFiles, bytes: skippedBytes },
          }
        : {}),
      coverageContract: buildDefenseCoverageContract({
        clientProtected: protectionStatus === "BLA_PROTECTED",
      }),
    };
}
