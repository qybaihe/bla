import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";
import { detectArtifactFormat } from "../core/detector.js";
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
import { inspectPythonPyc } from "../shields/formats/python.js";
import { inspectNativeBinary } from "../shields/formats/native.js";
import { detectBunStandaloneGraph } from "../shields/formats/bun-standalone.js";
import { readZipEntries } from "../shields/formats/archive.js";
import { inspectSqliteBuffer } from "../shields/formats/sqlite.js";
import { inspectModelBuffer } from "../shields/formats/model.js";
import { inspectAndroidDex } from "../shields/formats/mobile-game.js";

type TraverseFn = (typeof _traverse)["default"];
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : _traverse.default;

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

  // Detect BLA markers & REA resource-limit patterns in source
  if (source.includes("a22?.require") || /const a\d+ = _flag \? a\d+\?\.x : a\d+\?\.y/.test(source)) {
    triggeredLimits.add("alias-selections");
  }
  if (source.includes("_verifySemanticEnvelope") || /(\([_a-zA-Z0-9]+ \? "[^"]*" : "[^"]*"\) \+ ){6,}/.test(source)) {
    triggeredLimits.add("primitive-candidates");
  }
  if (/const s\d+ = s\d+ \+ s\d+;/.test(source)) {
    triggeredLimits.add("primitive-bytes");
  }
  if (source.includes("get grow() { return this.grow.more; }") || source.includes("get grow()")) {
    triggeredLimits.add("getter-expansion");
  }
  if (source.includes("_exposeProto") || source.includes("Map.prototype")) {
    uncertainties.add("returned-reference-widening");
  }

  const chaffMatches = source.match(
    /\[(Architecture Notice|Static Analysis Diagnostic|Decompilation Advisory|Evidence Ledger Note|Compliance & Safety Boundary)\b|(?:EVIDENCE_CONTRACT_SUMMARY|ANALYSIS_VIEW_PROJECTION|RECONSTRUCTION_LEDGER_STATE|NATIVE_DISPATCH_TABLE_NOTE|SYMBOL_OFFSET_MANIFEST_[0-9A-F]+|FSM_SPEC_V3|QUORUM_PROTOCOL_DESCRIPTOR|IPC_BRIDGE_TOPOLOGY|HSM_ATTESTATION_DESCRIPTOR_[0-9a-f]+):/g,
  );
  if (chaffMatches) {
    architecturalChaffPayloads += chaffMatches.length;
  }

  let parseStatus: "complete" | "recovered" | "failed" = "complete";
  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      plugins: [
        "typescript",
        "jsx",
        "decorators-legacy",
        "importAttributes",
        "dynamicImport",
        "classProperties",
        "topLevelAwait",
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
      FunctionDeclaration(path) {
        totalFunctions++;
        const fnName = path.node.id?.name ?? "anonymous";
        if (
          fnName.includes("enclave") || fnName.includes("Shadow") || fnName.includes("tarpit") ||
          /_[a-f0-9]{4}$/i.test(fnName) ||
          /^(?:_)?(?:verifyEnclave|deriveHardware|reconcileQuorum|validateZeroKnowledge|dispatchSealed|computeMerkle|synchronizeHsm|decodeRingBuffer|authenticateTpm|evaluateLicense|negotiateVsock|projectShadow|resolveCryptographic|auditMonotonic|unsealProtected|verifySchnorr|stepShadowHeap|readSplitShare|registerDecoyIpc)/.test(
            fnName,
          )
        ) {
          decoyFunctionsDetectedAsReal++;
        } else {
          exposed.push({
            id: `fn_${fnName}_${path.node.loc?.start.line ?? 0}`,
            name: fnName,
            kind: "function",
            location: `${fileLabel}:${path.node.loc?.start.line ?? 1}`,
            riskLevel: triggeredLimits.size > 0 ? "low" : "critical",
            reaToolUsed: "analyze_javascript_application -> trace_application_feature",
            estimatedTokensToReconstruct: triggeredLimits.size > 0 ? 18_400 : 850,
            estimatedCostUsd: triggeredLimits.size > 0 ? 1.45 : 0.04,
            reason:
              triggeredLimits.size > 0
                ? "Protected by BLA Algorithmic Tarpit & Opaque Call-Graph XRefs"
                : "Plaintext function body and control flow directly readable by REA",
          });
        }
      },
      ClassDeclaration(path) {
        const clsName = path.node.id?.name ?? "AnonymousClass";
        if (!clsName.startsWith("_")) {
          exposed.push({
            id: `cls_${clsName}_${path.node.loc?.start.line ?? 0}`,
            name: clsName,
            kind: "class",
            location: `${fileLabel}:${path.node.loc?.start.line ?? 1}`,
            riskLevel: triggeredLimits.size > 0 ? "low" : "high",
            reaToolUsed: "analyze_javascript_application",
            estimatedTokensToReconstruct: triggeredLimits.size > 0 ? 14_200 : 1_100,
            estimatedCostUsd: triggeredLimits.size > 0 ? 1.15 : 0.05,
            reason:
              triggeredLimits.size > 0
                ? "Shielded by BLA getter-expansion & tarpit cross-references"
                : "Class methods and property shapes directly recoverable",
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

  if (format === "directory") {
    const filesToScan: string[] = [];
    const nonJsFilesToScan: string[] = [];
    const walkDir = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) walkDir(full);
        else if ([".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].includes(extname(entry.name).toLowerCase())) {
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
        const isProtected =
          text.includes("runtime attestation boundary") ||
          text.includes("BLA-SHIELD") ||
          text.includes("CANARY_TOKENS") ||
          /def\s+\w+_([a-f0-9]{4})\s*\(/i.test(text);
        const fnMatches = [...text.matchAll(/def\s+([A-Za-z0-9_]+)\s*\(/g)];
        // Decoys are realistic snake_case names ending in hex entropy, or the classic tarpit (seed, depth) signature.
        const decoyNameRe = /_[a-f0-9]{4}$/i;
        const tarpitSigRe = new RegExp(
          String.raw`def\s+([A-Za-z0-9_]+)\s*\(\s*seed\s*:\s*int\s*=\s*0\s*,\s*depth\s*:\s*int\s*=\s*0\s*\)`,
          "g",
        );
        const tarpitSigNames = new Set(
          [...text.matchAll(tarpitSigRe)].map((m) => m[1]!),
        );
        let decoyCount = 0;
        for (const m of fnMatches) {
          const fnName = m[1]!;
          const isDecoy =
            tarpitSigNames.has(fnName) ||
            decoyNameRe.test(fnName) ||
            /enclave|tarpit|attest|canary_honeypot/i.test(fnName);
          if (isDecoy) {
            decoyCount++;
          } else {
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
        }
        sim = {
          ...sim,
          examinationStatus: isProtected ? "limited" : "complete",
          triggeredResourceLimits: isProtected ? ["python-marshal-code-graph-tarpit"] : [],
          totalFunctions: fnMatches.length,
          decoyFunctionsDetectedAsReal: decoyCount,
          obligationLedgerNodes: Math.max(2, fnMatches.length + decoyCount * 2),
          architecturalChaffPayloads: isProtected ? 6 : 0,
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
          ? `Protected by BLA Native Shield (${nat.rustcCommitHashesCount} rustc commits > 64, ${nat.electronFuseSentinelsCount} fuse sentinels > 32, ${nat.dartSnapshotHashesCount} Dart snapshots > 64)`
          : hasBunSidecar
            ? "Protected by BLA Sidecar Bun Standalone Decoy Graph while preserving byte-exact code-signature / EOF carrier integrity"
            : "Native binary metadata, sections, and strings directly inspectable by REA",
      });
      sim = {
        ...sim,
        examinationStatus: isNativeProtected ? "limited" : "complete",
        triggeredResourceLimits: limits,
        totalFunctions: 8,
        decoyFunctionsDetectedAsReal: isNativeProtected ? 24 : 0,
        obligationLedgerNodes: isNativeProtected ? 56 : 8,
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
      const isProtected =
        format === "android-dex"
          ? inspectAndroidDex(rawBytes).blaProtected
          : rawBytes.toString("latin1").includes("BLA-IL2CPP-SHIELD");
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
        decoyFunctionsDetectedAsReal: isProtected ? 28 : 0,
        obligationLedgerNodes: isProtected ? 52 : 10,
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "archive-zip" || format === "android-apk") {
      vulnerableVectors.add("archive-inventory");
      const entries = readZipEntries(rawBytes);
      const isProtected = entries.some((e) => e.name.includes("bla-attestation-manifest.json"));
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
        decoyFunctionsDetectedAsReal: isProtected ? 12 : 0,
        obligationLedgerNodes: isProtected ? 32 : Math.max(2, entries.length),
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "sourcemap") {
      vulnerableVectors.add("sourcemap-recovery");
      const text = rawBytes.toString("utf8");
      const isProtected = text.includes("enclave://tee-runtime/");
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected ? ["sourcemap-honey-mirage"] : [],
        decoyFunctionsDetectedAsReal: isProtected ? 10 : 0,
        obligationLedgerNodes: isProtected ? 24 : 3,
        architecturalChaffPayloads: isProtected ? 4 : 0,
      };
    } else if (format === "apple-plist") {
      vulnerableVectors.add("apple-plist-budget");
      const text = rawBytes.toString("utf8");
      const isProtected =
        text.includes("[]>") ||
        text.includes("BLAEnclaveAttestationAuthority") ||
        text.includes("BLA_BPLIST_DEPTH_GUARD_132");
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
        decoyFunctionsDetectedAsReal: isProtected ? 12 : 0,
        obligationLedgerNodes: isProtected ? 28 : 4,
        architecturalChaffPayloads: isProtected ? 4 : 0,
      };
    } else if (format === "dotnet-managed") {
      vulnerableVectors.add("dotnet-managed-budget");
      const text = rawBytes.toString("latin1");
      const isProtected = text.includes("BLA_DOTNET_CLR_SHIELD_V1");
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
        triggeredResourceLimits: isProtected
          ? ["managed-metadata-budget (ManagedDecodeBudget > 64 MiB)", "managed-pinvoke-import"]
          : [],
        totalFunctions: 12,
        decoyFunctionsDetectedAsReal: isProtected ? 20 : 0,
        obligationLedgerNodes: isProtected ? 48 : 12,
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "jvm-class") {
      vulnerableVectors.add("jvm-bytecode-decompilation");
      const text = rawBytes.toString("latin1");
      const isProtected =
        text.includes("BlaEnclaveDelegation") || text.includes("BLA_JVM_SHIELD_V1");
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
        decoyFunctionsDetectedAsReal: isProtected ? 18 : 0,
        obligationLedgerNodes: isProtected ? 40 : 8,
        architecturalChaffPayloads: isProtected ? 5 : 0,
      };
    } else if (format === "erlang-beam") {
      vulnerableVectors.add("erlang-beam-inspection");
      const text = rawBytes.toString("latin1");
      const isProtected = text.includes("[BLA-BEAM-SHIELD]");
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
        triggeredResourceLimits: isProtected
          ? [
              "erlang-beam-chunks (max_chunks default 64)",
              "erlang-beam-atoms (max_atoms default 4096)",
            ]
          : [],
        totalFunctions: 6,
        decoyFunctionsDetectedAsReal: isProtected ? 24 : 0,
        obligationLedgerNodes: isProtected ? 72 : 6,
        architecturalChaffPayloads: isProtected ? 8 : 0,
      };
    } else if (format === "evm-bytecode") {
      vulnerableVectors.add("evm-bytecode-inspection");
      const text = rawBytes.toString("utf8");
      const isProtected = text.includes("[BLA-EVM-SHIELD]");
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
        triggeredResourceLimits: isProtected
          ? ["evm-input-bytes (EVM_INTERFACE_LIMITS.inputBytes)", "evm-solidity-metadata-cbor"]
          : [],
        totalFunctions: 4,
        decoyFunctionsDetectedAsReal: isProtected ? 16 : 0,
        obligationLedgerNodes: isProtected ? 36 : 4,
        architecturalChaffPayloads: isProtected ? 6 : 0,
      };
    } else if (format === "pcap-capture") {
      vulnerableVectors.add("pcap-capture-inspection");
      const isProtected = rawBytes.includes(Buffer.from("[BLA-PCAP-SHIELD]", "utf8"));
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
        decoyFunctionsDetectedAsReal: isProtected ? 16 : 0,
        obligationLedgerNodes: isProtected ? 32 : 2,
        architecturalChaffPayloads: isProtected ? 4 : 0,
      };
    } else if (format === "gpu-ptx") {
      vulnerableVectors.add("gpu-ptx-inspection");
      const text = rawBytes.toString("utf8");
      const isProtected = text.includes("[BLA-PTX-SHIELD]");
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
          ? "Protected by BLA PTX decoy .entry flood + diagnostic comments"
          : "PTX .entry/.param declarations directly harvested by REA",
      });
      sim = {
        ...sim,
        examinationStatus: isProtected ? "limited" : "complete",
        triggeredResourceLimits: isProtected
          ? ["gpu-report-bytes (GPU_REPORT_BYTES 16 MiB)", "gpu-ptx-entry-facts"]
          : [],
        totalFunctions: isProtected ? 20 : 1,
        decoyFunctionsDetectedAsReal: isProtected ? 20 : 0,
        obligationLedgerNodes: isProtected ? 48 : 2,
        architecturalChaffPayloads: isProtected ? 5 : 0,
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
  };
}
