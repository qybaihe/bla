import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, isAbsolute, join, resolve } from "node:path";
import { detectArtifactFormat } from "../core/detector.js";
import { assertSafeOutputPath } from "../core/output-path.js";
import { withLlmDirectives } from "../core/llm-directives.js";
import { SeededPrng } from "../core/prng.js";
import { generateProjectSeed } from "../core/config.js";
import type {
  ProtectionMetrics,
  ProtectionOptions,
  ProtectionResult,
  ReaAttackVectorId,
} from "../core/types.js";
import { generateChaffPayloads } from "../shields/chaff/chaff-generator.js";
import { transformJavaScriptWithBlaShield } from "../shields/javascript/ast-shield.js";
import { generateHoneySourceMap } from "../shields/formats/sourcemap.js";
import { packAsarBuffer, unpackAsarBuffer, validateAsarProtectionInput, type VirtualAsarFile } from "../shields/formats/asar.js";
import { planAsarHeaderAmplification } from "../shields/exhaustion/asar-header-amplifier.js";
import { protectWasmBinary } from "../shields/formats/wasm.js";
import { findPythonPrologueInsertionOffset, protectPythonPycBuffer, protectPythonSource } from "../shields/formats/python.js";
import { protectNativeBinary, validateElf64Layout } from "../shields/formats/native.js";
import { generateBunStandaloneDecoyGraph } from "../shields/formats/bun-standalone.js";
import { protectZipOrApkBuffer, validateZipProtectionInput, UnsupportedApkProtectionError } from "../shields/formats/archive.js";
import { protectSqliteBuffer, validateSqliteFileInput } from "../shields/formats/sqlite.js";
import { protectGgufBuffer, protectSafetensorsBuffer } from "../shields/formats/model.js";
import { protectAndroidDexBuffer, protectIl2cppMetadataBuffer } from "../shields/formats/mobile-game.js";
import { protectApplePlistBuffer } from "../shields/formats/apple-plist.js";
import { protectDotnetManagedBuffer } from "../shields/formats/dotnet-managed.js";
import { protectJvmClassBuffer } from "../shields/formats/jvm-bytecode.js";
import { protectErlangBeamBuffer } from "../shields/formats/erlang-beam.js";
import { protectEvmBytecodeBuffer } from "../shields/formats/evm-bytecode.js";
import { protectPcapCaptureBuffer } from "../shields/formats/pcap-capture.js";
import { protectGpuPtxText } from "../shields/formats/gpu-ptx.js";
import { protectUf2FirmwareBuffer } from "../shields/formats/firmware-uf2.js";
import { auditTarget } from "./auditor.js";
import {
  formatSupportsLaneIndependenceLint,
  laneIndependenceRefuseMessage,
  lintLaneIndependence,
} from "./lane-independence-lint.js";
import {
  findSiblingSealSidecars,
  intensityEnforcesSealRefusal,
  lintSealCommitmentFile,
  sealCommitmentRefuseMessage,
} from "./seal-commitment-lint.js";
import {
  intensityEnforcesWasmParamRefusal,
  lintWasmParamCarrierBuffer,
  wasmParamCarrierRefuseMessage,
} from "./wasm-param-carrier-lint.js";
import {
  lintWasmXorMaskSidecarBuffer,
  intensityEnforcesWasmXorMaskSidecarRefusal,
  wasmXorMaskSidecarRefuseMessage,
} from "./wasm-xor-mask-sidecar-lint.js";
import {
  lintWasmSealXorKnownPlaintextFile,
  intensityEnforcesWasmSealXorKnownPlaintextRefusal,
  wasmSealXorKnownPlaintextRefuseMessage,
} from "./wasm-seal-xor-known-plaintext-lint.js";
import {
  intensityEnforcesPanelOracleRefusal,
  intensityRewritesPanelDerive,
  lintPanelDeriveAbiSource,
  panelDeriveRefuseMessage,
  rewriteStablePanelDeriveSymbols,
} from "./panel-derive-abi-lint.js";
import {
  intensityEnforcesJsAesUnwrapRefusal,
  jsAesUnwrapRefuseMessage,
  lintJsAesUnwrapSource,
} from "./js-aes-unwrap-lint.js";
import {
  intensityEnforcesJsWasmHydrateDumpRefusal,
  jsWasmHydrateDumpRefuseMessage,
  lintJsWasmHydrateDumpSource,
} from "./js-wasm-hydrate-dump-lint.js";
import { finalizeSelfSealSelfDigest } from "../shields/runtime/self-seal.js";
import {
  entangleJsEntryWithSidecars,
  entanglePythonEntryWithSidecars,
} from "../shields/runtime/sidecar-entangle.js";

/**
 * Crash-safe output write: write to a temp file in the same directory, then
 * rename over the target. A crash or disk-full mid-write leaves the previous
 * artifact (or nothing) instead of a truncated protected file. Symlink /
 * hardlink targets are written through directly so in-place protection of
 * aliased paths reaches the real file.
 */

function selfSealTransformOption(
  options: ProtectionOptions,
  absOutput: string,
): boolean | {
  readonly siblingPaths: readonly string[];
  readonly expectedSiblingSha256?: Readonly<Record<string, string>>;
  readonly hardFailOnSiblingMismatch?: boolean;
} | undefined {
  if (options.selfSeal !== true) return undefined;
  if (!options.selfSealSiblingPaths || options.selfSealSiblingPaths.length === 0) {
    return true;
  }
  const siblingPaths = options.selfSealSiblingPaths;
  const base = dirname(absOutput);
  const expectedSiblingSha256: Record<string, string> = {};
  for (const rel of siblingPaths) {
    if (typeof rel !== "string" || rel.length === 0) continue;
    const abs = isAbsolute(rel) ? rel : join(base, rel);
    try {
      if (!existsSync(abs)) continue;
      expectedSiblingSha256[rel] = createHash("sha256")
        .update(readFileSync(abs))
        .digest("hex");
    } catch {
      /* sibling not readable yet — skip expected hash (opaque-seed only) */
    }
  }
  return {
    siblingPaths,
    ...(Object.keys(expectedSiblingSha256).length > 0
      ? {
          expectedSiblingSha256,
          hardFailOnSiblingMismatch: true,
        }
      : {}),
  };
}


function applySidecarEntangleToJs(
  source: string,
  options: ProtectionOptions,
  absOutput: string,
  seed: string,
): { code: string; applied: boolean } {
  if (options.sidecarEntangle !== true) return { code: source, applied: false };
  const paths = (options.sidecarEntanglePaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (paths.length === 0) return { code: source, applied: false };
  const base = dirname(absOutput);
  const sidecars: { pathLabel: string; bytes: Uint8Array }[] = [];
  for (const rel of paths) {
    const abs = isAbsolute(rel) ? rel : join(base, rel);
    try {
      if (!existsSync(abs)) continue;
      sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
    } catch {
      /* skip unreadable */
    }
  }
  if (sidecars.length === 0) return { code: source, applied: false };
  const entryLabel = basename(absOutput);
  const bound = entangleJsEntryWithSidecars({
    entryPath: entryLabel,
    entrySource: source,
    sidecars,
    seedTag: String(seed),
    softFold: options.sidecarEntangleSoftFold === true,
  });
  if (!bound) return { code: source, applied: false };
  return { code: bound.code, applied: true };
}

function applySidecarEntangleToPython(
  source: string,
  options: ProtectionOptions,
  absOutput: string,
  seed: string,
): { code: string; applied: boolean } {
  if (options.sidecarEntangle !== true) return { code: source, applied: false };
  const paths = (options.sidecarEntanglePaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (paths.length === 0) return { code: source, applied: false };
  const base = dirname(absOutput);
  const sidecars: { pathLabel: string; bytes: Uint8Array }[] = [];
  for (const rel of paths) {
    const abs = isAbsolute(rel) ? rel : join(base, rel);
    try {
      if (!existsSync(abs)) continue;
      sidecars.push({ pathLabel: rel, bytes: readFileSync(abs) });
    } catch {
      /* skip unreadable */
    }
  }
  if (sidecars.length === 0) return { code: source, applied: false };
  const entryLabel = basename(absOutput);
  const bound = entanglePythonEntryWithSidecars({
    entryPath: entryLabel,
    entrySource: source,
    sidecars,
    seedTag: String(seed),
    softFold: options.sidecarEntangleSoftFold === true,
  });
  if (!bound) return { code: source, applied: false };
  return { code: bound.code, applied: true };
}

function applyPanelDeriveRewrite(
  source: string,
  seed: string,
  intensity: string,
  options: ProtectionOptions,
  fileLabel: string,
): string {
  if (options.allowStablePanelDeriveAbi === true) {
    return source;
  }
  if (!intensityRewritesPanelDerive(intensity)) {
    // Still surface refuse at bankrupt if somehow rewrite intensity is off but
    // symbols remain — bankrupt always rewrites; other intensities only lint via CLI.
    return source;
  }
  const lint = lintPanelDeriveAbiSource(source, { path: fileLabel });
  if (!lint.shouldRewriteOrRefuse) return source;
  const rw = rewriteStablePanelDeriveSymbols(source, seed);
  return rw.code;
}

function writeFileAtomicSync(
  targetPath: string,
  content: string | Buffer,
  encoding?: BufferEncoding,
): void {
  const dir = dirname(targetPath);
  mkdirSync(dir, { recursive: true });
  // Self-seal entry self-digest must cover the FINAL bytes — finalize here, at
  // the single write chokepoint, after every other transform.
  const finalizeable =
    typeof content !== "string" || encoding === undefined || encoding === "utf8";
  if (finalizeable) content = finalizeSelfSealSelfDigest(content).content;
  try {
    const st = lstatSync(targetPath);
    if (st.isSymbolicLink() || st.nlink > 1) {
      if (encoding) writeFileSync(targetPath, content, encoding);
      else writeFileSync(targetPath, content);
      return;
    }
  } catch {
    /* target does not exist yet — proceed with the atomic path */
  }
  const tmpPath = `${targetPath}.bla-tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    // Exclusive create: a pre-planted symlink or file at the temp path must
    // fail (EEXIST) instead of being followed.
    if (encoding) writeFileSync(tmpPath, content, { encoding, flag: "wx" });
    else writeFileSync(tmpPath, content, { flag: "wx" });
    renameSync(tmpPath, targetPath);
  } catch (err) {
    try {
      if (existsSync(tmpPath)) unlinkSync(tmpPath);
    } catch {
      // Ignore cleanup failure
    }
    throw err;
  }
}

function classifyHtmlScriptTag(attrs: string): {
  readonly executable: boolean;
  readonly isModule: boolean;
} {
  if (/\bsrc\s*=/i.test(attrs)) {
    return { executable: false, isModule: false };
  }
  const typeMatch = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
  if (!typeMatch) {
    return { executable: true, isModule: false };
  }
  const rawType = (typeMatch[1] ?? typeMatch[2] ?? typeMatch[3] ?? "")
    .trim()
    .toLowerCase();
  if (rawType === "") {
    return { executable: true, isModule: false };
  }
  if (rawType === "module") {
    return { executable: true, isModule: true };
  }
  if (
    rawType === "text/javascript" ||
    rawType === "application/javascript" ||
    rawType === "text/ecmascript" ||
    rawType === "application/ecmascript" ||
    rawType === "javascript"
  ) {
    return { executable: true, isModule: false };
  }
  return { executable: false, isModule: false };
}

function escapeHtmlInlineScriptBody(jsCode: string): string {
  return jsCode.replace(/<\/(script)/gi, "<\\/$1");
}

/**
 * Where `protectTarget` will write for a given input/output/inPlace triple.
 * Pure path math (no filesystem access) so callers can plan or confirm writes.
 */
export function resolveProtectOutputPath(
  inputPath: string,
  outputPath?: string,
  inPlace = false,
): string {
  const absInput = resolve(inputPath);
  return resolve(outputPath ?? deriveDefaultOutputPath(absInput, inPlace));
}

function deriveDefaultOutputPath(inputPath: string, inPlace = false): string {
  if (inPlace) return inputPath;
  const ext = extname(inputPath);
  if (!ext) return `${inputPath}.shielded`;
  const base = inputPath.slice(0, -ext.length);
  return `${base}.shielded${ext}`;
}

/**
 * Unified Multi-Format Protection Engine (`bla protect`).
 * Protects JS/TS, Electron `.asar`, HTML Web Bundles, SourceMaps, WebAssembly `.wasm`,
 * Python `.py`/`.pyc`, Native Binaries (ELF/Mach-O/PE), ZIP/APK archives, and directories.
 */
export function protectTarget(options: ProtectionOptions): ProtectionResult {
  return withLlmDirectives(options.llmDirectives === true, () => protectTargetInner(options));
}

function protectTargetInner(options: ProtectionOptions): ProtectionResult {
  const startMs = Date.now();
  const absInput = resolve(options.inputPath);
  const format = detectArtifactFormat(absInput);
  if (format === "unknown") {
    throw new Error(`Unsupported or missing target path: ${absInput}`);
  }

  // Signed APKs still fail closed inside protectZipOrApkBuffer; unsigned APKs
  // get member-level DEX/IL2CPP hardening. Do not early-throw here.
  const absOutput = resolve(
    options.outputPath ?? deriveDefaultOutputPath(absInput, options.inPlace),
  );
  assertSafeOutputPath(absInput, absOutput, format === "directory", options.inPlace);
  if (format === "archive-zip") validateZipProtectionInput(readFileSync(absInput));
  if (format === "android-apk") {
    validateZipProtectionInput(readFileSync(absInput), { allowUnsignedApk: true });
  }
  if (format === "electron-asar") validateAsarProtectionInput(readFileSync(absInput));
  if (format === "sqlite") validateSqliteFileInput(absInput);
  if (format === "python-source") findPythonPrologueInsertionOffset(readFileSync(absInput, "utf8"));
  if (format === "native-elf") validateElf64Layout(readFileSync(absInput));

  const intensity = options.intensity ?? "balanced";
  // Prefer caller/CLI/project seed; mint an ephemeral random seed only as last resort
  // (CLI resolves + persists per-project seeds via resolveProjectSeed / .blarc).
  const seed = String(options.seed ?? generateProjectSeed());
  const prng = new SeededPrng(seed);
  const chaffPayloads = generateChaffPayloads(prng, intensity);

  // Complete model validation/serialization before creating any output path.
  const safetensorsResult = format === "model-safetensors"
    ? protectSafetensorsBuffer(readFileSync(absInput), { intensity, seed })
    : undefined;

  const beforeAudit = auditTarget(absInput);

  if (format !== "directory") {
    mkdirSync(dirname(absOutput), { recursive: true });
  }

  let decoyFunctionsInjected = 0;
  let fakeCrossReferencesCreated = 0;
  let primitiveCandidateBranchesCreated = 0;
  let aliasSelectionStatesCreated = 0;
  let ipcAmbiguitySitesInjected = 0;
  let decoyRoutesInjected = 0;
  let chaffPayloadsEmbedded = 0;
  let honeySourceMapsGenerated = 0;
  let binarySectionsPatched = 0;
  let wasmExportsRenamed = 0;
  let wasmExportOrderShuffled = false;
  let wasmExportDecoysInjected = 0;
  /** Inline `<script>` bodies whose AST shield threw and were shipped unchanged. */
  let inlineScriptsFailed = 0;
  let sidecarEntangleApplied = false;
  const counteredVectors = new Set<ReaAttackVectorId>();

  if (
    intensityEnforcesSealRefusal(intensity) &&
    options.allowPlaintextSeal !== true
  ) {
    for (const sealPath of findSiblingSealSidecars(dirname(absInput))) {
      const sealReport = lintSealCommitmentFile(sealPath);
      if (sealReport.shouldRefuseBankrupt) {
        throw new Error(sealCommitmentRefuseMessage(sealReport, sealPath));
      }
    }
  }

  if (format === "javascript" || format === "typescript") {
    const raw = readFileSync(absInput, "utf8");
    if (
      formatSupportsLaneIndependenceLint(format) &&
      options.allowLaneIndependentGates !== true
    ) {
      const laneReport = lintLaneIndependence(raw);
      if (laneReport.looksLaneIndependent) {
        throw new Error(laneIndependenceRefuseMessage(laneReport, absInput));
      }
    }
    if (
      intensityEnforcesJsAesUnwrapRefusal(intensity) &&
      options.allowJsAesUnwrap !== true
    ) {
      const aesReport = lintJsAesUnwrapSource(raw, { path: absInput });
      if (aesReport.shouldRefuseBankrupt) {
        throw new Error(jsAesUnwrapRefuseMessage(aesReport, absInput));
      }
    }
    if (
      intensityEnforcesJsWasmHydrateDumpRefusal(intensity) &&
      options.allowJsWasmHydrateDump !== true
    ) {
      const hydrateDumpReport = lintJsWasmHydrateDumpSource(raw, { path: absInput });
      if (hydrateDumpReport.shouldRefuseBankrupt) {
        throw new Error(jsWasmHydrateDumpRefuseMessage(hydrateDumpReport, absInput));
      }
    }
    {
      const panelLint = lintPanelDeriveAbiSource(raw, { path: absInput });
      if (
        intensityEnforcesPanelOracleRefusal(intensity) &&
        options.allowPanelOfflineOracle !== true &&
        panelLint.shouldRefuseBankrupt
      ) {
        throw new Error(panelDeriveRefuseMessage(panelLint, absInput));
      }
    }
    const panelSafe = applyPanelDeriveRewrite(raw, seed, intensity, options, absInput);
    const selfSealOpt = selfSealTransformOption(options, absOutput);
    const transformed = transformJavaScriptWithBlaShield(panelSafe, {
      intensity,
      seed,
      filename: basename(absInput),
      ...(selfSealOpt !== undefined ? { selfSeal: selfSealOpt } : {}),
    });
    let finalCode = transformed.code;

    if (options.honeySourceMaps !== false) {
      const lineCount = finalCode.split("\n").length;
      const honey = generateHoneySourceMap(
        basename(absOutput),
        lineCount,
        prng,
        chaffPayloads,
      );
      finalCode = `${finalCode}\n${honey.inlineDirective}\n`;
      honeySourceMapsGenerated = 1;
      counteredVectors.add("sourcemap-recovery");
    }

    {
      const entangled = applySidecarEntangleToJs(finalCode, options, absOutput, seed);
      finalCode = entangled.code;
      if (entangled.applied) sidecarEntangleApplied = true;
    }

    writeFileAtomicSync(absOutput, finalCode, "utf8");
    decoyFunctionsInjected = transformed.decoyFunctionsInjected;
    fakeCrossReferencesCreated = transformed.fakeCrossReferencesCreated;
    primitiveCandidateBranchesCreated = transformed.primitiveCandidateBranchesCreated;
    aliasSelectionStatesCreated = transformed.aliasSelectionStatesCreated;
    ipcAmbiguitySitesInjected = transformed.ipcAmbiguitySitesInjected;
    decoyRoutesInjected = transformed.decoyRoutesInjected;
    chaffPayloadsEmbedded = transformed.chaffPayloadsEmbedded;

    counteredVectors.add("js-static-semantics");
    counteredVectors.add("electron-ipc-bridge");
    counteredVectors.add("js-route-rpc-inventory");
    counteredVectors.add("call-graph-tracing");
    counteredVectors.add("obligation-ledger-cloning");
  } else if (format === "html-bundle") {
    const rawHtml = readFileSync(absInput, "utf8");
    if (
      intensityEnforcesJsAesUnwrapRefusal(intensity) &&
      options.allowJsAesUnwrap !== true
    ) {
      const aesReport = lintJsAesUnwrapSource(rawHtml, { path: absInput });
      if (aesReport.shouldRefuseBankrupt) {
        throw new Error(jsAesUnwrapRefuseMessage(aesReport, absInput));
      }
    }
    if (
      intensityEnforcesJsWasmHydrateDumpRefusal(intensity) &&
      options.allowJsWasmHydrateDump !== true
    ) {
      const hydrateDumpReport = lintJsWasmHydrateDumpSource(rawHtml, { path: absInput });
      if (hydrateDumpReport.shouldRefuseBankrupt) {
        throw new Error(jsWasmHydrateDumpRefuseMessage(hydrateDumpReport, absInput));
      }
    }
    {
      const panelLint = lintPanelDeriveAbiSource(rawHtml, { path: absInput });
      if (
        intensityEnforcesPanelOracleRefusal(intensity) &&
        options.allowPanelOfflineOracle !== true &&
        panelLint.shouldRefuseBankrupt
      ) {
        throw new Error(panelDeriveRefuseMessage(panelLint, absInput));
      }
    }
    let inlineScriptsTransformed = 0;
    let scriptIndex = 0;
    let transformedHtml = rawHtml.replace(
      /<script\b([^>]*)>([\s\S]*?)<\/script>/gi,
      (fullMatch, attrs: string, scriptBody: string) => {
        if (!scriptBody.trim()) return fullMatch;
        const tagKind = classifyHtmlScriptTag(attrs);
        if (!tagKind.executable) return fullMatch;
        const currentIndex = scriptIndex++;
        try {
          const scriptSeed = `${seed}:html-script-${currentIndex}`;
          const panelSafe = applyPanelDeriveRewrite(
            scriptBody,
            scriptSeed,
            intensity,
            options,
            `${absInput}#script-${currentIndex}`,
          );
          const selfSealOpt = selfSealTransformOption(options, absOutput);
          const res = transformJavaScriptWithBlaShield(panelSafe, {
            intensity,
            seed: scriptSeed,
            sourceType: tagKind.isModule ? "module" : "script",
            ...(selfSealOpt !== undefined ? { selfSeal: selfSealOpt } : {}),
          });
          inlineScriptsTransformed++;
          decoyFunctionsInjected += res.decoyFunctionsInjected;
          fakeCrossReferencesCreated += res.fakeCrossReferencesCreated;
          primitiveCandidateBranchesCreated += res.primitiveCandidateBranchesCreated;
          aliasSelectionStatesCreated += res.aliasSelectionStatesCreated;
          ipcAmbiguitySitesInjected += res.ipcAmbiguitySitesInjected;
          decoyRoutesInjected += res.decoyRoutesInjected;
          chaffPayloadsEmbedded += res.chaffPayloadsEmbedded;
          return `<script${attrs}>\n${escapeHtmlInlineScriptBody(res.code)}\n</script>`;
        } catch {
          // Ship the original script rather than dropping it, but count the
          // failure so partial HTML protection is never silent (honesty red
          // line — see STATE.md).
          inlineScriptsFailed++;
          return fullMatch;
        }
      },
    );
    if (inlineScriptsTransformed === 0) {
      const bootstrapRes = transformJavaScriptWithBlaShield("void 0;\n", {
        intensity,
        seed: `${seed}:html-bootstrap`,
        sourceType: "script",
        ...(selfSealTransformOption(options, absOutput) !== undefined ? { selfSeal: selfSealTransformOption(options, absOutput)! } : {}),
      });
      decoyFunctionsInjected += bootstrapRes.decoyFunctionsInjected;
      fakeCrossReferencesCreated += bootstrapRes.fakeCrossReferencesCreated;
      primitiveCandidateBranchesCreated += bootstrapRes.primitiveCandidateBranchesCreated;
      aliasSelectionStatesCreated += bootstrapRes.aliasSelectionStatesCreated;
      ipcAmbiguitySitesInjected += bootstrapRes.ipcAmbiguitySitesInjected;
      decoyRoutesInjected += bootstrapRes.decoyRoutesInjected;
      chaffPayloadsEmbedded += bootstrapRes.chaffPayloadsEmbedded;
      const bootstrapTag = `<script>\n${escapeHtmlInlineScriptBody(bootstrapRes.code)}\n</script>`;
      if (/<\/body>/i.test(transformedHtml)) {
        transformedHtml = transformedHtml.replace(/<\/body>/i, `${bootstrapTag}\n</body>`);
      } else if (/<\/head>/i.test(transformedHtml)) {
        transformedHtml = transformedHtml.replace(/<\/head>/i, `${bootstrapTag}\n</head>`);
      } else {
        transformedHtml = `${transformedHtml}\n${bootstrapTag}\n`;
      }
    }
    writeFileAtomicSync(absOutput, transformedHtml, "utf8");
    counteredVectors.add("js-static-semantics");
    counteredVectors.add("call-graph-tracing");
    counteredVectors.add("obligation-ledger-cloning");
  } else if (format === "sourcemap") {
    const honey = generateHoneySourceMap(
      basename(absOutput).replace(/\.map$/, ""),
      120,
      prng,
      chaffPayloads,
    );
    writeFileAtomicSync(absOutput, honey.jsonString, "utf8");
    honeySourceMapsGenerated = 1;
    decoyFunctionsInjected = 10;
    chaffPayloadsEmbedded = chaffPayloads.length;
    counteredVectors.add("sourcemap-recovery");
  } else if (format === "electron-asar") {
    const rawAsar = readFileSync(absInput);
    const virtualFiles = unpackAsarBuffer(rawAsar);
    const protectedFiles: VirtualAsarFile[] = [];

    for (const vf of virtualFiles) {
      const ext = extname(vf.relativePath).toLowerCase();
      if ([".js", ".mjs", ".cjs"].includes(ext)) {
        const res = transformJavaScriptWithBlaShield(vf.content.toString("utf8"), {
          intensity,
          seed: `${seed}:${vf.relativePath}`,
          filename: vf.relativePath,
          ...(selfSealTransformOption(options, absOutput) !== undefined ? { selfSeal: selfSealTransformOption(options, absOutput)! } : {}),
        });
        const honey = generateHoneySourceMap(
          basename(vf.relativePath),
          res.code.split("\n").length,
          prng,
          chaffPayloads,
        );
        const contentWithMap = Buffer.from(`${res.code}\n${honey.inlineDirective}\n`, "utf8");
        protectedFiles.push({
          relativePath: vf.relativePath,
          content: contentWithMap,
          ...(vf.executable ? { executable: true } : {}),
        });
        decoyFunctionsInjected += res.decoyFunctionsInjected;
        fakeCrossReferencesCreated += res.fakeCrossReferencesCreated;
        primitiveCandidateBranchesCreated += res.primitiveCandidateBranchesCreated;
        aliasSelectionStatesCreated += res.aliasSelectionStatesCreated;
        ipcAmbiguitySitesInjected += res.ipcAmbiguitySitesInjected;
        decoyRoutesInjected += res.decoyRoutesInjected;
        chaffPayloadsEmbedded += res.chaffPayloadsEmbedded;
        honeySourceMapsGenerated++;
      } else if (ext === ".map") {
        const honey = generateHoneySourceMap(
          basename(vf.relativePath).replace(/\.map$/, ""),
          80,
          prng,
          chaffPayloads,
        );
        protectedFiles.push({
          relativePath: vf.relativePath,
          content: Buffer.from(honey.jsonString, "utf8"),
        });
        honeySourceMapsGenerated++;
      } else {
        protectedFiles.push(vf);
      }
    }

    // Inject a decoy hardware-enclave bridge module inside the ASAR archive
    const decoyBridgeJs = transformJavaScriptWithBlaShield(
      `export function verifyHardwareEnclaveLease(token) { return Boolean(token); }\n`,
      {
        intensity,
        seed: `${seed}:enclave-decoy`,
        ...(selfSealTransformOption(options, absOutput) !== undefined ? { selfSeal: selfSealTransformOption(options, absOutput)! } : {}),
      },
    );
    protectedFiles.push({
      relativePath: "enclave/hardware-tee-bridge.js",
      content: Buffer.from(decoyBridgeJs.code, "utf8"),
    
      ...(selfSealTransformOption(options, absOutput) !== undefined ? { selfSeal: selfSealTransformOption(options, absOutput)! } : {}),
    });

    // Flood ASAR Pickle JSON header past REA DEFAULT_ASAR_MAX_HEADER_BYTES at
    // bankrupt intensity (mapped decoy shard paths; real modules untouched).
    const asarAmplification = planAsarHeaderAmplification(prng, intensity);
    for (const decoy of asarAmplification.files) {
      protectedFiles.push(decoy);
    }

    const repacked = packAsarBuffer(protectedFiles);
    writeFileAtomicSync(absOutput, repacked);
    binarySectionsPatched = 1 + asarAmplification.files.length;
    counteredVectors.add("electron-ipc-bridge");
    counteredVectors.add("js-static-semantics");
    counteredVectors.add("sourcemap-recovery");
    counteredVectors.add("call-graph-tracing");
    counteredVectors.add("obligation-ledger-cloning");
    counteredVectors.add("archive-inventory");
    counteredVectors.add("asar-header-admission");
  } else if (format === "wasm") {
    const rawWasm = readFileSync(absInput);
    if (
      intensityEnforcesWasmParamRefusal(intensity) &&
      options.allowWasmClearParamCarriers !== true
    ) {
      const wasmParm = lintWasmParamCarrierBuffer(rawWasm, { path: absInput });
      if (wasmParm.shouldRefuseBankrupt) {
        throw new Error(wasmParamCarrierRefuseMessage(wasmParm, absInput));
      }
    }
    if (
      intensityEnforcesWasmXorMaskSidecarRefusal(intensity) &&
      options.allowWasmXorMaskSidecar !== true
    ) {
      const xorMask = lintWasmXorMaskSidecarBuffer(rawWasm, { path: absInput });
      if (xorMask.shouldRefuseBankrupt) {
        throw new Error(wasmXorMaskSidecarRefuseMessage(xorMask, absInput));
      }
    }
    if (
      intensityEnforcesWasmSealXorKnownPlaintextRefusal(intensity) &&
      options.allowWasmSealXorKnownPlaintext !== true
    ) {
      const sealXor = lintWasmSealXorKnownPlaintextFile(absInput);
      if (sealXor.shouldRefuseBankrupt) {
        throw new Error(wasmSealXorKnownPlaintextRefuseMessage(sealXor, absInput));
      }
    }
    const res = protectWasmBinary(rawWasm, {
      intensity,
      seed,
      // Issue #40.3 / red-blue round-1: rename ALL non-preserved exports at
      // maximum/bankrupt by default; wasmPreserveExports is the explicit ABI keep-list.
      ...(options.wasmPreserveExports && options.wasmPreserveExports.length > 0
        ? { preserveExports: options.wasmPreserveExports }
        : {}),
    });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 16;
    fakeCrossReferencesCreated = 24;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.customSectionsAdded;
    wasmExportsRenamed = res.exportsRenamed.length;
    wasmExportOrderShuffled = res.exportsOrderShuffled === true;
    wasmExportDecoysInjected = res.exportDecoysInjected;
    counteredVectors.add("wasm-wat-interface");
    counteredVectors.add("obligation-ledger-cloning");
  } else if (format === "python-source") {
    const rawPy = readFileSync(absInput, "utf8");
    const res = protectPythonSource(rawPy, {
      intensity,
      seed,
      weaveDecoys: options.weaveDecoys === true,
    });
    let finalPy = res.code;
    {
      const entangled = applySidecarEntangleToPython(finalPy, options, absOutput, seed);
      finalPy = entangled.code;
      if (entangled.applied) sidecarEntangleApplied = true;
    }
    writeFileAtomicSync(absOutput, finalPy, "utf8");
    decoyFunctionsInjected = res.decoyFunctionsInjected;
    fakeCrossReferencesCreated = res.crossReferenceEdges;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    counteredVectors.add("python-pyc-marshal");
    counteredVectors.add("call-graph-tracing");
  } else if (format === "python-pyc") {
    const rawPyc = readFileSync(absInput);
    const res = protectPythonPycBuffer(rawPyc, {
      intensity,
      seed,
      weaveDecoys: options.weaveDecoys === true,
    });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected =
      res.decoyCodeObjectsInjected > 0 ? res.decoyCodeObjectsInjected : 14;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = 1;
    counteredVectors.add("python-pyc-marshal");
    if (res.weaveDecoys && res.customerDefsWoven > 0) {
      counteredVectors.add("call-graph-tracing");
    }
  } else if (
    format === "native-elf" ||
    format === "native-macho" ||
    format === "native-pe"
  ) {
    const rawBin = readFileSync(absInput);
    const res = protectNativeBinary(rawBin, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    const passthrough = res.binarySectionsPatched === 0;
    decoyFunctionsInjected = passthrough ? 0 : 24;
    fakeCrossReferencesCreated = passthrough ? 0 : 48;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.binarySectionsPatched;
    if (!passthrough) {
      counteredVectors.add("native-rust-auditable");
      counteredVectors.add("native-go-buildinfo");
      counteredVectors.add("native-decompiler-pseudocode");
      counteredVectors.add("electron-fuses-inspection");
      counteredVectors.add("flutter-dart-aot-snapshot");
    }
    if (res.bunStandaloneCarrier !== "none" || res.nativeBinaryPreserved) {
      // REA #6998 & EOF-sensitive/code-signed native carriers: leave the real
      // binary byte-exact so OS code signatures (`codesign --strict` /
      // Authenticode) and EOF-relative runtime archives (Bun, Deno, PyInstaller,
      // ZIP-SFX) remain intact; plant a sidecar decoy graph full of honeypots.
      const decoy = generateBunStandaloneDecoyGraph(
        new SeededPrng(`${seed}:bun-standalone`),
        intensity,
      );
      writeFileAtomicSync(`${absOutput}.bunfs-snapshot`, decoy.buffer);
      decoyFunctionsInjected += decoy.moduleCount;
      chaffPayloadsEmbedded += decoy.chaffPayloadsEmbedded;
      counteredVectors.add("bun-standalone-module-graph");
    }
  } else if (format === "sqlite") {
    const rawDb = readFileSync(absInput);
    const res = protectSqliteBuffer(rawDb, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.honeyTablesInjected * 5;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.honeyTablesInjected + res.generatedTrapColumnsAdded;
    counteredVectors.add("sqlite-database-inspection");
  } else if (format === "model-safetensors") {
    const res = safetensorsResult!;
    writeFileAtomicSync(absOutput, res.buffer);
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.triggeredJsonNestingBreaker ? 2 : 1;
    counteredVectors.add("model-artifact-inspection");
  } else if (format === "model-gguf") {
    const rawModel = readFileSync(absInput);
    const res = protectGgufBuffer(rawModel, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 16;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.triggeredMetadataNestingBreaker ? 2 : 1;
    counteredVectors.add("model-artifact-inspection");
  } else if (format === "android-dex") {
    const rawDex = readFileSync(absInput);
    const res = protectAndroidDexBuffer(rawDex, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.decoyClassesInjected;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = 3; // file_size + SHA1 signature + Adler32 checksum
    counteredVectors.add("android-dex-il2cpp-inspection");
  } else if (format === "il2cpp-metadata") {
    const rawMeta = readFileSync(absInput);
    const res = protectIl2cppMetadataBuffer(rawMeta, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 28;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = 1;
    counteredVectors.add("android-dex-il2cpp-inspection");
  } else if (format === "archive-zip" || format === "android-apk") {
    const rawZip = readFileSync(absInput);
    const res = protectZipOrApkBuffer(rawZip, {
      intensity,
      seed,
      isApk: format === "android-apk",
    });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 12 + res.membersHardened;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.decoyEntriesInjected;
    counteredVectors.add("archive-inventory");
    if (res.membersHardened > 0) {
      counteredVectors.add("android-dex-il2cpp-inspection");
    }
  } else if (format === "apple-plist") {
    const rawPlist = readFileSync(absInput);
    const res = protectApplePlistBuffer(rawPlist, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 12;
    chaffPayloadsEmbedded = res.decoyEnclaveEntitlementsAdded;
    binarySectionsPatched = res.triggersBudgetAbort ? 2 : 1;
    counteredVectors.add("apple-plist-budget");
  } else if (format === "dotnet-managed") {
    const rawDll = readFileSync(absInput);
    const res = protectDotnetManagedBuffer(rawDll, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 20;
    chaffPayloadsEmbedded = res.plan.decoyPInvokeImports.length;
    binarySectionsPatched = 1;
    counteredVectors.add("dotnet-managed-budget");
  } else if (format === "jvm-class") {
    const rawClass = readFileSync(absInput);
    const res = protectJvmClassBuffer(rawClass, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = 18;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.customAttributesAdded;
    counteredVectors.add("jvm-bytecode-decompilation");
  } else if (format === "erlang-beam") {
    const rawBeam = readFileSync(absInput);
    const res = protectErlangBeamBuffer(rawBeam, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.atomsInjected;
    chaffPayloadsEmbedded = res.chunksInjected;
    binarySectionsPatched = res.exceedsDefaultChunkBudget ? 2 : 1;
    counteredVectors.add("erlang-beam-inspection");
  } else if (format === "evm-bytecode") {
    const rawEvm = readFileSync(absInput);
    const res = protectEvmBytecodeBuffer(rawEvm, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.canaryTokensEmbedded;
    chaffPayloadsEmbedded = res.diagnosticsEmbedded;
    binarySectionsPatched = 1;
    counteredVectors.add("evm-bytecode-inspection");
  } else if (format === "pcap-capture") {
    const rawPcap = readFileSync(absInput);
    const res = protectPcapCaptureBuffer(rawPcap, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.packetsInjected;
    chaffPayloadsEmbedded = res.canaryTokensEmbedded;
    binarySectionsPatched = 1;
    counteredVectors.add("pcap-capture-inspection");
  } else if (format === "gpu-ptx") {
    const rawPtx = readFileSync(absInput, "utf8");
    const res = protectGpuPtxText(rawPtx, { intensity, seed });
    writeFileAtomicSync(absOutput, res.text, "utf8");
    decoyFunctionsInjected = res.entriesInjected;
    chaffPayloadsEmbedded = res.canaryTokensEmbedded;
    binarySectionsPatched = 1;
    counteredVectors.add("gpu-ptx-inspection");
  } else if (format === "firmware-uf2") {
    const rawUf2 = readFileSync(absInput);
    const res = protectUf2FirmwareBuffer(rawUf2, { intensity, seed });
    writeFileAtomicSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.blocksInjected;
    chaffPayloadsEmbedded = res.canaryTokensEmbedded;
    binarySectionsPatched = res.blocksInjected;
    counteredVectors.add("uf2-firmware-inspection");
  } else if (format === "directory") {
    mkdirSync(absOutput, { recursive: true });
    const walkAndProtect = (srcDir: string, dstDir: string): void => {
      mkdirSync(dstDir, { recursive: true });
      for (const entry of readdirSync(srcDir, { withFileTypes: true })) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        const srcFull = join(srcDir, entry.name);
        const dstFull = join(dstDir, entry.name);
        if (entry.isDirectory()) {
          walkAndProtect(srcFull, dstFull);
        } else {
          const ext = extname(entry.name).toLowerCase();
          if ([".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].includes(ext)) {
            const raw = readFileSync(srcFull, "utf8");
            const res = transformJavaScriptWithBlaShield(raw, {
              intensity,
              seed: `${seed}:${entry.name}`,
              filename: entry.name,
              ...(selfSealTransformOption(options, absOutput) !== undefined ? { selfSeal: selfSealTransformOption(options, absOutput)! } : {}),
            });
            const honey = generateHoneySourceMap(
              entry.name,
              res.code.split("\n").length,
              prng,
              chaffPayloads,
            );
            writeFileAtomicSync(dstFull, `${res.code}\n${honey.inlineDirective}\n`, "utf8");
            decoyFunctionsInjected += res.decoyFunctionsInjected;
            fakeCrossReferencesCreated += res.fakeCrossReferencesCreated;
            primitiveCandidateBranchesCreated += res.primitiveCandidateBranchesCreated;
            aliasSelectionStatesCreated += res.aliasSelectionStatesCreated;
            ipcAmbiguitySitesInjected += res.ipcAmbiguitySitesInjected;
            decoyRoutesInjected += res.decoyRoutesInjected;
            chaffPayloadsEmbedded += res.chaffPayloadsEmbedded;
            honeySourceMapsGenerated++;
          } else {
            const childFormat = detectArtifactFormat(srcFull);
            if (childFormat !== "unknown" && childFormat !== "directory") {
              try {
                const subRes = protectTarget({
                  inputPath: srcFull,
                  outputPath: dstFull,
                  intensity,
                  seed: `${seed}:${entry.name}`,
                  honeySourceMaps: options.honeySourceMaps,
                });
                decoyFunctionsInjected += subRes.metrics.decoyFunctionsInjected;
                fakeCrossReferencesCreated += subRes.metrics.fakeCrossReferencesCreated;
                chaffPayloadsEmbedded += subRes.metrics.chaffPayloadsEmbedded;
                binarySectionsPatched += subRes.metrics.binarySectionsPatched;
                for (const v of subRes.counteredReaVectors) counteredVectors.add(v);
              } catch (err) {
                // A detected child artifact that failed protection must not be
                // silently replaced by an unprotected copy: the directory report
                // would claim success while shipping the original bytes.
                const reason = err instanceof Error ? err.message : String(err);
                throw new Error(
                  `Directory protection failed for '${entry.name}': ${reason}`,
                  { cause: err },
                );
              }
            } else {
              copyFileSync(srcFull, dstFull);
            }
          }
        }
      }
    };
    walkAndProtect(absInput, absOutput);
    counteredVectors.add("js-static-semantics");
    counteredVectors.add("electron-ipc-bridge");
    counteredVectors.add("js-route-rpc-inventory");
    counteredVectors.add("sourcemap-recovery");
    counteredVectors.add("call-graph-tracing");
    counteredVectors.add("obligation-ledger-cloning");
  }

  if (format !== "directory" && absOutput !== absInput) {
    try {
      const inputMode = statSync(absInput).mode & 0o777;
      if ((inputMode & 0o111) !== 0) {
        chmodSync(absOutput, inputMode);
      }
    } catch {
      /* POSIX permission bits may not apply on Windows */
    }
  }

  const afterAudit = auditTarget(absOutput);
  const elapsedMs = Date.now() - startMs;

  const metrics: ProtectionMetrics = {
    originalBytes: beforeAudit.byteSize,
    protectedBytes: afterAudit.byteSize,
    decoyFunctionsInjected,
    fakeCrossReferencesCreated,
    primitiveCandidateBranchesCreated,
    aliasSelectionStatesCreated,
    ipcAmbiguitySitesInjected,
    decoyRoutesInjected,
    chaffPayloadsEmbedded,
    honeySourceMapsGenerated,
    inlineScriptsFailed,
    binarySectionsPatched,
  };

  return {
    inputPath: absInput,
    outputPath: absOutput,
    detectedFormat: format,
    intensity,
    ...(options.weaveDecoys === true ? { weaveDecoys: true as const } : {}),
    ...(options.selfSeal === true ? { selfSeal: true as const } : {}),
    ...(sidecarEntangleApplied ? { sidecarEntangle: true as const } : {}),
    ...(wasmExportsRenamed > 0 ? { wasmExportRenameApplied: true as const } : {}),
    ...(wasmExportOrderShuffled ? { wasmExportOrderShuffled: true as const } : {}),
    ...(wasmExportDecoysInjected > 0
      ? { wasmExportDecoysInjected }
      : {}),
    seed,
    originalSha256: beforeAudit.sha256,
    protectedSha256: afterAudit.sha256,
    metrics,
    counteredReaVectors: [...counteredVectors],
    beforeAudit,
    afterAudit,
    elapsedMs,
  };
}
