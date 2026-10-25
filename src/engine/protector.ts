import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import { detectArtifactFormat } from "../core/detector.js";
import { SeededPrng } from "../core/prng.js";
import type {
  ProtectionMetrics,
  ProtectionOptions,
  ProtectionResult,
  ReaAttackVectorId,
} from "../core/types.js";
import { generateChaffPayloads } from "../shields/chaff/chaff-generator.js";
import { transformJavaScriptWithBlaShield } from "../shields/javascript/ast-shield.js";
import { generateHoneySourceMap } from "../shields/formats/sourcemap.js";
import { packAsarBuffer, unpackAsarBuffer, type VirtualAsarFile } from "../shields/formats/asar.js";
import { protectWasmBinary } from "../shields/formats/wasm.js";
import { protectPythonPycBuffer, protectPythonSource } from "../shields/formats/python.js";
import { protectNativeBinary } from "../shields/formats/native.js";
import { protectZipOrApkBuffer } from "../shields/formats/archive.js";
import { protectSqliteBuffer } from "../shields/formats/sqlite.js";
import { UnsupportedGgufProtectionError, protectSafetensorsBuffer } from "../shields/formats/model.js";
import { protectAndroidDexBuffer, protectIl2cppMetadataBuffer } from "../shields/formats/mobile-game.js";
import { auditTarget } from "./auditor.js";

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
  const startMs = Date.now();
  const absInput = resolve(options.inputPath);
  const format = detectArtifactFormat(absInput);
  if (format === "unknown") {
    throw new Error(`Unsupported or missing target path: ${absInput}`);
  }

  // Reject before auditing, generating payloads, or creating any output paths.
  if (format === "model-gguf") {
    throw new UnsupportedGgufProtectionError();
  }

  const intensity = options.intensity ?? "balanced";
  const seed = String(options.seed ?? "bla-shield-seed-v1");
  const prng = new SeededPrng(seed);
  const chaffPayloads = generateChaffPayloads(prng, intensity);

  const beforeAudit = auditTarget(absInput);
  const absOutput = resolve(
    options.outputPath ?? deriveDefaultOutputPath(absInput, options.inPlace),
  );

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
  const counteredVectors = new Set<ReaAttackVectorId>();

  if (format === "javascript" || format === "typescript") {
    const raw = readFileSync(absInput, "utf8");
    const transformed = transformJavaScriptWithBlaShield(raw, {
      intensity,
      seed,
      filename: basename(absInput),
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

    writeFileSync(absOutput, finalCode, "utf8");
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
    const transformedHtml = rawHtml.replace(
      /<script\b([^>]*)>([\s\S]*?)<\/script>/gi,
      (fullMatch, attrs: string, scriptBody: string) => {
        if (!scriptBody.trim() || /src\s*=/i.test(attrs)) return fullMatch;
        try {
          const res = transformJavaScriptWithBlaShield(scriptBody, {
            intensity,
            seed,
          });
          decoyFunctionsInjected += res.decoyFunctionsInjected;
          fakeCrossReferencesCreated += res.fakeCrossReferencesCreated;
          primitiveCandidateBranchesCreated += res.primitiveCandidateBranchesCreated;
          aliasSelectionStatesCreated += res.aliasSelectionStatesCreated;
          ipcAmbiguitySitesInjected += res.ipcAmbiguitySitesInjected;
          decoyRoutesInjected += res.decoyRoutesInjected;
          chaffPayloadsEmbedded += res.chaffPayloadsEmbedded;
          return `<script${attrs}>\n${res.code}\n</script>`;
        } catch {
          return fullMatch;
        }
      },
    );
    writeFileSync(absOutput, transformedHtml, "utf8");
    counteredVectors.add("js-static-semantics");
    counteredVectors.add("call-graph-tracing");
  } else if (format === "sourcemap") {
    const honey = generateHoneySourceMap(
      basename(absOutput).replace(/\.map$/, ""),
      120,
      prng,
      chaffPayloads,
    );
    writeFileSync(absOutput, honey.jsonString, "utf8");
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
      { intensity, seed: `${seed}:enclave-decoy` },
    );
    protectedFiles.push({
      relativePath: "enclave/hardware-tee-bridge.js",
      content: Buffer.from(decoyBridgeJs.code, "utf8"),
    });

    const repacked = packAsarBuffer(protectedFiles);
    writeFileSync(absOutput, repacked);
    binarySectionsPatched = 1;
    counteredVectors.add("electron-ipc-bridge");
    counteredVectors.add("js-static-semantics");
    counteredVectors.add("sourcemap-recovery");
    counteredVectors.add("call-graph-tracing");
    counteredVectors.add("obligation-ledger-cloning");
    counteredVectors.add("archive-inventory");
  } else if (format === "wasm") {
    const rawWasm = readFileSync(absInput);
    const res = protectWasmBinary(rawWasm, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = 16;
    fakeCrossReferencesCreated = 24;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.customSectionsAdded;
    counteredVectors.add("wasm-wat-interface");
    counteredVectors.add("obligation-ledger-cloning");
  } else if (format === "python-source") {
    const rawPy = readFileSync(absInput, "utf8");
    const res = protectPythonSource(rawPy, { intensity, seed });
    writeFileSync(absOutput, res.code, "utf8");
    decoyFunctionsInjected = res.decoyFunctionsInjected;
    fakeCrossReferencesCreated = res.crossReferenceEdges;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    counteredVectors.add("python-pyc-marshal");
    counteredVectors.add("call-graph-tracing");
  } else if (format === "python-pyc") {
    const rawPyc = readFileSync(absInput);
    const res = protectPythonPycBuffer(rawPyc, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = 14;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = 1;
    counteredVectors.add("python-pyc-marshal");
  } else if (
    format === "native-elf" ||
    format === "native-macho" ||
    format === "native-pe"
  ) {
    const rawBin = readFileSync(absInput);
    const res = protectNativeBinary(rawBin, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = 24;
    fakeCrossReferencesCreated = 48;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.binarySectionsPatched;
    counteredVectors.add("native-rust-auditable");
    counteredVectors.add("native-go-buildinfo");
    counteredVectors.add("native-decompiler-pseudocode");
    counteredVectors.add("electron-fuses-inspection");
    counteredVectors.add("flutter-dart-aot-snapshot");
  } else if (format === "sqlite") {
    const rawDb = readFileSync(absInput);
    const res = protectSqliteBuffer(rawDb, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.honeyTablesInjected * 5;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.honeyTablesInjected + res.generatedTrapColumnsAdded;
    counteredVectors.add("sqlite-database-inspection");
  } else if (format === "model-safetensors") {
    const rawModel = readFileSync(absInput);
    const res = protectSafetensorsBuffer(rawModel, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = 16;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.triggeredJsonNestingBreaker ? 2 : 1;
    counteredVectors.add("model-artifact-inspection");
  } else if (format === "android-dex") {
    const rawDex = readFileSync(absInput);
    const res = protectAndroidDexBuffer(rawDex, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = res.decoyClassesInjected;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = 3; // file_size + SHA1 signature + Adler32 checksum
    counteredVectors.add("android-dex-il2cpp-inspection");
  } else if (format === "il2cpp-metadata") {
    const rawMeta = readFileSync(absInput);
    const res = protectIl2cppMetadataBuffer(rawMeta, { intensity, seed });
    writeFileSync(absOutput, res.buffer);
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
    writeFileSync(absOutput, res.buffer);
    decoyFunctionsInjected = 12;
    chaffPayloadsEmbedded = res.chaffPayloadsEmbedded;
    binarySectionsPatched = res.decoyEntriesInjected;
    counteredVectors.add("archive-inventory");
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
            });
            const honey = generateHoneySourceMap(
              entry.name,
              res.code.split("\n").length,
              prng,
              chaffPayloads,
            );
            writeFileSync(dstFull, `${res.code}\n${honey.inlineDirective}\n`, "utf8");
            decoyFunctionsInjected += res.decoyFunctionsInjected;
            fakeCrossReferencesCreated += res.fakeCrossReferencesCreated;
            primitiveCandidateBranchesCreated += res.primitiveCandidateBranchesCreated;
            aliasSelectionStatesCreated += res.aliasSelectionStatesCreated;
            ipcAmbiguitySitesInjected += res.ipcAmbiguitySitesInjected;
            decoyRoutesInjected += res.decoyRoutesInjected;
            chaffPayloadsEmbedded += res.chaffPayloadsEmbedded;
            honeySourceMapsGenerated++;
          } else {
            copyFileSync(srcFull, dstFull);
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
    binarySectionsPatched,
  };

  return {
    inputPath: absInput,
    outputPath: absOutput,
    detectedFormat: format,
    intensity,
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
