import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { BLA_IDENTITY } from "../identity.js";
import type { BenchmarkReport, ShowcaseCaseResult } from "../core/types.js";
import { packAsarBuffer } from "../shields/formats/asar.js";
import { buildSampleSqliteDatabase } from "../shields/formats/sqlite.js";
import { buildSafetensorsBuffer } from "../shields/formats/model.js";
import { protectTarget } from "./protector.js";

/**
 * Showcase 1: DX-Ball Sound-Pan Calculation (Directly countering REA's #1 README Showcase!)
 */
const DX_BALL_SOURCE = `
function clampPan(panValue) {
  if (panValue < -10000) return -10000;
  if (panValue > 10000) return 10000;
  return panValue | 0;
}

function calculateSoundPan(paddleX, ballX, screenWidth) {
  const center = screenWidth >> 1;
  const delta = (ballX - center) * 18;
  const weighted = delta + ((paddleX - center) >> 2);
  return clampPan(weighted);
}

module.exports = { calculateSoundPan, clampPan };
`;

/**
 * Showcase 2: Notion Electron Clipboard Bridge (Directly countering REA's #2 README Showcase!)
 */
const NOTION_PRELOAD_SOURCE = `
const { contextBridge, ipcRenderer } = require("electron");

function exposeNotionClipboardBridge() {
  contextBridge.exposeInMainWorld("notionClipboard", {
    readRichBlocks: () => ipcRenderer.invoke("notion:clipboard:read-rich"),
    writeRichBlocks: (blocks) => ipcRenderer.invoke("notion:clipboard:write-rich", blocks),
    syncSelection: (range) => ipcRenderer.send("notion:clipboard:selection-sync", range),
  });
}

module.exports = { exposeNotionClipboardBridge };
`;

const NOTION_MAIN_SOURCE = `
const { ipcMain } = require("electron");

function registerNotionClipboardHandlers(store) {
  ipcMain.handle("notion:clipboard:read-rich", async () => {
    const res = await fetch("/api/v1/clipboard/blocks");
    return store.get("lastBlocks") || [];
  });
  ipcMain.handle("notion:clipboard:write-rich", async (_event, blocks) => {
    store.set("lastBlocks", blocks);
    return { ok: true, count: blocks.length };
  });
}

module.exports = { registerNotionClipboardHandlers };
`;

/**
 * Showcase 3: Enterprise Offline License & Entitlement Validator
 */
const LICENSE_VALIDATOR_SOURCE = `
function computeLicenseChecksum(serialKey, productCode) {
  let hash = 0x811c9dc5;
  const combined = serialKey + ":" + productCode + ":enterprise-v4";
  for (let i = 0; i < combined.length; i++) {
    hash ^= combined.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

function validateEnterpriseLicense(serialKey, productCode, expectedChecksum) {
  if (!serialKey || !serialKey.startsWith("ENT-")) return { valid: false, tier: "none" };
  const actual = computeLicenseChecksum(serialKey, productCode);
  return {
    valid: actual === (expectedChecksum >>> 0),
    tier: actual === (expectedChecksum >>> 0) ? "enterprise-unlimited" : "invalid",
    checksum: actual,
  };
}

module.exports = { computeLicenseChecksum, validateEnterpriseLicense };
`;

/**
 * Showcase 4: Minimal Valid WebAssembly Crypto Module (`add(a, b)` & `mix(x)` exported)
 */
function buildSampleWasmModule(): Buffer {
  // Valid WASM binary exporting `computeDigest(i32, i32) -> i32`
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version 1
    // Section 1: Type section (1 func type: (i32, i32) -> i32)
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    // Section 3: Function section (1 function of type 0)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export section ("computeDigest" -> func 0)
    0x07, 0x11, 0x01, 0x0d,
    0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74,
    0x00, 0x00,
    // Section 10: Code section (local.get 0, local.get 1, i32.xor, i32.const 42, i32.add, end)
    0x0a, 0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0x73, 0x41, 0x2a, 0x6a, 0x0b,
  ]);
}

/**
 * Showcase 5: Minimal Valid ELF64 x86_64 Native Binary with `.rodata` section
 */
function buildSampleElf64Binary(): Buffer {
  const bytes = Buffer.alloc(2048, 0);
  // ELF64 little-endian header
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  bytes.writeUInt16LE(2, 16); // ET_EXEC
  bytes.writeUInt16LE(0x3e, 18); // EM_X86_64
  bytes.writeUInt32LE(1, 20); // EV_CURRENT
  bytes.writeBigUInt64LE(64n, 32); // e_phoff
  bytes.writeBigUInt64LE(128n, 40); // e_shoff
  bytes.writeUInt16LE(64, 52); // e_ehsize
  bytes.writeUInt16LE(56, 54); // e_phentsize
  bytes.writeUInt16LE(1, 56); // e_phnum
  bytes.writeUInt16LE(64, 58); // e_shentsize
  bytes.writeUInt16LE(3, 60); // e_shnum
  bytes.writeUInt16LE(1, 62); // e_shstrndx

  // Program header 0: PT_LOAD covering file
  bytes.writeUInt32LE(1, 64); // PT_LOAD
  bytes.writeUInt32LE(4, 68); // PF_R
  bytes.writeBigUInt64LE(0n, 72); // p_offset
  bytes.writeBigUInt64LE(0x400000n, 80); // p_vaddr
  bytes.writeBigUInt64LE(BigInt(bytes.length), 96); // p_filesz
  bytes.writeBigUInt64LE(BigInt(bytes.length), 104); // p_memsz

  // Section header 1: .shstrtab at 192
  const names = Buffer.from("\0.shstrtab\0.rodata\0", "utf8");
  names.copy(bytes, 512);
  bytes.writeUInt32LE(1, 192); // sh_name
  bytes.writeUInt32LE(3, 196); // SHT_STRTAB
  bytes.writeBigUInt64LE(512n, 216); // sh_offset
  bytes.writeBigUInt64LE(BigInt(names.length), 224); // sh_size

  // Section header 2: .rodata at 256
  bytes.writeUInt32LE(11, 256); // sh_name (.rodata)
  bytes.writeUInt32LE(1, 260); // SHT_PROGBITS
  bytes.writeBigUInt64LE(2n, 264); // SHF_ALLOC (read-only!)
  bytes.writeBigUInt64LE(0x400400n, 272); // sh_addr
  bytes.writeBigUInt64LE(1024n, 280); // sh_offset
  bytes.writeBigUInt64LE(512n, 288); // sh_size
  bytes.write("/rustc/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/library/core", 1024, "latin1");
  return bytes;
}

function runCommonJsModule(code: string): Record<string, unknown> {
  const mod = { exports: {} as Record<string, unknown> };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    require: (id: string) => {
      if (id === "electron") {
        return {
          contextBridge: { exposeInMainWorld: () => undefined },
          ipcRenderer: { invoke: () => Promise.resolve([]), send: () => undefined },
          ipcMain: { handle: () => undefined, on: () => undefined },
        };
      }
      return {};
    },
    fetch: () => Promise.resolve({ json: () => ({}) }),
    process: { pid: 1234 },
    Math,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Map,
    Set,
    Buffer,
  };
  vm.runInNewContext(code, sandbox, { timeout: 5000 });
  return mod.exports;
}

/**
 * Runs eight synthetic fixtures with hypothetical costs and bounded runtime samples (`bla benchmark`).
 */
export async function runShowcaseBenchmark(): Promise<BenchmarkReport> {
  const tempDir = mkdtempSync(join(tmpdir(), "bla-benchmark-"));
  const cases: ShowcaseCaseResult[] = [];

  try {
    // 1. DX-Ball Sound-Pan Calculation
    {
      const srcPath = join(tempDir, "dx-ball-sound-pan.js");
      const outPath = join(tempDir, "dx-ball-sound-pan.shielded.js");
      writeFileSync(srcPath, DX_BALL_SOURCE, "utf8");
      const res = protectTarget({ inputPath: srcPath, outputPath: outPath, intensity: "bankrupt" });

      const origExports = runCommonJsModule(DX_BALL_SOURCE) as {
        calculateSoundPan: (px: number, bx: number, w: number) => number;
      };
      const protCode = (await import("node:fs")).readFileSync(outPath, "utf8");
      const protExports = runCommonJsModule(protCode) as {
        calculateSoundPan: (px: number, bx: number, w: number) => number;
      };
      const functionalOk =
        origExports.calculateSoundPan(320, 480, 640) ===
          protExports.calculateSoundPan(320, 480, 640) &&
        origExports.calculateSoundPan(100, 50, 640) ===
          protExports.calculateSoundPan(100, 50, 640);

      cases.push(buildCaseResult("dx-ball", "DX-Ball Sound-Pan Calculation", "REA Showcase #1 (dx-ball)", res, functionalOk, "Two calculateSoundPan input/output comparisons in a VM; not exhaustive equivalence."));
    }

    // 2. Notion Electron Clipboard Bridge (.asar)
    {
      const asarPath = join(tempDir, "notion-clipboard.asar");
      const outAsarPath = join(tempDir, "notion-clipboard.shielded.asar");
      const rawAsar = packAsarBuffer([
        {
          relativePath: "package.json",
          content: Buffer.from(JSON.stringify({ name: "notion-clipboard", main: "main.js" }), "utf8"),
        },
        { relativePath: "preload.js", content: Buffer.from(NOTION_PRELOAD_SOURCE, "utf8") },
        { relativePath: "main.js", content: Buffer.from(NOTION_MAIN_SOURCE, "utf8") },
      ]);
      writeFileSync(asarPath, rawAsar);
      const res = protectTarget({ inputPath: asarPath, outputPath: outAsarPath, intensity: "bankrupt" });
      cases.push(buildCaseResult("notion-electron", "Notion Electron Clipboard Bridge (.asar)", "REA Showcase #2 (notion)", res, null, "Not run: no Electron runtime or IPC behavior comparison."));
    }

    // 3. Enterprise Offline License & Crypto Guard
    {
      const srcPath = join(tempDir, "license-validator.js");
      const outPath = join(tempDir, "license-validator.shielded.js");
      writeFileSync(srcPath, LICENSE_VALIDATOR_SOURCE, "utf8");
      const res = protectTarget({ inputPath: srcPath, outputPath: outPath, intensity: "bankrupt" });

      const origExports = runCommonJsModule(LICENSE_VALIDATOR_SOURCE) as {
        computeLicenseChecksum: (k: string, p: string) => number;
        validateEnterpriseLicense: (k: string, p: string, c: number) => { valid: boolean; tier: string };
      };
      const protCode = (await import("node:fs")).readFileSync(outPath, "utf8");
      const protExports = runCommonJsModule(protCode) as typeof origExports;
      const expectedSum = origExports.computeLicenseChecksum("ENT-9942-ABCD", "pro-suite");
      const origCheck = origExports.validateEnterpriseLicense("ENT-9942-ABCD", "pro-suite", expectedSum);
      const protCheck = protExports.validateEnterpriseLicense("ENT-9942-ABCD", "pro-suite", expectedSum);
      const functionalOk = origCheck.valid === true && protCheck.valid === true && origCheck.tier === protCheck.tier;

      cases.push(buildCaseResult("license-guard", "Enterprise License & Crypto Validator", "SaaS Client Entitlement Core", res, functionalOk, "One license input: valid and tier fields compared; not exhaustive equivalence."));
    }

    // 4. WebAssembly Crypto Module (.wasm)
    {
      const wasmPath = join(tempDir, "crypto-core.wasm");
      const outWasmPath = join(tempDir, "crypto-core.shielded.wasm");
      const rawWasm = buildSampleWasmModule();
      writeFileSync(wasmPath, rawWasm);
      const res = protectTarget({ inputPath: wasmPath, outputPath: outWasmPath, intensity: "bankrupt" });

      const protWasmBytes = (await import("node:fs")).readFileSync(outWasmPath);
      const validWasm = WebAssembly.validate(protWasmBytes);
      const origMod = new WebAssembly.Module(new Uint8Array(rawWasm));
      const protMod = new WebAssembly.Module(new Uint8Array(protWasmBytes));
      const origInst = new WebAssembly.Instance(origMod);
      const protInst = new WebAssembly.Instance(protMod);
      const origFn = origInst.exports.computeDigest as (a: number, b: number) => number;
      const protFn = protInst.exports.computeDigest as (a: number, b: number) => number;
      const functionalOk = validWasm && origFn(17, 29) === protFn(17, 29);

      cases.push(buildCaseResult("wasm-core", "WebAssembly Crypto Kernel (.wasm)", "REA inspect_wasm_artifact", res, functionalOk, "WebAssembly validation and one computeDigest input/output comparison; not exhaustive equivalence."));
    }

    // 5. Native ELF64 Rust/Go Binary
    {
      const elfPath = join(tempDir, "enclave-daemon.elf");
      const outElfPath = join(tempDir, "enclave-daemon.shielded.elf");
      writeFileSync(elfPath, buildSampleElf64Binary());
      const res = protectTarget({ inputPath: elfPath, outputPath: outElfPath, intensity: "bankrupt" });
      cases.push(buildCaseResult("native-elf", "Native ELF64 Rust/Go/Electron/Dart Binary", "REA inspect_rust_binary / inspect_electron_fuses / identify_flutter_build", res, null, "Not run: no independent runtime behavior comparison."));
    }

    // 6. Local SQLite 3 Entitlement Database (.sqlite)
    {
      const dbPath = join(tempDir, "entitlements.sqlite");
      const outDbPath = join(tempDir, "entitlements.shielded.sqlite");
      writeFileSync(dbPath, buildSampleSqliteDatabase());
      const res = protectTarget({ inputPath: dbPath, outputPath: outDbPath, intensity: "bankrupt" });
      cases.push(buildCaseResult("sqlite-db", "Local SQLite Entitlement Database (.sqlite)", "REA inspect_sqlite_database", res, null, "Not run: no independent runtime behavior comparison."));
    }

    // 7. Edge AI Safetensors Model (.safetensors)
    {
      const modelPath = join(tempDir, "proprietary-weights.safetensors");
      const outModelPath = join(tempDir, "proprietary-weights.shielded.safetensors");
      writeFileSync(
        modelPath,
        buildSafetensorsBuffer({
          encoder_proj: { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] },
        }),
      );
      const res = protectTarget({ inputPath: modelPath, outputPath: outModelPath, intensity: "bankrupt" });
      cases.push(buildCaseResult("safetensors-model", "Proprietary Edge AI Model (.safetensors)", "REA inspect_model_artifact", res, null, "Not run: no independent runtime behavior comparison."));
    }

    // 8. Android Dalvik Bytecode (classes.dex)
    {
      const dexPath = join(tempDir, "classes.dex");
      const outDexPath = join(tempDir, "classes.shielded.dex");
      const baseDex = Buffer.alloc(112, 0);
      baseDex.write("dex\n035\0", 0, "ascii");
      baseDex.writeUInt32LE(112, 32);
      baseDex.writeUInt32LE(112, 36);
      baseDex.writeUInt32LE(0x12345678, 40);
      writeFileSync(dexPath, baseDex);
      const res = protectTarget({ inputPath: dexPath, outputPath: outDexPath, intensity: "bankrupt" });
      cases.push(buildCaseResult("android-dex", "Android Dalvik Bytecode (classes.dex)", "REA search_android_classes (JADX/JEB)", res, null, "Not run: no independent runtime behavior comparison."));
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }

  const totalBeforeTokens = cases.reduce((acc, c) => acc + c.before.estimatedTokens, 0);
  const totalAfterTokens = cases.reduce((acc, c) => acc + c.after.estimatedTokens, 0);
  const totalBeforeCost = cases.reduce((acc, c) => acc + c.before.estimatedCostUsd, 0);
  const totalAfterCost = cases.reduce((acc, c) => acc + c.after.estimatedCostUsd, 0);

  return {
    evidenceBasis: "synthetic-fixtures-and-hypothetical-estimates",
    reaExecuted: false,
    agentExecuted: false,
    timestamp: new Date().toISOString(),
    blaVersion: BLA_IDENTITY.version,
    cases,
    aggregateTokenMultiplier: Number((totalAfterTokens / Math.max(1, totalBeforeTokens)).toFixed(1)),
    aggregateCostMultiplier: Number((totalAfterCost / Math.max(0.01, totalBeforeCost)).toFixed(1)),
  };
}

function buildCaseResult(
  id: string,
  title: string,
  reaShowcaseReference: string,
  res: ReturnType<typeof protectTarget>,
  functionalCheckPassed: boolean | null,
  functionalCheckScope: string,
): ShowcaseCaseResult {
  const bEst = res.beforeAudit.agentEstimates[0]!;
  const aEst = res.afterAudit.agentEstimates[0]!;
  return {
    id,
    title,
    reaShowcaseReference,
    format: res.detectedFormat,
    before: {
      exposureScore: res.beforeAudit.exposureScore,
      examinationStatus: res.beforeAudit.reaSimulation.examinationStatus,
      obligationNodes: res.beforeAudit.reaSimulation.obligationLedgerNodes,
      estimatedTokens: bEst.estimatedInputTokens,
      estimatedCostUsd: bEst.estimatedCostUsd,
      estimatedSeconds: bEst.estimatedWallClockSeconds,
      agentOutcome: bEst.outcomeVerdict,
    },
    after: {
      exposureScore: res.afterAudit.exposureScore,
      examinationStatus: res.afterAudit.reaSimulation.examinationStatus,
      triggeredLimits: res.afterAudit.reaSimulation.triggeredResourceLimits,
      obligationNodes: res.afterAudit.reaSimulation.obligationLedgerNodes,
      estimatedTokens: aEst.estimatedInputTokens,
      estimatedCostUsd: aEst.estimatedCostUsd,
      estimatedSeconds: aEst.estimatedWallClockSeconds,
      agentOutcome: aEst.outcomeVerdict,
    },
    tokenMultiplier: Number((aEst.estimatedInputTokens / Math.max(1, bEst.estimatedInputTokens)).toFixed(1)),
    costMultiplier: Number((aEst.estimatedCostUsd / Math.max(0.01, bEst.estimatedCostUsd)).toFixed(1)),
    functionalCheckPassed: functionalCheckPassed === true,
    functionalCheckStatus: functionalCheckPassed === null ? "not-run" : functionalCheckPassed ? "passed" : "failed",
    functionalCheckScope,
  };
}
