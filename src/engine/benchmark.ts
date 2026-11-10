import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { BLA_IDENTITY } from "../identity.js";
import type { BenchmarkReport, ShowcaseCaseResult } from "../core/types.js";
import { getDatabaseSyncClass, isNodeSqliteAvailable } from "../core/sqlite-runtime.js";
import { packAsarBuffer, unpackAsarBuffer } from "../shields/formats/asar.js";
import { buildSampleSqliteDatabase } from "../shields/formats/sqlite.js";
import { buildSafetensorsBuffer, validateSafetensorsBuffer } from "../shields/formats/model.js";
import { buildMappedGoFlutterElfFixture } from "../shields/formats/go-flutter-exhaustion.js";
import { inspectAndroidDex } from "../shields/formats/mobile-game.js";
import { inspectErlangBeam } from "../shields/formats/erlang-beam.js";
import { inspectEvmBytecode } from "../shields/formats/evm-bytecode.js";
import { inspectPcapCapture } from "../shields/formats/pcap-capture.js";
import { inspectGpuPtx } from "../shields/formats/gpu-ptx.js";
import { auditTarget } from "./auditor.js";
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
 * Showcase 5: ELF64 with mapped `.go.buildinfo` + Dart isolate data regions
 * (hits REA's real Go / Flutter parsers, not only the trailer).
 */
function buildSampleElf64Binary(): Buffer {
  return buildMappedGoFlutterElfFixture();
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

function runElectronAsarClipboardHarness(
  preloadCode: string,
  mainCode: string,
  virtualFiles: ReadonlyMap<string, Buffer> = new Map(),
): {
  readonly exposedKey: string;
  readonly bridgeMethods: readonly string[];
  readonly handlersRegistered: number;
} {
  let exposedKey = "";
  let exposedApi: Record<string, (...args: unknown[]) => unknown> = {};
  const handlers = new Map<string, (...args: unknown[]) => unknown>();
  const sentEvents: Array<{ channel: string; payload: unknown }> = [];

  const electronMock = {
    contextBridge: {
      exposeInMainWorld: (key: string, api: Record<string, (...args: unknown[]) => unknown>) => {
        exposedKey = key;
        exposedApi = api;
      },
    },
    ipcRenderer: {
      invoke: (channel: string, ...args: unknown[]) => {
        const handler = handlers.get(channel);
        return handler ? handler({}, ...args) : Promise.resolve([]);
      },
      send: (channel: string, payload: unknown) => {
        sentEvents.push({ channel, payload });
      },
    },
    ipcMain: {
      handle: (channel: string, fn: (...args: unknown[]) => unknown) => {
        handlers.set(channel, fn);
      },
      on: () => undefined,
    },
  };

  const fsMock = {
    readFileSync: (filePath: string, encoding?: string) => {
      const base = String(filePath).split(/[\\/]/).pop() ?? String(filePath);
      const buf = virtualFiles.get(base) ?? virtualFiles.get(String(filePath));
      if (!buf) {
        return readFileSync(filePath, encoding as BufferEncoding);
      }
      return encoding ? buf.toString(encoding as BufferEncoding) : buf;
    },
  };

  const pathMock = {
    join: (...parts: string[]) => parts.join("/"),
    resolve: (...parts: string[]) => parts.join("/"),
    dirname: (p: string) => p.split("/").slice(0, -1).join("/") || ".",
  };

  const makeSandbox = (mod: { exports: Record<string, unknown> }) => ({
    module: mod,
    exports: mod.exports,
    __dirname: "/asar",
    __filename: "/asar/index.js",
    require: (id: string) => {
      if (id === "electron") return electronMock;
      if (id === "fs" || id === "node:fs") return fsMock;
      if (id === "path" || id === "node:path") return pathMock;
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
  });

  const mainMod = { exports: {} as Record<string, unknown> };
  vm.runInNewContext(mainCode, makeSandbox(mainMod), { timeout: 5000 });
  const preloadMod = { exports: {} as Record<string, unknown> };
  vm.runInNewContext(preloadCode, makeSandbox(preloadMod), { timeout: 5000 });

  const storeMap = new Map<string, unknown>();
  const store = {
    get: (k: string) => storeMap.get(k),
    set: (k: string, v: unknown) => storeMap.set(k, v),
  };

  const regFn =
    typeof mainMod.exports.registerNotionClipboardHandlers === "function"
      ? (mainMod.exports.registerNotionClipboardHandlers as (s: typeof store) => void)
      : (Object.values(mainMod.exports).find((v) => typeof v === "function") as
          | ((s: typeof store) => void)
          | undefined);
  if (regFn) regFn(store);

  const exposeFn =
    typeof preloadMod.exports.exposeNotionClipboardBridge === "function"
      ? (preloadMod.exports.exposeNotionClipboardBridge as () => void)
      : (Object.values(preloadMod.exports).find((v) => typeof v === "function") as
          | (() => void)
          | undefined);
  if (exposeFn) exposeFn();

  return {
    exposedKey,
    bridgeMethods: Object.keys(exposedApi).sort(),
    handlersRegistered: handlers.size,
  };
}

/**
 * Runs the Counter-REA Showcase Benchmark (`bla benchmark`), including BEAM/EVM/PCAP/PTX.
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
        clampPan: (v: number) => number;
      };
      const protCode = readFileSync(outPath, "utf8");
      const protExports = runCommonJsModule(protCode) as typeof origExports;
      const functionalOk =
        origExports.calculateSoundPan(320, 480, 640) ===
          protExports.calculateSoundPan(320, 480, 640) &&
        origExports.calculateSoundPan(100, 50, 640) ===
          protExports.calculateSoundPan(100, 50, 640) &&
        origExports.clampPan(-25000) === protExports.clampPan(-25000) &&
        origExports.clampPan(25000) === protExports.clampPan(25000);

      cases.push(buildCaseResult("dx-ball", "DX-Ball Sound-Pan Calculation", "REA Showcase #1 (dx-ball)", res, functionalOk));
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

      const unpacked = unpackAsarBuffer(readFileSync(outAsarPath));
      const virtualMap = new Map<string, Buffer>();
      for (const entry of unpacked) {
        virtualMap.set(entry.relativePath, entry.content);
        virtualMap.set(`/asar/${entry.relativePath}`, entry.content);
      }
      const pkgEntry = unpacked.find((f) => f.relativePath === "package.json");
      const preloadEntry = unpacked.find((f) => f.relativePath === "preload.js");
      const mainEntry = unpacked.find((f) => f.relativePath === "main.js");
      let functionalOk = false;
      if (pkgEntry && preloadEntry && mainEntry) {
        const pkgJson = JSON.parse(pkgEntry.content.toString("utf8")) as {
          name?: string;
          main?: string;
        };
        const origHarness = runElectronAsarClipboardHarness(
          NOTION_PRELOAD_SOURCE,
          NOTION_MAIN_SOURCE,
        );
        const protHarness = runElectronAsarClipboardHarness(
          preloadEntry.content.toString("utf8"),
          mainEntry.content.toString("utf8"),
          virtualMap,
        );
        functionalOk =
          pkgJson.name === "notion-clipboard" &&
          pkgJson.main === "main.js" &&
          origHarness.exposedKey === "notionClipboard" &&
          protHarness.exposedKey === "notionClipboard" &&
          origHarness.bridgeMethods.length === 3 &&
          protHarness.bridgeMethods.length === 3 &&
          origHarness.handlersRegistered === 2 &&
          protHarness.handlersRegistered === 2;
      }
      cases.push(buildCaseResult("notion-electron", "Notion Electron Clipboard Bridge (.asar)", "REA Showcase #2 (notion)", res, functionalOk));
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
      const protCode = readFileSync(outPath, "utf8");
      const protExports = runCommonJsModule(protCode) as typeof origExports;
      const expectedSum = origExports.computeLicenseChecksum("ENT-9942-ABCD", "pro-suite");
      const origCheck = origExports.validateEnterpriseLicense("ENT-9942-ABCD", "pro-suite", expectedSum);
      const protCheck = protExports.validateEnterpriseLicense("ENT-9942-ABCD", "pro-suite", expectedSum);
      const origReject = origExports.validateEnterpriseLicense("FREE-0000", "pro-suite", expectedSum);
      const protReject = protExports.validateEnterpriseLicense("FREE-0000", "pro-suite", expectedSum);
      const functionalOk =
        origCheck.valid === true &&
        protCheck.valid === true &&
        origCheck.tier === protCheck.tier &&
        origReject.valid === false &&
        protReject.valid === false;

      cases.push(buildCaseResult("license-guard", "Enterprise License & Crypto Validator", "SaaS Client Entitlement Core", res, functionalOk));
    }

    // 4. WebAssembly Crypto Module (.wasm)
    {
      const wasmPath = join(tempDir, "crypto-core.wasm");
      const outWasmPath = join(tempDir, "crypto-core.shielded.wasm");
      const rawWasm = buildSampleWasmModule();
      writeFileSync(wasmPath, rawWasm);
      const res = protectTarget({ inputPath: wasmPath, outputPath: outWasmPath, intensity: "bankrupt" });

      const protWasmBytes = readFileSync(outWasmPath);
      const validWasm = WebAssembly.validate(protWasmBytes);
      const origMod = new WebAssembly.Module(new Uint8Array(rawWasm));
      const protMod = new WebAssembly.Module(new Uint8Array(protWasmBytes));
      const origInst = new WebAssembly.Instance(origMod);
      const protInst = new WebAssembly.Instance(protMod);
      const origFn = origInst.exports.computeDigest as (a: number, b: number) => number;
      // Bankrupt renames non-preserved ABI by default (red-blue round-1); resolve
      // the live export (decoy aliases share the same func index).
      const protExportTable = protInst.exports as Record<string, unknown>;
      const protFn = (
        typeof protExportTable.computeDigest === "function"
          ? protExportTable.computeDigest
          : Object.values(protExportTable).find((v) => typeof v === "function")
      ) as ((a: number, b: number) => number) | undefined;
      const functionalOk =
        validWasm &&
        typeof protFn === "function" &&
        origFn(17, 29) === protFn(17, 29) &&
        origFn(0, 255) === protFn(0, 255);

      cases.push(buildCaseResult("wasm-core", "WebAssembly Crypto Kernel (.wasm)", "REA inspect_wasm_artifact", res, functionalOk));
    }

    // 5. Native ELF64 Rust/Go Binary
    {
      const elfPath = join(tempDir, "enclave-daemon.elf");
      const outElfPath = join(tempDir, "enclave-daemon.shielded.elf");
      const origElf = buildSampleElf64Binary();
      writeFileSync(elfPath, origElf);
      const res = protectTarget({ inputPath: elfPath, outputPath: outElfPath, intensity: "bankrupt" });
      const protElf = readFileSync(outElfPath);
      const afterAudit = auditTarget(outElfPath);
      // Verify ELF64 header (magic, 64-bit class, machine, entry point, program header table) is preserved
      const functionalOk =
        protElf.length >= origElf.length &&
        protElf.subarray(0, 64).equals(origElf.subarray(0, 64)) &&
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        afterAudit.reaSimulation.triggeredResourceLimits.some((l) =>
          l.includes("maximum_rustc_hashes"),
        );
      cases.push(buildCaseResult("native-elf", "Native ELF64 Rust/Go/Electron/Dart Binary", "REA inspect_rust_binary / inspect_electron_fuses / identify_flutter_build", res, functionalOk));
    }

    // 6. Local SQLite 3 Entitlement Database (.sqlite)
    // Degrade gracefully on Node < 22.13 / --no-experimental-sqlite: skip this target
    // rather than hard-failing the entire Counter-REA showcase.
    if (isNodeSqliteAvailable()) {
      const dbPath = join(tempDir, "entitlements.sqlite");
      const outDbPath = join(tempDir, "entitlements.shielded.sqlite");
      writeFileSync(dbPath, buildSampleSqliteDatabase());
      const res = protectTarget({ inputPath: dbPath, outputPath: outDbPath, intensity: "bankrupt" });
      const afterAudit = auditTarget(outDbPath);

      const DatabaseSync = getDatabaseSyncClass();
      const origDb = new DatabaseSync(dbPath);
      const protDb = new DatabaseSync(outDbPath);
      let sqlParityOk = false;
      try {
        // Querying business tables directly works without custom scalar functions:
        const origRows = origDb
          .prepare("SELECT account_id, plan_tier, offline_token FROM license_cache ORDER BY account_id")
          .all();
        const protRows = protDb
          .prepare("SELECT account_id, plan_tier, offline_token FROM license_cache ORDER BY account_id")
          .all();
        // Register the application UDF to run full PRAGMA integrity_check across all tables:
        protDb.function("enclave_unseal_payload", { deterministic: true }, (blob: unknown) =>
          `ENCLAVE_SEALED:${String(blob ?? "")}`,
        );
        const integrity = protDb.prepare("PRAGMA integrity_check").get() as
          | { integrity_check?: string }
          | undefined;
        sqlParityOk =
          integrity?.integrity_check === "ok" &&
          origRows.length > 0 &&
          JSON.stringify(origRows) === JSON.stringify(protRows);
      } finally {
        origDb.close();
        protDb.close();
      }

      const functionalOk =
        sqlParityOk &&
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        afterAudit.reaSimulation.triggeredResourceLimits.some((l) =>
          l.includes("SqliteColumnEvaluationFailure"),
        );
      cases.push(buildCaseResult("sqlite-db", "Local SQLite Entitlement Database (.sqlite)", "REA inspect_sqlite_database", res, functionalOk));
    }

    // 7. Edge AI Safetensors Model (.safetensors)
    {
      const modelPath = join(tempDir, "proprietary-weights.safetensors");
      const outModelPath = join(tempDir, "proprietary-weights.shielded.safetensors");
      const tensorWeights = Buffer.alloc(32);
      for (let i = 0; i < 8; i++) {
        tensorWeights.writeFloatLE((i + 1) * 0.25, i * 4);
      }
      const rawModel = buildSafetensorsBuffer(
        {
          encoder_proj: { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] },
          layer_norm_weight: { dtype: "F32", shape: [4], data_offsets: [16, 32] },
        },
        tensorWeights,
      );
      writeFileSync(modelPath, rawModel);
      const res = protectTarget({ inputPath: modelPath, outputPath: outModelPath, intensity: "bankrupt" });
      const afterAudit = auditTarget(outModelPath);

      const origParsed = validateSafetensorsBuffer(rawModel);
      const protParsed = validateSafetensorsBuffer(readFileSync(outModelPath));
      const origProj = origParsed.header.encoder_proj as { dtype: string; shape: number[]; data_offsets: [number, number] };
      const protProj = protParsed.header.encoder_proj as { dtype: string; shape: number[]; data_offsets: [number, number] };
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        origProj.dtype === protProj.dtype &&
        JSON.stringify(origProj.shape) === JSON.stringify(protProj.shape) &&
        origParsed.tensorData.equals(protParsed.tensorData);
      cases.push(buildCaseResult("safetensors-model", "Proprietary Edge AI Model (.safetensors)", "REA inspect_model_artifact", res, functionalOk));
    }

    // 8. Android Dalvik Bytecode (classes.dex)
    {
      const dexPath = join(tempDir, "classes.dex");
      const outDexPath = join(tempDir, "classes.shielded.dex");
      const appDescriptor = Buffer.from(
        "Lcom/enterprise/vault/LicenseVerifier;\0verifyOfflineSignature\0",
        "utf8",
      );
      const baseDex = Buffer.alloc(112 + appDescriptor.length, 0);
      baseDex.write("dex\n035\0", 0, "ascii");
      baseDex.writeUInt32LE(baseDex.length, 32);
      baseDex.writeUInt32LE(112, 36);
      baseDex.writeUInt32LE(0x12345678, 40);
      appDescriptor.copy(baseDex, 112);
      writeFileSync(dexPath, baseDex);
      const res = protectTarget({ inputPath: dexPath, outputPath: outDexPath, intensity: "bankrupt" });
      const protDex = readFileSync(outDexPath);
      const dexInfo = inspectAndroidDex(protDex);
      const storedSha1 = protDex.subarray(12, 32);
      const computedSha1 = createHash("sha1").update(protDex.subarray(32)).digest();
      const functionalOk =
        dexInfo.validDex &&
        dexInfo.blaProtected &&
        storedSha1.equals(computedSha1) &&
        protDex.subarray(112, 112 + appDescriptor.length).equals(appDescriptor);
      cases.push(buildCaseResult("android-dex", "Android Dalvik Bytecode (classes.dex)", "REA search_android_classes (JADX/JEB)", res, functionalOk));
    }

    // 9. Apple PropertyList (Info.plist)
    {
      const plistPath = join(tempDir, "Info.plist");
      const outPlistPath = join(tempDir, "Info.shielded.plist");
      const origPlist = [
        `<?xml version="1.0" encoding="UTF-8"?>`,
        `<plist version="1.0"><dict>`,
        `  <key>CFBundleIdentifier</key><string>com.bla.desktop</string>`,
        `  <key>CFBundleShortVersionString</key><string>3.2.3</string>`,
        `  <key>CFBundleExecutable</key><string>bla-daemon</string>`,
        `</dict></plist>`,
      ].join("\n");
      writeFileSync(plistPath, origPlist, "utf8");
      const res = protectTarget({ inputPath: plistPath, outputPath: outPlistPath, intensity: "bankrupt" });
      const protPlist = readFileSync(outPlistPath, "utf8");
      const afterAudit = auditTarget(outPlistPath);
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        /<key>CFBundleIdentifier<\/key>\s*<string>com\.bla\.desktop<\/string>/.test(protPlist) &&
        /<key>CFBundleShortVersionString<\/key>\s*<string>3\.2\.3<\/string>/.test(protPlist) &&
        /<key>CFBundleExecutable<\/key>\s*<string>bla-daemon<\/string>/.test(protPlist);
      cases.push(buildCaseResult("apple-plist", "Apple Bundle PropertyList (Info.plist)", "REA inspect_apple_bundle", res, functionalOk));
    }

    // 10. .NET Managed CLR Assembly (.dll)
    {
      const dllPath = join(tempDir, "EnterpriseVault.dll");
      const outDllPath = join(tempDir, "EnterpriseVault.shielded.dll");
      const clrMetadataSym = Buffer.from(
        "EnterpriseVault.Core.LicenseGuard\0VerifyOfflineLease\0",
        "utf8",
      );
      const peClr = Buffer.alloc(160 + clrMetadataSym.length, 0);
      peClr.write("MZ", 0, "ascii");
      peClr.writeUInt32LE(0x40, 0x3c);
      peClr.write("PE\0\0", 0x40, "ascii");
      peClr.write("BSJB", 96, "ascii");
      clrMetadataSym.copy(peClr, 160);
      writeFileSync(dllPath, peClr);
      const res = protectTarget({ inputPath: dllPath, outputPath: outDllPath, intensity: "bankrupt" });
      const protDll = readFileSync(outDllPath);
      const afterAudit = auditTarget(outDllPath);
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        protDll.length > peClr.length &&
        protDll.subarray(0, peClr.length).equals(peClr);
      cases.push(buildCaseResult("dotnet-managed", ".NET Managed CLR Assembly (.dll)", "REA inspect_dotnet_assembly", res, functionalOk));
    }

    // 11. Erlang BEAM OTP module (.beam)
    {
      const beamPath = join(tempDir, "enclave_guard.beam");
      const outBeamPath = join(tempDir, "enclave_guard.shielded.beam");
      const chunk = (name: string, body: Buffer): Buffer => {
        const pad = (4 - (body.length % 4)) % 4;
        const hdr = Buffer.alloc(8);
        hdr.write(name, 0, "latin1");
        hdr.writeUInt32BE(body.length, 4);
        return Buffer.concat([hdr, body, Buffer.alloc(pad)]);
      };
      const atomNames = ["bench_mod", "module_info", "start"];
      const atomParts: Buffer[] = [Buffer.alloc(4)];
      atomParts[0]!.writeUInt32BE(atomNames.length);
      for (const n of atomNames) {
        const enc = Buffer.from(n, "utf8");
        atomParts.push(Buffer.from([enc.length]), enc);
      }
      const codeBody = Buffer.alloc(20);
      codeBody.writeUInt32BE(16, 0);
      codeBody.writeUInt32BE(0, 4);
      codeBody.writeUInt32BE(169, 8);
      codeBody.writeUInt32BE(4, 12);
      codeBody.writeUInt32BE(2, 16);
      const expBody = Buffer.alloc(16);
      expBody.writeUInt32BE(1, 0);
      expBody.writeUInt32BE(2, 4);
      expBody.writeUInt32BE(0, 8);
      expBody.writeUInt32BE(1, 12);
      const codeChunk = chunk("Code", codeBody);
      const expChunk = chunk("ExpT", expBody);
      const form = Buffer.concat([
        Buffer.from("BEAM", "latin1"),
        chunk("AtU8", Buffer.concat(atomParts)),
        codeChunk,
        expChunk,
      ]);
      const seed = Buffer.concat([
        Buffer.from("FOR1", "latin1"),
        (() => {
          const b = Buffer.alloc(4);
          b.writeUInt32BE(form.length);
          return b;
        })(),
        form,
      ]);
      writeFileSync(beamPath, seed);
      const res = protectTarget({ inputPath: beamPath, outputPath: outBeamPath, intensity: "bankrupt" });
      const protBeam = readFileSync(outBeamPath);
      const beamInfo = inspectErlangBeam(protBeam);
      const afterAudit = auditTarget(outBeamPath);
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        beamInfo.validMagic &&
        beamInfo.blaProtected &&
        beamInfo.formSize === protBeam.length - 8 &&
        protBeam.includes(expBody);
      cases.push(buildCaseResult("erlang-beam", "Erlang/OTP BEAM Module (.beam)", "REA inspect_erlang_beam", res, functionalOk));
    }

    // 12. EVM contract bytecode (.evm / .bin)
    {
      const evmPath = join(tempDir, "Vault.evm");
      const outEvmPath = join(tempDir, "Vault.shielded.evm");
      // Realistic Solidity dispatcher runtime bytecode:
      // PUSH1 0x80 PUSH1 0x40 MSTORE CALLDATASIZE ISZERO PUSH1 0x1b JUMPI
      // PUSH1 0x00 CALLDATALOAD PUSH1 0xe0 SHR DUP1 PUSH4 0x67e408a7 EQ PUSH1 0x20 JUMPI
      // JUMPDEST STOP JUMPDEST PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
      const origEvm = Buffer.from(
        "60806040523615601b5760003560e01c806367e408a7146020575b005b602a60005260206000f3",
        "hex",
      );
      writeFileSync(evmPath, origEvm);
      const res = protectTarget({ inputPath: evmPath, outputPath: outEvmPath, intensity: "bankrupt" });
      const protEvm = readFileSync(outEvmPath);
      const evmInfo = inspectEvmBytecode(protEvm);
      const afterAudit = auditTarget(outEvmPath);
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        res.metrics.protectedBytes >= 4_000_000 &&
        evmInfo.hasSolidityMetadata &&
        protEvm.subarray(0, origEvm.length).equals(origEvm);
      cases.push(buildCaseResult("evm-bytecode", "EVM Contract Bytecode (Solidity metadata)", "REA inspect_evm_bytecode / evmole", res, functionalOk));
    }

    // 13. PCAP capture (.pcap)
    {
      const pcapPath = join(tempDir, "enclave-traffic.pcap");
      const outPcapPath = join(tempDir, "enclave-traffic.shielded.pcap");
      const hdr = Buffer.alloc(24);
      hdr.writeUInt32LE(0xa1b2c3d4, 0);
      hdr.writeUInt16LE(2, 4);
      hdr.writeUInt16LE(4, 6);
      hdr.writeUInt32LE(65535, 16);
      hdr.writeUInt32LE(1, 20);
      // Include an initial application Ethernet/IPv4/UDP packet record (46 bytes frame)
      const appFrame = Buffer.alloc(46, 0x41);
      appFrame[12] = 0x08;
      appFrame[13] = 0x00;
      const recHdr = Buffer.alloc(16);
      recHdr.writeUInt32LE(1700000000, 0);
      recHdr.writeUInt32LE(125, 4);
      recHdr.writeUInt32LE(appFrame.length, 8);
      recHdr.writeUInt32LE(appFrame.length, 12);
      const origPcap = Buffer.concat([hdr, recHdr, appFrame]);
      writeFileSync(pcapPath, origPcap);
      const res = protectTarget({ inputPath: pcapPath, outputPath: outPcapPath, intensity: "bankrupt" });
      const protPcap = readFileSync(outPcapPath);
      const pcapInfo = inspectPcapCapture(protPcap);
      const afterAudit = auditTarget(outPcapPath);
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        pcapInfo.validMagic &&
        pcapInfo.packetCount > 1 &&
        protPcap.subarray(0, origPcap.length).equals(origPcap);
      cases.push(buildCaseResult("pcap-capture", "libpcap Network Capture (.pcap)", "REA inspect_pcap_capture (tshark JSON)", res, functionalOk));
    }

    // 14. NVIDIA PTX text module (.ptx)
    {
      const ptxPath = join(tempDir, "enclave_kernel.ptx");
      const outPtxPath = join(tempDir, "enclave_kernel.shielded.ptx");
      const origPtx = [
        `.version 7.5`,
        `.target sm_70`,
        `.address_size 64`,
        ``,
        `.visible .entry real_kernel(.param .u64 real_kernel_param_0)`,
        `{`,
        `  .reg .b64 %rd<3>;`,
        `  .reg .f32 %f<3>;`,
        `  ld.param.u64 %rd1, [real_kernel_param_0];`,
        `  ld.global.f32 %f1, [%rd1];`,
        `  add.f32 %f2, %f1, 0f3F800000;`,
        `  st.global.f32 [%rd1], %f2;`,
        `  ret;`,
        `}`,
        ``,
      ].join("\n");
      writeFileSync(ptxPath, origPtx, "utf8");
      const res = protectTarget({ inputPath: ptxPath, outputPath: outPtxPath, intensity: "bankrupt" });
      const protPtx = readFileSync(outPtxPath, "utf8");
      const ptxInfo = inspectGpuPtx(protPtx);
      const afterAudit = auditTarget(outPtxPath);
      const functionalOk =
        afterAudit.protectionStatus === "BLA_PROTECTED" &&
        ptxInfo.looksLikePtx &&
        ptxInfo.blaProtected &&
        protPtx.startsWith(origPtx);
      cases.push(buildCaseResult("gpu-ptx", "NVIDIA PTX Text Module (.ptx)", "REA inspect_gpu_artifact (PTX)", res, functionalOk));
    }

  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }

  const totalBeforeTokens = cases.reduce((acc, c) => acc + c.before.estimatedTokens, 0);
  const totalAfterTokens = cases.reduce((acc, c) => acc + c.after.estimatedTokens, 0);
  const totalBeforeCost = cases.reduce((acc, c) => acc + c.before.estimatedCostUsd, 0);
  const totalAfterCost = cases.reduce((acc, c) => acc + c.after.estimatedCostUsd, 0);

  return {
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
  functionalCheckPassed: boolean,
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
    functionalCheckPassed,
  };
}
