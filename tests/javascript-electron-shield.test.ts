import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vm from "node:vm";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { generateHoneySourceMap } from "../src/shields/formats/sourcemap.js";
import { packAsarBuffer, unpackAsarBuffer } from "../src/shields/formats/asar.js";
import { SeededPrng } from "../src/core/prng.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import { auditTarget } from "../src/engine/auditor.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";

describe("JavaScript, TypeScript & Electron AST Shield", () => {
  it("preserves exact runtime outputs on DX-Ball sound-pan logic while inflating call graph and exhausting REA budgets", () => {
    const dxBallPath = path.resolve(process.cwd(), "examples/dx-ball-sound-pan/sound-pan.js");
    const originalCode = fs.readFileSync(dxBallPath, "utf8");

    const result = transformJavaScriptWithBlaShield(originalCode, {
      intensity: "bankrupt",
      seed: "dx-ball-test",
    });

    expect(result.decoyFunctionsInjected).toBeGreaterThanOrEqual(36);
    expect(result.fakeCrossReferencesCreated).toBeGreaterThanOrEqual(80);
    expect(result.primitiveCandidateBranchesCreated).toBeGreaterThanOrEqual(512);
    expect(result.aliasSelectionStatesCreated).toBeGreaterThanOrEqual(4_194_304);

    // Execute both original and protected modules in isolated VMs and compare outputs across multiple inputs
    const runModule = (code: string) => {
      const mod = { exports: {} as Record<string, (...args: number[]) => unknown> };
      const ctx = vm.createContext({
        module: mod,
        exports: mod.exports,
        fetch: () => Promise.resolve({}),
        Math,
        Object,
        Array,
        String,
        Number,
        Boolean,
        Map,
        Set,
      });
      vm.runInContext(code, ctx, { timeout: 3000 });
      return mod.exports;
    };

    const origExports = runModule(originalCode);
    const protExports = runModule(result.code);

    for (const [paddleX, ballX] of [
      [0, 0],
      [160, 80],
      [320, 320],
      [480, 600],
      [640, 120],
    ]) {
      expect(protExports.calculateSoundPan(paddleX!, ballX!, 640)).toEqual(
        origExports.calculateSoundPan(paddleX!, ballX!, 640),
      );
    }
    expect(protExports.clampPan(-25000)).toEqual(origExports.clampPan(-25000));
    expect(protExports.clampPan(25000)).toEqual(origExports.clampPan(25000));
  });

  it("neutralizes Electron literal IPC channel pairing while keeping runtime IPC channels intact", () => {
    const bridgePath = path.resolve(process.cwd(), "examples/notion-electron-bridge/electron-bridge.js");
    const originalCode = fs.readFileSync(bridgePath, "utf8");

    const protectedRes = transformJavaScriptWithBlaShield(originalCode, {
      intensity: "bankrupt",
      seed: "electron-bridge-test",
    });

    expect(protectedRes.ipcAmbiguitySitesInjected).toBeGreaterThanOrEqual(12);
    expect(protectedRes.primitiveCandidateBranchesCreated).toBeGreaterThanOrEqual(2048);

    // Execute protected Electron bridge with a mock Electron runtime and verify real handlers work
    const registeredHandlers = new Map<string, (...args: unknown[]) => unknown>();
    const exposedBridges = new Map<string, Record<string, (...args: unknown[]) => unknown>>();

    const mod = { exports: {} as Record<string, (...args: unknown[]) => unknown> };
    const ctx = vm.createContext({
      module: mod,
      exports: mod.exports,
      require: (id: string) => {
        if (id === "electron") {
          return {
            contextBridge: {
              exposeInMainWorld: (name: string, api: Record<string, (...args: unknown[]) => unknown>) => {
                exposedBridges.set(name, api);
              },
            },
            ipcRenderer: {
              invoke: (channel: string, payload?: unknown) => {
                const fn = registeredHandlers.get(channel);
                return fn ? fn({}, payload) : null;
              },
              send: () => undefined,
            },
            ipcMain: {
              handle: (channel: string, fn: (...args: unknown[]) => unknown) => {
                registeredHandlers.set(channel, fn);
              },
              on: () => undefined,
            },
          };
        }
        return {};
      },
      fetch: () => Promise.resolve({}),
      Math,
      Object,
      Array,
      String,
      Number,
      Boolean,
      Map,
      Set,
    });
    vm.runInContext(protectedRes.code, ctx, { timeout: 3000 });

    const backingStore = new Map<string, unknown>();
    mod.exports.setupPreloadClipboardBridge();
    mod.exports.setupMainClipboardHandlers(backingStore);

    expect(exposedBridges.has("notionClipboard")).toBe(true);
    const api = exposedBridges.get("notionClipboard")!;
    expect( registeredHandlers.has("notion:clipboard:read-rich")).toBe(true);
    expect(registeredHandlers.has("notion:clipboard:write-rich")).toBe(true);

    const writePromise = api.writeRichBlocks([{ id: "blk-1" }]) as Promise<{ saved: boolean; count: number }>;
    return writePromise.then((res) => {
      expect(res).toEqual({ saved: true, count: 1 });
    });
  });

  it("packs, unpacks, and protects Electron .asar archives with valid SHA-256 block integrity", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-asar-test-"));
    try {
      const rawAsar = packAsarBuffer([
        {
          relativePath: "package.json",
          content: Buffer.from(JSON.stringify({ name: "demo-electron", main: "main.js" }), "utf8"),
        },
        {
          relativePath: "main.js",
          content: Buffer.from(
            `const { ipcMain } = require("electron");\nipcMain.handle("secret:channel", () => "ok");\n`,
            "utf8",
          ),
        },
      ]);

      const unpackedBefore = unpackAsarBuffer(rawAsar);
      expect(unpackedBefore.length).toBe(2);

      const asarFile = path.join(tmpDir, "app.asar");
      const outAsarFile = path.join(tmpDir, "app.bla.asar");
      fs.writeFileSync(asarFile, rawAsar);

      const auditBefore = auditTarget(asarFile);
      expect(auditBefore.detectedFormat).toBe("electron-asar");

      const protResult = protectTarget({
        inputPath: asarFile,
        outputPath: outAsarFile,
        intensity: "balanced",
        seed: "asar-e2e",
      });
      expect(fs.existsSync(protResult.outputPath)).toBe(true);

      const unpackedAfter = unpackAsarBuffer(fs.readFileSync(outAsarFile));
      expect(unpackedAfter.length).toBeGreaterThan(unpackedBefore.length);

      const verification = verifyTarget(outAsarFile, asarFile);
      expect(verification.overallPassed).toBe(false);
      expect(verification.heuristicChecksPassed).toBe(true);
      expect(verification.functionalIntegrityVerified).toBe(false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("generates valid VLQ v3 Honey Source Maps that misdirect REA source reconstruction", () => {
    const prng = new SeededPrng("sourcemap-seed");
    const chaff = generateChaffPayloads(prng, "balanced");
    const generated = generateHoneySourceMap("bundle.bla.js", 60, prng, chaff);

    expect(generated.mapObject.version).toBe(3);
    expect(generated.mapObject.sourceRoot).toBe("enclave://tee-runtime/");
    expect(generated.mapObject.sources.length).toBe(3);
    expect(generated.mapObject.sources[0]).toContain("src/enclave/");
    expect(generated.mapObject.sourcesContent.length).toBe(3);
    expect(generated.mapObject.mappings).toContain(";");
    expect(generated.inlineDirective).toContain("sourceMappingURL=data:application/json");
  });
});
