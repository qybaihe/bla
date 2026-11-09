import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vm from "node:vm";
import { getDatabaseSyncClass, isNodeSqliteAvailable } from "../src/core/sqlite-runtime.js";
import { SeededPrng } from "../src/core/prng.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import { generateRuntimeDeceptionSnippet } from "../src/shields/runtime/runtime-shield.js";
import {
  ELECTRON_FUSE_SENTINEL_BYTES,
  ELECTRON_FUSE_STATE,
  hardenAndOverflowElectronFuses,
  inspectElectronFusesInBuffer,
} from "../src/shields/formats/electron-fuses.js";
import {
  buildSampleSqliteDatabase,
  inspectSqliteBuffer,
  protectSqliteBuffer,
} from "../src/shields/formats/sqlite.js";
import {
  buildSafetensorsBuffer,
  inspectModelBuffer,
  protectGgufBuffer,
  protectSafetensorsBuffer,
} from "../src/shields/formats/model.js";
import {
  inspectAndroidDex,
  protectAndroidDexBuffer,
  protectIl2cppMetadataBuffer,
} from "../src/shields/formats/mobile-game.js";
import { blaVitePlugin, BlaWebpackPlugin } from "../src/bundler/index.js";

describe("Deep Vertical Shields (Runtime Deception, Electron Fuses, SQLite, AI Models, DEX/IL2CPP, Bundlers)", () => {
  it("executes the Anti-CDP / Anti-Frida 'Truman Show' runtime deception shield without side effects", () => {
    const prng = new SeededPrng("runtime-test");
    const chaff = generateChaffPayloads(prng, "bankrupt");
    const snippet = generateRuntimeDeceptionSnippet(prng, "bankrupt", chaff);

    expect(snippet.shadowListenersCount).toBe(10);
    const registeredEvents: string[] = [];
    const fakeGlobal: Record<string, unknown> = {
      navigator: { webdriver: true },
      addEventListener: (evName: string) => {
        registeredEvents.push(evName);
      },
    };
    fakeGlobal.globalThis = fakeGlobal;

    const ctx = vm.createContext(fakeGlobal);
    vm.runInContext(snippet.code, ctx, { timeout: 2000 });

    expect(registeredEvents.length).toBe(10);
    expect(registeredEvents).toContain("enclave:vsock:attestation-ready");
  });

  it("hardens vulnerable Electron Fuse V1 wires in-place and overflows REA's 32-sentinel capacity limit", () => {
    // Build a synthetic binary containing 1 vulnerable Electron Fuse V1 wire
    // where RunAsNode [0] = '1' (enabled) and EnableNodeCliInspectArguments [3] = '1' (enabled)
    const vulnerableWire = Buffer.concat([
      Buffer.alloc(64, 0),
      ELECTRON_FUSE_SENTINEL_BYTES,
      Buffer.from([
        0x01, // version 1
        0x06, // 6 fuses
        ELECTRON_FUSE_STATE.ENABLED, // [0] RunAsNode = ENABLED (vulnerable!)
        ELECTRON_FUSE_STATE.DISABLED, // [1] EnableCookieEncryption = DISABLED
        ELECTRON_FUSE_STATE.ENABLED, // [2] EnableNodeOptionsEnvironmentVariable = ENABLED
        ELECTRON_FUSE_STATE.ENABLED, // [3] EnableNodeCliInspectArguments = ENABLED (vulnerable!)
        ELECTRON_FUSE_STATE.DISABLED, // [4] EnableEmbeddedAsarIntegrityValidation = DISABLED
        ELECTRON_FUSE_STATE.DISABLED, // [5] OnlyLoadAppFromAsar = DISABLED
      ]),
      Buffer.alloc(64, 0),
    ]);

    const before = inspectElectronFusesInBuffer(vulnerableWire);
    expect(before.sentinelCount).toBe(1);
    expect(before.runAsNodeEnabled).toBe(true);
    expect(before.nodeCliInspectEnabled).toBe(true);
    expect(before.exceedsReaSentinelLimit).toBe(false);

    const prng = new SeededPrng("fuse-test");
    const res = hardenAndOverflowElectronFuses(vulnerableWire, prng);
    expect(res.patchedInPlaceCount).toBe(1);
    expect(res.decoySentinelsInjected).toBe(34);

    const combined = Buffer.concat([vulnerableWire, res.decoySentinelsBuffer]);
    const after = inspectElectronFusesInBuffer(combined);
    expect(after.sentinelCount).toBe(35);
    expect(after.exceedsReaSentinelLimit).toBe(true);
    expect(after.runAsNodeEnabled).toBe(false);
    expect(after.nodeCliInspectEnabled).toBe(false);
    expect(after.asarIntegrityEnforced).toBe(true);
    expect(after.onlyLoadFromAsarEnforced).toBe(true);
  });

  it.skipIf(!isNodeSqliteAvailable())("protects SQLite 3 databases with Honey Tables and Generated Column Traps while keeping original tables readable", () => {
    const DatabaseSync = getDatabaseSyncClass();
    const rawSqlite = buildSampleSqliteDatabase();
    const beforeInfo = inspectSqliteBuffer(rawSqlite);
    expect(beforeInfo.validSqlite).toBe(true);
    expect(beforeInfo.tableNames).toContain("license_cache");
    expect(beforeInfo.blaProtected).toBe(false);

    const protectedSqlite = protectSqliteBuffer(rawSqlite, {
      intensity: "bankrupt",
      seed: "sqlite-test",
    });
    expect(protectedSqlite.honeyTablesInjected).toBe(5);
    expect(protectedSqlite.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedSqlite.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedSqlite.generatedTrapColumnsAdded).toBe(3);
    expect(protectedSqlite.buffer.toString("utf8")).toContain("canary_transport_redaction");
    expect(protectedSqlite.buffer.toString("utf8")).toContain("system_diagnostic_log");
    expect(protectedSqlite.buffer.toString("utf8")).toContain("AKIAIOSFODNN7EXAMPLE");
    expect(protectedSqlite.buffer.toString("utf8")).toContain("DarwinProcessOwnershipInspectionError");

    const afterInfo = inspectSqliteBuffer(protectedSqlite.buffer);
    expect(afterInfo.validSqlite).toBe(true);
    expect(afterInfo.blaProtected).toBe(true);
    expect(afterInfo.hasGeneratedTrapColumns).toBe(true);

    // Verify real application table (`license_cache`) is 100% intact AND
    // REA's bare read-only `SELECT * FROM enclave_key_hierarchy` fails on the virtual generated column!
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-sqlite-verify-"));
    const dbFile = path.join(tmpDir, "verify.sqlite");
    try {
      fs.writeFileSync(dbFile, protectedSqlite.buffer);
      const reaReadOnlyDb = new DatabaseSync(dbFile, {
        readOnly: true,
        allowExtension: false,
      });
      try {
        const realRow = reaReadOnlyDb
          .prepare("SELECT account_id, plan_tier, offline_token FROM license_cache")
          .get() as { account_id: string; plan_tier: string; offline_token: string };
        expect(realRow).toEqual({
          account_id: "acct_prod_01",
          plan_tier: "enterprise",
          offline_token: "tok_live_9988776655",
        });

        // REA's full-row projection on the honey table must throw because `enclave_unseal_payload` is not registered on REA's connection
        expect(() => {
          reaReadOnlyDb.prepare("SELECT * FROM enclave_key_hierarchy LIMIT 5").all();
        }).toThrow();
      } finally {
        reaReadOnlyDb.close();
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("adds Safetensors canary metadata and a valid JSON nesting breaker", () => {
    const rawSafetensors = buildSafetensorsBuffer({
      attn_weights: { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] },
    });

    const beforeSt = inspectModelBuffer(rawSafetensors);
    expect(beforeSt.validModel).toBe(true);
    expect(beforeSt.format).toBe("safetensors");
    expect(beforeSt.blaProtected).toBe(false);

    const protSt = protectSafetensorsBuffer(rawSafetensors, {
      intensity: "bankrupt",
      seed: "safetensors-seed",
    });
    expect(protSt.triggeredJsonNestingBreaker).toBe(true);
    expect(protSt.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protSt.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protSt.buffer.toString("utf8")).toContain("enclave.canary.token.0");
    expect(protSt.buffer.toString("utf8")).toContain("enclave.diagnostic.0");
    expect(protSt.buffer.toString("utf8")).toContain("AKIAIOSFODNN7EXAMPLE");
    expect(protSt.buffer.toString("utf8")).toContain("enclave_topology_seal");

    const afterSt = inspectModelBuffer(protSt.buffer);
    expect(afterSt.validModel).toBe(true);
    expect(afterSt.exceedsReaNestingLimit).toBe(true);
    expect(afterSt.blaProtected).toBe(true);

    // GGUF v3 model shield
    const protGguf = protectGgufBuffer(Buffer.alloc(0), {
      intensity: "bankrupt",
      seed: "gguf-seed",
    });
    expect(protGguf.triggeredMetadataNestingBreaker).toBe(true);
    expect(protGguf.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protGguf.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protGguf.buffer.toString("latin1")).toContain("enclave.canary.token.0");
    expect(protGguf.buffer.toString("latin1")).toContain("enclave.diagnostic.0");
    expect(protGguf.buffer.toString("latin1")).toContain("AKIAIOSFODNN7EXAMPLE");

    const afterGguf = inspectModelBuffer(protGguf.buffer);
    expect(afterGguf.validModel).toBe(true);
    expect(afterGguf.format).toBe("gguf");
    expect(afterGguf.exceedsReaNestingLimit).toBe(true);
    expect(afterGguf.blaProtected).toBe(true);
  });

  it("protects Android DEX (classes.dex) and Unity IL2CPP (global-metadata.dat) containers", () => {
    const dexInput = Buffer.alloc(112, 0);
    dexInput.write("dex\n035\0", 0, "latin1");
    dexInput.writeUInt32LE(112, 36);
    const resDex = protectAndroidDexBuffer(dexInput, {
      intensity: "balanced",
      seed: "dex-seed",
    });
    expect(resDex.decoyClassesInjected).toBeGreaterThanOrEqual(28);

    const dexInfo = inspectAndroidDex(resDex.buffer);
    expect(dexInfo.validDex).toBe(true);
    expect(dexInfo.fileSize).toBe(resDex.buffer.length);
    expect(dexInfo.blaProtected).toBe(true);

    const il2cppInput = Buffer.alloc(256, 0);
    il2cppInput.writeUInt32LE(0xfab11baf, 0);
    const resIl2cpp = protectIl2cppMetadataBuffer(il2cppInput, {
      intensity: "balanced",
      seed: "il2cpp-seed",
    });
    expect(resIl2cpp.decoyLiteralsInjected).toBe(128);
    expect(resIl2cpp.buffer.readUInt32LE(0)).toBe(0xfab11baf);
  });

  it("integrates seamlessly with Vite / Rollup and Webpack bundler plugins", () => {
    const vitePlugin = blaVitePlugin({ intensity: "balanced", seed: "vite-seed" });
    expect(vitePlugin.name).toBe("vite-plugin-bla-shield");
    expect(vitePlugin.enforce).toBe("post");

    const chunkOut = vitePlugin.renderChunk(
      `export function verifyToken(t) { return t === "secret-vite-bundle-key"; }`,
      { fileName: "assets/index-abc123.js" },
    );
    expect(chunkOut).not.toBeNull();
    expect(chunkOut!.code).not.toMatch(/_bla|\$00_AAA|__bla/);
    expect(chunkOut!.map).toBeDefined();
    expect(chunkOut!.map!.sourceRoot).toBe("enclave://tee-runtime/");

    // Test Webpack plugin asset update hook
    const assets: Record<string, { source: () => string; size: () => number }> = {
      "main.bundle.js": {
        source: () => `function calc(x) { return x + 1; }`,
        size: () => 33,
      },
    };
    const wp = new BlaWebpackPlugin({ intensity: "stealth", seed: "wp-seed" });
    wp.apply({
      hooks: {
        compilation: {
          tap: (_name, cb) => {
            cb({
              hooks: {
                processAssets: {
                  tap: (_opts, fn) => fn(assets),
                },
              },
              updateAsset: (name, newSource) => {
                assets[name] = newSource;
              },
            });
          },
        },
      },
    });
    expect(assets["main.bundle.js"]!.source()).not.toMatch(/_bla|\$00_AAA|__bla/);
  });
});
