import { describe, expect, it, vi } from "vitest";
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
    // Decoy event names are now seed-derived (anti static de-blinding): assert
    // the plausible `<namespace>:<channel>:<action>` shape and distinctness
    // instead of a fixed literal a static stripper could key on.
    expect(new Set(registeredEvents).size).toBe(10);
    for (const ev of registeredEvents) {
      expect(ev).toMatch(/^[a-z0-9]+:[a-z0-9-]+:[a-z0-9-]+$/);
    }
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
    expect(afterInfo.trapMode).toBe("stock");
    expect(protectedSqlite.trapMode).toBe("stock");

    // The opt-in function form of the trap columns, as releases up to 3.4.3 wrote them.
    const evalTrapSqlite = protectSqliteBuffer(rawSqlite, {
      intensity: "bankrupt",
      seed: "sqlite-test",
      evalTrap: true,
    });
    expect(evalTrapSqlite.honeyTablesInjected).toBe(5);
    expect(evalTrapSqlite.generatedTrapColumnsAdded).toBe(3);
    expect(evalTrapSqlite.trapMode).toBe("eval");
    const evalTrapInfo = inspectSqliteBuffer(evalTrapSqlite.buffer);
    expect(evalTrapInfo.blaProtected).toBe(true);
    expect(evalTrapInfo.hasGeneratedTrapColumns).toBe(true);
    expect(evalTrapInfo.trapMode).toBe("eval");

    // A bare read-only connection that registers nothing: the shipped application, sqlite3, REA.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-sqlite-verify-"));
    const withBareReadOnlyDb = (
      name: string,
      buffer: Buffer,
      use: (db: InstanceType<typeof DatabaseSync>) => void,
    ): void => {
      const dbFile = path.join(tmpDir, name);
      fs.writeFileSync(dbFile, buffer);
      const db = new DatabaseSync(dbFile, { readOnly: true, allowExtension: false });
      try {
        // The real application table (`license_cache`) is 100% intact in both modes.
        const realRow = db
          .prepare("SELECT account_id, plan_tier, offline_token FROM license_cache")
          .get() as { account_id: string; plan_tier: string; offline_token: string };
        expect(realRow).toEqual({
          account_id: "acct_prod_01",
          plan_tier: "enterprise",
          offline_token: "tok_live_9988776655",
        });
        use(db);
      } finally {
        db.close();
      }
    };
    try {
      // Default: everything BLA added is plain SQL, so the database stays fully usable.
      withBareReadOnlyDb("stock.sqlite", protectedSqlite.buffer, (db) => {
        const honeyRows = db.prepare("SELECT * FROM enclave_key_hierarchy LIMIT 5").all() as Array<{
          sealed_payload: string;
          unsealed_preview: string;
        }>;
        expect(honeyRows.length).toBe(5);
        for (const row of honeyRows) {
          expect(row.unsealed_preview).toBe(`ENCLAVE_SEALED:${row.sealed_payload}`);
        }
        expect(db.prepare("PRAGMA integrity_check").all()).toEqual([{ integrity_check: "ok" }]);
      });

      // evalTrap: the full-row projection on the honey table throws because
      // `enclave_unseal_payload` is not registered on the client's connection.
      withBareReadOnlyDb("eval.sqlite", evalTrapSqlite.buffer, (db) => {
        expect(() => {
          db.prepare("SELECT * FROM enclave_key_hierarchy LIMIT 5").all();
        }).toThrow(/enclave_unseal_payload/);
      });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("adds Safetensors and GGUF canary metadata using each container’s supported structure", () => {
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
    const emptyGguf = Buffer.alloc(24, 0);
    emptyGguf.write("GGUF", 0, "ascii");
    emptyGguf.writeUInt32LE(3, 4);
    const protGguf = protectGgufBuffer(emptyGguf, {
      intensity: "bankrupt",
      seed: "gguf-seed",
    });
    expect(protGguf.triggeredMetadataNestingBreaker).toBe(false);
    expect(protGguf.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protGguf.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protGguf.buffer.toString("latin1")).toContain("enclave.canary.token.0");
    expect(protGguf.buffer.toString("latin1")).toContain("enclave.diagnostic.0");
    expect(protGguf.buffer.toString("latin1")).toContain("AKIAIOSFODNN7EXAMPLE");

    const afterGguf = inspectModelBuffer(protGguf.buffer);
    expect(afterGguf.validModel).toBe(true);
    expect(afterGguf.format).toBe("gguf");
    expect(afterGguf.exceedsReaNestingLimit).toBe(false);
    expect(afterGguf.blaProtected).toBe(true);
  });

  it("protects Android DEX (classes.dex) and Unity IL2CPP (global-metadata.dat) containers", () => {
    const dexInput = Buffer.alloc(112, 0);
    dexInput.write("dex\n035\0", 0, "latin1");
    dexInput.writeUInt32LE(112, 32);
    dexInput.writeUInt32LE(112, 36);
    dexInput.writeUInt32LE(0x12345678, 40);
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
    expect(chunkOut!.map).toBeNull();
    const chunk = { type: "chunk" as const, fileName: "assets/index-abc123.js", ...chunkOut! };
    const emitFile = vi.fn(() => "map");
    vitePlugin.generateBundle.call({ emitFile }, undefined, { [chunk.fileName]: chunk });
    expect(emitFile).toHaveBeenCalledWith(expect.objectContaining({
      fileName: "assets/index-abc123.js.map",
      source: expect.stringContaining("enclave://tee-runtime/"),
    }));

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
