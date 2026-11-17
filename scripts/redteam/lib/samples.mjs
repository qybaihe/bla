import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { join } from "node:path";
import { BLA_ROOT } from "./paths.mjs";

const require = createRequire(import.meta.url);

/** Load BLA compiled modules (dist/). */
export async function loadBla() {
  const base = join(BLA_ROOT, "dist/shields/formats");
  return {
    buildMappedGoFlutterElfFixture: (
      await import(join(base, "go-flutter-exhaustion.js"))
    ).buildMappedGoFlutterElfFixture,
    protectNativeBinary: (await import(join(base, "native.js")))
      .protectNativeBinary,
    resolveElf64SectionNames: (await import(join(base, "native.js")))
      .resolveElf64SectionNames,
    validateElf64Layout: (await import(join(base, "native.js")))
      .validateElf64Layout,
    protectErlangBeamBuffer: (await import(join(base, "erlang-beam.js")))
      .protectErlangBeamBuffer,
    protectEvmBytecodeBuffer: (await import(join(base, "evm-bytecode.js")))
      .protectEvmBytecodeBuffer,
    protectPcapCaptureBuffer: (await import(join(base, "pcap-capture.js")))
      .protectPcapCaptureBuffer,
    protectGpuPtxText: (await import(join(base, "gpu-ptx.js"))).protectGpuPtxText,
    buildSafetensorsBuffer: (await import(join(base, "model.js")))
      .buildSafetensorsBuffer,
    protectSafetensorsBuffer: (await import(join(base, "model.js")))
      .protectSafetensorsBuffer,
    protectGgufBuffer: (await import(join(base, "model.js"))).protectGgufBuffer,
    packAsarBuffer: (await import(join(base, "asar.js"))).packAsarBuffer,
    unpackAsarBuffer: (await import(join(base, "asar.js"))).unpackAsarBuffer,
    protectWasmBinary: (await import(join(base, "wasm.js"))).protectWasmBinary,
    inspectWasmBinary: (await import(join(base, "wasm.js"))).inspectWasmBinary,
    protectSqliteBuffer: (await import(join(base, "sqlite.js"))).protectSqliteBuffer,
    buildSampleSqliteDatabase: (await import(join(base, "sqlite.js")))
      .buildSampleSqliteDatabase,
    inspectSqliteBuffer: (await import(join(base, "sqlite.js"))).inspectSqliteBuffer,
    inspectElectronFusesBuffer: (
      await import(join(base, "electron-fuses.js"))
    ).inspectElectronFusesBuffer,
    planAsarHeaderAmplification: (
      await import(join(BLA_ROOT, "dist/shields/exhaustion/asar-header-amplifier.js"))
    ).planAsarHeaderAmplification,
    planWasmInterfaceBudgetExhaustion: (
      await import(
        join(BLA_ROOT, "dist/shields/exhaustion/wasm-interface-exhaustion.js")
      )
    ).planWasmInterfaceBudgetExhaustion,
    SeededPrng: (await import(join(BLA_ROOT, "dist/core/prng.js"))).SeededPrng,
    REA_INTERNAL_LIMITS: (await import(join(BLA_ROOT, "dist/identity.js")))
      .REA_INTERNAL_LIMITS,
    BLA_VERSION: require(join(BLA_ROOT, "package.json")).version,
    transformJavaScriptWithBlaShield: (
      await import(join(BLA_ROOT, "dist/shields/javascript/ast-shield.js"))
    ).transformJavaScriptWithBlaShield,
  };
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

function beamChunk(name, payload) {
  const pad = (4 - (payload.length % 4)) % 4;
  return Buffer.concat([
    Buffer.from(name, "latin1"),
    u32be(payload.length),
    payload,
    Buffer.alloc(pad),
  ]);
}

/** Minimal valid BEAM with non-compact AtU8. */
export function buildMinimalBeam() {
  const atoms = Buffer.concat([
    u32be(3),
    Buffer.from([4]),
    Buffer.from("main"),
    Buffer.from([6]),
    Buffer.from("module"),
    Buffer.from([4]),
    Buffer.from("init"),
  ]);
  const code = Buffer.alloc(20);
  code.writeUInt32BE(16, 0);
  const body = Buffer.concat([
    beamChunk("AtU8", atoms),
    beamChunk("Code", code),
    beamChunk("StrT", Buffer.from("x")),
  ]);
  return Buffer.concat([
    Buffer.from("FOR1"),
    u32be(4 + body.length),
    Buffer.from("BEAM"),
    body,
  ]);
}

/** Minimal EVM runtime bytecode (no metadata). */
export function buildMinimalEvm() {
  return Buffer.from("6080604052348015600f575f80fd5b50", "hex");
}

/** Minimal classic libpcap (empty global header only → protect appends decoys). */
export function buildEmptyPcap() {
  return Buffer.alloc(0);
}

/** Minimal classic libpcap global header (LE magic). */
export function buildMinimalPcap() {
  const h = Buffer.alloc(24, 0);
  h.writeUInt32LE(0xa1b2c3d4, 0);
  h.writeUInt16LE(2, 4);
  h.writeUInt16LE(4, 6);
  h.writeUInt32LE(65535, 16);
  h.writeUInt32LE(1, 20); // LINKTYPE_ETHERNET
  return h;
}

export function buildMinimalPtx() {
  return Buffer.from(
    `.version 7.0
.target sm_70
.address_size 64
.visible .entry demo(.param .u64 out) { ret; }
`,
    "utf8",
  );
}

export function buildMinimalSafetensors(bla) {
  return bla.buildSafetensorsBuffer(
    {
      weight: { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] },
      __metadata__: { model: "redteam-demo" },
    },
    Buffer.alloc(16),
  );
}

/** Tiny GGUF v3 with one string KV — protect injects nesting breaker. */
export function buildMinimalGguf() {
  // Magic GGUF, version 3, tensor_count=0, kv_count=0
  const b = Buffer.alloc(24, 0);
  b.write("GGUF", 0);
  b.writeUInt32LE(3, 4);
  b.writeBigUInt64LE(0n, 8);
  b.writeBigUInt64LE(0n, 16);
  return b;
}


/** Minimal Electron ASAR with package.json + main.js. */
export function buildMinimalAsar(bla) {
  return bla.packAsarBuffer([
    {
      relativePath: "package.json",
      content: Buffer.from(
        JSON.stringify({ name: "redteam-asar", main: "main.js" }),
        "utf8",
      ),
    },
    {
      relativePath: "main.js",
      content: Buffer.from(
        "exports.ping = function ping() { return 42; };\n",
        "utf8",
      ),
    },
  ]);
}

/** Minimal valid WASM exporting computeDigest(i32,i32)->i32. */
export function buildMinimalWasm() {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x11, 0x01, 0x0d,
    0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74,
    0x00, 0x00,
    0x0a, 0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0x73, 0x41, 0x2a, 0x6a, 0x0b,
  ]);
}

/**
 * Build the red-team sample matrix: one entry per empirically runnable format.
 */
export async function buildSampleMatrix() {
  const bla = await loadBla();
  const intensity = "bankrupt";
  const seed = "bla-redteam-empirical-v1";

  const elfRaw = bla.buildMappedGoFlutterElfFixture();
  const elfHard = bla.protectNativeBinary(elfRaw, { intensity, seed });

  const beamRaw = buildMinimalBeam();
  const beamHard = bla.protectErlangBeamBuffer(beamRaw, { intensity, seed });

  const evmRaw = buildMinimalEvm();
  const evmHard = bla.protectEvmBytecodeBuffer(evmRaw, { intensity, seed });

  const pcapRaw = buildMinimalPcap();
  const pcapHard = bla.protectPcapCaptureBuffer(pcapRaw, {
    intensity,
    seed,
  });

  const ptxRaw = buildMinimalPtx();
  const ptxHard = bla.protectGpuPtxText(ptxRaw.toString('utf8'), { intensity, seed });

  const stRaw = buildMinimalSafetensors(bla);
  const stHard = bla.protectSafetensorsBuffer(stRaw, { intensity, seed });

  let ggufRaw = buildMinimalGguf();
  let ggufHard;
  try {
    ggufHard = bla.protectGgufBuffer(ggufRaw, { intensity, seed });
  } catch (err) {
    ggufHard = { buffer: ggufRaw, error: String(err?.message ?? err) };
  }

  // Electron ASAR — densify header past DEFAULT_ASAR_MAX_HEADER_BYTES (16 MiB).
  const asarRaw = buildMinimalAsar(bla);
  const asarFiles = [...bla.unpackAsarBuffer(asarRaw)];
  const asarPlan = bla.planAsarHeaderAmplification(
    new bla.SeededPrng(`${seed}:asar`),
    intensity,
  );
  for (const decoy of asarPlan.files) asarFiles.push(decoy);
  const asarHard = {
    buffer: bla.packAsarBuffer(asarFiles),
    decoyFiles: asarPlan.files.length,
    estimatedHeaderBytes: asarPlan.estimatedHeaderBytes,
    exceedsDefaultAdmission: asarPlan.exceedsDefaultAdmission,
  };

  // WASM — bankrupt interface exhaustion past 32 MiB representation budget.
  const wasmRaw = buildMinimalWasm();
  const wasmHard = bla.protectWasmBinary(wasmRaw, { intensity, seed });

  // SQLite — honey tables + canaries (REA inspect is Node 24.15+ gated).
  let sqliteRaw = Buffer.alloc(0);
  let sqliteHard = {
    buffer: Buffer.alloc(0),
    error: null,
    honeyTablesInjected: 0,
    canaryTokensEmbedded: 0,
  };
  try {
    sqliteRaw = bla.buildSampleSqliteDatabase();
    // The probe below validates the evaluation trap, which is opt-in.
    sqliteHard = bla.protectSqliteBuffer(sqliteRaw, { intensity, seed, evalTrap: true });
  } catch (err) {
    sqliteHard = {
      buffer: sqliteRaw,
      error: String(err?.message ?? err),
      honeyTablesInjected: 0,
      canaryTokensEmbedded: 0,
    };
  }


  // JavaScript — real REA semantic resource limits (authoritative for JS claims)
  const jsRawText = `/**
 * pricing engine — tiered discount + margin gate
 */
const BASE_RATE = 0.085;
const VAT_RATE = 0.13;
const BANKRUPT_THRESHOLD = 1e-6;
function balanced(qty, listPrice) {
  let discount = 1;
  if (qty >= 500) discount = 0.8;
  else if (qty >= 100) discount = 0.9;
  const unit = listPrice * discount * (1 + VAT_RATE);
  return Math.round(unit * 100) / 100;
}
function bankrupt(margin, notional) {
  const ratio = margin / Math.max(notional, BANKRUPT_THRESHOLD);
  return ratio < BASE_RATE;
}
function quote(qty, listPrice, margin) {
  if (bankrupt(margin, qty * listPrice)) return { ok: false, reason: "margin" };
  return { ok: true, unit: balanced(qty, listPrice), vat: VAT_RATE };
}
module.exports = { balanced, bankrupt, quote, BASE_RATE, VAT_RATE };
`;
  const jsRaw = Buffer.from(jsRawText, "utf8");
  const jsHard = bla.transformJavaScriptWithBlaShield(jsRawText, {
    intensity,
    seed: `${seed}:js`,
    sourceType: "commonjs",
  });

  // JavaScript strings — three known values, to see what REA recovers of them
  // at its default budgets and with every semantic_precision budget raised.
  const jsStringValues = {
    endpoint: "https://licensing.acme-internal.example/v2/activate",
    channel: "license:activate",
    digest: createHash("sha256").update("bla-redteam-js-strings").digest("hex"),
  };
  const jsStringsRawText = `const API = ${JSON.stringify(jsStringValues.endpoint)};
const CHANNEL = ${JSON.stringify(jsStringValues.channel)};
const EXPECTED = ${JSON.stringify(jsStringValues.digest)};
function check(h) { return h === EXPECTED; }
function activate(send) { return send(CHANNEL, API); }
module.exports = { API, CHANNEL, check, activate };
`;
  const jsStringsHard = bla.transformJavaScriptWithBlaShield(jsStringsRawText, {
    intensity,
    seed: `${seed}:js-strings`,
    sourceType: "commonjs",
  });

  return {
    bla,
    intensity,
    seed,
    samples: {
      javascript_strings: {
        format: "javascript_strings",
        before: Buffer.from(jsStringsRawText, "utf8"),
        after: Buffer.from(jsStringsHard.code, "utf8"),
        meta: { values: jsStringValues },
      },
      go_flutter_elf: {
        format: "go_flutter_elf",
        before: elfRaw,
        after: elfHard.buffer,
        meta: {
          mappedGo: elfHard.mappedGoBuildInfoPlanted,
          mappedFlutter: elfHard.mappedFlutterPoolPlanted,
          goTripsMax: elfHard.goBuildInfoExceedsLimit,
        },
      },
      erlang_beam: {
        format: "erlang_beam",
        before: beamRaw,
        after: beamHard.buffer,
        meta: {
          atomsInjected: beamHard.atomsInjected,
          chunksInjected: beamHard.chunksInjected,
          exceedsDefaultChunkBudget: beamHard.exceedsDefaultChunkBudget,
        },
      },
      evm_bytecode: {
        format: "evm_bytecode",
        before: evmRaw,
        after: evmHard.buffer,
        meta: {
          approachesInputBudget: evmHard.approachesInputBudget,
          afterBytes: evmHard.buffer.length,
        },
      },
      pcap_capture: {
        format: "pcap_capture",
        before: pcapRaw,
        after: pcapHard.buffer,
        meta: {
          estimatedTsharkJsonBytes: pcapHard.estimatedTsharkJsonBytes,
          exceedsTsharkJsonBudget: pcapHard.exceedsTsharkJsonBudget,
          packetsInjected: pcapHard.packetsInjected,
        },
      },
      gpu_ptx: {
        format: "gpu_ptx",
        before: ptxRaw,
        after: Buffer.from(ptxHard.text, "utf8"),
        meta: { entriesInjected: ptxHard.entriesInjected },
      },
      safetensors: {
        format: "safetensors",
        before: stRaw,
        after: stHard.buffer,
        meta: {
          triggeredJsonNestingBreaker: stHard.triggeredJsonNestingBreaker,
          canaryTokensEmbedded: stHard.canaryTokensEmbedded,
        },
      },
      gguf: {
        format: "gguf",
        before: ggufRaw,
        after: ggufHard.buffer,
        meta: {
          error: ggufHard.error,
          triggeredMetadataNestingBreaker:
            ggufHard.triggeredMetadataNestingBreaker === true,
        },
      },
      electron_asar: {
        format: "electron_asar",
        before: asarRaw,
        after: asarHard.buffer,
        meta: {
          decoyFiles: asarHard.decoyFiles,
          estimatedHeaderBytes: asarHard.estimatedHeaderBytes,
          exceedsDefaultAdmission: asarHard.exceedsDefaultAdmission,
        },
      },
      wasm_module: {
        format: "wasm_module",
        before: wasmRaw,
        after: wasmHard.buffer,
        meta: {
          customSectionsAdded: wasmHard.customSectionsAdded,
          interfaceDescriptorsEmbedded: wasmHard.interfaceDescriptorsEmbedded,
          projectedInterfaceChargeBytes: wasmHard.projectedInterfaceChargeBytes,
          exceedsRepresentationBudget: wasmHard.exceedsRepresentationBudget,
          exportDecoysInjected: wasmHard.exportDecoysInjected,
        },
      },
      sqlite_db: {
        format: "sqlite_db",
        before: sqliteRaw,
        after: sqliteHard.buffer,
        meta: {
          error: sqliteHard.error,
          honeyTablesInjected: sqliteHard.honeyTablesInjected,
          canaryTokensEmbedded: sqliteHard.canaryTokensEmbedded,
        },
      },
      electron_fuses: {
        // Same hardened ELF carries decoy Electron fuse sentinels (34 > 32).
        format: "electron_fuses",
        before: elfRaw,
        after: elfHard.buffer,
        meta: {
          electronFuseSentinelsInjected: elfHard.electronFuseSentinelsInjected,
        },
      },
      javascript: {
        format: "javascript",
        before: jsRaw,
        after: Buffer.from(jsHard.code, "utf8"),
        meta: {
          decoyFunctionsInjected: jsHard.decoyFunctionsInjected,
          aliasSelectionStatesCreated: jsHard.aliasSelectionStatesCreated,
          primitiveCandidateBranchesCreated: jsHard.primitiveCandidateBranchesCreated,
        },
      },
    },
  };
}
