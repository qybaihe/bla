import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  planDotnetManagedBudgetExhaustion,
  protectDotnetManagedBuffer,
} from "../src/shields/formats/dotnet-managed.js";
import {
  buildFlutterPoolExhaustionPayload,
  buildGoBuildInfoExhaustionPayload,
  buildMappedFlutterIsolatePoolPlant,
  buildMappedGoBuildInfoPlant,
  buildMappedGoFlutterElfFixture,
} from "../src/shields/formats/go-flutter-exhaustion.js";
import {
  inspectAndroidDex,
  protectAndroidDexBuffer,
  protectIl2cppMetadataBuffer,
} from "../src/shields/formats/mobile-game.js";
import {
  buildSafetensorsBuffer,
  inspectModelBuffer,
  protectGgufBuffer,
  protectSafetensorsBuffer,
  validateSafetensorsBuffer,
} from "../src/shields/formats/model.js";
import { inspectPcapCapture, protectPcapCaptureBuffer } from "../src/shields/formats/pcap-capture.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";

/**
 * The shields below are reachable from `protectTarget` (`src/engine/protector.ts`)
 * or exported from `src/index.ts`, but had no dedicated suite — a malformed-input
 * regression would have been caught only by an integration test, if at all.
 * `SECURITY.md` names parser robustness as reportable class #2, so these pin the
 * two contracts that matter: refuse rather than synthesise, and keep the original
 * bytes the protection is built on.
 */

const DEX_HEADER = Buffer.from("dex\n035\0", "latin1");
const IL2CPP_MAGIC = 0xfab11baf;
const PCAP_MAGIC_LE = 0xa1b2c3d4;
const LINKTYPE_ETHERNET = 1;

function dexFixture(size = 256): Buffer {
  const buffer = Buffer.alloc(size, 0);
  DEX_HEADER.copy(buffer, 0);
  buffer.writeUInt32LE(size, 32);
  return buffer;
}

function il2cppFixture(size = 512): Buffer {
  const buffer = Buffer.alloc(size, 0);
  buffer.writeUInt32LE(IL2CPP_MAGIC, 0);
  return buffer;
}

function pcapHeader(linkType = LINKTYPE_ETHERNET): Buffer {
  const header = Buffer.alloc(24, 0);
  header.writeUInt32LE(PCAP_MAGIC_LE, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(linkType, 20);
  return header;
}

describe("android dex shield", () => {
  it("refuses a container without the dex header instead of synthesising one", () => {
    expect(() => protectAndroidDexBuffer(Buffer.from("not a dex container"))).toThrow(
      /refusing to synthesize/,
    );
    expect(inspectAndroidDex(Buffer.alloc(200)).validDex).toBe(false);
  });

  it("leaves the protected container self-consistent (file_size, Adler32, signature)", () => {
    const result = protectAndroidDexBuffer(dexFixture(), {
      intensity: "bankrupt",
      seed: "dex-seed",
    });
    expect(result.decoyClassesInjected).toBeGreaterThanOrEqual(8);

    const inspected = inspectAndroidDex(result.buffer);
    expect(inspected.validDex).toBe(true);
    expect(inspected.fileSize).toBe(result.buffer.length);
    // `blaProtected` is only true when the stored Adler32 and file_size match the
    // rewritten bytes and the decoy class descriptor survived.
    expect(inspected.blaProtected).toBe(true);
  });
});

describe("il2cpp metadata shield", () => {
  it("refuses a container without the 0xFAB11BAF magic", () => {
    expect(() => protectIl2cppMetadataBuffer(Buffer.alloc(300))).toThrow(
      /refusing to synthesize/,
    );
  });

  it("keeps the magic and never shrinks the container", () => {
    const input = il2cppFixture();
    const result = protectIl2cppMetadataBuffer(input, {
      intensity: "balanced",
      seed: "il2cpp-seed",
    });
    expect(result.buffer.readUInt32LE(0)).toBe(IL2CPP_MAGIC);
    expect(result.buffer.length).toBeGreaterThanOrEqual(input.length);
  });
});

describe("dotnet managed shield", () => {
  it("keeps the exhaustion plan under the REA representation ceiling at every intensity", () => {
    const totals = (["stealth", "balanced", "maximum", "bankrupt"] as const).map((intensity) => {
      const plan = planDotnetManagedBudgetExhaustion(
        new SeededPrng(`dotnet-${intensity}`),
        intensity,
      );
      expect(plan.decoyPInvokeImports).toHaveLength(16);
      return plan.totalReaRepresentationChargeBytes;
    });
    for (const total of totals) expect(total).toBeLessThan(64 * 1024 * 1024);
    // Higher intensity means a bigger flood, never a smaller one.
    for (let i = 1; i < totals.length; i++) {
      expect(totals[i]!).toBeGreaterThanOrEqual(totals[i - 1]!);
    }
  });

  it("appends its metadata without touching the original bytes", () => {
    const input = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), Buffer.alloc(64, 7)]);
    const result = protectDotnetManagedBuffer(input, {
      intensity: "balanced",
      seed: "dotnet-seed",
    });
    expect(result.buffer.subarray(0, input.length).equals(input)).toBe(true);
    expect(result.buffer.length).toBeGreaterThan(input.length);
  });
});

describe("pcap capture shield", () => {
  it("refuses a capture without a 24-byte global header", () => {
    expect(() => protectPcapCaptureBuffer(Buffer.alloc(8))).toThrow(/global header/);
    expect(inspectPcapCapture(Buffer.alloc(8)).validMagic).toBe(false);
  });

  it("at bankrupt it floods past the tshark budget and is recognisable afterwards", () => {
    const input = pcapHeader();
    const result = protectPcapCaptureBuffer(input, { intensity: "bankrupt", seed: "pcap-seed" });
    expect(result.buffer.subarray(0, 24).equals(input)).toBe(true);
    expect(result.exceedsTsharkJsonBudget).toBe(true);
    expect(result.answerFloodPackets).toBeGreaterThan(0);

    const inspected = inspectPcapCapture(result.buffer);
    expect(inspected.validMagic).toBe(true);
    expect(inspected.exactFraming).toBe(true);
    expect(inspected.decoyPacketCount).toBeGreaterThanOrEqual(8);
    expect(inspected.blaProtected).toBe(true);
  });

  it("at balanced it stays inside the tshark budget with no answer flood", () => {
    const result = protectPcapCaptureBuffer(pcapHeader(), {
      intensity: "balanced",
      seed: "pcap-seed",
    });
    expect(result.exceedsTsharkJsonBudget).toBe(false);
    expect(result.answerFloodPackets).toBe(0);
    expect(inspectPcapCapture(result.buffer).exactFraming).toBe(true);
  });
});

describe("go / flutter exhaustion plants", () => {
  it("only the top intensities overflow the REA build-info cap", () => {
    const balanced = buildGoBuildInfoExhaustionPayload(new SeededPrng("go-balanced"), "balanced");
    expect(balanced.exceedsMaxBuildInfoBytes).toBe(false);

    const bankrupt = buildGoBuildInfoExhaustionPayload(new SeededPrng("go-bankrupt"), "bankrupt");
    expect(bankrupt.exceedsMaxBuildInfoBytes).toBe(true);
    expect(bankrupt.moduleBytes).toBeGreaterThan(balanced.moduleBytes);
    expect(bankrupt.moduleBytes).toBeGreaterThan(REA_INTERNAL_LIMITS.GO_MAX_BUILD_INFO_BYTES);
  });

  it("never overflows the section it is planted in", () => {
    for (const intensity of ["balanced", "maximum", "bankrupt"] as const) {
      const go = buildMappedGoBuildInfoPlant(intensity, 512);
      expect(go.buffer.length).toBeLessThanOrEqual(512);

      const flutter = buildMappedFlutterIsolatePoolPlant(512, new SeededPrng(`flutter-${intensity}`));
      expect(flutter.buffer.length).toBeLessThanOrEqual(512);
    }
    // A section too small to hold anything yields an empty plant, not an overflow.
    expect(buildMappedGoBuildInfoPlant("bankrupt", 8).buffer.length).toBe(0);
    expect(buildMappedFlutterIsolatePoolPlant(0, new SeededPrng("empty")).buffer.length).toBe(0);
  });

  it("trips the Dart pool ceilings and ships a real ELF64 fixture", () => {
    const pool = buildFlutterPoolExhaustionPayload(new SeededPrng("dart-pool"));
    expect(pool.snapshotHashes).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_SNAPSHOT_HASH_CANDIDATES,
    );
    expect(pool.buffer.length).toBeGreaterThan(0);

    const elf = buildMappedGoFlutterElfFixture();
    expect(elf.subarray(0, 4)).toEqual(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    expect(elf[4]).toBe(2);
  });
});

describe("model shields", () => {
  it("refuses malformed safetensors and non-GGUF containers", () => {
    expect(() => validateSafetensorsBuffer(Buffer.from("nope"))).toThrow(/truncated header/);
    expect(() => protectSafetensorsBuffer(Buffer.alloc(64, 1))).toThrow(/header length/);
    expect(() => protectGgufBuffer(Buffer.from("GGUF"))).toThrow(/refusing to replace it/);
    expect(inspectModelBuffer(Buffer.concat([Buffer.from("GGUF"), Buffer.alloc(40, 1)])).validModel).toBe(
      false,
    );
  });

  it("keeps a protected safetensors buffer parseable with its tensor bytes intact", () => {
    const tensorData = Buffer.alloc(16, 0xab);
    const fixture = buildSafetensorsBuffer(
      { w: { dtype: "F32", shape: [4], data_offsets: [0, 16] } },
      tensorData,
    );
    expect(() => validateSafetensorsBuffer(fixture)).not.toThrow();

    const result = protectSafetensorsBuffer(fixture, { intensity: "balanced", seed: "st-seed" });
    const reparsed = validateSafetensorsBuffer(result.buffer);
    expect(reparsed.tensorData.equals(tensorData)).toBe(true);
    expect(result.triggeredJsonNestingBreaker).toBe(true);
    expect(inspectModelBuffer(result.buffer).blaProtected).toBe(true);
  });
});
