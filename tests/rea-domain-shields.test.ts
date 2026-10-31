import { describe, expect, it } from "vitest";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import {
  inspectNativeBinary,
  protectNativeBinary,
  validateElf64Layout,
  resolveElf64SectionNames,
} from "../src/shields/formats/native.js";
import {
  buildGoBuildInfoExhaustionPayload,
  buildFlutterPoolExhaustionPayload,
  buildMappedGoFlutterElfFixture,
} from "../src/shields/formats/go-flutter-exhaustion.js";
import {
  inspectErlangBeam,
  protectErlangBeamBuffer,
} from "../src/shields/formats/erlang-beam.js";
import {
  inspectEvmBytecode,
  protectEvmBytecodeBuffer,
  buildSolidityMetadataTrailer,
} from "../src/shields/formats/evm-bytecode.js";
import {
  inspectPcapCapture,
  protectPcapCaptureBuffer,
} from "../src/shields/formats/pcap-capture.js";
import {
  inspectGpuPtx,
  protectGpuPtxText,
  FIRMWARE_HARDENING_SKIP_REASON,
  GPU_OBJECT_HARDENING_SKIP_REASON,
} from "../src/shields/formats/gpu-ptx.js";
import {
  inspectUf2Firmware,
  protectUf2FirmwareBuffer,
  UF2_BLOCK_BYTES,
  UF2_SHIELD_MARKER,
} from "../src/shields/formats/firmware-uf2.js";
import { detectArtifactFormat } from "../src/core/detector.js";
import { SeededPrng } from "../src/core/prng.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

function shieldedElfFixture(): Buffer {
  const elf = Buffer.alloc(512, 0);
  elf[0] = 0x7f;
  elf[1] = 0x45;
  elf[2] = 0x4c;
  elf[3] = 0x46;
  elf[4] = 2;
  elf[5] = 1;
  elf[6] = 1;
  elf.writeUInt16LE(0x3e, 18);
  const eShoff = 64;
  const shEntSize = 64;
  const shNum = 3;
  elf.writeBigUInt64LE(BigInt(eShoff), 40);
  elf.writeUInt16LE(shEntSize, 58);
  elf.writeUInt16LE(shNum, 60);
  elf.writeUInt16LE(1, 62);
  const shstrtabOffset = 256;
  Buffer.from("\0.shstrtab\0.rodata\0", "utf8").copy(elf, shstrtabOffset);
  const sh1 = eShoff + shEntSize;
  elf.writeUInt32LE(1, sh1 + 0);
  elf.writeUInt32LE(3, sh1 + 4);
  elf.writeBigUInt64LE(BigInt(shstrtabOffset), sh1 + 24);
  elf.writeBigUInt64LE(BigInt(18), sh1 + 32);
  const rodataOffset = 320;
  const rodata = Buffer.from(
    "/rustc/a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4/library/core\0",
    "utf8",
  );
  rodata.copy(elf, rodataOffset);
  const sh2 = eShoff + shEntSize * 2;
  elf.writeUInt32LE(11, sh2 + 0);
  elf.writeUInt32LE(1, sh2 + 4);
  elf.writeBigUInt64LE(BigInt(2), sh2 + 8);
  elf.writeBigUInt64LE(BigInt(rodataOffset), sh2 + 24);
  elf.writeBigUInt64LE(BigInt(rodata.length), sh2 + 32);
  return elf;
}

describe("REA domain shields — Go / Flutter / BEAM / EVM / PCAP / PTX", () => {
  it("embeds framed Go buildinfo + pclntab bait and Flutter pool past REA caps in native trailer", () => {
    const prng = new SeededPrng("go-flutter-unit");
    const go = buildGoBuildInfoExhaustionPayload(prng, "balanced");
    expect(go.buffer.includes(Buffer.from("ff20476f206275696c64696e663a", "hex"))).toBe(
      true,
    );
    expect(go.buffer.toString("latin1")).toContain("[BLA-GO-BUILDINFO]");
    expect(go.buffer.toString("latin1")).toContain(".gopclntab");
    expect(go.buffer.toString("latin1")).toContain("runtime.moduledata");

    const flutter = buildFlutterPoolExhaustionPayload(prng);
    expect(flutter.snapshotHashes).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_SNAPSHOT_HASH_CANDIDATES,
    );
    expect(flutter.packageAndDartUris).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_POOL_URIS,
    );
    expect(flutter.classLikeTokens).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_POOL_TOKENS,
    );
    expect(flutter.buffer.toString("utf8")).toContain("[BLA-FLUTTER-POOL-EXHAUST]");
    expect(flutter.buffer.toString("utf8")).toContain("package:enclave_tarpit_0/");

    const protectedElf = protectNativeBinary(shieldedElfFixture(), {
      intensity: "balanced",
      seed: "native-go-flutter",
    });
    expect(protectedElf.dartPoolUrisInjected).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_POOL_URIS,
    );
    expect(protectedElf.dartPoolTokensInjected).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_POOL_TOKENS,
    );
    const after = inspectNativeBinary(protectedElf.buffer);
    expect(after.goBuildInfoFramed).toBe(true);
    expect(after.hasGoBuildInfo).toBe(true);
    expect(after.dartPoolPackageUriCount).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_POOL_URIS,
    );
    expect(after.dartPoolTokenCount).toBeGreaterThan(
      REA_INTERNAL_LIMITS.DART_MAX_POOL_TOKENS,
    );
    // ELF magic preserved (runtime/section integrity red line)
    expect(protectedElf.buffer.subarray(0, 4).toString("latin1")).toBe("\x7fELF");
  });

  it("protects Erlang BEAM: valid FOR1/BEAM, atoms preserved+extended, chunks past default 64", () => {
    // Minimal hand-authored BEAM matching REA fixture shape
    const u32 = (n: number) => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n);
      return b;
    };
    const pad4 = (b: Buffer) => {
      const p = (4 - (b.length % 4)) % 4;
      return p === 0 ? b : Buffer.concat([b, Buffer.alloc(p)]);
    };
    const chunk = (name: string, payload: Buffer) =>
      Buffer.concat([Buffer.from(name, "latin1"), u32(payload.length), pad4(payload)]);
    const atomNames = ["demo_mod", "module_info", "start"];
    const atomBody = Buffer.concat([
      u32(atomNames.length),
      ...atomNames.map((n) => {
        const e = Buffer.from(n, "utf8");
        return Buffer.concat([Buffer.from([e.length]), e]);
      }),
    ]);
    const code = Buffer.concat([
      u32(16),
      u32(0),
      u32(169),
      u32(4),
      u32(2),
      Buffer.from("code"),
    ]);
    const form = Buffer.concat([
      Buffer.from("BEAM", "latin1"),
      chunk("AtU8", atomBody),
      chunk("Code", code),
      chunk("ExpT", Buffer.concat([u32(1), u32(2), u32(0), u32(1)])),
    ]);
    const raw = Buffer.concat([
      Buffer.from("FOR1", "latin1"),
      u32(form.length),
      form,
    ]);

    const before = inspectErlangBeam(raw);
    expect(before.validMagic).toBe(true);
    expect(before.atomCount).toBe(3);
    expect(before.chunkCount).toBe(3);

    const res = protectErlangBeamBuffer(raw, {
      intensity: "balanced",
      seed: "beam-test",
    });
    expect(res.exceedsDefaultChunkBudget).toBe(true);
    expect(res.chunksInjected).toBeGreaterThan(0);
    expect(res.atomsInjected).toBeGreaterThan(0);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.buffer.toString("utf8")).toContain("[BLA-BEAM-SHIELD]");

    const after = inspectErlangBeam(res.buffer);
    expect(after.validMagic).toBe(true);
    expect(after.chunkCount).toBeGreaterThan(
      REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_CHUNKS,
    );
    expect(after.atomCount).toBeGreaterThan(3);
    // Original first atoms preserved (index stability)
    expect(res.buffer.toString("utf8")).toContain("demo_mod");
    expect(res.buffer.toString("utf8")).toContain("module_info");

    const tmp = path.join(os.tmpdir(), `bla-beam-${Date.now()}.beam`);
    fs.writeFileSync(tmp, res.buffer);
    expect(detectArtifactFormat(tmp)).toBe("erlang-beam");
    fs.unlinkSync(tmp);
  });

  it("protects EVM bytecode with Solidity terminal CBOR metadata + canaries", () => {
    const runtime = Buffer.from("6080604052348015600f575f80fd5b50", "hex"); // common preamble fragment
    const res = protectEvmBytecodeBuffer(runtime, {
      intensity: "balanced",
      seed: "evm-test",
    });
    expect(res.metadataBytes).toBeGreaterThan(10);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    const after = inspectEvmBytecode(res.buffer);
    expect(after.hasSolidityMetadata).toBe(true);
    expect(after.blaProtected).toBe(true);
    expect(res.buffer.toString("utf8")).toContain("[BLA-EVM-SHIELD]");
    // Original runtime prefix preserved
    expect(res.buffer.subarray(0, runtime.length).equals(runtime)).toBe(true);
    // Metadata length suffix consistent
    const metaLen =
      res.buffer[res.buffer.length - 2]! * 256 + res.buffer[res.buffer.length - 1]!;
    expect(metaLen).toBe(after.metadataBytes);

    const trailer = buildSolidityMetadataTrailer([
      ["solc", Buffer.from([0, 8, 30])],
      ["bla", "ok"],
    ]);
    expect(trailer.length).toBeGreaterThan(4);

    const tmp = path.join(os.tmpdir(), `bla-evm-${Date.now()}.evm`);
    fs.writeFileSync(tmp, res.buffer);
    expect(detectArtifactFormat(tmp)).toBe("evm-bytecode");
    fs.unlinkSync(tmp);
  });

  it("protects PCAP captures: magic preserved, decoy packets + canaries present", () => {
    const res = protectPcapCaptureBuffer(Buffer.alloc(0), {
      intensity: "balanced",
      seed: "pcap-test",
    });
    expect(res.packetsInjected).toBeGreaterThanOrEqual(8);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    const after = inspectPcapCapture(res.buffer);
    expect(after.validMagic).toBe(true);
    expect(after.packetCount).toBe(res.packetsInjected);
    expect(after.blaProtected).toBe(true);
    expect(res.buffer.includes(Buffer.from("[BLA-PCAP-SHIELD]", "utf8"))).toBe(
      true,
    );

    const tmp = path.join(os.tmpdir(), `bla-pcap-${Date.now()}.pcap`);
    fs.writeFileSync(tmp, res.buffer);
    expect(detectArtifactFormat(tmp)).toBe("pcap-capture");
    fs.unlinkSync(tmp);
  });

  it("protects GPU PTX text with decoy .entry kernels; documents firmware skip", () => {
    const src = `.version 7.5\n.target sm_70\n.address_size 64\n\n.visible .entry real_kernel(.param .u64 a)\n{\n  ret;\n}\n`;
    const res = protectGpuPtxText(src, { intensity: "balanced", seed: "ptx-test" });
    expect(res.entriesInjected).toBeGreaterThanOrEqual(16);
    expect(res.text).toContain("[BLA-PTX-SHIELD]");
    expect(res.text).toContain("real_kernel"); // original preserved
    expect(res.text.indexOf("real_kernel")).toBeLessThan(
      res.text.indexOf("[BLA-PTX-SHIELD]"),
    );
    const after = inspectGpuPtx(res.text);
    expect(after.looksLikePtx).toBe(true);
    expect(after.entryCount).toBeGreaterThan(1);
    expect(after.blaProtected).toBe(true);
    expect(FIRMWARE_HARDENING_SKIP_REASON.toLowerCase()).toContain("firmware");

    const tmp = path.join(os.tmpdir(), `bla-ptx-${Date.now()}.ptx`);
    fs.writeFileSync(tmp, res.text);
    expect(detectArtifactFormat(tmp)).toBe("gpu-ptx");
    fs.unlinkSync(tmp);
  });


  it("protects UF2 firmware: original blocks byte-exact, only not-main/file-container decoys", () => {
    // Minimal real main-flash block (RP2040 family) — must survive untouched.
    const real = Buffer.alloc(UF2_BLOCK_BYTES, 0);
    real.writeUInt32LE(0x0a324655, 0);
    real.writeUInt32LE(0x9e5d5157, 4);
    real.writeUInt32LE(0x00002000, 8); // familyId flag only (MAIN flash)
    real.writeUInt32LE(0x10000000, 12);
    real.writeUInt32LE(256, 16);
    real.writeUInt32LE(0, 20);
    real.writeUInt32LE(1, 24);
    real.writeUInt32LE(0xe48bff56, 28); // RP2040
    real.write("REAL_FLASH_PAYLOAD", 32, "utf8");
    real.writeUInt32LE(0x0ab16f30, UF2_BLOCK_BYTES - 4);

    const res = protectUf2FirmwareBuffer(real, {
      intensity: "balanced",
      seed: "uf2-test",
    });
    expect(res.originalBlocksPreserved).toBe(1);
    expect(res.blocksInjected).toBeGreaterThanOrEqual(8);
    expect(res.notMainFlashBlocks).toBeGreaterThan(0);
    expect(res.fileContainerBlocks).toBeGreaterThan(0);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    // Prefix byte-exact
    expect(res.buffer.subarray(0, UF2_BLOCK_BYTES).equals(real)).toBe(true);
    expect(res.buffer.includes(Buffer.from(UF2_SHIELD_MARKER, "utf8"))).toBe(true);
    expect(res.buffer.includes(Buffer.from("REAL_FLASH_PAYLOAD", "utf8"))).toBe(true);

    // Every injected block must carry not-main-flash and/or file-container.
    for (let off = UF2_BLOCK_BYTES; off + UF2_BLOCK_BYTES <= res.buffer.length; off += UF2_BLOCK_BYTES) {
      expect(res.buffer.readUInt32LE(off)).toBe(0x0a324655);
      expect(res.buffer.readUInt32LE(off + 4)).toBe(0x9e5d5157);
      expect(res.buffer.readUInt32LE(off + UF2_BLOCK_BYTES - 4)).toBe(0x0ab16f30);
      const flags = res.buffer.readUInt32LE(off + 8);
      const safe = (flags & 0x1) !== 0 || (flags & 0x1000) !== 0;
      expect(safe).toBe(true);
    }

    const after = inspectUf2Firmware(res.buffer);
    expect(after.validMagic).toBe(true);
    expect(after.blaProtected).toBe(true);
    expect(after.blockCount).toBe(1 + res.blocksInjected);

    const tmp = path.join(os.tmpdir(), `bla-uf2-${Date.now()}.uf2`);
    fs.writeFileSync(tmp, res.buffer);
    expect(detectArtifactFormat(tmp)).toBe("firmware-uf2");
    fs.unlinkSync(tmp);
  });

  it("plants Go buildinfo into mapped .go.buildinfo and Flutter pool into isolate region", () => {
    const fixture = buildMappedGoFlutterElfFixture();
    const layoutBefore = validateElf64Layout(fixture);
    const namesBefore = resolveElf64SectionNames(fixture, layoutBefore);
    expect(namesBefore.has(".go.buildinfo")).toBe(true);
    expect(namesBefore.has(".isolate")).toBe(true);
    const goSec = namesBefore.get(".go.buildinfo")!;
    const isoSec = namesBefore.get(".isolate")!;

    const res = protectNativeBinary(fixture, {
      intensity: "bankrupt",
      seed: "mapped-go-flutter",
    });
    expect(res.mappedGoBuildInfoPlanted).toBe(true);
    expect(res.mappedFlutterPoolPlanted).toBe(true);
    expect(res.goBuildInfoExceedsLimit).toBe(true);

    // Section headers / PT_LOAD unchanged (red line)
    const layoutAfter = validateElf64Layout(res.buffer);
    expect(layoutAfter.programHeaders.length).toBe(layoutBefore.programHeaders.length);
    expect(layoutAfter.sectionHeaders.length).toBe(layoutBefore.sectionHeaders.length);
    for (let i = 0; i < layoutBefore.programHeaders.length; i++) {
      expect(layoutAfter.programHeaders[i]!.offset).toBe(
        layoutBefore.programHeaders[i]!.offset,
      );
      expect(layoutAfter.programHeaders[i]!.filesz).toBe(
        layoutBefore.programHeaders[i]!.filesz,
      );
    }

    // Magic sits inside the mapped .go.buildinfo file range
    const goSlice = res.buffer.subarray(goSec.offset, goSec.offset + goSec.size);
    expect(goSlice.includes(Buffer.from("ff20476f206275696c64696e663a", "hex"))).toBe(
      true,
    );
    expect(goSlice.toString("latin1")).toContain("[BLA-GO-MAPPED]");

    // Pool strings sit inside the isolate region (after preserved snapshot header)
    const isoSlice = res.buffer.subarray(isoSec.offset, isoSec.offset + isoSec.size);
    expect(isoSlice[0]).toBe(0xf5);
    expect(isoSlice.toString("utf8")).toContain("package:m0/b.dart");
    expect(isoSlice.toString("utf8")).toContain("dart:d0");
    expect(isoSlice.toString("utf8")).toContain("Node_0_X");
    expect(isoSlice.toString("utf8")).toContain("[BLA-FLUTTER-MAPPED]");
  });

  it("expands OTP28+ compact AtU8 atom tables while keeping compact encoding", () => {
    const u32 = (n: number) => {
      const b = Buffer.alloc(4);
      b.writeInt32BE(n);
      return b;
    };
    const pad4 = (b: Buffer) => {
      const p = (4 - (b.length % 4)) % 4;
      return p === 0 ? b : Buffer.concat([b, Buffer.alloc(p)]);
    };
    const chunk = (name: string, payload: Buffer) =>
      Buffer.concat([Buffer.from(name, "latin1"), (() => { const x = Buffer.alloc(4); x.writeUInt32BE(payload.length); return x; })(), pad4(payload)]);
    // Compact: negated count + compact-u lengths (len<<4 for len<16)
    const names = ["compact_mod", "module_info", "go"];
    const atomParts: Buffer[] = [u32(-names.length)];
    for (const n of names) {
      const enc = Buffer.from(n, "utf8");
      atomParts.push(Buffer.from([(enc.length << 4) & 0xff]), enc);
    }
    const atomBody = Buffer.concat(atomParts);
    const code = Buffer.concat([
      (() => { const b = Buffer.alloc(4); b.writeUInt32BE(16); return b; })(),
      Buffer.alloc(16),
    ]);
    const form = Buffer.concat([
      Buffer.from("BEAM", "latin1"),
      chunk("AtU8", atomBody),
      chunk("Code", code),
    ]);
    const raw = Buffer.concat([
      Buffer.from("FOR1", "latin1"),
      (() => { const b = Buffer.alloc(4); b.writeUInt32BE(form.length); return b; })(),
      form,
    ]);
    expect(inspectErlangBeam(raw).atomCount).toBe(3);

    const res = protectErlangBeamBuffer(raw, {
      intensity: "balanced",
      seed: "beam-compact",
    });
    expect(res.atomsInjected).toBeGreaterThan(0);
    const after = inspectErlangBeam(res.buffer);
    expect(after.validMagic).toBe(true);
    expect(after.atomCount).toBeGreaterThan(3);
    // Still compact: declared count is negative
    const afterChunks = res.buffer.toString("latin1");
    expect(afterChunks).toContain("compact_mod");
    expect(afterChunks).toContain("[BLA-BEAM-SHIELD]");
    // Locate AtU8 payload and assert compact sign bit preserved
    const atu8At = res.buffer.indexOf(Buffer.from("AtU8", "latin1"));
    expect(atu8At).toBeGreaterThanOrEqual(0);
    const declared = res.buffer.readInt32BE(atu8At + 8);
    expect(declared).toBeLessThan(0);
    expect(Math.abs(declared)).toBe(after.atomCount);
  });

  it("bankrupt EVM approaches the full 4 MiB inputBytes budget; balanced stays lean", () => {
    const runtime = Buffer.from([0x00]); // STOP
    const lean = protectEvmBytecodeBuffer(runtime, {
      intensity: "balanced",
      seed: "evm-lean",
    });
    expect(lean.paddingBytes).toBe(0);
    expect(lean.buffer.length).toBeLessThan(64 * 1024);

    const bankrupt = protectEvmBytecodeBuffer(runtime, {
      intensity: "bankrupt",
      seed: "evm-bankrupt",
    });
    expect(bankrupt.approachesInputBudget).toBe(true);
    expect(bankrupt.buffer.length).toBeGreaterThanOrEqual(
      REA_INTERNAL_LIMITS.EVM_INPUT_BYTES - 8192,
    );
    expect(bankrupt.buffer.length).toBeLessThanOrEqual(
      REA_INTERNAL_LIMITS.EVM_INPUT_BYTES,
    );
    // Runtime prefix + JUMPDEST padding preserved as inert fallthrough
    expect(bankrupt.buffer[0]).toBe(0x00);
    expect(bankrupt.paddingBytes).toBeGreaterThan(3_000_000);
    const after = inspectEvmBytecode(bankrupt.buffer);
    expect(after.hasSolidityMetadata).toBe(true);
    expect(after.blaProtected).toBe(true);
  });

  it("bankrupt PCAP decoys estimate past TSHARK_JSON_MAX_BYTES while staying valid libpcap", () => {
    const res = protectPcapCaptureBuffer(Buffer.alloc(0), {
      intensity: "bankrupt",
      seed: "pcap-bankrupt",
    });
    expect(res.packetsInjected).toBeGreaterThanOrEqual(48);
    expect(res.estimatedTsharkJsonBytes).toBeGreaterThan(
      REA_INTERNAL_LIMITS.PCAP_TSHARK_JSON_MAX_BYTES,
    );
    expect(res.exceedsTsharkJsonBudget).toBe(true);
    const after = inspectPcapCapture(res.buffer);
    expect(after.validMagic).toBe(true);
    expect(after.packetCount).toBe(res.packetsInjected);
    expect(after.blaProtected).toBe(true);
    // Nested HTTP headers present
    expect(res.buffer.includes(Buffer.from("X-BLA-Nested-0:", "utf8"))).toBe(true);
  });

  it("documents SPIR-V / CUDA fatbinary / AMD GPU object skip alongside firmware", () => {
    expect(GPU_OBJECT_HARDENING_SKIP_REASON.toLowerCase()).toContain("spir-v");
    expect(GPU_OBJECT_HARDENING_SKIP_REASON.toLowerCase()).toContain("cuda");
    expect(GPU_OBJECT_HARDENING_SKIP_REASON.toLowerCase()).toContain("amd");
    expect(FIRMWARE_HARDENING_SKIP_REASON.toLowerCase()).toContain("firmware");
  });

});
