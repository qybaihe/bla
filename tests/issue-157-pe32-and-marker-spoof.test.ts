import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { getDatabaseSyncClass } from "../src/core/sqlite-runtime.js";
import { auditTarget } from "../src/engine/auditor.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { generateAndroidR8Counter } from "../src/shields/formats/android-r8.js";
import { inspectErlangBeam } from "../src/shields/formats/erlang-beam.js";
import { inspectEvmBytecode } from "../src/shields/formats/evm-bytecode.js";
import { UF2_BLOCK_BYTES, inspectUf2Firmware } from "../src/shields/formats/firmware-uf2.js";
import { inspectGpuPtx } from "../src/shields/formats/gpu-ptx.js";
import { inspectJvmClass } from "../src/shields/formats/jvm-bytecode.js";
import { buildSafetensorsBuffer } from "../src/shields/formats/model.js";
import {
  InvalidNativeBinaryError,
  inspectNativeBinary,
  protectNativeBinary,
  validateElf64Layout,
  validateElfLayout,
} from "../src/shields/formats/native.js";
import { inspectPcapCapture } from "../src/shields/formats/pcap-capture.js";
import { inspectPythonPyc } from "../src/shields/formats/python.js";
import { inspectSqliteBuffer } from "../src/shields/formats/sqlite.js";
import { inspectWasmBinary } from "../src/shields/formats/wasm.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-issue157-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/** Builds a minimal valid PE32 (32-bit) or PE32+ (64-bit) image with `.text` and `.rdata` plus header slack. */
function buildSyntheticPe(opts: {
  readonly pe32Plus: boolean;
  readonly machine: number;
  readonly imageBase?: bigint;
}): Buffer {
  const peOffset = 0x80;
  const optHeaderSize = opts.pe32Plus ? 0xf0 : 0xe0;
  const sizeOfHeaders = 0x400;
  const fileAlignment = 0x200;
  const sectionAlignment = 0x1000;
  const textRawOffset = 0x400;
  const textRawSize = 0x200;
  const rdataRawOffset = 0x600;
  const rdataRawSize = 0x200;
  const totalBytes = rdataRawOffset + rdataRawSize;

  const buf = Buffer.alloc(totalBytes, 0);
  buf.write("MZ", 0, "ascii");
  buf.writeUInt32LE(peOffset, 0x3c);
  buf.write("PE\0\0", peOffset, "ascii");

  const coff = peOffset + 4;
  buf.writeUInt16LE(opts.machine, coff + 0);
  buf.writeUInt16LE(2, coff + 2); // NumberOfSections = 2 (.text, .rdata)
  buf.writeUInt16LE(optHeaderSize, coff + 16);
  buf.writeUInt16LE(opts.pe32Plus ? 0x0022 : 0x0102, coff + 18);

  const opt = coff + 20;
  buf.writeUInt16LE(opts.pe32Plus ? 0x20b : 0x10b, opt + 0);
  buf.writeUInt32LE(textRawSize, opt + 4); // SizeOfCode
  buf.writeUInt32LE(rdataRawSize, opt + 8); // SizeOfInitializedData
  buf.writeUInt32LE(0x1000, opt + 16); // AddressOfEntryPoint
  buf.writeUInt32LE(0x1000, opt + 20); // BaseOfCode
  if (opts.pe32Plus) {
    buf.writeBigUInt64LE(opts.imageBase ?? 0x140000000n, opt + 24);
  } else {
    buf.writeUInt32LE(0x2000, opt + 24); // BaseOfData
    buf.writeUInt32LE(Number(opts.imageBase ?? 0x00400000n) >>> 0, opt + 28);
  }
  buf.writeUInt32LE(sectionAlignment, opt + 32);
  buf.writeUInt32LE(fileAlignment, opt + 36);
  buf.writeUInt32LE(0x3000, opt + 56); // SizeOfImage
  buf.writeUInt32LE(sizeOfHeaders, opt + 60); // SizeOfHeaders

  const sec0 = opt + optHeaderSize;
  buf.write(".text", sec0, "ascii");
  buf.writeUInt32LE(0x100, sec0 + 8);
  buf.writeUInt32LE(0x1000, sec0 + 12);
  buf.writeUInt32LE(textRawSize, sec0 + 16);
  buf.writeUInt32LE(textRawOffset, sec0 + 20);
  buf.writeUInt32LE(0x60000020, sec0 + 36);

  const sec1 = sec0 + 40;
  buf.write(".rdata", sec1, "ascii");
  buf.writeUInt32LE(0x100, sec1 + 8);
  buf.writeUInt32LE(0x2000, sec1 + 12);
  buf.writeUInt32LE(rdataRawSize, sec1 + 16);
  buf.writeUInt32LE(rdataRawOffset, sec1 + 20);
  buf.writeUInt32LE(0x40000040, sec1 + 36);

  // Minimal return instruction + readable string in .rdata
  buf[textRawOffset] = 0xc3;
  buf.write("HelloPE32\0", rdataRawOffset, "ascii");
  return buf;
}

/** Builds a minimal valid ELF32 (32-bit x86) or ELF64 (AArch64) executable with PT_LOAD + section table. */
function buildSyntheticElf(opts: { readonly is64: boolean; readonly machine: number }): Buffer {
  const shstr = Buffer.from("\0.text\0.rodata\0.shstrtab\0", "ascii");
  const codeOffset = 0x200;
  const codeSize = 0x40;
  const roOffset = 0x240;
  const roSize = 0x40;
  const shstrOffset = 0x280;
  const shoff = 0x300;
  const shentsize = opts.is64 ? 64 : 40;
  const shnum = 4;
  const totalSize = shoff + shnum * shentsize;
  const buf = Buffer.alloc(totalSize, 0);

  buf[0] = 0x7f;
  buf.write("ELF", 1, "ascii");
  buf[4] = opts.is64 ? 2 : 1; // EI_CLASS
  buf[5] = 1; // little-endian
  buf[6] = 1; // EV_CURRENT

  if (opts.is64) {
    const ehoff = 64;
    const phentsize = 56;
    buf.writeUInt16LE(3, 16); // ET_DYN (.so shared library)
    buf.writeUInt16LE(opts.machine, 18);
    buf.writeUInt32LE(1, 20);
    buf.writeBigUInt64LE(0x200n, 24);
    buf.writeBigUInt64LE(BigInt(ehoff), 32); // e_phoff
    buf.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
    buf.writeUInt16LE(ehoff, 52);
    buf.writeUInt16LE(phentsize, 54);
    buf.writeUInt16LE(2, 56);
    buf.writeUInt16LE(shentsize, 58);
    buf.writeUInt16LE(shnum, 60);
    buf.writeUInt16LE(3, 62);

    // PT_LOAD 0 (RX)
    const ph0 = ehoff;
    buf.writeUInt32LE(1, ph0 + 0);
    buf.writeUInt32LE(5, ph0 + 4);
    buf.writeBigUInt64LE(0n, ph0 + 8);
    buf.writeBigUInt64LE(0x1000n, ph0 + 16);
    buf.writeBigUInt64LE(0x1000n, ph0 + 24);
    buf.writeBigUInt64LE(BigInt(roOffset + roSize), ph0 + 32);
    buf.writeBigUInt64LE(BigInt(roOffset + roSize), ph0 + 40);
    buf.writeBigUInt64LE(0x1000n, ph0 + 48);

    // PT_DYNAMIC (type = 2, no PT_INTERP -> valid ET_DYN .so)
    const ph1 = ehoff + phentsize;
    buf.writeUInt32LE(2, ph1 + 0);
    buf.writeUInt32LE(4, ph1 + 4);
    buf.writeBigUInt64LE(BigInt(roOffset), ph1 + 8);
    buf.writeBigUInt64LE(0x1240n, ph1 + 16);
    buf.writeBigUInt64LE(0x1240n, ph1 + 24);
    buf.writeBigUInt64LE(BigInt(roSize), ph1 + 32);
    buf.writeBigUInt64LE(BigInt(roSize), ph1 + 40);
    buf.writeBigUInt64LE(8n, ph1 + 48);

    const writeSh64 = (
      idx: number,
      nameOff: number,
      type: number,
      flags: bigint,
      addr: bigint,
      off: number,
      size: number,
    ) => {
      const p = shoff + idx * 64;
      buf.writeUInt32LE(nameOff, p + 0);
      buf.writeUInt32LE(type, p + 4);
      buf.writeBigUInt64LE(flags, p + 8);
      buf.writeBigUInt64LE(addr, p + 16);
      buf.writeBigUInt64LE(BigInt(off), p + 24);
      buf.writeBigUInt64LE(BigInt(size), p + 32);
      buf.writeBigUInt64LE(16n, p + 48);
    };
    writeSh64(1, 1, 1, 6n, 0x1200n, codeOffset, codeSize);
    writeSh64(2, 7, 1, 2n, 0x1240n, roOffset, roSize);
    writeSh64(3, 15, 3, 0n, 0n, shstrOffset, shstr.length);
  } else {
    const ehoff = 52;
    const phentsize = 32;
    buf.writeUInt16LE(3, 16); // ET_DYN (.so shared library)
    buf.writeUInt16LE(opts.machine, 18);
    buf.writeUInt32LE(1, 20);
    buf.writeUInt32LE(0x1200, 24);
    buf.writeUInt32LE(ehoff, 28); // e_phoff
    buf.writeUInt32LE(shoff, 32); // e_shoff
    buf.writeUInt16LE(ehoff, 40);
    buf.writeUInt16LE(phentsize, 42);
    buf.writeUInt16LE(2, 44);
    buf.writeUInt16LE(shentsize, 46);
    buf.writeUInt16LE(shnum, 48);
    buf.writeUInt16LE(3, 50);

    // PT_LOAD 0
    const ph0 = ehoff;
    buf.writeUInt32LE(1, ph0 + 0);
    buf.writeUInt32LE(0, ph0 + 4);
    buf.writeUInt32LE(0x1000, ph0 + 8);
    buf.writeUInt32LE(0x1000, ph0 + 12);
    buf.writeUInt32LE(roOffset + roSize, ph0 + 16);
    buf.writeUInt32LE(roOffset + roSize, ph0 + 20);
    buf.writeUInt32LE(5, ph0 + 24);
    buf.writeUInt32LE(0x1000, ph0 + 28);

    // PT_DYNAMIC (type = 2, no PT_INTERP -> valid ET_DYN .so)
    const ph1 = ehoff + phentsize;
    buf.writeUInt32LE(2, ph1 + 0);
    buf.writeUInt32LE(roOffset, ph1 + 4);
    buf.writeUInt32LE(0x1240, ph1 + 8);
    buf.writeUInt32LE(0x1240, ph1 + 12);
    buf.writeUInt32LE(roSize, ph1 + 16);
    buf.writeUInt32LE(roSize, ph1 + 20);
    buf.writeUInt32LE(4, ph1 + 24);
    buf.writeUInt32LE(4, ph1 + 28);

    const writeSh32 = (
      idx: number,
      nameOff: number,
      type: number,
      flags: number,
      addr: number,
      off: number,
      size: number,
    ) => {
      const p = shoff + idx * 40;
      buf.writeUInt32LE(nameOff, p + 0);
      buf.writeUInt32LE(type, p + 4);
      buf.writeUInt32LE(flags, p + 8);
      buf.writeUInt32LE(addr, p + 12);
      buf.writeUInt32LE(off, p + 16);
      buf.writeUInt32LE(size, p + 20);
      buf.writeUInt32LE(16, p + 32);
    };
    writeSh32(1, 1, 1, 6, 0x1200, codeOffset, codeSize);
    writeSh32(2, 7, 1, 2, 0x1240, roOffset, roSize);
    writeSh32(3, 15, 3, 0, 0, shstrOffset, shstr.length);
  }

  buf[codeOffset] = 0xc3;
  buf.write("HelloELF\0", roOffset, "ascii");
  shstr.copy(buf, shstrOffset);
  return buf;
}

describe("Issue #157: Architecture-matched PE32/ARM64/ELF32 `.enclave` islands & zero unmapped overlay", () => {
  it("emits true 32-bit x86 islands, R-X 0x60000020 section flags, in-bounds RVAs, Windows-only diagnostics, and zero unmapped overlay on PE32", () => {
    const dir = makeTempDir();
    const inPath = join(dir, "sample32.exe");
    const outPath = join(dir, "sample32.hardened.exe");
    const rawPe32 = buildSyntheticPe({
      pe32Plus: false,
      machine: 0x014c, // IMAGE_FILE_MACHINE_I386
      imageBase: 0x00400000n,
    });
    writeFileSync(inPath, rawPe32);

    const prot = protectTarget({
      inputPath: inPath,
      outputPath: outPath,
      intensity: "bankrupt",
      seed: "pe32-issue-157",
    });
    expect(prot.detectedFormat).toBe("native-pe");

    const outPe = readFileSync(outPath);
    const info = inspectNativeBinary(outPe);
    expect(info.bits).toBe(32);
    expect(info.peMappedSectionInjected).toBe(true);
    expect(info.blaProtected).toBe(true);

    const peOffset = outPe.readUInt32LE(0x3c);
    const numSections = outPe.readUInt16LE(peOffset + 4 + 2);
    expect(numSections).toBe(3);

    const optOffset = peOffset + 24;
    const sizeOfImage = outPe.readUInt32LE(optOffset + 56);
    const imageBase = outPe.readUInt32LE(optOffset + 28);

    const optHeaderSize = outPe.readUInt16LE(peOffset + 4 + 16);
    const sec2 = peOffset + 24 + optHeaderSize + 2 * 40;
    expect(outPe.subarray(sec2, sec2 + 8).toString("ascii")).toBe(".enclave");
    // Must be R-X executable code (0x60000020), not non-executable R-- data
    expect(outPe.readUInt32LE(sec2 + 36)).toBe(0x60000020);

    const enclaveRva = outPe.readUInt32LE(sec2 + 12);
    const enclaveRawSize = outPe.readUInt32LE(sec2 + 16);
    const enclaveRawPtr = outPe.readUInt32LE(sec2 + 20);
    // Zero unmapped trailing overlay past the mapped `.enclave` section!
    expect(outPe.length).toBe(enclaveRawPtr + enclaveRawSize);
    expect(enclaveRva).toBeGreaterThanOrEqual(0x3000);
    expect(enclaveRva).toBeLessThan(sizeOfImage);

    // First island in `.enclave` uses 32-bit cdecl/stdcall prologue (no 64-bit REX prefix)
    expect(outPe[enclaveRawPtr]).toBe(0x55);
    expect(outPe[enclaveRawPtr + 1]).toBe(0x89);
    expect(outPe[enclaveRawPtr + 2]).toBe(0xe5);
    expect(outPe[enclaveRawPtr + 3]).toBe(0x83);
    expect(outPe[enclaveRawPtr + 4]).toBe(0xec);

    // Islands include direct intra-section CALL rel32 edges so call-graph degree > 0
    const firstFourIslands = outPe.subarray(enclaveRawPtr, enclaveRawPtr + 256);
    expect(firstFourIslands.includes(0xe8)).toBe(true);

    const text = outPe.toString("latin1");
    expect(text).toContain("i686-pc-windows-msvc");
    expect(text).not.toContain("x86_64-pc-windows-msvc");
    expect(text).not.toContain("DarwinProcessOwnershipInspectionError");
    expect(text).not.toContain("business_logic_present=false");
    expect(text).not.toContain("userland_pseudocode_is_synthetic_padding");
    expect(text).not.toContain("(inert_stub)");
    expect(text).not.toContain("bla_canary_synthetic_");

    // Every SYMBOL_OFFSET_MANIFEST hex address must fall inside [ImageBase, ImageBase + SizeOfImage)
    const manifestAddrs = [
      ...text.matchAll(
        /\.(?:text\.enclave_entry|rodata\.abi_shim|data\.dispatch_vtable)=0x([0-9a-f]{8})/g,
      ),
    ].map((m) => Number.parseInt(m[1]!, 16));
    expect(manifestAddrs.length).toBeGreaterThanOrEqual(4);
    for (const va of manifestAddrs) {
      expect(va).toBeGreaterThanOrEqual(imageBase);
      expect(va).toBeLessThan(imageBase + sizeOfImage);
    }

    const ver = verifyTarget(outPath, inPath);
    expect(ver.overallPassed).toBe(true);
  });

  it("supports ARM64 Windows PE32+ (`0xaa64`) and 32-bit/ARM64 Linux ELF binaries end-to-end", () => {
    const rawArmPe = buildSyntheticPe({
      pe32Plus: true,
      machine: 0xaa64,
      imageBase: 0x140000000n,
    });
    const armPeProtected = protectNativeBinary(rawArmPe, {
      intensity: "balanced",
      seed: "arm64-pe-test",
    });
    expect(inspectNativeBinary(armPeProtected.buffer).peMappedSectionInjected).toBe(true);
    const armPeText = armPeProtected.buffer.toString("latin1");
    expect(armPeText).toContain("aarch64-pc-windows-msvc");
    expect(armPeText).not.toContain("DarwinProcessOwnershipInspectionError");

    // 32-bit ELF (`EI_CLASS = 1`, `EM_386 = 3`)
    const dir = makeTempDir();
    const elf32In = join(dir, "libnative32.so");
    const elf32Out = join(dir, "libnative32.hardened.so");
    const rawElf32 = buildSyntheticElf({ is64: false, machine: 3 });
    expect(() => validateElf64Layout(rawElf32)).toThrow(InvalidNativeBinaryError);
    const layout32 = validateElfLayout(rawElf32);
    expect(layout32.bits).toBe(32);
    writeFileSync(elf32In, rawElf32);

    const elf32Prot = protectTarget({
      inputPath: elf32In,
      outputPath: elf32Out,
      intensity: "bankrupt",
      seed: "elf32-test",
    });
    expect(elf32Prot.detectedFormat).toBe("native-elf");
    const elf32Bytes = readFileSync(elf32Out);
    expect(elf32Bytes.length).toBeLessThan(200_000); // No 1.15 MB unmapped overlay!
    expect(elf32Bytes.toString("latin1")).not.toContain("DarwinProcessOwnershipInspectionError");
    expect(verifyTarget(elf32Out, elf32In).overallPassed).toBe(true);

    // 64-bit ARM64 ELF (`EI_CLASS = 2`, `EM_AARCH64 = 0xb7`)
    const rawElfArm64 = buildSyntheticElf({ is64: true, machine: 0xb7 });
    const elfArm64Res = protectNativeBinary(rawElfArm64, {
      intensity: "balanced",
      seed: "elf-arm64-test",
    });
    expect(elfArm64Res.elfMappedSectionInjected).toBe(true);
    expect(inspectNativeBinary(elfArm64Res.buffer).blaProtected).toBe(true);
  });

  it("removes self-sabotaging `-bla-enclave` and `# bla-shield:` banners from R8 decoy mappings", () => {
    const r8 = generateAndroidR8Counter(new SeededPrng("r8-test"), "balanced");
    expect(r8.mappingText).not.toContain("bla-enclave");
    expect(r8.mappingText).not.toContain("bla-shield");
    expect(r8.mappingText).toContain("# compiler: R8");
  });
});

describe("Issue #155 extended hardening: anti-marker-spoofing across formats & SQLite generated-column accuracy", () => {
  it("does not misclassify ordinary SQLite 3.31+ tables with GENERATED ALWAYS AS columns as BLA_PROTECTED", () => {
    const dir = makeTempDir();
    const dbPath = join(dir, "invoices.sqlite");
    const DatabaseSync = getDatabaseSyncClass();
    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE invoices (
        id INTEGER PRIMARY KEY,
        subtotal REAL NOT NULL,
        tax REAL GENERATED ALWAYS AS (subtotal * 0.1) STORED
      );
      INSERT INTO invoices (subtotal) VALUES (120.0);
    `);
    db.close();

    const summary = inspectSqliteBuffer(readFileSync(dbPath));
    expect(summary.validSqlite).toBe(true);
    expect(summary.hasGeneratedTrapColumns).toBe(false);
    expect(summary.blaProtected).toBe(false);
    expect(summary.decorationState).toBe("undecorated");

    const audit = auditTarget(dbPath);
    expect(audit.exposedItems.some((item) => item.riskLevel !== "low")).toBe(true);
  });

  it("rejects single-marker / trailing-garbage spoofing across UF2, PCAP, BEAM, EVM, PTX, PYC, WASM, GGUF, Safetensors, bplist, and JVM .class", () => {
    const dir = makeTempDir();

    // 1. UF2 firmware: trailing raw marker or main-flash block with marker must fail
    const uf2Block = Buffer.alloc(UF2_BLOCK_BYTES, 0);
    uf2Block.writeUInt32LE(0x0a324655, 0);
    uf2Block.writeUInt32LE(0x9e5d5157, 4);
    uf2Block.writeUInt32LE(0x00000000, 8); // main-flash flag (not decoy!)
    uf2Block.writeUInt32LE(0x08000000, 12);
    uf2Block.writeUInt32LE(32, 16);
    uf2Block.writeUInt32LE(0, 20);
    uf2Block.writeUInt32LE(1, 24);
    Buffer.from("[BLA-UF2-SHIELD]", "utf8").copy(uf2Block, 32);
    uf2Block.writeUInt32LE(0x0ab16f30, UF2_BLOCK_BYTES - 4);
    const uf2Base = join(dir, "fw.uf2");
    const uf2Spoof = join(dir, "fw.spoof.uf2");
    const uf2Real = join(dir, "fw.real.uf2");
    writeFileSync(uf2Base, uf2Block);
    writeFileSync(uf2Spoof, Buffer.concat([uf2Block, uf2Block, uf2Block, uf2Block]));
    expect(inspectUf2Firmware(readFileSync(uf2Spoof)).blaProtected).toBe(false);
    expect(verifyTarget(uf2Spoof, uf2Base).overallPassed).toBe(false);
    protectTarget({ inputPath: uf2Base, outputPath: uf2Real, seed: "uf2-ok" });
    expect(verifyTarget(uf2Real, uf2Base).overallPassed).toBe(true);

    // 2. PCAP capture: appending raw `[BLA-PCAP-SHIELD]` past valid packet records must fail
    const pcapHdr = Buffer.alloc(24, 0);
    pcapHdr.writeUInt32LE(0xa1b2c3d4, 0);
    pcapHdr.writeUInt16LE(2, 4);
    pcapHdr.writeUInt16LE(4, 6);
    pcapHdr.writeUInt32LE(65535, 16);
    pcapHdr.writeUInt32LE(1, 20);
    const pcapBase = join(dir, "trace.pcap");
    const pcapSpoof = join(dir, "trace.spoof.pcap");
    const pcapReal = join(dir, "trace.real.pcap");
    writeFileSync(pcapBase, pcapHdr);
    writeFileSync(pcapSpoof, Buffer.concat([pcapHdr, Buffer.from("[BLA-PCAP-SHIELD]", "utf8")]));
    expect(inspectPcapCapture(readFileSync(pcapSpoof)).blaProtected).toBe(false);
    expect(verifyTarget(pcapSpoof, pcapBase).overallPassed).toBe(false);
    protectTarget({ inputPath: pcapBase, outputPath: pcapReal, seed: "pcap-ok" });
    expect(verifyTarget(pcapReal, pcapBase).overallPassed).toBe(true);

    // 3. Erlang BEAM: appending `[BLA-BEAM-SHIELD]` past FOR1 container must fail
    const atu8Payload = Buffer.from([0, 0, 0, 1, 4, 0x74, 0x65, 0x73, 0x74, 0, 0, 0]);
    const atu8Chunk = Buffer.concat([
      Buffer.from("AtU8", "ascii"),
      Buffer.from([0, 0, 0, 9]),
      atu8Payload,
    ]);
    const beamBody = Buffer.concat([Buffer.from("BEAM", "ascii"), atu8Chunk]);
    const beamFormSize = Buffer.alloc(4);
    beamFormSize.writeUInt32BE(beamBody.length, 0);
    const beamBuf = Buffer.concat([Buffer.from("FOR1", "ascii"), beamFormSize, beamBody]);
    const beamBase = join(dir, "mod.beam");
    const beamSpoof = join(dir, "mod.spoof.beam");
    const beamReal = join(dir, "mod.real.beam");
    writeFileSync(beamBase, beamBuf);
    writeFileSync(beamSpoof, Buffer.concat([beamBuf, Buffer.from("[BLA-BEAM-SHIELD]", "utf8")]));
    expect(inspectErlangBeam(readFileSync(beamSpoof)).blaProtected).toBe(false);
    expect(verifyTarget(beamSpoof, beamBase).overallPassed).toBe(false);
    protectTarget({ inputPath: beamBase, outputPath: beamReal, seed: "beam-ok" });
    expect(verifyTarget(beamReal, beamBase).overallPassed).toBe(true);

    // 4. EVM bytecode: raw `[BLA-EVM-SHIELD]` outside terminal CBOR metadata must fail
    const evmRaw = Buffer.from([0x60, 0x00, 0x60, 0x00, 0xf3]);
    const evmSpoofBuf = Buffer.concat([evmRaw, Buffer.from("[BLA-EVM-SHIELD]", "utf8")]);
    expect(inspectEvmBytecode(evmSpoofBuf).blaProtected).toBe(false);

    // 5. GPU PTX: marker without valid `.version` / `.target` PTX directives must fail
    const fakePtx = [
      "// [BLA-PTX-SHIELD]",
      ...Array.from({ length: 4 }, (_, i) => `// DIAG: fake_${i}`),
      ...Array.from(
        { length: 8 },
        (_, i) =>
          `.visible .entry bla_tarpit_kernel_${i}_abcd(.param .u64 bla_tarpit_kernel_${i}_abcd_param_0) { ret; }`,
      ),
    ].join("\n");
    expect(inspectGpuPtx(fakePtx).blaProtected).toBe(false);

    // 6. Python .pyc: single marker string inside user bytecode constants must fail
    const pycHdr = Buffer.alloc(16, 0);
    pycHdr.writeUInt16LE(3495, 0);
    pycHdr[2] = 0x0d;
    pycHdr[3] = 0x0a;
    const pycSpoofBuf = Buffer.concat([
      pycHdr,
      Buffer.from("s\x20\x00\x00\x00PROTECTED_CANARY_CREDENTIAL=fake", "latin1"),
    ]);
    expect(inspectPythonPyc(pycSpoofBuf).blaProtected).toBe(false);

    // 7. WASM: single empty `bla.enclave.manifest` custom section must fail audit/verify
    const wasmHeader = Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
      0x03, 0x02, 0x01, 0x00,
      // Export section (id=7, 1 export "run")
      0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00,
      0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
    ]);
    const secName = Buffer.from("bla.enclave.manifest", "utf8");
    const singleCustomSec = Buffer.concat([
      Buffer.from([0x00, secName.length + 1, secName.length]),
      secName,
    ]);
    const wasmBase = join(dir, "mod.wasm");
    const wasmSpoof = join(dir, "mod.spoof.wasm");
    const wasmReal = join(dir, "mod.real.wasm");
    writeFileSync(wasmBase, wasmHeader);
    writeFileSync(wasmSpoof, Buffer.concat([wasmHeader, singleCustomSec]));
    expect(inspectWasmBinary(readFileSync(wasmSpoof)).exactFraming).toBe(true);
    expect(verifyTarget(wasmSpoof, wasmBase).overallPassed).toBe(false);
    protectTarget({ inputPath: wasmBase, outputPath: wasmReal, seed: "wasm-ok" });
    expect(verifyTarget(wasmReal, wasmBase).overallPassed).toBe(true);

    // 8. Safetensors: single `bla.x` metadata key without >32 nesting breaker must fail verify
    const stBaseBuf = buildSafetensorsBuffer(
      { weight: { dtype: "F32", shape: [4], data_offsets: [0, 16] } },
      Buffer.alloc(16, 0),
    );
    const stSpoofBuf = buildSafetensorsBuffer(
      {
        __metadata__: { "bla.x": "1" },
        weight: { dtype: "F32", shape: [4], data_offsets: [0, 16] },
      },
      Buffer.alloc(16, 0),
    );
    const stBase = join(dir, "m.safetensors");
    const stSpoof = join(dir, "m.spoof.safetensors");
    const stReal = join(dir, "m.real.safetensors");
    writeFileSync(stBase, stBaseBuf);
    writeFileSync(stSpoof, stSpoofBuf);
    expect(verifyTarget(stSpoof, stBase).overallPassed).toBe(false);
    protectTarget({ inputPath: stBase, outputPath: stReal, seed: "st-ok" });
    expect(verifyTarget(stReal, stBase).overallPassed).toBe(true);

    // 9. GGUF: a protection marker after the metadata table must fail verify.
    const ggufBaseBuf = Buffer.alloc(24, 0);
    ggufBaseBuf.write("GGUF", 0, "ascii");
    ggufBaseBuf.writeUInt32LE(3, 4);
    const ggufBase = join(dir, "m.gguf");
    const ggufSpoof = join(dir, "m.spoof.gguf");
    const ggufReal = join(dir, "m.real.gguf");
    writeFileSync(ggufBase, ggufBaseBuf);
    writeFileSync(ggufSpoof, Buffer.concat([ggufBaseBuf, Buffer.from(" BLA-MODEL-SHIELD")]));
    expect(verifyTarget(ggufSpoof, ggufBase).overallPassed).toBe(false);
    protectTarget({ inputPath: ggufBase, outputPath: ggufReal, seed: "gguf-ok" });
    expect(verifyTarget(ggufReal, ggufBase).overallPassed).toBe(true);

    // 10. Apple binary plist (`bplist00`): single depth-guard token without full canary corpus must fail verify
    const bplistBaseBuf = Buffer.from("YnBsaXN0MDDQCAAAAAAAAAEBAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAJ", "base64");
    const bplistSpoofBuf = Buffer.concat([
      bplistBaseBuf,
      Buffer.from("\0BLA_BPLIST_DEPTH_GUARD_132\0enclave\0enclave\0", "latin1"),
    ]);
    const bplistBase = join(dir, "Info.plist");
    const bplistSpoof = join(dir, "Info.spoof.plist");
    const bplistReal = join(dir, "Info.real.plist");
    writeFileSync(bplistBase, bplistBaseBuf);
    writeFileSync(bplistSpoof, bplistSpoofBuf);
    expect(verifyTarget(bplistSpoof, bplistBase).overallPassed).toBe(false);
    protectTarget({ inputPath: bplistBase, outputPath: bplistReal, seed: "bplist-ok" });
    expect(verifyTarget(bplistReal, bplistBase).overallPassed).toBe(true);

    // 11. JVM `.class`: raw `BlaEnclaveDelegation` + 6 `StateNode_` strings appended past `.class` EOF must fail
    // Minimal complete JVM class: cp_count=2 (#1 = Class -> #1 selfstub, wait: #1 = Utf8 "A", #2 = Class(#1), cp_count=3)
    const jvmComplete = Buffer.from([
      0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x37,
      0x00, 0x03, // constant_pool_count = 3
      0x01, 0x00, 0x01, 0x41, // #1 = Utf8 "A"
      0x07, 0x00, 0x01, // #2 = Class(#1)
      0x00, 0x21, // access_flags
      0x00, 0x02, // this_class = #2
      0x00, 0x00, // super_class = 0
      0x00, 0x00, // interfaces_count = 0
      0x00, 0x00, // fields_count = 0
      0x00, 0x00, // methods_count = 0
      0x00, 0x00, // attributes_count = 0
    ]);
    const jvmTrailingSpoof = Buffer.concat([
      jvmComplete,
      Buffer.from(
        [
          "BlaEnclaveDelegation",
          ...Array.from({ length: 6 }, (_, i) => `com/enclave/tarpit/StateNode_0${i}_pc_1234`),
        ].join("\0"),
        "utf8",
      ),
    ]);
    expect(inspectJvmClass(jvmTrailingSpoof).blaProtected).toBe(false);
    const jvmBase = join(dir, "App.class");
    const jvmSpoof = join(dir, "App.spoof.class");
    const jvmReal = join(dir, "App.real.class");
    writeFileSync(jvmBase, jvmComplete);
    writeFileSync(jvmSpoof, jvmTrailingSpoof);
    expect(verifyTarget(jvmSpoof, jvmBase).overallPassed).toBe(false);
    protectTarget({ inputPath: jvmBase, outputPath: jvmReal, seed: "jvm-ok" });
    expect(verifyTarget(jvmReal, jvmBase).overallPassed).toBe(true);
  });
});
