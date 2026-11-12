import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  applyDefenseScoreHonesty,
  collectDefenseScoreGaps,
} from "../src/engine/defense-score-honesty.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { buildGoBuildInfoExhaustionPayload } from "../src/shields/formats/go-flutter-exhaustion.js";
import {
  inspectNativeBinary,
  protectNativeBinary,
  resolveElf64SectionNames,
  validateElf64Layout,
} from "../src/shields/formats/native.js";

/**
 * Builds a realistic stripped ELF64 shared library (`ET_DYN` with `PT_PHDR`,
 * `PT_LOAD` RX, `PT_LOAD` RW+BSS, `PT_DYNAMIC`, and section header table).
 */
function buildRealisticElf64SharedObject(machine: 0x3e | 0xb7 = 0x3e): Buffer {
  // Layout:
  // [0..64)       ELF64 Header
  // [64..288)     4 Program Headers * 56 bytes (PT_PHDR, PT_LOAD RX, PT_LOAD RW, PT_DYNAMIC)
  // [288..512)    .text + .rodata (inside RX PT_LOAD [0..512))
  // [512..640)    .dynamic + .data (inside RW PT_LOAD [512..640), memsz = 128 + 256 BSS)
  // [640..720)    .shstrtab (80 bytes)
  // [720..1104)   6 Section Headers * 64 bytes (NULL, .text, .rodata, .dynamic, .bss, .shstrtab)
  const totalBytes = 1104;
  const buf = Buffer.alloc(totalBytes, 0);

  // ELF64 header
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // ELFDATA2LSB
  buf[6] = 1; // EV_CURRENT
  buf.writeUInt16LE(3, 16); // e_type = ET_DYN (.so)
  buf.writeUInt16LE(machine, 18); // EM_X86_64 or EM_AARCH64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x180n, 24); // e_entry
  buf.writeBigUInt64LE(64n, 32); // e_phoff = 64
  buf.writeBigUInt64LE(720n, 40); // e_shoff = 720
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(56, 54); // e_phentsize
  buf.writeUInt16LE(4, 56); // e_phnum = 4
  buf.writeUInt16LE(64, 58); // e_shentsize
  buf.writeUInt16LE(6, 60); // e_shnum = 6
  buf.writeUInt16LE(5, 62); // e_shstrndx = 5

  const pageAlign = machine === 0xb7 ? 0x10000n : 0x1000n;

  // PH 0: PT_PHDR (type 6)
  const ph0 = 64;
  buf.writeUInt32LE(6, ph0 + 0);
  buf.writeUInt32LE(4, ph0 + 4); // PF_R
  buf.writeBigUInt64LE(64n, ph0 + 8);
  buf.writeBigUInt64LE(64n, ph0 + 16);
  buf.writeBigUInt64LE(64n, ph0 + 24);
  buf.writeBigUInt64LE(224n, ph0 + 32);
  buf.writeBigUInt64LE(224n, ph0 + 40);
  buf.writeBigUInt64LE(8n, ph0 + 48);

  // PH 1: PT_LOAD RX [0..512)
  const ph1 = 64 + 56;
  buf.writeUInt32LE(1, ph1 + 0);
  buf.writeUInt32LE(5, ph1 + 4); // PF_R | PF_X
  buf.writeBigUInt64LE(0n, ph1 + 8);
  buf.writeBigUInt64LE(0n, ph1 + 16);
  buf.writeBigUInt64LE(0n, ph1 + 24);
  buf.writeBigUInt64LE(512n, ph1 + 32);
  buf.writeBigUInt64LE(512n, ph1 + 40);
  buf.writeBigUInt64LE(pageAlign, ph1 + 48);

  // PH 2: PT_LOAD RW [512..640) at vaddr pageAlign + 0x200
  const rwVaddr = pageAlign + 0x200n;
  const ph2 = 64 + 112;
  buf.writeUInt32LE(1, ph2 + 0);
  buf.writeUInt32LE(6, ph2 + 4); // PF_R | PF_W
  buf.writeBigUInt64LE(512n, ph2 + 8);
  buf.writeBigUInt64LE(rwVaddr, ph2 + 16);
  buf.writeBigUInt64LE(rwVaddr, ph2 + 24);
  buf.writeBigUInt64LE(128n, ph2 + 32);
  buf.writeBigUInt64LE(384n, ph2 + 40); // +256 BSS
  buf.writeBigUInt64LE(pageAlign, ph2 + 48);

  // PH 3: PT_DYNAMIC (type 2) inside RW PT_LOAD
  const ph3 = 64 + 168;
  buf.writeUInt32LE(2, ph3 + 0);
  buf.writeUInt32LE(6, ph3 + 4);
  buf.writeBigUInt64LE(512n, ph3 + 8);
  buf.writeBigUInt64LE(rwVaddr, ph3 + 16);
  buf.writeBigUInt64LE(rwVaddr, ph3 + 24);
  buf.writeBigUInt64LE(64n, ph3 + 32);
  buf.writeBigUInt64LE(64n, ph3 + 40);
  buf.writeBigUInt64LE(8n, ph3 + 48);

  // Real code stub in .text [288..352)
  buf.write("real_exported_fn\0", 352, "ascii");
  buf[288] = 0xc3; // ret

  // .shstrtab at [640..720)
  const shstr = "\0.text\0.rodata\0.dynamic\0.bss\0.shstrtab\0";
  buf.write(shstr, 640, "ascii");

  // SH 1: .text
  const sh1 = 720 + 64;
  buf.writeUInt32LE(1, sh1 + 0);
  buf.writeUInt32LE(1, sh1 + 4); // SHT_PROGBITS
  buf.writeBigUInt64LE(6n, sh1 + 8); // SHF_ALLOC | SHF_EXECINSTR
  buf.writeBigUInt64LE(288n, sh1 + 16);
  buf.writeBigUInt64LE(288n, sh1 + 24);
  buf.writeBigUInt64LE(64n, sh1 + 32);

  // SH 2: .rodata
  const sh2 = 720 + 128;
  buf.writeUInt32LE(7, sh2 + 0);
  buf.writeUInt32LE(1, sh2 + 4);
  buf.writeBigUInt64LE(2n, sh2 + 8); // SHF_ALLOC
  buf.writeBigUInt64LE(352n, sh2 + 16);
  buf.writeBigUInt64LE(352n, sh2 + 24);
  buf.writeBigUInt64LE(160n, sh2 + 32);

  // SH 3: .dynamic
  const sh3 = 720 + 192;
  buf.writeUInt32LE(15, sh3 + 0);
  buf.writeUInt32LE(6, sh3 + 4); // SHT_DYNAMIC
  buf.writeBigUInt64LE(3n, sh3 + 8); // SHF_WRITE | SHF_ALLOC
  buf.writeBigUInt64LE(rwVaddr, sh3 + 16);
  buf.writeBigUInt64LE(512n, sh3 + 24);
  buf.writeBigUInt64LE(64n, sh3 + 32);

  // SH 4: .bss
  const sh4 = 720 + 256;
  buf.writeUInt32LE(24, sh4 + 0);
  buf.writeUInt32LE(8, sh4 + 4); // SHT_NOBITS
  buf.writeBigUInt64LE(3n, sh4 + 8);
  buf.writeBigUInt64LE(rwVaddr + 128n, sh4 + 16);
  buf.writeBigUInt64LE(640n, sh4 + 24);
  buf.writeBigUInt64LE(256n, sh4 + 32);

  // SH 5: .shstrtab
  const sh5 = 720 + 320;
  buf.writeUInt32LE(29, sh5 + 0);
  buf.writeUInt32LE(3, sh5 + 4); // SHT_STRTAB
  buf.writeBigUInt64LE(0n, sh5 + 8);
  buf.writeBigUInt64LE(0n, sh5 + 16);
  buf.writeBigUInt64LE(640n, sh5 + 24);
  buf.writeBigUInt64LE(80n, sh5 + 32);

  return buf;
}

describe("Issue #176: ELF64 .so mapped .enclave PT_LOAD hardening, marker hygiene & defenseScore honesty", () => {
  it("injects a mapped RX PT_LOAD + .enclave section with x86-64 islands & Itanium RTTI on ELF64 .so and breaks naive head-truncation", () => {
    const rawSo = buildRealisticElf64SharedObject(0x3e);
    const beforeLayout = validateElf64Layout(rawSo);
    expect(beforeLayout.phnum).toBe(4);
    expect(beforeLayout.shnum).toBe(6);

    const res = protectNativeBinary(rawSo, {
      intensity: "bankrupt",
      seed: "issue-176-elf-so",
    });
    expect(res.elfMappedSectionInjected).toBe(true);
    expect(res.decoyFunctionIslandsInjected).toBe(32);

    const afterLayout = validateElf64Layout(res.buffer);
    expect(afterLayout.phnum).toBe(5);
    expect(afterLayout.shnum).toBe(7);

    // PT_PHDR updated to relocated program header table inside the new mapped PT_LOAD
    const ptPhdr = afterLayout.programHeaders[0]!;
    const newPtLoad = afterLayout.programHeaders[4]!;
    expect(newPtLoad.type).toBe(1); // PT_LOAD
    expect(newPtLoad.flags).toBe(5); // PF_R | PF_X (strict W^X)
    expect(Number(newPtLoad.vaddr % 0x1000n)).toBe(Number(BigInt(newPtLoad.offset) % 0x1000n));
    expect(ptPhdr.offset).toBe(newPtLoad.offset);
    expect(ptPhdr.vaddr).toBe(newPtLoad.vaddr);

    // `.enclave` SHT_PROGBITS section lies inside the new PT_LOAD segment
    const secNames = resolveElf64SectionNames(res.buffer, afterLayout);
    const enclaveSec = secNames.get(".enclave");
    expect(enclaveSec).toBeDefined();
    expect(enclaveSec!.type).toBe(1); // SHT_PROGBITS
    expect(enclaveSec!.flags).toBe(6n); // SHF_ALLOC | SHF_EXECINSTR
    expect(enclaveSec!.offset).toBeGreaterThanOrEqual(newPtLoad.offset);
    expect(enclaveSec!.offset + enclaveSec!.size).toBeLessThanOrEqual(
      newPtLoad.offset + newPtLoad.filesz,
    );

    // Mapped `.enclave` bytes contain x86-64 CET prologue (`endbr64; push rbp; mov rbp, rsp`) and Itanium C++ RTTI
    const mappedSlice = res.buffer.subarray(
      enclaveSec!.offset,
      enclaveSec!.offset + enclaveSec!.size,
    );
    expect(
      mappedSlice.includes(Buffer.from([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5])),
    ).toBe(true);
    expect(mappedSlice.toString("latin1")).toContain("_ZTS31EnclaveRing0AttestationVerifier");

    // Naive `head -c <origLen> hardened.so` truncates the relocated e_phoff / e_shoff and fails ELF layout validation
    const truncated = res.buffer.subarray(0, rawSo.length);
    expect(truncated.equals(rawSo)).toBe(false);
    expect(() => validateElf64Layout(truncated)).toThrow(/program header table out of bounds/);

    // Also verify AArch64 (`EM_AARCH64`, 64 KiB page align)
    const arm64So = buildRealisticElf64SharedObject(0xb7);
    const arm64Res = protectNativeBinary(arm64So, {
      intensity: "balanced",
      seed: "issue-176-arm64",
    });
    expect(arm64Res.elfMappedSectionInjected).toBe(true);
    const arm64Layout = validateElf64Layout(arm64Res.buffer);
    const arm64Load = arm64Layout.programHeaders[4]!;
    expect(arm64Load.align).toBe(0x10000n);
    expect(arm64Load.offset % 0x10000).toBe(0);
  });

  it("replaces 1 MiB 'A' padding and self-identifying BLA banners in native trailers", () => {
    const prng = new SeededPrng("issue-176-hygiene");
    const goPayload = buildGoBuildInfoExhaustionPayload(prng, "bankrupt", {
      omitBanner: true,
    });
    const goText = goPayload.buffer.toString("latin1");
    expect(goPayload.exceedsMaxBuildInfoBytes).toBe(true);
    expect(goText).not.toContain("A".repeat(64));
    expect(goText).not.toContain("BLA_CANARY=");
    expect(goText).not.toContain("github.com/bla/");
    expect(goText).toContain("dep\tgithub.com/");

    const rawSo = buildRealisticElf64SharedObject(0x3e);
    const res = protectNativeBinary(rawSo, {
      intensity: "bankrupt",
      seed: "issue-176-hygiene-elf",
    });
    const allLatin1 = res.buffer.toString("latin1");
    expect(allLatin1).not.toContain("[BLA-NATIVE-SHIELD-V1]");
    expect(allLatin1).not.toContain("[BLA-GO-BUILDINFO]");
    expect(allLatin1).not.toContain("[BLA-FLUTTER-POOL-EXHAUST]");
    expect(allLatin1).not.toContain("[COGNITIVE_ARMOR_INTERLOCK:");
    expect(allLatin1).not.toContain("A".repeat(64));

    const inspected = inspectNativeBinary(res.buffer);
    expect(inspected.blaProtected).toBe(true);
    expect(inspected.elfMappedSectionInjected).toBe(true);
    expect(inspected.nativeMappedSectionInjected).toBe(true);
  });

  it("caps post-link native defenseScore honestly (<=78 mapped, <=68 trailer-only) instead of claiming 93", () => {
    const mappedHonesty = applyDefenseScoreHonesty(97, {
      detectedFormat: "native-elf",
      sidecarEntangleEnabled: false,
      nativeMappedSectionInjected: true,
    });
    expect(mappedHonesty.gaps.map((g) => g.id)).toContain("native-postlink-cfg-untouched");
    expect(mappedHonesty.gaps.map((g) => g.id)).not.toContain("native-trailer-unmapped");
    expect(mappedHonesty.cappedScore).toBe(78);

    const unmappedHonesty = collectDefenseScoreGaps({
      detectedFormat: "native-macho",
      nativeMappedSectionInjected: false,
    });
    expect(unmappedHonesty.map((g) => g.id)).toContain("native-trailer-unmapped");

    const dir = mkdtempSync(join(tmpdir(), "bla-issue-176-"));
    try {
      const soPath = join(dir, "libdemo.so");
      writeFileSync(soPath, buildRealisticElf64SharedObject(0x3e));

      const hardenReport = hardenProject({
        directory: dir,
        intensity: "bankrupt",
        seed: "issue-176-harden",
      });
      expect(hardenReport.overallSuccess).toBe(true);
      const soArtifact = hardenReport.artifacts.find((a) =>
        a.relativePath.endsWith("libdemo.so"),
      )!;
      expect(soArtifact).toBeDefined();
      expect(soArtifact.defenseScore).toBeLessThanOrEqual(78);

      const verifyRep = verifyTarget(soArtifact.outputPath, soPath);
      expect(verifyRep.defenseScore).toBeLessThanOrEqual(78);
      expect(
        verifyRep.defenseScoreGaps?.some((g) => g.id === "native-postlink-cfg-untouched"),
      ).toBe(true);
      expect(
        verifyRep.agentActions?.some((a) => a.id === "compile-with-bla-headers"),
      ).toBe(true);

      const hardenedBytes = readFileSync(soArtifact.outputPath);
      expect(inspectNativeBinary(hardenedBytes).elfMappedSectionInjected).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
