import { describe, expect, it } from "vitest";
import { validateElf64Layout } from "../src/shields/formats/native.js";

const SHENT = 64;

interface ElfOptions {
  readonly sectionCount: number;
  /** Optional 1-based section index pair that will be given identical file ranges. */
  readonly overlap?: readonly [number, number];
}

/** Minimal but structurally consistent ELF64 (ET_EXEC, no program headers). */
function buildElf64(options: ElfOptions): Buffer {
  const shoff = 64;
  const shTableEnd = shoff + options.sectionCount * SHENT;
  const dataBytes = options.sectionCount; // one byte per file-backed section
  const total = shTableEnd + dataBytes;
  const b = Buffer.alloc(total, 0);

  b.write("\u007fELF", 0, "latin1");
  b[4] = 2; // 64-bit
  b[5] = 1; // little endian
  b[6] = 1; // EV_CURRENT
  b.writeUInt16LE(2, 16); // e_type = ET_EXEC
  b.writeUInt16LE(62, 18); // e_machine = x86-64
  b.writeUInt32LE(1, 20); // e_version
  b.writeBigUInt64LE(0n, 24); // e_entry
  b.writeBigUInt64LE(0n, 32); // e_phoff
  b.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
  b.writeUInt16LE(64, 52); // e_ehsize
  b.writeUInt16LE(56, 54); // e_phentsize
  b.writeUInt16LE(0, 56); // e_phnum
  b.writeUInt16LE(SHENT, 58); // e_shentsize
  b.writeUInt16LE(options.sectionCount, 60); // e_shnum
  b.writeUInt16LE(0, 62); // e_shstrndx

  for (let s = 1; s < options.sectionCount; s++) {
    const off = shoff + s * SHENT;
    const isOverlapLower = options.overlap !== undefined && s === options.overlap[0];
    const isOverlapUpper = options.overlap !== undefined && s === options.overlap[1];
    b.writeUInt32LE(s, off); // sh_name
    b.writeUInt32LE(1, off + 4); // sh_type = PROGBITS
    b.writeBigUInt64LE(BigInt(shTableEnd + (s - 1)), off + 24); // sh_offset
    b.writeBigUInt64LE(1n, off + 32); // sh_size
    if (isOverlapLower || isOverlapUpper) {
      // Both members of the pair share one file range.
      b.writeBigUInt64LE(BigInt(shTableEnd), off + 24);
      b.writeBigUInt64LE(1n, off + 32);
    }
  }
  return b;
}

describe("ELF64 section-overlap validation", () => {
  it("handles a maximum-section-count file without quadratic work", () => {
    const elf = buildElf64({ sectionCount: 65_535 });
    const started = Date.now();
    const layout = validateElf64Layout(elf);
    const elapsed = Date.now() - started;

    expect(layout.sectionHeaders).toHaveLength(65_535);
    expect(elapsed).toBeLessThan(10_000);
  });

  it("still refuses overlapping file-backed sections", () => {
    const elf = buildElf64({ sectionCount: 64, overlap: [3, 7] });
    expect(() => validateElf64Layout(elf)).toThrow(/have overlapping file ranges/);
  });
});