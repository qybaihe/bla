import { describe, expect, it } from "vitest";
import { inspectNativeBinary } from "../src/shields/formats/native.js";

describe("native ELF32 inspection honesty", () => {
  it("flags an ELF32 whose program-header table cannot be validated", () => {
    const bytes = Buffer.alloc(52);
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;
    bytes[4] = 1; // ELFCLASS32
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // EV_CURRENT
    bytes.writeUInt16LE(3, 18); // EM_386
    bytes.writeUInt32LE(0xfffffff0, 28); // e_phoff past EOF
    bytes.writeUInt16LE(32, 42); // e_phentsize
    bytes.writeUInt16LE(4, 44); // e_phnum
    const inspection = inspectNativeBinary(bytes);
    expect(inspection.format).toBe("native-elf");
    expect(inspection.bits).toBe(32);
    expect(inspection.elf32ValidationFailed).toBe(true);
  });
});