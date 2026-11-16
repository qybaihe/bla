import { describe, expect, it } from "vitest";
import { packAsarBuffer, unpackAsarBuffer } from "../src/shields/formats/asar.js";
import { readZipEntries, writeZipArchive, UnsupportedArchiveError } from "../src/shields/formats/archive.js";
import { parseGgufLayout } from "../src/shields/formats/gguf-layout.js";
import { protectJvmClassBuffer } from "../src/shields/formats/jvm-bytecode.js";
import { protectPythonPycBuffer } from "../src/shields/formats/python.js";
import { InvalidSafetensorsError, validateSafetensorsBuffer } from "../src/shields/formats/model.js";
import { parseWasmExportSectionPayload } from "../src/shields/formats/wasm.js";

/**
 * Malformed-input contracts that the existing suites did not pin yet. Each
 * case documents the exact fail-closed behavior a hostile artifact triggers.
 */
describe("malformed-input coverage gaps (fail-closed contracts)", () => {
  it("rejects a ZIP whose central-directory sizes use the 0xffffffff ZIP64 sentinel", () => {
    const input = writeZipArchive([{ name: "file.txt", data: Buffer.from("harmless content ".repeat(8)) }]);
    // Locate the central-directory header via the EOCD link and poison its
    // compressed/uncompressed size fields with the ZIP64 sentinel.
    const eocdSig = input.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    expect(eocdSig).toBeGreaterThan(0);
    const cdOffset = input.readUInt32LE(eocdSig + 16);
    const poisoned = Buffer.from(input);
    poisoned.writeUInt32LE(0xffffffff, cdOffset + 20);
    poisoned.writeUInt32LE(0xffffffff, cdOffset + 24);
    expect(() => readZipEntries(poisoned)).toThrow(UnsupportedArchiveError);
  });

  it("defensively bounds a truncated or hostile WASM export section", () => {
    // Control: one complete entry parses.
    const valid = Buffer.from([0x01, 0x02, 0x61, 0x62, 0x00, 0x00]);
    expect(parseWasmExportSectionPayload(valid)).toEqual([
      { kind: 0, name: "ab", index: 0 },
    ]);
    // count=2 but the second entry's name length is truncated: fail closed
    // to an empty section instead of guessing.
    const truncated = Buffer.from([0x02, 0x03, 0x61, 0x62, 0x00, 0x01, 0x00]);
    expect(parseWasmExportSectionPayload(truncated)).toEqual([]);
    // Oversized declared name length must not over-read.
    const oversized = Buffer.from([0x01, 0xff, 0xff, 0x7f]);
    expect(parseWasmExportSectionPayload(oversized)).toEqual([]);
    // Unknown export kind aborts the whole section (fail closed to empty).
    const badKind = Buffer.from([0x01, 0x01, 0x61, 0x7f, 0x00]);
    expect(parseWasmExportSectionPayload(badKind)).toEqual([]);
  });

  it("refuses an ASAR symlink entry whose target escapes the archive root", () => {
    const hostile = {
      relativePath: "app",
      content: Buffer.alloc(0),
      link: "../outside.js",
    };
    expect(() => packAsarBuffer([hostile])).toThrow();
    // Control: a contained link packs and unpacks cleanly.
    const packed = packAsarBuffer([
      { relativePath: "app", content: Buffer.from("console.log(1);\n"), },
      { relativePath: "link", content: Buffer.alloc(0), link: "app" },
    ]);
    const unpacked = unpackAsarBuffer(packed, { allowLinks: true });
    expect(unpacked.find((e) => e.relativePath === "link")?.link).toBe("app");
  });

  it("throws on a .pyc with a malformed header instead of shielding garbage", () => {
    expect(() =>
      protectPythonPycBuffer(Buffer.from("not-a-pyc-at-all"), { seed: "pyc-gap" }),
    ).toThrow(/Invalid CPython \.pyc header/);
    // Truncated-but-magic-bearing input must also refuse rather than pass through.
    expect(() =>
      protectPythonPycBuffer(Buffer.from([0xcb, 0x0d, 0x0a, 0x00]), { seed: "pyc-gap" }),
    ).toThrow();
  });

  it("rejects a safetensors header containing duplicate JSON fields", () => {
    const dupField =
      '{"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}, "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}';
    const header = Buffer.from(dupField, "utf8");
    const bytes = Buffer.concat([
      (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(header.length)); return b; })(),
      header,
      Buffer.alloc(4),
    ]);
    expect(() => validateSafetensorsBuffer(bytes)).toThrow(InvalidSafetensorsError);
    expect(() => validateSafetensorsBuffer(bytes)).toThrow(/duplicate JSON field/);
  });

  it("returns null from parseGgufLayout on hostile KV strings and deep nesting", () => {
    const header = (kvCount: bigint): Buffer => {
      const b = Buffer.alloc(24);
      b.write("GGUF", 0, "ascii");
      b.writeUInt32LE(3, 4);
      b.writeBigUInt64LE(0n, 8);
      b.writeBigUInt64LE(kvCount, 16);
      return b;
    };
    // Control: a single plain string KV parses.
    const ok = Buffer.concat([
      header(1n),
      (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(1n); return b; })(),
      Buffer.from("k", "utf8"),
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(8); return b; })(),
      (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(1n); return b; })(),
      Buffer.from("v", "utf8"),
    ]);
    expect(parseGgufLayout(ok)?.kvs.length).toBe(1);

    // Hostile: the key declares a u64 length far beyond the buffer.
    const hostileKey = Buffer.concat([
      header(1n),
      (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(0xffff_ffff_ffff_ffffn); return b; })(),
      Buffer.from("k", "utf8"),
    ]);
    expect(parseGgufLayout(hostileKey)).toBeNull();

    // Hostile: 65 nested ARRAY frames exceed MAX_VALUE_DEPTH (64).
    let value = Buffer.alloc(4);
    value.writeUInt32LE(4); // innermost UINT32
    for (let i = 0; i < 65; i++) {
      const frame = Buffer.alloc(12);
      frame.writeUInt32LE(9, 0); // ARRAY
      frame.writeBigUInt64LE(1n, 4); // count = 1
      value = Buffer.concat([frame, value]);
    }
    const deep = Buffer.concat([
      header(1n),
      (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(1n); return b; })(),
      Buffer.from("d", "utf8"),
      value,
    ]);
    expect(parseGgufLayout(deep)).toBeNull();
  });

  it("pins the JVM class shield's fail-closed modes on malformed input", () => {
    const opts = { intensity: "balanced" as const, seed: "jvm-gap" };
    // Non-class garbage: trailer mode (documented synthetic-stub contract),
    // never a synthesized structural class.
    const garbage = protectJvmClassBuffer(Buffer.from("totally not a class file"), opts);
    expect(garbage.mode).toBe("trailer");
    expect(garbage.constantPoolEntriesAdded).toBe(0);
    // CAFEBABE header with a truncated constant pool: the structural walk
    // fails and the shield falls back to the trailer instead of guessing.
    const stub = Buffer.alloc(24);
    stub.writeUInt32BE(0xcafebabe, 0);
    stub.writeUInt16BE(0x0037, 4); // major version 55
    stub.writeUInt16BE(0xffff, 8); // cpCount beyond any parsable table
    const truncatedCp = protectJvmClassBuffer(stub, opts);
    expect(truncatedCp.mode).toBe("trailer");
    expect(truncatedCp.constantPoolEntriesAdded).toBe(0);
  });
});
