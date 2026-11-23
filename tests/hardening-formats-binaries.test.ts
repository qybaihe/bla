import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { generateAndroidDexXrefCounter } from "../src/shields/formats/android-dex-xref.js";
import {
  DEX_MAP_TYPE,
  compareDexUtf16,
  dexChecksumsValid,
  insertDexString,
  parseDexLayout,
} from "../src/shields/formats/dex-layout.js";
import { protectErlangBeamBuffer } from "../src/shields/formats/erlang-beam.js";
import {
  buildSolidityMetadataTrailer,
  inspectEvmBytecode,
  protectEvmBytecodeBuffer,
} from "../src/shields/formats/evm-bytecode.js";
import { protectUf2FirmwareBuffer, UF2_BLOCK_BYTES } from "../src/shields/formats/firmware-uf2.js";
import { buildMappedGoFlutterElfFixture } from "../src/shields/formats/go-flutter-exhaustion.js";
import { protectGpuPtxText } from "../src/shields/formats/gpu-ptx.js";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import { inspectJvmClass, protectJvmClassBuffer } from "../src/shields/formats/jvm-bytecode.js";
import { protectAndroidDexBuffer } from "../src/shields/formats/mobile-game.js";
import {
  protectNativeBinary,
  resolveElf64SectionNames,
  validateElf64Layout,
} from "../src/shields/formats/native.js";
import { inspectPcapCapture, protectPcapCaptureBuffer } from "../src/shields/formats/pcap-capture.js";
import { protectPythonPycBuffer, protectPythonSource } from "../src/shields/formats/python.js";
import { PY3 } from "./helpers/python-interpreter.js";

const intensities = ["stealth", "balanced", "maximum", "bankrupt"] as const;
const seed = "binary-hardening";
const options = { intensity: "stealth", seed } as const;

function withScratch(run: (directory: string) => void): void {
  const directory = mkdtempSync(join(tmpdir(), "bla-format-regression-"));
  try {
    run(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function pythonForMinor(minor: number): string | undefined {
  return [`python3.${minor}`, ...(PY3 ? [PY3] : [])].find((candidate) =>
    spawnSync(candidate, ["-I", "-c", `import sys; sys.exit(sys.version_info[:2] != (3,${minor}))`]).status === 0,
  );
}

function compilePyc(python: string, source: string): Buffer {
  return execFileSync(python, [
    "-I", "-c",
    [
      "import importlib.util, marshal, sys",
      "code = compile(sys.stdin.read(), 'sample.py', 'exec')",
      "sys.stdout.buffer.write(importlib.util.MAGIC_NUMBER + bytes(12) + marshal.dumps(code))",
    ].join("\n"),
  ], { input: source });
}

describe("CPython binary and source protection", () => {
  it("refuses a header-only, truncated, or non-code marshal root", () => {
    const header = Buffer.from("a70d0d0a000000000000000000000000", "hex");
    const truncatedCode = Buffer.concat([header, Buffer.from([0xe3]), Buffer.alloc(12)]);
    const nonCode = Buffer.concat([header, Buffer.from([0x4e])]);
    const invalidFields = Buffer.concat([header, Buffer.from([0x63]), Buffer.alloc(20), Buffer.alloc(12, 0x4e)]);
    for (const input of [header, truncatedCode, nonCode, invalidFields]) {
      expect(() => protectPythonPycBuffer(input)).toThrow(/root code object/);
    }
  });

  for (const minor of [11, 12, 13, 14]) {
    const python = pythonForMinor(minor);
    it.skipIf(!python)(`round-trips marshal strings and executes valid .pyc on CPython 3.${minor}`, () => {
      const input = compilePyc(python!, "def add(n):\n    return n + 2\nVALUE = add(5)\n");
      const output = protectPythonPycBuffer(input, { seed, intensity: "bankrupt", weaveDecoys: true });
      const weaveSupported = minor <= 12;
      expect(output.weaveDecoys).toBe(weaveSupported);
      if (weaveSupported) {
        expect(output.decoyCodeObjectsInjected).toBeGreaterThan(0);
        expect(output.customerDefsWoven).toBe(1);
      } else {
        expect(output.decoyCodeObjectsInjected).toBe(0);
        expect(output.customerDefsWoven).toBe(0);
        expect(output.buffer.subarray(0, input.length)).toEqual(input);
      }
      const script = `
import dis, io, marshal, sys, types
stream = io.BytesIO(sys.stdin.buffer.read())
stream.seek(16)
root = marshal.load(stream)
scope = {}
exec(root, scope)
assert scope["VALUE"] == 7
def check(obj):
    for c in obj.co_consts:
        if isinstance(c, types.CodeType):
            if c.co_name == "add":
                check(c)
            else:
                assert [i.opname for i in dis.get_instructions(c)] == ["RESUME", "LOAD_CONST", "RETURN_VALUE"]
                assert types.FunctionType(c, {})() is None
check(root)
seen = set()
while stream.tell() < len(stream.getbuffer()):
    offset = stream.tell()
    value = marshal.load(stream)
    record = stream.getbuffer()[offset:stream.tell()]
    assert isinstance(value, str)
    assert record[0] == (0x61 if value.isascii() else 0x75)
    assert record[5:].tobytes().decode("utf-8") == value
    seen.add(record[0])
assert seen == {0x61, 0x75}
`;
      execFileSync(python!, ["-I", "-c", script], { input: output.buffer, stdio: "pipe" });
    });
  }

  it.skipIf(!PY3)("keeps the module annotation mapping or its absence intact", () => {
    for (const source of [
      "assert '__annotations__' not in globals() and '__annotate__' not in globals()\n",
      "count: int = 7\n_ann = globals()['__annotate__'](1) if '__annotate__' in globals() else globals()['__annotations__']\nassert _ann == {'count': int}\n",
    ]) {
      const result = protectPythonSource(source, { ...options, weaveDecoys: true });
      execFileSync(PY3!, ["-I", "-c", "import sys; exec(sys.stdin.read(), {})"], { input: result.code, stdio: "pipe" });
    }
  });

  const pep701 = pythonForMinor(12) ?? pythonForMinor(13);
  it.skipIf(!pep701)("accepts multiline single-quoted PEP 701 format fields", () => {
    const source = 'def render():\n    return f"{7:\n    {3}}"\nassert render() == "  7"\n';
    const output = protectPythonSource(source, { ...options, weaveDecoys: true });
    expect(output.customerDefsWoven).toBe(1);
    execFileSync(pep701!, ["-I", "-"], { input: output.code, stdio: "pipe" });
  });
});

describe("DEX framing and identifiers", () => {
  const original = generateAndroidDexXrefCounter(new SeededPrng(seed), "stealth").dexBuffer;

  it("validates versions, endianness, header sizes and file bounds before rewriting", () => {
    const v041 = Buffer.alloc(256);
    v041.write("dex\n041\0", "latin1");
    v041.writeUInt32LE(128, 32);
    v041.writeUInt32LE(0x78, 36);
    v041.writeUInt32LE(0x12345678, 40);
    v041.writeUInt32LE(v041.length, 112);
    expect(() => protectAndroidDexBuffer(v041)).toThrow(/v041/);
    expect(parseDexLayout(v041)).toBeNull();

    const unknown = Buffer.from(original);
    unknown.write("036", 4, "ascii");
    expect(() => protectAndroidDexBuffer(unknown)).toThrow(/version/);
    for (const [at, value, message] of [
      [36, 0x78, /header_size/],
      [40, 0x78563412, /endian_tag/],
      [32, original.length + 1, /file_size/],
      [52, original.length - 1, /map_list/],
      [60, original.length - 1, /section.*bounds/],
    ] as const) {
      const malformed = Buffer.from(original);
      malformed.writeUInt32LE(value, at);
      expect(() => protectAndroidDexBuffer(malformed)).toThrow(message);
    }

    const v040 = Buffer.from(original);
    v040.write("040", 4, "ascii");
    expect(dexChecksumsValid(protectAndroidDexBuffer(v040, options).buffer)).toBe(true);
  });

  it("orders every cross-reference index and emits verifier-safe Log.d call sites", () => {
    const layout = parseDexLayout(original)!;
    expect(layout).not.toBeNull();
    const strings = layout.strings.map(({ text }) => text);
    expect(strings).toEqual([...strings].sort(compareDexUtf16));
    expect(layout.typeIds).toEqual([...layout.typeIds].sort((a, b) => a - b));
    const descriptor = (index: number) => strings[layout.typeIds[index]!];
    const logIndex = layout.methodIds.findIndex(({ classIdx }) => descriptor(classIdx) === "Landroid/util/Log;");
    const log = layout.methodIds[logIndex]!;
    expect(strings[log.nameIdx]).toBe("d");
    const proto = layout.protoIds[log.protoIdx]!;
    expect(descriptor(proto.returnTypeIdx)).toBe("I");
    expect(strings[proto.shortyIdx]).toBe("ILL");
    expect(original.readUInt32LE(proto.parametersOff)).toBe(2);
    for (const at of [4, 6]) {
      expect(descriptor(original.readUInt16LE(proto.parametersOff + at))).toBe("Ljava/lang/String;");
    }
    expect(layout.methodIds.map(({ classIdx }) => classIdx)).toEqual(
      layout.methodIds.map(({ classIdx }) => classIdx).sort((a, b) => a - b),
    );
    const declarations = layout.classDefs.map((def) => def.classIdx);
    expect(declarations).toEqual([...declarations].sort((a, b) => a - b));
    for (const def of layout.classDefs) {
      expect(strings[def.sourceFileIdx]).toBe("BlaDexXref.java");
      const method = layout.classData.find(({ offset }) => offset === def.classDataOff)!.directMethods[0]!;
      expect(layout.methodIds[method.idxDiff]!.classIdx).toBe(def.classIdx);
      const code = layout.codeItems.find(({ offset }) => offset === method.codeOff)!.raw;
      expect(code.readUInt16LE(0)).toBe(2);
      expect(code.readUInt16LE(16)).toBe(0x001a); // const-string v0
      expect(strings[code.readUInt16LE(18)]).toBe("BLA-DEX-XREF-V1");
      expect(code.readUInt16LE(20)).toBe(0x011a); // const-string v1
      expect(strings[code.readUInt16LE(22)]).toBe("BlaDexXref.java");
      expect(code.readUInt16LE(24)).toBe(0x2071); // invoke-static with two arguments
      expect(code.readUInt16LE(26)).toBe(logIndex);
      expect(code.readUInt16LE(28)).toBe(0x0010); // v0, v1
      expect(code.readUInt16LE(30)).toBe(0x000e); // return-void
    }
  });

  it("writes map entries in physical order and keeps appended MUTF-8 strings contiguous", () => {
    const note = "\u0000\u{1f40d}";
    const rewritten = insertDexString(original, note)!;
    expect(rewritten).not.toBeNull();
    for (const bytes of [original, rewritten]) {
      const layout = parseDexLayout(bytes)!;
      expect(layout).not.toBeNull();
      const offsets = layout.map.map(({ offset }) => offset);
      expect(offsets).toEqual([...offsets].sort((a, b) => a - b));
      const section = layout.map.find(({ type }) => type === DEX_MAP_TYPE.STRING_DATA_ITEM)!;
      expect(section.size).toBe(layout.strings.length);
      let cursor = section.offset;
      for (const item of layout.strings) {
        expect(item.dataOff).toBe(cursor);
        cursor += item.raw.length;
      }
      expect(dexChecksumsValid(bytes)).toBe(true);
    }
    expect(parseDexLayout(rewritten)!.strings.at(-1)!.text).toBe(`\uffff${note}`);
  });
});

function jvmClass(cpCount: number, attrsCount = 0): Buffer {
  const header = Buffer.from("cafebabe000000370000", "hex");
  header.writeUInt16BE(cpCount, 8);
  const constants = Buffer.concat([
    Buffer.from("01000a426f756e64436c617373070001", "hex"), // BoundClass
    Buffer.from("0100106a6176612f6c616e672f4f626a656374070003", "hex"), // java/lang/Object
    Buffer.from("010014426c61456e636c61766544656c65676174696f6e", "hex"), // BlaEnclaveDelegation
  ]);
  const filler = Buffer.alloc((cpCount - 6) * 3);
  for (let i = 0; i < filler.length; i += 3) filler[i] = 1; // empty CONSTANT_Utf8
  const body = Buffer.from("0021000200040000000000000000", "hex");
  body.writeUInt16BE(attrsCount, 12);
  const attrs = Buffer.alloc(attrsCount * 6);
  for (let i = 0; i < attrs.length; i += 6) attrs.writeUInt16BE(5, i);
  return Buffer.concat([header, constants, filler, body, attrs]);
}

describe("JVM limits", () => {
  const basic = protectJvmClassBuffer(jvmClass(6), options);
  const nearLimit = jvmClass(0xffff - basic.constantPoolEntriesAdded);
  const output = protectJvmClassBuffer(nearLimit, options);

  it("reuses the attribute name and reaches the exact legal constant pool maximum", () => {
    expect(output.buffer.readUInt16BE(8)).toBe(0xffff);
    expect(output.customAttributesAdded).toBe(1);
    expect(inspectJvmClass(output.buffer)).toMatchObject({ validClass: true, blaProtected: true });
    expect(inspectJvmClass(Buffer.concat([output.buffer, Buffer.from([0])])).validClass).toBe(false);
    expect(() => protectJvmClassBuffer(jvmClass(0xffff), options)).toThrow(/constant pool.*slots/);
    expect(() => protectJvmClassBuffer(jvmClass(6, 0xffff), options)).toThrow(/attribute table is full/);
    const nearAttrLimit = protectJvmClassBuffer(jvmClass(6, 0xfffe), options);
    expect(inspectJvmClass(nearAttrLimit.buffer).validClass).toBe(true);
  });

  it.skipIf(spawnSync("java", ["-version"]).status !== 0)("loads the near-limit class in OpenJDK", () => {
    withScratch((dir) => {
      const input = join(dir, "BoundClass.class");
      writeFileSync(input, output.buffer);
      writeFileSync(join(dir, "Verify.java"), `
import java.nio.file.*;
class Verify extends ClassLoader {
  public static void main(String[] args) throws Exception {
    byte[] bytes = Files.readAllBytes(Path.of(args[0]));
    Verify loader = new Verify();
    Class<?> cls = loader.defineClass(null, bytes, 0, bytes.length);
    loader.resolveClass(cls);
    if (!cls.getName().equals("BoundClass")) throw new AssertionError(cls);
  }
}
`);
      execFileSync("java", [join(dir, "Verify.java"), input], { stdio: "pipe" });
    });
  });
});

describe("native section preservation", () => {
  it("keeps the live Go and Flutter section contents while writing decoys outside them", () => {
    const original = buildMappedGoFlutterElfFixture();
    const before = resolveElf64SectionNames(original, validateElf64Layout(original));
    // Test both the trailer route and the dedicated mapped section route.
    for (const mapped of [false, true]) {
      const input = Buffer.from(original);
      if (mapped) {
        input.writeUInt16LE(2, 56);
        input.writeBigUInt64LE(640n, 32);
        original.copy(input, 640, 64, 120);
        input.writeUInt32LE(2, 696); // PT_DYNAMIC
      }
      const output = protectNativeBinary(input, { intensity: "bankrupt", seed });
      const after = resolveElf64SectionNames(output.buffer, validateElf64Layout(output.buffer));
      expect(output.elfMappedSectionInjected).toBe(mapped);
      expect(output.mappedGoBuildInfoPlanted).toBe(false);
      expect(output.mappedFlutterPoolPlanted).toBe(false);
      for (const name of [".go.buildinfo", ".isolate"]) {
        const { offset, size } = before.get(name)!;
        expect(after.get(name)).toMatchObject({ offset, size });
        expect(output.buffer.subarray(offset, offset + size)).toEqual(original.subarray(offset, offset + size));
      }
      expect(output.buffer.subarray(input.length).includes(Buffer.from("ff20476f206275696c64696e663a", "hex"))).toBe(true);
      expect(output.buffer.subarray(input.length).includes(Buffer.from("package:"))).toBe(true);
    }
  });
});

describe("EVM deployment and metadata", () => {
  for (const intensity of intensities) {
    it(`enforces the EIP-170 ceiling at ${intensity}`, () => {
      const settings = { intensity, seed, enforceEip170Cap: true };
      const normal = protectEvmBytecodeBuffer(Buffer.from([0]), settings);
      const baseAtCap = Buffer.alloc(24_576 - normal.metadataBytes - 2);
      expect(protectEvmBytecodeBuffer(baseAtCap, settings).buffer.length).toBe(24_576);
      for (const size of [baseAtCap.length + 1, 24_577]) {
        expect(() => protectEvmBytecodeBuffer(Buffer.alloc(size), settings)).toThrow(/EIP-170/);
      }
    });
  }

  it("strips only a complete BLA-specific map and preserves raw marker lookalikes", () => {
    const code = Buffer.from([0x60, 0x00, 0x00]);
    const notAMap = Buffer.concat([Buffer.from([0xa1]), Buffer.from("[BLA-EVM-SHIELD] bla_evm_canary")]);
    const malformed = Buffer.concat([notAMap, Buffer.from([0, notAMap.length])]);
    const wrongKeys = buildSolidityMetadataTrailer([["ipfs", "bla_evm_canary [BLA-EVM-SHIELD]"]]);
    const valid = protectEvmBytecodeBuffer(code, options).buffer;
    const damaged = Buffer.from(valid);
    damaged[code.length] = damaged[code.length]! + 1; // declare an extra pair without encoding it

    expect(inspectEvmBytecode(valid).blaProtected).toBe(true);
    expect(protectEvmBytecodeBuffer(valid, options).buffer).toEqual(valid);
    expect(inspectEvmBytecode(wrongKeys).hasSolidityMetadata).toBe(true);
    for (const input of [Buffer.concat([code, malformed]), Buffer.concat([code, wrongKeys]), damaged]) {
      expect(inspectEvmBytecode(input).blaProtected).toBe(false);
      expect(protectEvmBytecodeBuffer(input, options).buffer.subarray(0, input.length)).toEqual(input);
    }
  });
});

it("writes UF2 decoys as ordinary NOT_MAIN_FLASH comments", () => {
  const input = Buffer.alloc(UF2_BLOCK_BYTES);
  input.writeUInt32LE(0x0a324655, 0);
  input.writeUInt32LE(0x9e5d5157, 4);
  input.writeUInt32LE(0x2000, 8);
  input.writeUInt32LE(0x10000000, 12);
  input.writeUInt32LE(256, 16);
  input.writeUInt32LE(1, 24);
  input.writeUInt32LE(0xe48bff56, 28);
  input.writeUInt32LE(0x0ab16f30, input.length - 4);
  const output = protectUf2FirmwareBuffer(input, options);
  expect(output.blocksInjected).toBeGreaterThan(0);
  expect(output.notMainFlashBlocks).toBe(output.blocksInjected);
  expect(output.fileContainerBlocks).toBe(0);
  expect(output.decoyFamilies).toBe(2);
  expect(output.buffer.subarray(0, input.length)).toEqual(input);
  for (let i = 1; i <= output.blocksInjected; i++) {
    const at = i * UF2_BLOCK_BYTES;
    expect(output.buffer.readUInt32LE(at + 8)).toBe(1);
    expect(output.buffer.readUInt32LE(at + 20)).toBe(i);
    expect(output.buffer.readUInt32LE(at + 24)).toBe(output.blocksInjected + 1);
    expect(output.buffer.readUInt32LE(at + 28)).toBe(0);
  }
});

describe("classic PCAP framing", () => {
  for (const magic of ["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"]) {
    it(`preserves byte order, timestamp resolution, and snaplen for ${magic}`, () => {
      const header = Buffer.alloc(24);
      header.write(magic, "hex");
      const le = magic.startsWith("d4") || magic.startsWith("4d");
      const nano = magic.includes("3c");
      const u32 = (bytes: Buffer, at: number) => le ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
      if (le) {
        header.writeUInt16LE(2, 4);
        header.writeUInt16LE(4, 6);
        header.writeUInt32LE(96, 16);
        header.writeUInt32LE(1, 20);
      } else {
        header.writeUInt16BE(2, 4);
        header.writeUInt16BE(4, 6);
        header.writeUInt32BE(96, 16);
        header.writeUInt32BE(1, 20);
      }
      const output = protectPcapCaptureBuffer(header, { intensity: "bankrupt", seed });
      expect(output.packetsInjected).toBeGreaterThan(0);
      expect(output.answerFloodPackets).toBe(0);
      expect(output.buffer.subarray(0, 24)).toEqual(header);
      let at = 24;
      for (let i = 0; i < output.packetsInjected; i++) {
        if (i === 1) expect(u32(output.buffer, at + 4)).toBe(nano ? 1_000_000 : 1_000);
        const captured = u32(output.buffer, at + 8);
        const original = u32(output.buffer, at + 12);
        expect(captured).toBe(Math.min(96, original));
        at += 16 + captured;
      }
      expect(at).toBe(output.buffer.length);
      expect(inspectPcapCapture(output.buffer)).toMatchObject({
        validMagic: true, exactFraming: true, versionMajor: 2, versionMinor: 4,
        packetCount: output.packetsInjected,
      });
    });
  }

  it("leaves captures with a non-Ethernet link type byte-identical", () => {
    const input = Buffer.from("a1b23c4d0002000400000000000000000000ffff00000065", "hex");
    const output = protectPcapCaptureBuffer(input, { intensity: "bankrupt", seed });
    expect(output).toMatchObject({ buffer: input, packetsInjected: 0, answerFloodPackets: 0 });
  });
});

function beam(table: "Atom" | "AtU8", payload: Buffer): Buffer {
  const header = Buffer.from("FOR1\0\0\0\0BEAM" + table + "\0\0\0\0", "latin1");
  const padded = Buffer.concat([header, payload, Buffer.alloc((4 - payload.length % 4) % 4)]);
  padded.writeUInt32BE(padded.length - 8, 4);
  padded.writeUInt32BE(payload.length, 16);
  return padded;
}

describe("BEAM atom tables", () => {
  for (const table of ["Atom", "AtU8"] as const) {
    it(`validates every declared ${table} entry and preserves its wire bytes`, () => {
      for (const malformed of [
        "000000020161", // fewer entries than declared
        "000000010261", // truncated name
        "00000001016100", // unconsumed payload
        "000000000161", // declared empty with a payload
        "ffffffff2061", // invalid compact field, or negative Atom count
      ]) {
        expect(() => protectErlangBeamBuffer(beam(table, Buffer.from(malformed, "hex"))))
          .toThrow(/Malformed BEAM.*atom table/);
      }
      const names = Buffer.from(table === "Atom" ? "01e9" : "02c3a9", "hex");
      const input = beam(table, Buffer.concat([Buffer.from("00000001", "hex"), names]));
      const output = protectErlangBeamBuffer(input, options);
      expect(output.buffer.readUInt32BE(20)).toBe(1 + output.atomsInjected);
      expect(output.buffer.subarray(24, 24 + names.length)).toEqual(names);
    });
  }

  it("preserves compact AtU8 entries and refuses a truncated compact length", () => {
    const valid = beam("AtU8", Buffer.from("ffffffff1061", "hex"));
    const result = protectErlangBeamBuffer(valid, options);
    expect(result.buffer.readInt32BE(20)).toBe(-1 - result.atomsInjected);
    expect(result.buffer.subarray(24, 26)).toEqual(Buffer.from([0x10, 0x61]));
    expect(() => protectErlangBeamBuffer(beam("AtU8", Buffer.from("ffffffff18ff", "hex"))))
      .toThrow(/atom table/);
  });
});

it("avoids PTX symbol collisions with existing globals, functions, entries and prior passes", () => {
  const module = ".version 7.5\n.target sm_80\n.address_size 64\n";
  const plain = protectGpuPtxText(module, options);
  const names = [...plain.text.matchAll(/\.entry (\w+)\(/g)].map((m) => m[1]!);
  const input = module + `
.extern .global .align 4 .u32 ${names[0]};
.visible .const .align 4 .u32 ${names[1]} = 0;
.extern .func (.param .b32 ret) ${names[2]}();
.visible .entry ${names[3]}() { ret; }
`;
  const first = protectGpuPtxText(input, options);
  const second = protectGpuPtxText(first.text, options);
  expect(first.text.startsWith(input)).toBe(true);
  expect(second.text.startsWith(first.text)).toBe(true);
  const injected = [...second.text.slice(input.length).matchAll(/\.entry (\w+)\(/g)].map((m) => m[1]!);
  expect(injected).toHaveLength(first.entriesInjected + second.entriesInjected);
  expect(new Set(injected).size).toBe(injected.length);
  for (const name of names.slice(0, 4)) expect(injected).not.toContain(name);
});

describe("generated concurrent anchors", () => {
  it("uses per-call volatile scratch for C and atomic RMW for Go", () => {
    const c = emitCompileTimeNativeHeader("c", options).content;
    expect(c).toMatch(/static const uint32_t shadow_heap_slots\[32\]/);
    expect(c).toMatch(/volatile uint32_t scratch = shadow_heap_slots\[/);
    expect(c).not.toMatch(/shadow_heap_slots\[[^\]]+\]\s*\^=/);

    const go = emitCompileTimeNativeHeader("go", options).content;
    expect(go).toContain("atomic.LoadUint32(slot)");
    expect(go).toContain("atomic.CompareAndSwapUint32(slot, previous, previous^acc)");
    expect(go).not.toMatch(/ShadowHeapSlots\[[^\]]+\]\s*\^=/);
  });

  it.skipIf(spawnSync("cc", ["--version"]).status !== 0)("compiles and runs the C anchor", () => {
    withScratch((dir) => {
      const file = join(dir, "sample.c");
      const out = join(dir, "sample");
      const header = emitCompileTimeNativeHeader("c", options);
      writeFileSync(join(dir, header.filename), header.content);
      writeFileSync(file, '#include "bla_shield.h"\nint main(void) { return BLA_SHIELD_ANCHOR(7) != BLA_SHIELD_ANCHOR(7); }\n');
      execFileSync("cc", ["-std=c11", "-O2", file, "-o", out], { stdio: "pipe" });
      execFileSync(out, [], { stdio: "pipe" });
    });
  });

  const racePlatforms = ["darwin:arm64", "darwin:x64", "linux:x64", "linux:arm64"];
  const goRaceAvailable = racePlatforms.includes(`${process.platform}:${process.arch}`) &&
    spawnSync("go", ["env", "CGO_ENABLED"], { encoding: "utf8" }).stdout?.trim() === "1";
  it.skipIf(!goRaceAvailable)("runs concurrent Go anchor calls under the Go race detector", () => {
    withScratch((dir) => {
      const header = emitCompileTimeNativeHeader("go", options);
      writeFileSync(join(dir, header.filename), header.content);
      writeFileSync(join(dir, "main.go"), `
package main
import "sync"
func main() {
    var workers sync.WaitGroup
    for i := 0; i < 8; i++ {
        workers.Add(1)
        go func() {
            defer workers.Done()
            for i := 0; i < 500; i++ {
                EnclaveTarpit0(uint32(i), 0)
            }
        }()
    }
    workers.Wait()
}
`);
      execFileSync("go", ["run", "-race", header.filename, "main.go"], { cwd: dir, stdio: "pipe", timeout: 60_000 });
    });
  }, 65_000);
});
