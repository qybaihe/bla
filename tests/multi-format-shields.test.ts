import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { inspectWasmBinary, protectWasmBinary } from "../src/shields/formats/wasm.js";
import {
  inspectPythonPyc,
  protectPythonPycBuffer,
  protectPythonSource,
} from "../src/shields/formats/python.js";
import { inspectNativeBinary, protectNativeBinary } from "../src/shields/formats/native.js";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import {
  protectZipOrApkBuffer,
  readZipEntries,
  writeZipArchive,
} from "../src/shields/formats/archive.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";

describe("Multi-Format Shields (WASM, Python, Native ELF/Mach-O/PE, C/Rust/Go Headers, ZIP/APK)", () => {
  it("protects WebAssembly (.wasm) binaries while preserving WebAssembly.validate() and exported execution", () => {
    // Minimal valid WASM module exporting `compute_score(i32) -> i32` = x * 42 + 7
    const rawWasm = Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
      0x03, 0x02, 0x01, 0x00,
      0x07, 0x11, 0x01, 0x0d, 0x63, 0x6f, 0x6d, 0x70,
      0x75, 0x74, 0x65, 0x5f, 0x73, 0x63, 0x6f, 0x72,
      0x65, 0x00, 0x00,
      0x0a, 0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x41,
      0x2a, 0x6c, 0x41, 0x07, 0x6a, 0x0b,
    ]);

    const infoBefore = inspectWasmBinary(rawWasm);
    expect(infoBefore.validMagic).toBe(true);
    expect(infoBefore.exportNames).toContain("compute_score");

    const protectedRes = protectWasmBinary(rawWasm, {
      intensity: "balanced",
      seed: "wasm-test-seed",
    });
    expect(protectedRes.customSectionsAdded).toBe(9);
    // balanced intensity stays under the 32 MiB REA interface budget; bankrupt exceeds.
    expect(protectedRes.exceedsRepresentationBudget).toBe(false);
    expect(protectedRes.exportDecoysInjected).toBe(2);
    expect(protectedRes.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedRes.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedRes.chaffPayloadsEmbedded).toBeGreaterThanOrEqual(4);

    const infoAfter = inspectWasmBinary(protectedRes.buffer);
    expect(infoAfter.validMagic).toBe(true);
    expect(infoAfter.debugModuleName).toContain("tee_hardware_enclave_transport_stub_");
    expect(infoAfter.customSectionNames).toContain("bla.canary.credentials");
    expect(infoAfter.customSectionNames).toContain("bla.system.diagnostics");
    expect(protectedRes.buffer.toString("utf8")).toContain("AKIAIOSFODNN7EXAMPLE");
    expect(protectedRes.buffer.toString("utf8")).toContain("DarwinProcessOwnershipInspectionError");

    // Validate with V8's native WebAssembly engine and execute exported function
    expect(WebAssembly.validate(new Uint8Array(protectedRes.buffer))).toBe(true);

    const modBefore = new WebAssembly.Module(new Uint8Array(rawWasm));
    const instBefore = new WebAssembly.Instance(modBefore);
    const fnBefore = instBefore.exports.compute_score as (x: number) => number;

    const modAfter = new WebAssembly.Module(new Uint8Array(protectedRes.buffer));
    const instAfter = new WebAssembly.Instance(modAfter);
    const fnAfter = instAfter.exports.compute_score as (x: number) => number;

    expect(fnAfter(10)).toBe(fnBefore(10));
    expect(fnAfter(10)).toBe(427);
  });

  it("protects Python (.py) source and CPython (.pyc) bytecode while preserving module semantics", () => {
    const pyPath = path.resolve(process.cwd(), "examples/python-offline-engine/pricing_engine.py");
    const rawPy = fs.readFileSync(pyPath, "utf8");

    const protectedPy = protectPythonSource(rawPy, {
      intensity: "balanced",
      seed: "python-test-seed",
    });

    expect(protectedPy.decoyFunctionsInjected).toBeGreaterThanOrEqual(10);
    expect(protectedPy.crossReferenceEdges).toBeGreaterThanOrEqual(20);
    expect(protectedPy.code).toContain("runtime attestation boundary");
    expect(protectedPy.code).not.toMatch(/_bla_/i);
    expect(protectedPy.code).not.toContain("BLA-SHIELD");
    expect(protectedPy.code).toContain("def calculate_dynamic_quote");
    expect(protectedPy.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedPy.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedPy.code).toContain("CANARY_TOKENS");
    expect(protectedPy.code).toContain("AKIAIOSFODNN7EXAMPLE");
    expect(protectedPy.code).toContain("DarwinProcessOwnershipInspectionError");
    expect(protectedPy.code).toContain("https:/canary_");
    // Live warm + shared slot: decoys are not empty unreferenced stubs
    expect(protectedPy.code).toMatch(/\["warm"\]\s*=/);
    expect(protectedPy.code).toMatch(/dict\s*=\s*\{"epoch":/);

    // Test .pyc shield on a synthetic CPython 3.11 .pyc buffer
    const fakePycHeader = Buffer.alloc(16);
    fakePycHeader.writeUInt16LE(3495, 0); // Python 3.11 magic
    fakePycHeader[2] = 0x0d;
    fakePycHeader[3] = 0x0a;
    const fakeMarshalPayload = Buffer.from(
      "e30000000000000000000000000200000040000000730400000064005300",
      "hex",
    );
    const rawPyc = Buffer.concat([fakePycHeader, fakeMarshalPayload]);

    const protectedPyc = protectPythonPycBuffer(rawPyc, {
      intensity: "balanced",
      seed: "pyc-seed",
    });
    expect(protectedPyc.buffer.length).toBeGreaterThan(rawPyc.length);
    expect(protectedPyc.buffer.subarray(0, 16).equals(rawPyc.subarray(0, 16))).toBe(true);
    expect(protectedPyc.canaryTokensEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedPyc.diagnosticsEmbedded).toBeGreaterThanOrEqual(2);
    expect(protectedPyc.buffer.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
    expect(protectedPyc.buffer.toString("latin1")).toContain("DarwinProcessOwnershipInspectionError");

    const pycInfo = inspectPythonPyc(protectedPyc.buffer);
    expect(pycInfo.validPyc).toBe(true);
    expect(pycInfo.blaProtected).toBe(true);
  });

  it("trips REA's MAX_RUSTC_HASHES (64) and injects decoy Rust/Go metadata into Native ELF64 binaries", () => {
    // Build a synthetic ELF64 binary with a .rodata section
    const elf = Buffer.alloc(512, 0);
    elf[0] = 0x7f;
    elf[1] = 0x45;
    elf[2] = 0x4c;
    elf[3] = 0x46;
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[6] = 1;
    elf.writeUInt16LE(0x3e, 18); // x86_64

    const eShoff = 64;
    const shEntSize = 64;
    const shNum = 3;
    elf.writeBigUInt64LE(BigInt(eShoff), 40);
    elf.writeUInt16LE(shEntSize, 58);
    elf.writeUInt16LE(shNum, 60);
    elf.writeUInt16LE(1, 62); // e_shstrndx = 1

    const shstrtabOffset = 256;
    const shstrtab = Buffer.from("\0.shstrtab\0.rodata\0", "utf8");
    shstrtab.copy(elf, shstrtabOffset);

    const sh1 = eShoff + shEntSize;
    elf.writeUInt32LE(1, sh1 + 0);
    elf.writeUInt32LE(3, sh1 + 4);
    elf.writeBigUInt64LE(BigInt(shstrtabOffset), sh1 + 24);
    elf.writeBigUInt64LE(BigInt(shstrtab.length), sh1 + 32);

    const rodataOffset = 320;
    const rodataContent = Buffer.from(
      "/rustc/a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4/library/core\0",
      "utf8",
    );
    rodataContent.copy(elf, rodataOffset);

    const sh2 = eShoff + shEntSize * 2;
    elf.writeUInt32LE(11, sh2 + 0); // .rodata
    elf.writeUInt32LE(1, sh2 + 4); // SHT_PROGBITS
    elf.writeBigUInt64LE(BigInt(2), sh2 + 8); // SHF_ALLOC
    elf.writeBigUInt64LE(BigInt(rodataOffset), sh2 + 24);
    elf.writeBigUInt64LE(BigInt(rodataContent.length), sh2 + 32);

    const beforeInfo = inspectNativeBinary(elf);
    expect(beforeInfo.format).toBe("native-elf");
    expect(beforeInfo.rustcCommitHashesCount).toBe(1);

    const protectedElf = protectNativeBinary(elf, {
      intensity: "balanced",
      seed: "elf-seed",
    });
    expect(protectedElf.rustcHashesInjected).toBeGreaterThan(
      REA_INTERNAL_LIMITS.RUST_MAX_COMMIT_HASHES,
    );
    expect(protectedElf.binarySectionsPatched).toBeGreaterThanOrEqual(2);

    const afterInfo = inspectNativeBinary(protectedElf.buffer);
    expect(afterInfo.rustcCommitHashesCount).toBeGreaterThan(
      REA_INTERNAL_LIMITS.RUST_MAX_COMMIT_HASHES,
    );
    expect(afterInfo.blaProtected).toBe(true);
  });

  it("emits compile-time C/C++, Rust, and Go shield headers with >64 rustc hashes and opaque predicates", () => {
    const cHeader = emitCompileTimeNativeHeader("c", {
      intensity: "balanced",
      seed: "header-seed",
    });
    const rustHeader = emitCompileTimeNativeHeader("rust", {
      intensity: "balanced",
      seed: "header-seed",
    });
    const goHeader = emitCompileTimeNativeHeader("go", {
      intensity: "balanced",
      seed: "header-seed",
    });

    expect(cHeader.filename).toBe("bla_shield.h");
    expect(cHeader.content).toContain("BLA_SHIELD_ANCHOR");
    expect(cHeader.content).toContain("#if defined(_MSC_VER) && !defined(__clang__)");
    expect(cHeader.content).toContain("#define BLA_NOINLINE __declspec(noinline)");
    expect(cHeader.content).toContain("#pragma warning(disable: 4100 4127 4189 4505)");
    expect(cHeader.content).toContain('extern "C"');
    expect(cHeader.content).toContain("enclave_keep_data_table");
    expect(cHeader.content).toContain("enclave_keep_fn_table");
    expect(rustHeader.filename).toBe("bla_shield.rs");
    expect(rustHeader.content).toContain("BLA_RUSTC_OVERFLOW_TABLE");
    expect(goHeader.filename).toBe("bla_shield.go");
    expect(goHeader.content).toContain("func EnclaveTarpit0");
  });

  it("protects supported minimal ZIP archives while preserving existing entries", () => {
    const rawZip = writeZipArchive([
      {
        name: "assets/index.js",
        data: Buffer.from(`function verifyApp() { return "prod-token-987654321"; }\n`, "utf8"),
      },
      {
        name: "META-INF/MANIFEST.MF",
        data: Buffer.from("Manifest-Version: 1.0\n", "utf8"),
      },
    ]);

    const entriesBefore = readZipEntries(rawZip);
    expect(entriesBefore.length).toBe(2);

    const protectedZip = protectZipOrApkBuffer(rawZip, {
      intensity: "balanced",
      seed: "zip-test-seed",
      isApk: false,
    });

    expect(protectedZip.decoyEntriesInjected).toBe(6); // manifest + canary file + 4 shadow decoys
    expect(protectedZip.chaffPayloadsEmbedded).toBeGreaterThanOrEqual(4);

    const entriesAfter = readZipEntries(protectedZip.buffer);
    expect(entriesAfter.length).toBe(8); // 2 originals + manifest + canary + 4 decoys
    expect(
      entriesAfter.some((e) => e.name === "assets/enclave/bla-attestation-manifest.json"),
    ).toBe(true);
    expect(
      entriesAfter.some((e) => e.name === "assets/enclave/bla-canary-tokens.txt"),
    ).toBe(true);
    expect(protectedZip.canaryTokensEmbedded).toBeGreaterThan(0);
  });
});
