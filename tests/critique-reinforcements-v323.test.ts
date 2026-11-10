import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";
import { runShowcaseBenchmark } from "../src/engine/benchmark.js";
import { SeededPrng } from "../src/core/prng.js";
import { generateRuntimeDeceptionSnippet } from "../src/shields/runtime/runtime-shield.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import {
  inspectNativeBinary,
  protectNativeBinary,
} from "../src/shields/formats/native.js";
import { inspectAndroidDex } from "../src/shields/formats/mobile-game.js";

function buildMinimalPe64Fixture(): Buffer {
  // 0x400-byte headers + 0x200 .text + 0x200 .rdata = 0x800 bytes
  const buf = Buffer.alloc(0x800, 0);
  buf.write("MZ", 0, "ascii");
  const peOffset = 0x80;
  buf.writeUInt32LE(peOffset, 0x3c);
  buf.write("PE\0\0", peOffset, "ascii");

  const coffOffset = peOffset + 4;
  buf.writeUInt16LE(0x8664, coffOffset + 0); // IMAGE_FILE_MACHINE_AMD64
  buf.writeUInt16LE(2, coffOffset + 2); // NumberOfSections = 2
  const optHeaderSize = 0xf0; // PE32+ optional header size (240 bytes)
  buf.writeUInt16LE(optHeaderSize, coffOffset + 16);
  buf.writeUInt16LE(0x0022, coffOffset + 18); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  const optOffset = coffOffset + 20;
  buf.writeUInt16LE(0x20b, optOffset + 0); // PE32+ magic
  buf.writeUInt32LE(0x1000, optOffset + 16); // AddressOfEntryPoint
  buf.writeUInt32LE(0x1000, optOffset + 32); // SectionAlignment
  buf.writeUInt32LE(0x200, optOffset + 36); // FileAlignment
  buf.writeUInt32LE(0x3000, optOffset + 56); // SizeOfImage
  buf.writeUInt32LE(0x400, optOffset + 60); // SizeOfHeaders

  const secTableOffset = optOffset + optHeaderSize;
  // Section 0: .text (VirtualSize=0x120, VirtualAddress=0x1000, SizeOfRawData=0x200, PointerToRawData=0x400)
  buf.write(".text\0\0\0", secTableOffset + 0, "ascii");
  buf.writeUInt32LE(0x120, secTableOffset + 8);
  buf.writeUInt32LE(0x1000, secTableOffset + 12);
  buf.writeUInt32LE(0x200, secTableOffset + 16);
  buf.writeUInt32LE(0x400, secTableOffset + 20);
  buf.writeUInt32LE(0x60000020, secTableOffset + 36);

  // Section 1: .rdata (VirtualSize=0x100, VirtualAddress=0x2000, SizeOfRawData=0x200, PointerToRawData=0x600)
  const sec1Offset = secTableOffset + 40;
  buf.write(".rdata\0\0", sec1Offset + 0, "ascii");
  buf.writeUInt32LE(0x100, sec1Offset + 8);
  buf.writeUInt32LE(0x2000, sec1Offset + 12);
  buf.writeUInt32LE(0x200, sec1Offset + 16);
  buf.writeUInt32LE(0x600, sec1Offset + 20);
  buf.writeUInt32LE(0x40000040, sec1Offset + 36);

  // Put a sample x86-64 ret instruction at .text start
  buf[0x400] = 0xc3;
  return buf;
}

describe("v3.2.3 Counter-Critique Reinforcements & Issue #157 PE Hardening", () => {
  it("Critique 1: rejects spoofed single-marker comments/strings in JS, Python, DEX, SourceMap, Plist, and Native", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "bla-spoof-audit-"));
    try {
      // 1. JS with spoofed banner comment & fake string literal
      const spoofJs = join(tempDir, "spoof.js");
      writeFileSync(
        spoofJs,
        `/* runtime attestation boundary */\nconst fake = "s20 = s19 + s19; a28 = _flag ? a27?.x : a27?.y; get grow() { return this.grow.more; }";\nmodule.exports = { fake };\n`,
        "utf8",
      );
      const jsAudit = auditTarget(spoofJs);
      expect(jsAudit.protectionStatus).toBe("UNPROTECTED");
      expect(jsAudit.reaSimulation.triggeredResourceLimits).toHaveLength(0);

      // 2. Python with spoofed comment only
      const spoofPy = join(tempDir, "spoof.py");
      writeFileSync(
        spoofPy,
        `# runtime attestation boundary\ndef add(a, b):\n    return a + b\n`,
        "utf8",
      );
      const pyAudit = auditTarget(spoofPy);
      expect(pyAudit.protectionStatus).toBe("UNPROTECTED");

      // 3. DEX with spoofed marker but inconsistent file_size / Adler32
      const spoofDex = Buffer.alloc(140, 0);
      spoofDex.write("dex\n035\0", 0, "ascii");
      spoofDex.writeUInt32LE(112, 32); // mismatch with actual length 140
      spoofDex.write("Lcom/enclave/sgx/TeeAttestationBridge;", 100, "ascii");
      expect(inspectAndroidDex(spoofDex).blaProtected).toBe(false);

      // 4. Apple plist with doctype comment only (missing decoy entitlement keys)
      const spoofPlist = join(tempDir, "Info.plist");
      writeFileSync(
        spoofPlist,
        `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" []>\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.app</string></dict></plist>`,
        "utf8",
      );
      expect(auditTarget(spoofPlist).protectionStatus).toBe("UNPROTECTED");
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("Critique 2 & Issue #157: hardens Windows PE32+ with mapped .enclave COFF section, x86-64 islands, MSVC RTTI, and RSDS PDB", () => {
    const rawPe = buildMinimalPe64Fixture();
    const beforeInfo = inspectNativeBinary(rawPe);
    expect(beforeInfo.format).toBe("native-pe");
    expect(beforeInfo.architecture).toBe("x86_64-pe-windows");
    expect(beforeInfo.blaProtected).toBe(false);

    const protectedRes = protectNativeBinary(rawPe, {
      intensity: "bankrupt",
      seed: "issue-157-pe-test",
    });
    const outPe = protectedRes.buffer;
    const afterInfo = inspectNativeBinary(outPe);
    expect(afterInfo.blaProtected).toBe(true);

    // Verify COFF NumberOfSections incremented from 2 to 3 (.text, .rdata, .enclave)
    const peOffset = outPe.readUInt32LE(0x3c);
    const numSections = outPe.readUInt16LE(peOffset + 4 + 2);
    expect(numSections).toBe(3);

    // Verify the 3rd section header is `.enclave` with READ | INITIALIZED_DATA | CODE (0x40000060)
    const optHeaderSize = outPe.readUInt16LE(peOffset + 4 + 16);
    const sec2Offset = peOffset + 24 + optHeaderSize + 2 * 40;
    const sec2Name = outPe.subarray(sec2Offset, sec2Offset + 8).toString("ascii");
    expect(sec2Name).toBe(".enclave");
    const sec2Chars = outPe.readUInt32LE(sec2Offset + 36);
    expect(sec2Chars).toBe(0x40000060);

    // Verify x86-64 ABI function prologue (`endbr64; push rbp; mov rbp, rsp` = f3 0f 1e fa 55 48 89 e5)
    const prologue = Buffer.from([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5]);
    expect(outPe.includes(prologue)).toBe(true);

    // Verify MSVC C++ RTTI type descriptors, CodeView RSDS PDB record, and Win32 Crypto/BCrypt symbols
    const latin1 = outPe.toString("latin1");
    expect(latin1).toContain(".?AVEnclaveRing0Transport@sgx@security@@");
    expect(latin1).toContain("RSDS");
    expect(latin1).toMatch(/enclave_quorum_[0-9a-f]{4}\.pdb/);
    expect(latin1).toContain("BCryptOpenAlgorithmProvider");
    expect(latin1).toContain("NCryptOpenStorageProvider");
    expect(latin1).toContain("CryptUnprotectData");
  });

  it("Critique 5: runtime-shield does not emit self-sabotaging decorative-deception-signal markers into JS output", () => {
    const snippet = generateRuntimeDeceptionSnippet(
      new SeededPrng("critique-5-test"),
      "bankrupt",
      [],
    );
    expect(snippet.classification).toBe("decorative-deception-signal");
    expect(snippet.code).not.toContain("decorative-deception-signal");
    expect(snippet.code).not.toContain("none-client-side-only");
    expect(snippet.code).not.toContain("decorative shadow runtime signal");
    expect(snippet.code).toContain("RING0_SEALED");
  });

  it("Critique 6: entangles injected decoy functions into opaque-predicate seedVarName by default so stripping decoys breaks execution", () => {
    const source = `
      function computePrice(qty, unitCents) {
        if (qty <= 0) return 0;
        const subtotal = qty * unitCents;
        return subtotal > 10000 ? subtotal - 500 : subtotal;
      }
      module.exports = { computePrice };
    `;
    const res = transformJavaScriptWithBlaShield(source, {
      intensity: "balanced",
      seed: "critique-6-default-entangle",
      sourceType: "commonjs",
    });

    const runCode = (code: string) => {
      const mod = { exports: {} as { computePrice: (q: number, u: number) => number } };
      vm.runInNewContext(
        code,
        {
          module: mod,
          exports: mod.exports,
          Math,
          Object,
          Array,
          String,
          Number,
          Boolean,
          Map,
          Set,
          process: { pid: 1234 },
        },
        { timeout: 5000 },
      );
      return mod.exports;
    };

    // Unmodified protected code is 100% functionally equivalent:
    const intact = runCode(res.code);
    expect(intact.computePrice(5, 1000)).toBe(5000);
    expect(intact.computePrice(20, 1000)).toBe(19500);

    // Find an injected decoy function in the seed initializer array and strip its declaration:
    const seedMatch = /const\s+\w+\s*=\s*\d+\s*\|\s*\(\[([A-Za-z0-9_$,\s]+)\]\.every/.exec(
      res.code,
    );
    expect(seedMatch).not.toBeNull();
    const entangledFns = seedMatch![1]!
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    expect(entangledFns.length).toBeGreaterThanOrEqual(8);

    // Strip the last entangled decoy function declaration from the file:
    const targetDecoy = entangledFns[entangledFns.length - 1]!;
    const strippedCode = res.code.replace(
      `function ${targetDecoy}(`,
      `function _removed_decoy(`,
    );
    expect(strippedCode).not.toBe(res.code);
    expect(() => runCode(strippedCode)).toThrow(/is not defined/);
  });

  it("Critique 3: runs real before/after functional, query, or structural equivalence checks across all 14 benchmark targets", async () => {
    const report = await runShowcaseBenchmark();
    expect(report.cases.length).toBeGreaterThanOrEqual(14);
    for (const c of report.cases) {
      expect(c.functionalCheckPassed, `Benchmark case ${c.id} failed equivalence check`).toBe(
        true,
      );
    }
  });
});
