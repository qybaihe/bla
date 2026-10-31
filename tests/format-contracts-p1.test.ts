import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { parse } from "@babel/parser";
import { describe, expect, it } from "vitest";
import {
  blaEsbuildPlugin,
  blaRollupPlugin,
  inferCarrierFromRollupFormat,
  inferEsbuildLoader,
} from "../src/bundler/index.js";
import {
  packAsarBuffer,
  unpackAsarBuffer,
  UnsupportedAsarError,
  validateAsarBuffer,
  validateAsarProtectionInput,
} from "../src/shields/formats/asar.js";
import {
  ELECTRON_FUSE_SENTINEL_BYTES,
  ELECTRON_FUSE_STATE,
  hardenElectronFusesWithContext,
  inspectElectronFusesBuffer,
  UnsupportedElectronFuseContextError,
} from "../src/shields/formats/electron-fuses.js";
import {
  InvalidNativeBinaryError,
  protectNativeBinary,
  validateElf64Layout,
} from "../src/shields/formats/native.js";
import {
  findPythonPrologueInsertionOffset,
  InvalidPythonSourceError,
  protectPythonSource,
} from "../src/shields/formats/python.js";
import {
  InvalidJavaScriptCarrierError,
  transformJavaScriptWithBlaShield,
} from "../src/shields/javascript/ast-shield.js";

function buildRawAsarBuffer(
  headerObj: unknown,
  payload: Buffer = Buffer.alloc(0),
): Buffer {
  const jsonBytes = Buffer.from(JSON.stringify(headerObj), "utf8");
  const jsonStringSize = jsonBytes.length;
  const alignedJsonSize = Math.ceil(jsonStringSize / 4) * 4;
  const innerPickleSize = alignedJsonSize + 4;
  const headerSize = innerPickleSize + 4;

  const headerBuffer = Buffer.alloc(8 + headerSize, 0);
  headerBuffer.writeUInt32LE(4, 0);
  headerBuffer.writeUInt32LE(headerSize, 4);
  headerBuffer.writeUInt32LE(innerPickleSize, 8);
  headerBuffer.writeUInt32LE(jsonStringSize, 12);
  jsonBytes.copy(headerBuffer, 16);

  return Buffer.concat([headerBuffer, payload]);
}

function buildValidElf64Fixture(options?: {
  readonly bssExtraBytes?: bigint;
  readonly embedElectronFuse?: boolean;
}): Buffer {
  // Layout (total 1024 bytes):
  // [0..64)      ELF64 Header (64 bytes)
  // [64..176)    Program Header Table: 2 entries * 56 bytes = 112 bytes
  // [176..512)   Section 1 (.rodata, SHT_PROGBITS, 168 bytes) + Section 2 (.eh_frame, SHT_PROGBITS, 168 bytes)
  // [512..640)   Section 3 (.data, SHT_PROGBITS, 128 bytes) + Section 4 (.bss, SHT_NOBITS, at offset 640, size 4096)
  // [640..704)   Section 5 (.shstrtab, SHT_STRTAB, 64 bytes)
  // [704..1088)  Section Header Table: 6 entries * 64 bytes = 384 bytes -> total 1088 bytes
  const totalSize = 1088;
  const buf = Buffer.alloc(totalSize, 0);

  // ELF64 magic + ELFCLASS64 (2) + ELFDATA2LSB (1) + EV_CURRENT (1)
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = 2; // 64-bit
  buf[5] = 1; // little-endian
  buf[6] = 1; // version
  buf.writeUInt16LE(2, 16); // e_type = ET_EXEC
  buf.writeUInt16LE(0x3e, 18); // e_machine = EM_X86_64
  buf.writeUInt32LE(1, 20); // e_version
  buf.writeBigUInt64LE(0x400000n, 24); // e_entry
  buf.writeBigUInt64LE(64n, 32); // e_phoff = 64
  buf.writeBigUInt64LE(704n, 40); // e_shoff = 704
  buf.writeUInt16LE(64, 52); // e_ehsize = 64
  buf.writeUInt16LE(56, 54); // e_phentsize = 56
  buf.writeUInt16LE(2, 56); // e_phnum = 2
  buf.writeUInt16LE(64, 58); // e_shentsize = 64
  buf.writeUInt16LE(6, 60); // e_shnum = 6
  buf.writeUInt16LE(5, 62); // e_shstrndx = 5

  // Program Header 0: PT_LOAD (read-only segment covering [0..512))
  const ph0 = 64;
  buf.writeUInt32LE(1, ph0 + 0); // PT_LOAD
  buf.writeUInt32LE(4, ph0 + 4); // PF_R
  buf.writeBigUInt64LE(0n, ph0 + 8); // p_offset = 0
  buf.writeBigUInt64LE(0x400000n, ph0 + 16); // p_vaddr
  buf.writeBigUInt64LE(0x400000n, ph0 + 24); // p_paddr
  buf.writeBigUInt64LE(512n, ph0 + 32); // p_filesz = 512
  buf.writeBigUInt64LE(512n, ph0 + 40); // p_memsz = 512
  buf.writeBigUInt64LE(0x1000n, ph0 + 48); // p_align

  // Program Header 1: PT_LOAD (read-write data + BSS segment ending at EOF!)
  // Note: p_offset = 512, p_filesz = 576 (512 + 576 === 1088 === totalSize!),
  // while p_memsz = 576 + bssExtraBytes (e.g. 4672 bytes > p_filesz)
  const bssExtra = options?.bssExtraBytes ?? 4096n;
  const ph1 = 64 + 56;
  buf.writeUInt32LE(1, ph1 + 0); // PT_LOAD
  buf.writeUInt32LE(6, ph1 + 4); // PF_R | PF_W
  buf.writeBigUInt64LE(512n, ph1 + 8); // p_offset = 512
  buf.writeBigUInt64LE(0x600000n, ph1 + 16); // p_vaddr
  buf.writeBigUInt64LE(0x600000n, ph1 + 24); // p_paddr
  buf.writeBigUInt64LE(576n, ph1 + 32); // p_filesz = 576 (reaches EOF 1088)
  buf.writeBigUInt64LE(576n + bssExtra, ph1 + 40); // p_memsz > p_filesz (BSS!)
  buf.writeBigUInt64LE(0x1000n, ph1 + 48); // p_align

  // Populate .rodata [176..344) and .eh_frame [344..512)
  buf.write("RODATA_PAYLOAD_V1\0", 176, "ascii");
  if (options?.embedElectronFuse) {
    const fusePos = 200;
    ELECTRON_FUSE_SENTINEL_BYTES.copy(buf, fusePos);
    const wireStart = fusePos + ELECTRON_FUSE_SENTINEL_BYTES.length;
    buf[wireStart] = 1; // version 1
    buf[wireStart + 1] = 6; // 6 fuses
    buf[wireStart + 2 + 0] = ELECTRON_FUSE_STATE.ENABLED; // RunAsNode = '1' (vulnerable)
    buf[wireStart + 2 + 1] = ELECTRON_FUSE_STATE.DISABLED; // CookieEncryption = '0'
    buf[wireStart + 2 + 2] = ELECTRON_FUSE_STATE.ENABLED; // NodeOptions = '1'
    buf[wireStart + 2 + 3] = ELECTRON_FUSE_STATE.ENABLED; // NodeCliInspect = '1'
    buf[wireStart + 2 + 4] = ELECTRON_FUSE_STATE.DISABLED; // AsarIntegrity = '0'
    buf[wireStart + 2 + 5] = ELECTRON_FUSE_STATE.DISABLED; // OnlyLoadAppFromAsar = '0'
  }
  buf.write("EH_FRAME_CIE_FDE\0", 344, "ascii");
  buf.write("RW_DATA_BLOCK\0", 512, "ascii");
  buf.write("\0.rodata\0.eh_frame\0.data\0.bss\0.shstrtab\0", 640, "ascii");

  const writeShdr = (
    idx: number,
    nameOff: number,
    type: number,
    flags: bigint,
    addr: bigint,
    offset: bigint,
    size: bigint,
  ) => {
    const base = 704 + idx * 64;
    buf.writeUInt32LE(nameOff, base + 0);
    buf.writeUInt32LE(type, base + 4);
    buf.writeBigUInt64LE(flags, base + 8);
    buf.writeBigUInt64LE(addr, base + 16);
    buf.writeBigUInt64LE(offset, base + 24);
    buf.writeBigUInt64LE(size, base + 32);
  };

  // Section 0: SHT_NULL
  writeShdr(0, 0, 0, 0n, 0n, 0n, 0n);
  // Section 1: .rodata (SHT_PROGBITS = 1, SHF_ALLOC = 2) [176..344)
  writeShdr(1, 1, 1, 2n, 0x4000b0n, 176n, 168n);
  // Section 2: .eh_frame (SHT_PROGBITS = 1, SHF_ALLOC = 2) [344..512)
  writeShdr(2, 9, 1, 2n, 0x400158n, 344n, 168n);
  // Section 3: .data (SHT_PROGBITS = 1, SHF_WRITE | SHF_ALLOC = 3) [512..640)
  writeShdr(3, 19, 1, 3n, 0x600000n, 512n, 128n);
  // Section 4: .bss (SHT_NOBITS = 8, SHF_WRITE | SHF_ALLOC = 3) at 640, size 4096
  writeShdr(4, 25, 8, 3n, 0x600080n, 640n, bssExtra);
  // Section 5: .shstrtab (SHT_STRTAB = 3) [640..704)
  writeShdr(5, 30, 3, 0n, 0n, 640n, 64n);

  return buf;
}

describe("P1 Format Contracts (#13 ASAR, #14 Python, #15 JS/Bundler, #16 ELF64, #17 Electron Fuses)", () => {
  describe("Issue #13: ASAR node preservation and fail-closed validation", () => {
    it("preserves normal files, empty files, nested directories, executable flags, links, and unpacked nodes across pack/unpack", () => {
      const entries = [
        {
          relativePath: "package.json",
          content: Buffer.from('{"name":"app","main":"dist/index.js"}', "utf8"),
        },
        {
          relativePath: "dist/empty.txt",
          content: Buffer.alloc(0),
        },
        {
          relativePath: "dist/bin/launcher",
          content: Buffer.from("#!/bin/sh\necho ok\n", "utf8"),
          executable: true,
        },
        {
          relativePath: "dist/current-launcher",
          content: Buffer.alloc(0),
          link: "bin/launcher",
        },
        {
          relativePath: "native/addon.node",
          content: Buffer.alloc(0),
          unpacked: true,
          size: 4096,
          executable: true,
        },
      ] as const;

      const packed = packAsarBuffer(entries);
      const unpacked = unpackAsarBuffer(packed, {
        allowUnpacked: true,
        allowLinks: true,
      });

      expect(unpacked).toHaveLength(5);
      expect(unpacked[0]?.relativePath).toBe("package.json");
      expect(unpacked[0]?.content.toString("utf8")).toBe(
        '{"name":"app","main":"dist/index.js"}',
      );
      expect(unpacked[1]?.relativePath).toBe("dist/empty.txt");
      expect(unpacked[1]?.content.length).toBe(0);
      expect(unpacked[2]?.relativePath).toBe("dist/bin/launcher");
      expect(unpacked[2]?.executable).toBe(true);
      expect(unpacked[3]?.relativePath).toBe("dist/current-launcher");
      expect(unpacked[3]?.link).toBe("bin/launcher");
      expect(unpacked[4]?.relativePath).toBe("native/addon.node");
      expect(unpacked[4]?.unpacked).toBe(true);
      expect(unpacked[4]?.size).toBe(4096);
      expect(unpacked[4]?.executable).toBe(true);

      // Fail closed in standalone protection validation when unpacked nodes exist without companion handling
      expect(() => validateAsarProtectionInput(packed)).toThrow(
        UnsupportedAsarError,
      );
      expect(
        validateAsarProtectionInput(packed, { allowUnpacked: true }),
      ).toHaveLength(5);
    });

    it("rejects invalid offsets (undefined, NaN, negative, non-numeric, out-of-bounds) and escaping symlinks with UnsupportedAsarError", () => {
      const payload = Buffer.from("hello world", "utf8");

      // 1. Missing offset on packed node
      const missingOffset = buildRawAsarBuffer(
        { files: { "a.txt": { size: 5 } } },
        payload,
      );
      expect(() => validateAsarBuffer(missingOffset)).toThrow(
        UnsupportedAsarError,
      );

      // 2. NaN / non-numeric offset
      const nanOffset = buildRawAsarBuffer(
        { files: { "a.txt": { size: 5, offset: "NaN" } } },
        payload,
      );
      expect(() => validateAsarBuffer(nanOffset)).toThrow(UnsupportedAsarError);

      // 3. Partially numeric offset ("12abc")
      const partialNumeric = buildRawAsarBuffer(
        { files: { "a.txt": { size: 5, offset: "0abc" } } },
        payload,
      );
      expect(() => validateAsarBuffer(partialNumeric)).toThrow(
        UnsupportedAsarError,
      );

      // 4. Negative offset ("-1")
      const negativeOffset = buildRawAsarBuffer(
        { files: { "a.txt": { size: 5, offset: "-1" } } },
        payload,
      );
      expect(() => validateAsarBuffer(negativeOffset)).toThrow(
        UnsupportedAsarError,
      );

      // 5. Out-of-bounds size
      const outOfBounds = buildRawAsarBuffer(
        { files: { "a.txt": { size: 999, offset: "0" } } },
        payload,
      );
      expect(() => validateAsarBuffer(outOfBounds)).toThrow(
        UnsupportedAsarError,
      );

      // 6. Escaping link target ("../../etc/passwd")
      const escapingLink = buildRawAsarBuffer({
        files: {
          sub: {
            files: {
              evil: { link: "../../etc/passwd" },
            },
          },
        },
      });
      expect(() => validateAsarBuffer(escapingLink)).toThrow(
        UnsupportedAsarError,
      );

      // 7. Unknown node shape
      const unknownNode = buildRawAsarBuffer({
        files: {
          mystery: { customType: "device" },
        },
      });
      expect(() => validateAsarBuffer(unknownNode)).toThrow(
        UnsupportedAsarError,
      );
    });
  });

  describe("Issue #14: Python module docstring and future-import prologue placement", () => {
    const PYTHON_BIN =
      ["python3", "python"].find((candidate) => {
        const res = spawnSync(candidate, ["-c", "import sys; sys.exit(0)"], {
          stdio: "pipe",
        });
        return res.status === 0;
      }) ?? "python3";

    function verifyPythonAstAndDocstring(
      code: string,
      expectedDocstring: string | null,
      expectedFutureNames: readonly string[],
    ): void {
      const tmpDir = mkdtempSync(join(tmpdir(), "bla-py-test-"));
      const pyFile = join(tmpDir, "module_under_test.py");
      try {
        writeFileSync(pyFile, code, "utf8");
        const script = [
          "import ast, json, sys",
          "with open(sys.argv[1], 'rb') as f: src = f.read()",
          "tree = ast.parse(src, filename=sys.argv[1])",
          "compile(tree, sys.argv[1], 'exec')",
          "doc = ast.get_docstring(tree, clean=False)",
          "futures = []",
          "for node in tree.body:",
          "    if isinstance(node, ast.ImportFrom) and node.module == '__future__':",
          "        futures.extend(alias.name for alias in node.names)",
          "print(json.dumps({'doc': doc, 'futures': futures}))",
        ].join("\n");
        const stdout = execFileSync(PYTHON_BIN, ["-c", script, pyFile], {
          encoding: "utf8",
        });
        const parsed = JSON.parse(stdout.trim()) as {
          doc: string | null;
          futures: string[];
        };
        expect(parsed.doc).toBe(expectedDocstring);
        expect(parsed.futures).toEqual(expectedFutureNames);
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    }

    it("preserves module __doc__ and single-line from __future__ import (Input A)", () => {
      const inputA = [
        '"""Public module documentation."""',
        "from __future__ import annotations",
        "value = 1",
        "",
      ].join("\n");

      const analysis = findPythonPrologueInsertionOffset(inputA);
      expect(analysis.hasDocstring).toBe(true);
      expect(analysis.futureImports).toEqual([
        "from __future__ import annotations",
      ]);

      const result = protectPythonSource(inputA, { seed: "issue-14-a" });
      expect(
        result.code.startsWith(
          '"""Public module documentation."""\nfrom __future__ import annotations\n',
        ),
      ).toBe(true);
      verifyPythonAstAndDocstring(
        result.code,
        "Public module documentation.",
        ["annotations"],
      );
    });

    it("preserves multi-line parenthesized from __future__ import without splitting (Input B)", () => {
      const inputB = [
        "from __future__ import (",
        "    annotations,",
        "    division,",
        ")",
        "value = 1",
        "",
      ].join("\n");

      const analysis = findPythonPrologueInsertionOffset(inputB);
      expect(analysis.hasDocstring).toBe(false);
      expect(analysis.futureImports).toHaveLength(1);

      const result = protectPythonSource(inputB, { seed: "issue-14-b" });
      expect(
        result.code.startsWith(
          "from __future__ import (\n    annotations,\n    division,\n)\n",
        ),
      ).toBe(true);
      verifyPythonAstAndDocstring(result.code, null, [
        "annotations",
        "division",
      ]);
    });

    it("handles backslash-continued future imports, multi-line/raw docstrings, comments, CRLF, empty files, and fails closed on invalid syntax", () => {
      const crlfSource = [
        "#!/usr/bin/env python3",
        "# -*- coding: utf-8 -*-",
        'r"""Multi-line raw docstring',
        'with "inner quotes" and # comment.',
        '"""',
        "# Interleaved comment",
        "from __future__ import \\",
        "    annotations, \\",
        "    generator_stop",
        "",
        "def compute(x: int) -> int:",
        "    return x + 1",
        "",
      ].join("\r\n");

      const crlfResult = protectPythonSource(crlfSource, {
        seed: "issue-14-crlf",
      });
      expect(crlfResult.code.includes("\r\n")).toBe(true);
      // Verify every '\n' is part of '\r\n'
      expect(crlfResult.code.replace(/\r\n/g, "").includes("\n")).toBe(false);
      verifyPythonAstAndDocstring(
        crlfResult.code,
        'Multi-line raw docstring\nwith "inner quotes" and # comment.\n',
        ["annotations", "generator_stop"],
      );

      // Empty file and docstring-only file
      const emptyResult = protectPythonSource("", { seed: "issue-14-empty" });
      verifyPythonAstAndDocstring(emptyResult.code, null, []);

      const docOnlyResult = protectPythonSource("'Single-line docstring.'", {
        seed: "issue-14-doconly",
      });
      verifyPythonAstAndDocstring(
        docOnlyResult.code,
        "Single-line docstring.",
        [],
      );

      // Fail closed on unclosed docstring or unclosed future import or misplaced future import
      expect(() =>
        protectPythonSource('"""Unclosed docstring\nx = 1'),
      ).toThrow(InvalidPythonSourceError);
      expect(() =>
        protectPythonSource("from __future__ import (\n    annotations\n"),
      ).toThrow(InvalidPythonSourceError);
      expect(() =>
        protectPythonSource("x = 1\nfrom __future__ import annotations\n"),
      ).toThrow(InvalidPythonSourceError);
    });
  });

  describe("Issue #15: JavaScript carrier preservation and bundler loader contracts", () => {
    it("preserves classic script / IIFE carrier without injecting export declarations", () => {
      const iifeSource = "(() => {\n  const answer = 42;\n  globalThis.__iifeResult = answer;\n})();";
      const result = transformJavaScriptWithBlaShield(iifeSource, {
        sourceType: "script",
        filename: "bundle.iife.js",
        seed: "issue-15-iife",
      });

      expect(result.carrierType).toBe("script");
      expect(result.exportedSymbols).toEqual([]);
      expect(/\bexport\b/.test(result.code)).toBe(false);

      // Must parse cleanly in strict "script" mode
      expect(() =>
        parse(result.code, { sourceType: "script", errorRecovery: false }),
      ).not.toThrow();

      // Must execute cleanly as a classic VM Script
      const sandbox: Record<string, unknown> = {};
      vm.createContext(sandbox);
      new vm.Script(result.code).runInContext(sandbox);
      expect(sandbox.__iifeResult).toBe(42);
    });

    it("preserves exact ESM export surface and is not fooled by 'module.exports' in comments or strings", () => {
      const esmSource = [
        "// Comment mentioning module.exports = { decoy: true }",
        'const banner = "module.exports = require(\\"x\\")";',
        "export const publicValue = 100;",
        "export function publicHelper() { return banner; }",
      ].join("\n");

      const result = transformJavaScriptWithBlaShield(esmSource, {
        filename: "index.mjs",
        seed: "issue-15-esm",
      });

      expect(result.carrierType).toBe("module");
      expect(result.exportedSymbols).toEqual(["publicValue", "publicHelper"]);

      const cjsSource = [
        '"use strict";',
        "const message = 'export function notAnExport() {}';",
        "module.exports = { message };",
      ].join("\n");

      const cjsResult = transformJavaScriptWithBlaShield(cjsSource, {
        filename: "index.cjs",
        seed: "issue-15-cjs",
      });
      expect(cjsResult.carrierType).toBe("commonjs");
      expect(cjsResult.exportedSymbols).toEqual([]);
      expect(cjsResult.code.trimStart().startsWith('"use strict";')).toBe(true);
      expect(() =>
        parse(cjsResult.code, { sourceType: "script", errorRecovery: false }),
      ).not.toThrow();

      // Fail closed when ESM syntax is passed to a script/commonjs carrier
      expect(() =>
        transformJavaScriptWithBlaShield("export const x = 1;", {
          sourceType: "script",
        }),
      ).toThrow(InvalidJavaScriptCarrierError);
    });

    it("preserves Rollup output format carrier and esbuild js/jsx/ts/tsx loaders", async () => {
      expect(inferCarrierFromRollupFormat("iife")).toBe("script");
      expect(inferCarrierFromRollupFormat("umd")).toBe("script");
      expect(inferCarrierFromRollupFormat("cjs")).toBe("commonjs");
      expect(inferCarrierFromRollupFormat("es")).toBe("module");

      expect(inferEsbuildLoader("src/Component.tsx")).toBe("tsx");
      expect(inferEsbuildLoader("src/View.jsx")).toBe("jsx");
      expect(inferEsbuildLoader("src/util.mts")).toBe("ts");
      expect(inferEsbuildLoader("src/util.cts")).toBe("ts");
      expect(inferEsbuildLoader("src/index.mjs")).toBe("js");

      const rollupPlugin = blaRollupPlugin({ honeySourceMap: false });
      const iifeChunk = rollupPlugin.renderChunk(
        "(() => { const x = 1; })();",
        { fileName: "app.js" },
        { format: "iife" },
      );
      expect(iifeChunk).not.toBeNull();
      expect(/\bexport\b/.test(iifeChunk!.code)).toBe(false);

      // Test blaEsbuildPlugin onLoad with .tsx and .jsx files
      const tmpDir = mkdtempSync(join(tmpdir(), "bla-esbuild-test-"));
      try {
        const tsxPath = join(tmpDir, "Widget.tsx");
        const jsxPath = join(tmpDir, "Button.jsx");
        writeFileSync(
          tsxPath,
          'export const Widget = (props: { label: string }) => <div className="w">{props.label}</div>;\n',
          "utf8",
        );
        writeFileSync(
          jsxPath,
          'export const Button = () => <button type="button">Click</button>;\n',
          "utf8",
        );

        let registeredCallback:
          | ((args: {
              path: string;
            }) => Promise<{ contents: string; loader: string } | null>)
          | undefined;
        const esbuildPlugin = blaEsbuildPlugin();
        esbuildPlugin.setup({
          onLoad(_opts, cb) {
            registeredCallback = cb;
          },
        });

        expect(registeredCallback).toBeDefined();
        const tsxLoaded = await registeredCallback!({ path: tsxPath });
        expect(tsxLoaded?.loader).toBe("tsx");
        expect(tsxLoaded?.contents).toContain("<div");

        const jsxLoaded = await registeredCallback!({ path: jsxPath });
        expect(jsxLoaded?.loader).toBe("jsx");
        expect(jsxLoaded?.contents).toContain("<button");
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe("Issue #16: ELF64 PT_LOAD / BSS and section boundary preservation", () => {
    it("preserves PT_LOAD p_offset/p_filesz/p_memsz (BSS) and adjacent section boundaries without overlap", () => {
      const elfFixture = buildValidElf64Fixture({ bssExtraBytes: 8192n });
      const layoutBefore = validateElf64Layout(elfFixture);

      expect(layoutBefore.programHeaders[1]?.filesz).toBe(576);
      expect(layoutBefore.programHeaders[1]?.memsz).toBe(576n + 8192n);

      const protectedElf = protectNativeBinary(elfFixture, {
        seed: "issue-16-elf",
      });
      const layoutAfter = validateElf64Layout(protectedElf.buffer);

      // Every PT_LOAD segment and section header must be 100% preserved
      expect(layoutAfter.programHeaders).toEqual(layoutBefore.programHeaders);
      expect(layoutAfter.sectionHeaders).toEqual(layoutBefore.sectionHeaders);

      // Original payload bytes [0..elfFixture.length) must be byte-for-byte identical
      expect(
        protectedElf.buffer.subarray(0, elfFixture.length).equals(elfFixture),
      ).toBe(true);
    });

    it("fails closed with InvalidNativeBinaryError on truncated headers, p_memsz < p_filesz, and overlapping sections", () => {
      // 1. Truncated ELF header (< 64 bytes)
      const truncated = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
      expect(() => validateElf64Layout(truncated)).toThrow(
        InvalidNativeBinaryError,
      );
      expect(() => protectNativeBinary(truncated)).toThrow(
        InvalidNativeBinaryError,
      );

      // 2. PT_LOAD with p_memsz < p_filesz
      const badBss = buildValidElf64Fixture();
      const ph1 = 64 + 56;
      badBss.writeBigUInt64LE(576n, ph1 + 32); // p_filesz = 576
      badBss.writeBigUInt64LE(128n, ph1 + 40); // p_memsz = 128 < p_filesz!
      expect(() => validateElf64Layout(badBss)).toThrow(
        InvalidNativeBinaryError,
      );

      // 3. Overlapping file-backed sections (.rodata extended into .eh_frame)
      const overlappingSec = buildValidElf64Fixture();
      const shdr1 = 704 + 1 * 64;
      overlappingSec.writeBigUInt64LE(300n, shdr1 + 32); // [176..476) overlaps .eh_frame [344..512)!
      expect(() => validateElf64Layout(overlappingSec)).toThrow(
        InvalidNativeBinaryError,
      );
    });
  });

  describe("Issue #17: Context-verified Electron fuse hardening", () => {
    it("distinguishes absent, unsupported, truncated, and ambiguous sentinels without mutating non-Electron files", () => {
      // 1. Absent sentinel
      const noSentinel = Buffer.alloc(128, 0x41);
      expect(inspectElectronFusesBuffer(noSentinel).status).toBe("absent");

      // 2. Truncated wire after sentinel
      const truncatedWire = Buffer.concat([
        Buffer.alloc(16, 0),
        ELECTRON_FUSE_SENTINEL_BYTES,
        Buffer.from([0x01, 0x08, 0x30, 0x31]), // declares length 8, only 2 bytes present
      ]);
      const truncInsp = inspectElectronFusesBuffer(truncatedWire);
      expect(truncInsp.status).toBe("unsupported");
      expect(truncInsp.diagnostic).toContain("truncated");

      // 3. Invalid fuse wire byte (e.g. arbitrary ASCII text following sentinel)
      const invalidWireByte = Buffer.concat([
        Buffer.alloc(16, 0),
        ELECTRON_FUSE_SENTINEL_BYTES,
        Buffer.from([0x01, 0x06, 0x30, 0x31, 0x78, 0x30, 0x31, 0x31]), // 0x78 ('x') is invalid
      ]);
      expect(inspectElectronFusesBuffer(invalidWireByte).status).toBe(
        "unsupported",
      );

      // 4. Multiple real V1 fuse blocks -> ambiguous
      const validWire = Buffer.from([
        0x01,
        0x06,
        ELECTRON_FUSE_STATE.ENABLED,
        ELECTRON_FUSE_STATE.DISABLED,
        ELECTRON_FUSE_STATE.ENABLED,
        ELECTRON_FUSE_STATE.ENABLED,
        ELECTRON_FUSE_STATE.DISABLED,
        ELECTRON_FUSE_STATE.DISABLED,
      ]);
      const ambiguousBuf = Buffer.concat([
        Buffer.alloc(16, 0),
        ELECTRON_FUSE_SENTINEL_BYTES,
        validWire,
        Buffer.alloc(16, 0),
        ELECTRON_FUSE_SENTINEL_BYTES,
        validWire,
      ]);
      expect(inspectElectronFusesBuffer(ambiguousBuf).status).toBe("ambiguous");
    });

    it("fails closed when hardening context lacks container, ASAR integrity, or signing policy, and reports separate statuses when verified", () => {
      const electronElf = buildValidElf64Fixture({ embedElectronFuse: true });
      const asarHash = createHash("sha256")
        .update("verified-asar-header")
        .digest("hex");

      // Without context, protectNativeBinary must NOT mutate the embedded real fuse wire
      const protectedDefault = protectNativeBinary(electronElf);
      const beforeFuseCheck = inspectElectronFusesBuffer(
        protectedDefault.buffer,
      );
      expect(beforeFuseCheck.status).toBe("verified");
      expect(beforeFuseCheck.hardened).toBe(false);
      expect(beforeFuseCheck.runAsNodeEnabled).toBe(true);

      // Missing ASAR integrity -> fail closed
      expect(() =>
        hardenElectronFusesWithContext(electronElf, {
          electronVersion: "32.1.0",
          hasEmbeddedAsarIntegrity: false,
          codeSigningPolicy: "will-resign",
        }),
      ).toThrow(UnsupportedElectronFuseContextError);

      // Non-native container -> fail closed
      const rawNonContainer = Buffer.concat([
        Buffer.alloc(32, 0),
        ELECTRON_FUSE_SENTINEL_BYTES,
        Buffer.from([0x01, 0x06, 0x31, 0x30, 0x31, 0x31, 0x30, 0x30]),
      ]);
      expect(() =>
        hardenElectronFusesWithContext(rawNonContainer, {
          electronVersion: "32.1.0",
          hasEmbeddedAsarIntegrity: true,
          asarHeaderHash: asarHash,
          codeSigningPolicy: "will-resign",
        }),
      ).toThrow(UnsupportedElectronFuseContextError);

      // Valid context -> succeeds and reports fusePolicy, asarIntegrityStatus, signatureStatus separately
      const hardenedReport = hardenElectronFusesWithContext(electronElf, {
        electronVersion: "32.1.0",
        asarPath: "resources/app.asar",
        hasEmbeddedAsarIntegrity: true,
        asarHeaderHash: asarHash,
        codeSigningPolicy: "will-resign",
        injectDecoySentinelOverflow: true,
      });

      expect(hardenedReport.fusePolicy.status).toBe("hardened");
      expect(hardenedReport.asarIntegrityStatus).toBe("verified");
      expect(hardenedReport.signatureStatus).toBe("unverified-requires-resign");
      expect(hardenedReport.mutatedFuses).toContain("RunAsNode");
      expect(hardenedReport.mutatedFuses).toContain(
        "EnableEmbeddedAsarIntegrityValidation",
      );

      const postInspect = inspectElectronFusesBuffer(hardenedReport.buffer);
      expect(postInspect.status).toBe("verified");
      expect(postInspect.hardened).toBe(true);
      expect(postInspect.runAsNodeEnabled).toBe(false);
      expect(postInspect.asarIntegrityEnforced).toBe(true);
      expect(postInspect.onlyLoadFromAsarEnforced).toBe(true);
      expect(postInspect.exceedsReaSentinelLimit).toBe(true);
    });
  });
});
