import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_BLA_CONFIG, loadBlaConfig } from "../src/core/config.js";
import { parseCliArgs } from "../src/cli.js";
import { protectWasmBinary } from "../src/shields/formats/wasm.js";

function uleb(n: number): number[] {
  const out: number[] = [];
  do {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n) byte |= 0x80;
    out.push(byte);
  } while (n);
  return out;
}

function section(id: number, body: number[]): number[] {
  return [id, ...uleb(body.length), ...body];
}

function nameBytes(s: string): number[] {
  const b = [...Buffer.from(s, "utf8")];
  return [...uleb(b.length), ...b];
}

/** Two-export module: public `add` + internal-looking `__bla_internal_x`. */
function minimalTwoExportWasm(): Buffer {
  const typeBody = [2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7f];
  const funcBody = [2, 0, 1];
  const exportBody = [
    2,
    ...nameBytes("add"),
    0,
    0,
    ...nameBytes("__bla_internal_x"),
    0,
    1,
  ];
  const code0 = [0, 0x20, 0, 0x20, 1, 0x6a, 0x0b];
  const code1 = [0, 0x41, 1, 0x0b];
  const codeBody = [
    2,
    ...uleb(code0.length),
    ...code0,
    ...uleb(code1.length),
    ...code1,
  ];
  return Buffer.from([
    0x00,
    0x61,
    0x73,
    0x6d,
    1,
    0,
    0,
    0,
    ...section(1, typeBody),
    ...section(3, funcBody),
    ...section(7, exportBody),
    ...section(10, codeBody),
  ]);
}

describe("wasmPreserveExports .blarc / CLI / protect parity (#40.3)", () => {
  it("DEFAULT_BLA_CONFIG leaves wasmPreserveExports undefined", () => {
    expect(DEFAULT_BLA_CONFIG.wasmPreserveExports).toBeUndefined();
  });

  it("loadBlaConfig honors wasmPreserveExports array", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-preserve-"));
    try {
      writeFileSync(
        join(dir, ".blarc"),
        JSON.stringify({ wasmPreserveExports: ["add", "run"] }),
        "utf8",
      );
      const loaded = loadBlaConfig(dir);
      expect(loaded.config.wasmPreserveExports).toEqual(["add", "run"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("parseCliArgs accepts --wasm-preserve-exports list", () => {
    const a = parseCliArgs([
      "protect",
      "x.wasm",
      "--wasm-preserve-exports",
      "add,run",
    ]);
    expect(a.wasmPreserveExports).toEqual(["add", "run"]);
    const b = parseCliArgs([
      "protect",
      "x.wasm",
      "--wasm-preserve-exports=add",
    ]);
    expect(b.wasmPreserveExports).toEqual(["add"]);
  });

  it("protectWasmBinary keeps listed ABI while renaming internal export", () => {
    const raw = minimalTwoExportWasm();
    const res = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "wasm-preserve-test",
      preserveExports: ["add"],
    });
    const fromNames = res.exportsRenamed.map((r) => r.from);
    expect(fromNames).toContain("__bla_internal_x");
    expect(fromNames).not.toContain("add");
    const mod = new WebAssembly.Module(new Uint8Array(res.buffer));
    const inst = new WebAssembly.Instance(mod);
    expect(Object.keys(inst.exports)).toContain("add");
    expect(Object.keys(inst.exports)).not.toContain("__bla_internal_x");
    expect(
      (inst.exports as { add: (a: number, b: number) => number }).add(2, 3),
    ).toBe(5);
  });

  it("bankrupt without preserveExports renames public ABI names", () => {
    const raw = minimalTwoExportWasm();
    const res = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "wasm-no-preserve-renames-public",
    });
    const fromNames = res.exportsRenamed.map((r) => r.from);
    expect(fromNames).toContain("add");
    expect(fromNames).toContain("__bla_internal_x");
    const mod = new WebAssembly.Module(new Uint8Array(res.buffer));
    const inst = new WebAssembly.Instance(mod);
    expect(Object.keys(inst.exports)).not.toContain("add");
    expect(Object.keys(inst.exports)).not.toContain("__bla_internal_x");
  });
});
