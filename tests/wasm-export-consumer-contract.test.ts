import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";
import {
  inspectWasmBinary,
  isAbiMandatedWasmExport,
  protectWasmBinary,
} from "../src/shields/formats/wasm.js";

/**
 * Renaming a WASM export is only a defense when whoever calls it still can.
 * Three callers exist: a host that looks a name up because a spec says so
 * (never renamed), a file in the same project (kept, and reported), and
 * somebody outside the project (renamed, with the old → new map handed back).
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(root: string, rel: string, content: string | Buffer): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), content);
}

const section = (id: number, payload: number[]): number[] => [id, payload.length, ...payload];
const name = (text: string): number[] => [text.length, ...Buffer.from(text, "utf8")];

/**
 * (module
 *   (memory (export "memory") 1)
 *   (func (export "_start"))
 *   (func (export "compute") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
 *   (func (export "secretCheck") (param i32 i32) (result i32) local.get 0 local.get 1 i32.mul))
 */
function wasiStyleModule(): Buffer {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, [0x02, 0x60, 0x00, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]),
    ...section(3, [0x03, 0x00, 0x01, 0x01]),
    ...section(5, [0x01, 0x00, 0x01]),
    ...section(7, [
      0x04,
      ...name("_start"), 0x00, 0x00,
      ...name("memory"), 0x02, 0x00,
      ...name("compute"), 0x00, 0x01,
      ...name("secretCheck"), 0x00, 0x02,
    ]),
    ...section(10, [
      0x03,
      0x02, 0x00, 0x0b,
      0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
      0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6c, 0x0b,
    ]),
  ]);
}

const LOADER_CJS = `const fs = require("node:fs");
const path = require("node:path");
const bytes = fs.readFileSync(path.join(__dirname, "core.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
instance.exports._start();
console.log("sum", instance.exports.compute(2, 3), "pages", instance.exports.memory.buffer.byteLength / 65536);
`;

describe("WASM exports and the code that calls them", () => {
  it("the fixture is a valid module", () => {
    const raw = wasiStyleModule();
    expect(WebAssembly.validate(new Uint8Array(raw))).toBe(true);
    expect(inspectWasmBinary(raw).exportNames.slice().sort()).toEqual([
      "_start",
      "compute",
      "memory",
      "secretCheck",
    ]);
  });

  it("never renames a name a host looks up by specification", () => {
    for (const mandated of [
      "_start",
      "_initialize",
      "memory",
      "__indirect_function_table",
      "__heap_base",
      "__data_end",
      "__wasm_call_ctors",
      "__wbindgen_malloc",
      "__wbindgen_add_to_stack_pointer",
      "cabi_realloc",
      "stackSave",
      "asyncify_start_unwind",
      "dynCall_vii",
    ]) {
      expect(isAbiMandatedWasmExport(mandated), mandated).toBe(true);
    }
    for (const ordinary of ["compute", "secretCheck", "main", "start", "memoryStats", "_private", "__debug_dump"]) {
      expect(isAbiMandatedWasmExport(ordinary), ordinary).toBe(false);
    }

    const hardened = protectWasmBinary(wasiStyleModule(), { intensity: "bankrupt", seed: "abi-seed" });
    const names = inspectWasmBinary(hardened.buffer).exportNames;
    expect(names).toContain("_start");
    expect(names).toContain("memory");
    expect(names).not.toContain("compute");
    expect(names).not.toContain("secretCheck");
    expect(hardened.exportsRenamed.map((r) => r.from).sort()).toEqual(["compute", "secretCheck"]);

    // A WASI-style host still starts it, and the renamed exports still compute.
    const instance = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array(hardened.buffer)), {});
    const exports = instance.exports as Record<string, unknown>;
    expect(() => (exports._start as () => void)()).not.toThrow();
    expect((exports.memory as WebAssembly.Memory).buffer.byteLength).toBe(65536);
    const renamedTo = (from: string): string => hardened.exportsRenamed.find((r) => r.from === from)!.to;
    expect((exports[renamedTo("compute")] as (a: number, b: number) => number)(2, 3)).toBe(5);
    expect((exports[renamedTo("secretCheck")] as (a: number, b: number) => number)(6, 7)).toBe(42);
  });

  it("keeps an export another file in the project calls, and hands back the map for the rest", () => {
    const dir = tempDir("bla-wasm-contract-");
    put(dir, "package.json", JSON.stringify({ name: "w", version: "1.0.0", main: "dist/loader.cjs" }));
    put(dir, "dist/core.wasm", wasiStyleModule());
    put(dir, "dist/loader.cjs", LOADER_CJS);
    // Sorts before the loader and happens to have a method called `compute`:
    // the report should still name the file that loads the module.
    put(dir, "dist/a-ledger.cjs", "module.exports = { compute(items) { return items.length; } };\n");

    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "contract-seed",
      applyStateRoot: tempDir("bla-wasm-state-"),
    });
    expect(report.overallSuccess).toBe(true);
    const wasm = report.artifacts.find((a) => a.relativePath === "dist/core.wasm")!;

    // `compute` is called by dist/loader.cjs: renaming it would break the
    // project's own loader, so it stays — and the report says who uses it.
    expect(wasm.wasmExportsAutoPreserved).toEqual([{ name: "compute", referencedBy: "dist/loader.cjs" }]);
    // `secretCheck` has no caller here: renamed, with the map for anyone outside.
    expect(wasm.wasmExportRenames?.map((r) => r.from)).toEqual(["secretCheck"]);
    expect(wasm.wasmExportRenames?.[0]).toMatchObject({ kind: expect.any(String), to: expect.any(String) });

    const names = inspectWasmBinary(readFileSync(wasm.outputPath)).exportNames;
    expect(names).toEqual(expect.arrayContaining(["_start", "memory", "compute"]));
    expect(names).not.toContain("secretCheck");

    const steps = report.nextSteps?.join("\n") ?? "";
    expect(steps).toMatch(/1 WASM export\(s\) were renamed in dist\/core\.wasm .* artifacts\[\]\.wasmExportRenames/);

    // The hardened loader and the hardened module still work together.
    const run = spawnSync(process.execPath, ["loader.cjs"], {
      cwd: join(dir, ".bla-hardened", "dist"),
      encoding: "utf8",
      timeout: 60000,
    });
    expect({ status: run.status, stdout: run.stdout, stderr: run.stderr.slice(0, 400) }).toEqual({
      status: 0,
      stdout: "sum 5 pages 1\n",
      stderr: "",
    });
  }, 240000);

  it("an explicit keep-list is honoured and not reported as a guess", () => {
    const dir = tempDir("bla-wasm-contract-");
    put(dir, "dist/core.wasm", wasiStyleModule());

    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "contract-seed",
      wasmPreserveExports: ["secretCheck"],
      applyStateRoot: tempDir("bla-wasm-state-"),
    });
    expect(report.overallSuccess).toBe(true);
    const wasm = report.artifacts[0]!;
    expect(wasm.wasmExportsAutoPreserved).toBeUndefined();
    expect(wasm.wasmExportRenames?.map((r) => r.from)).toEqual(["compute"]);
    const names = inspectWasmBinary(readFileSync(wasm.outputPath)).exportNames;
    expect(names).toEqual(expect.arrayContaining(["_start", "memory", "secretCheck"]));
    expect(names).not.toContain("compute");
  }, 240000);

  it("balanced leaves every export name alone", () => {
    const dir = tempDir("bla-wasm-contract-");
    put(dir, "dist/core.wasm", wasiStyleModule());
    const report = hardenProject({
      directory: dir,
      intensity: "balanced",
      seed: "contract-seed",
      applyStateRoot: tempDir("bla-wasm-state-"),
    });
    expect(report.overallSuccess).toBe(true);
    expect(report.artifacts[0]!.wasmExportRenames).toBeUndefined();
    expect(inspectWasmBinary(readFileSync(report.artifacts[0]!.outputPath)).exportNames).toEqual(
      expect.arrayContaining(["_start", "memory", "compute", "secretCheck"]),
    );
  }, 240000);
});
