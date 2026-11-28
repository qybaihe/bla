import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runInNewContext } from "node:vm";
import { parse } from "@babel/parser";
import { type PluginBuild, build as esbuild, transform as esbuildTransform } from "esbuild";
import { rollup } from "rollup";
import { afterEach, describe, expect, it } from "vitest";
import { BlaWebpackPlugin, blaEsbuildPlugin, blaRollupPlugin } from "../src/bundler/index.js";
import { isHoneySourceMapObject } from "../src/shields/formats/honey-sourcemap-shape.js";
import { SeededPrng } from "../src/core/prng.js";
import { encryptStrings } from "../src/engine/encrypt-strings.js";
import { protectTarget } from "../src/engine/protector.js";
import { type ChaffPayload, generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import { generateHypothesisRevisionDecoy } from "../src/shields/deception/hypothesis-revision-decoy.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import {
  type SelfSealOptions,
  generateSelfSealSnippet,
} from "../src/shields/runtime/self-seal.js";
import {
  bindPythonSidecarEntanglement,
  bindSidecarEntanglement,
  bindWasmSidecarEntanglement,
  detectWasmJsLoaderCarrier,
  entangleAsarMainJsWithSidecars,
  entangleWasmLoaderWithSidecars,
  generateSidecarGgufLoaderSnippet,
  generateSidecarPycLoaderSnippet,
  generateSidecarSafetensorsLoaderSnippet,
  generateSidecarSqliteLoaderSnippet,
  listStaticEsmModuleSpecifiers,
} from "../src/shields/runtime/sidecar-entangle.js";
import { generatePythonTarpit } from "../src/shields/tarpit/tarpit-generator.js";

const roots: string[] = [];
const pythonAvailable = spawnSync("python3", ["--version"]).status === 0;
const marker = "private-original-source-24f0b4";
const sourceMap = JSON.stringify({ version: 3, sources: ["private.ts"], sourcesContent: [marker], mappings: "AAAA", names: [] });
const sourceMapDataUrl = `data:application/json;base64,${Buffer.from(sourceMap).toString("base64")}`;

function tempDir(): string {
  const root = mkdtempSync(join(tmpdir(), "bla-hardening-regression-"));
  roots.push(root);
  return root;
}

function put(root: string, file: string, body: string | Buffer): string {
  const path = join(root, file);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body);
  return path;
}

function run(program: string, args: string[], cwd: string) {
  return spawnSync(program, args, { cwd, encoding: "utf8", timeout: 15_000 });
}

function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("bundler output and JavaScript transform metadata", () => {
  it.each([true, "inline", "hidden", false] as const)(
    "publishes only honey maps for protected hashed chunks (sourcemap: %s)",
    async (sourcemap) => {
      const dir = tempDir();
      const one = put(dir, "one.js", `/* ${marker} */\nconsole.log(1);\n`);
      const two = put(dir, "two.js", `/* ${marker} */\nconsole.log(2);\n`);
      const ignoredA = put(dir, "ignored-a.js", "console.log('ignored-a');");
      const ignoredB = put(dir, "ignored-b.js", "console.log('ignored-b');");
      const include = /\.js$/g;
      const exclude = /ignored-/g;
      include.lastIndex = 100;
      exclude.lastIndex = 100;
      const bundle = await rollup({
        input: [one, two, ignoredA, ignoredB],
        plugins: [blaRollupPlugin({ seed: "honey-output", intensity: "stealth", include, exclude })],
      });
      try {
        const { output } = await bundle.write({
          dir: join(dir, "out"),
          format: "cjs",
          entryFileNames: "assets/[name]-[hash].js",
          sourcemapFileNames: "maps/[name]-[hash].map",
          sourcemap,
        });
        const testedChunks = output.filter((item) => item.type === "chunk" && !item.name.startsWith("ignored"));
        expect(testedChunks).toHaveLength(2);
        expect(
          output.filter((item) => {
            if (item.type !== "asset") return false;
            try {
              return isHoneySourceMapObject(JSON.parse(String(item.source)));
            } catch {
              return false;
            }
          }),
        ).toHaveLength(2);
        for (const chunk of testedChunks) {
          if (chunk.type !== "chunk") throw new Error("expected a chunk");
          expect(chunk.map).toBeNull();
          expect(chunk.code).not.toContain("data:application/json");
          expect(chunk.code.includes("sourceMappingURL=")).toBe(sourcemap === true || sourcemap === "inline");
          expect(run(process.execPath, [join(dir, "out", chunk.fileName)], dir).stdout.trim()).toBe(chunk.name === "one" ? "1" : "2");
        }
        for (const item of output) {
          if (item.type !== "asset") continue;
          expect(readFileSync(join(dir, "out", item.fileName), "utf8")).not.toContain(marker);
        }
        expect(include.lastIndex).toBe(100);
        expect(exclude.lastIndex).toBe(100);
      } finally {
        await bundle.close();
      }
    },
  );

  it("removes real Rollup maps even with honey maps disabled", async () => {
    const dir = tempDir();
    const input = put(dir, "app.js", `/* ${marker} */\nconsole.log(7);\n`);
    const bundle = await rollup({ input, plugins: [blaRollupPlugin({ honeySourceMap: false })] });
    try {
      const { output } = await bundle.generate({ sourcemap: true });
      expect(output).toHaveLength(1);
      expect(output[0].map).toBeNull();
      expect(output[0].code).not.toContain("sourceMappingURL=");
    } finally {
      await bundle.close();
    }
  });

  it.each([true, false])("scrubs Webpack assets and attached directives (honey maps: %s)", (honeySourceMap) => {
    const dir = tempDir();
    const raw = (value: string) => ({ source: () => value, size: () => Buffer.byteLength(value) });
    const assets = {
      "main.cjs": raw(`/*# sourceURL=private-source.js */\nmodule.exports = 41;\n//# sourceMappingURL=${sourceMapDataUrl}`),
      "next.cjs": raw("module.exports = 42;\n//# sourceMappingURL=maps/custom.map"),
      "main.cjs.map": raw(sourceMap),
      "maps/custom.map": raw(sourceMap),
    } as Record<string, ReturnType<typeof raw>>;
    new BlaWebpackPlugin({ seed: "webpack-maps", honeySourceMap, include: /\.cjs$/g }).apply({
      hooks: {
        compilation: {
          tap(_name, start) {
            start({
              hooks: { processAssets: { tap: (_options, finish) => finish(assets) } },
              updateAsset: (name, source) => { assets[name] = source; },
              emitAsset: (name, source) => { assets[name] = source; },
              deleteAsset: (name) => { delete assets[name]; },
            });
          },
        },
      },
    });
    const require = createRequire(join(dir, "entry.cjs"));
    expect(assets["maps/custom.map"]).toBeUndefined();
    for (const [name, value] of [["main.cjs", 41], ["next.cjs", 42]] as const) {
      const js = assets[name]!.source();
      expect(js).not.toMatch(/source(?:Mapping)?URL\s*=|private-source/);
      expect(require(put(dir, name, js))).toBe(value);
      if (honeySourceMap) {
        expect(isHoneySourceMapObject(JSON.parse(String(assets[`${name}.map`]!.source())))).toBe(
          true,
        );
        expect(assets[`${name}.map`]!.source()).not.toContain(marker);
      } else {
        expect(assets[`${name}.map`]).toBeUndefined();
      }
    }
  });

  it("handles esbuild's file namespace without shadowing another plugin's virtual modules", async () => {
    const dir = tempDir();
    const input = put(dir, "app.js", 'import answer from "virtual.js"; console.log(answer);');
    const build = await esbuild({
      entryPoints: [input],
      bundle: true,
      platform: "node",
      write: false,
      plugins: [
        blaEsbuildPlugin({ include: /\.js$/g, failBuildOnError: true }),
        {
          name: "fixture-virtual-module",
          setup(build: PluginBuild) {
            build.onResolve({ filter: /^virtual\.js$/ }, () => ({ namespace: "fixture", path: "virtual.js" }));
            build.onLoad({ filter: /./, namespace: "fixture" }, () => ({ contents: "export default 42" }));
          },
        },
      ],
    });
    const output = put(dir, "out.cjs", build.outputFiles[0]!.text);
    const result = run(process.execPath, [output], dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("42");
  });

  it("drops map and debugger directives on attached Babel comments", () => {
    const source = `/*# sourceMappingURL=${sourceMapDataUrl} */\nconst n = 42 /*@ sourceURL=private.js */;\nn;\n//# sourceMappingURL=private.js.map`;
    const { code } = transformJavaScriptWithBlaShield(source, { seed: "attached-source-directives" });
    expect(code).not.toMatch(/source(?:Mapping)?URL\s*=/);
    expect(runInNewContext(code)).toBe(42);
  });

  it("honors classic JSX factories and fragment bindings after compiling the hardened source", async () => {
    const source = `/** @jsx factory.create */
       /** @jsxFrag marker */
       const factory = { create(component, props, child) { return [component, child]; } };
       const marker = "fragment";
       module.exports = <><item /></>;`;
    const { code } = transformJavaScriptWithBlaShield(source, { filename: "entry.jsx", seed: "js-pragma" });
    expect(code).toContain("@jsx factory.create");
    expect(code).toContain("@jsxFrag marker");
    const compiled = await esbuildTransform(code, { loader: "jsx", format: "cjs" });
    const module = { exports: null };
    runInNewContext(compiled.code, { module });
    expect(module.exports).toEqual(["fragment", ["item", undefined]]);
  });

  it("keeps JSX import-source pragmas visible to the downstream compiler", async () => {
    const source = "/** @jsxImportSource @fixture/runtime */\nexport const element = <item />;";
    const { code } = transformJavaScriptWithBlaShield(source, { filename: "entry.jsx", seed: "js-import-source" });
    const compiled = await esbuildTransform(code, { loader: "jsx", jsx: "automatic" });
    expect(compiled.code).toContain("@fixture/runtime/jsx-runtime");
  });
});

describe("JavaScript runtime equivalence", () => {
  it("preserves user aliases and removes only the generated stage-two markers", () => {
    const source = `var _blaS = log.push("S"); var _blaT = log.push("T");\nlog.join(",");`;
    const { code } = transformJavaScriptWithBlaShield(source, { seed: "user-alias" });
    expect(runInNewContext(code, { log: [] })).toBe("S,T");

    const dir = tempDir();
    const path = put(dir, "license.cjs", 'globalThis.result = "FLAG{test_regression_generated_aliases}";');
    expect(encryptStrings({ path, seed: "alias-provenance" }).totalEncrypted).toBe(1);
    const encrypted = readFileSync(path, "utf8");
    expect(encrypted).toMatch(/var _blaS=/);
    const hardened = transformJavaScriptWithBlaShield(encrypted, { sourceType: "script", seed: "generated-alias" });
    expect(hardened.code).not.toMatch(/\b_bla[ST]\b/);
    const sandbox = { result: undefined };
    runInNewContext(hardened.code, sandbox);
    expect(sandbox.result).toBe("FLAG{test_regression_generated_aliases}");
  });

  it("preserves direct eval bindings through sloppy parameters and parameter initializers", () => {
    const dir = tempDir();
    const source = `
      const parentValue = 39;
      function invoke(eval, initial = eval("parentValue")) {
        const parentValue = 41;
        const localValue = 3;
        return [initial, eval("parentValue + localValue")];
      }
      console.log(JSON.stringify(invoke(eval)));
    `;
    const { code } = transformJavaScriptWithBlaShield(source, {
      filename: "main.cjs", seed: "sloppy-eval", intensity: "maximum",
    });
    const result = run(process.execPath, [put(dir, "main.cjs", code)], dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("[39,44]");
  });

  it("keeps default and aliased function names observable before an ESM cycle evaluates the entry", () => {
    const dir = tempDir();
    put(dir, "peer.mjs", `
      import alpha, { published } from "./entry.mjs";
      export const state = [alpha.name, published.name, alpha(), published()];
    `);
    const { code } = transformJavaScriptWithBlaShield(`
      import { state } from "./peer.mjs";
      export default function localDefault() { return "first"; }
      function localAlias() { return "second"; }
      export { localAlias as published };
      console.log(JSON.stringify(state));
    `, { filename: "entry.mjs", intensity: "bankrupt", seed: "cycle-name" });
    const result = run(process.execPath, [put(dir, "entry.mjs", code)], dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe('["localDefault","localAlias","first","second"]');
  });

  it("runs Math-dependent transforms outside with and leaves closed-over scope lookup intact", () => {
    const { code } = transformJavaScriptWithBlaShield(`
      let later;
      const scope = { Math: null, message: "enclosed" };
      function work() {
        const Math = { value: 7 };
        with (scope) {
          later = function closure() { return [message, 12345]; };
          return [message, 98765];
        }
      }
      function lookup() {
        const Math = { value: 7 };
        with ({ Math: { value: 8 } }) { return Math.value; }
      }
      [work(), later(), lookup()];
    `, { seed: "with-runtime-scope", intensity: "bankrupt", sourceType: "script" });
    expect(runInNewContext(code)).toEqual([["enclosed", 98765], ["enclosed", 12345], 8]);
  });

  it("does not read process.pid or need an enumerable mesh array at startup", () => {
    const process = { get pid() { throw new Error("PID is unavailable"); } };
    const decoys = generateHypothesisRevisionDecoy(new SeededPrng("sandbox"), "maximum");
    expect(() => runInNewContext(decoys.code, { process })).not.toThrow();
    const { code } = transformJavaScriptWithBlaShield("21 * 2;", { seed: "sandbox", intensity: "bankrupt" });
    expect(code).not.toMatch(/\[[\w$\s,]+\]\.every\(/);
    expect(runInNewContext(code, { process })).toBe(42);
  });
});

describe("self-seal and entry prologues", () => {
  it("rejects invalid and reserved JavaScript identifiers in all self-seal name overrides", () => {
    const names = ["bindingName", "esmRequireHelperIdent", "esmMetaUrlIdent", "esmCapReadIdent", "esmCapHashIdent"] as const;
    for (const name of names) {
      for (const value of ["return", "class", "await", "two words", "eval", ""]) {
        expect(() => generateSelfSealSnippet(new SeededPrng("identifiers"), { [name]: value })).toThrow(/JavaScript identifier/);
      }
    }
    const valid = generateSelfSealSnippet(new SeededPrng("identifier"), { bindingName: "époch" });
    expect(() => parse(valid.code, { sourceType: "module" })).not.toThrow();
  });

  it("turns initialization, path, read, and hash exceptions into hard integrity failures", () => {
    const dir = tempDir();
    const self = put(dir, "exists.cjs", "entry bytes");
    const runtimeRequire = createRequire(self);
    const fail = () => { throw new Error("unavailable"); };
    const hard: SelfSealOptions = { hardFailOnSiblingMismatch: true, envFingerprint: false };
    const { code } = generateSelfSealSnippet(new SeededPrng("hard-seal"), hard);
    const harnesses = [
      { require: fail, __filename: self },
      { require: runtimeRequire, __filename: join(dir, "missing.cjs") },
      { require: runtimeRequire, __dirname: dir },
      { require: (name: string) => name === "node:crypto" ? { createHash: fail } : runtimeRequire(name), __filename: self },
      { require: (name: string) => name === "node:fs" ? { ...runtimeRequire(name), readSync: () => 0 } : runtimeRequire(name), __filename: self },
    ];
    for (const context of harnesses) {
      expect(() => runInNewContext(`${code}\nthrow Error("entry ran")`, { Buffer, ...context })).toThrow(/^integrity check failed$/);
    }
    const esm = generateSelfSealSnippet(new SeededPrng("hard-esm"), {
      ...hard, esmRequireHelperIdent: "getRequire", esmMetaUrlIdent: "badUrl",
    });
    expect(() => runInNewContext(esm.code, { Buffer, getRequire: () => runtimeRequire, badUrl: "not a URL" }))
      .toThrow(/^integrity check failed$/);

    const intact = transformJavaScriptWithBlaShield("console.log(42);", {
      filename: "main.cjs", seed: "self-sealed", selfSeal: hard,
    });
    const result = run(process.execPath, [put(dir, "main.cjs", intact.code)], dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("42");
  });

  it.each([
    '"use strict"\n"custom directive"\n',
    '"use strict" /* keep this */;\n"custom directive" /* trailing */\n',
  ])("preserves the exact directive prologue and CJS strict behavior", (prologue) => {
    const dir = tempDir();
    const source = '#!/usr/bin/env node\n/* License banner */\n' + prologue +
      'console.log((function(){ return this })() === undefined);\n';
    const bound = bindSidecarEntanglement({
      entryPath: "main.cjs", entryBytes: Buffer.from(source),
      sidecarPaths: ["pin.bin"], sidecarBytes: [Buffer.from("pin")],
    });
    const ast = parse(bound.code, { sourceType: "script" });
    expect(ast.program.directives.map((item) => item.value.value)).toEqual(["use strict", "custom directive"]);
    expect(bound.code.startsWith("#!/usr/bin/env node\n/* License banner */")).toBe(true);
    put(dir, "pin.bin", "pin");
    const result = run(process.execPath, [put(dir, "main.cjs", bound.code)], dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("true");
  });

  it.each([
    { main: "nested/main.mjs", manifest: "package.json", type: "commonjs" },
    { main: "nested/main.js", manifest: "package.json", type: "module" },
    { main: "nested/main.js", manifest: "nested/package.json", type: "module" },
  ])("binds ASAR ESM main members using their archive package context (%j)", ({ main, manifest, type }) => {
    const dir = tempDir();
    const body = Buffer.from('"custom directive"\nconsole.log(typeof require, "body executed");');
    const pin = Buffer.from("pin");
    const pkg = JSON.stringify({ main, type: manifest === "package.json" ? type : "commonjs" });
    const extraManifest = manifest === "package.json" ? [] : [{ relativePath: manifest, content: Buffer.from(JSON.stringify({ type })) }];
    const expectedHex = sha256(Buffer.concat([Buffer.from("app.asar\0pin.bin\0"), pin, Buffer.from("\0bla-sidecar-v1")]));
    const result = entangleAsarMainJsWithSidecars({
      members: [
        { relativePath: main, content: body },
        { relativePath: "package.json", content: Buffer.from(pkg) },
        { relativePath: "pin.bin", content: pin },
        ...extraManifest,
      ],
      entryPath: "app.asar", sidecarPaths: ["pin.bin"], expectedHex,
    });
    expect(result?.mainRelativePath).toBe(main);
    expect(result?.inject.preamble).toContain("createRequire");
    for (const member of result!.members) put(dir, member.relativePath, member.content);
    const success = run(process.execPath, [main], dir);
    expect(success.status, success.stderr).toBe(0);
    expect(success.stdout.trim()).toBe("undefined body executed");
    rmSync(join(dir, "pin.bin"));
    const failure = run(process.execPath, [main], dir);
    expect(failure.status).not.toBe(0);
    expect(failure.stderr).toContain("integrity binding mismatch");
    expect(failure.stdout).toBe("");
  });
});

function wasmWithScore(score: number): Buffer {
  return Buffer.from([
    0, 97, 115, 109, 1, 0, 0, 0,       // Magic and version
    1, 5, 1, 0x60, 0, 1, 0x7f,       // () -> i32
    3, 2, 1, 0,                       // Function of type 0
    7, 9, 1, 5, 115, 99, 111, 114, 101, 0, 0, // Export "score"
    10, 6, 1, 4, 0, 0x41, score, 0x0b,       // i32.const score
  ]);
}

describe("WASM loader contracts", () => {
  it("detects syntax-only ESM and every same-line static dependency", () => {
    const source = 'await Promise.resolve();';
    expect(detectWasmJsLoaderCarrier("loader.js", source)).toBe("module");
    expect(detectWasmJsLoaderCarrier("loader.cjs", source)).toBeNull();
    const imports = 'import fs from "node:fs";import "./dep.js";export { readFile } from "node:fs/promises";';
    expect(listStaticEsmModuleSpecifiers(imports)).toEqual(["node:fs", "./dep.js", "node:fs/promises"]);
    expect(detectWasmJsLoaderCarrier("loader.js", imports)).toBeNull();
    expect(detectWasmJsLoaderCarrier("loader.js", imports.replace('import "./dep.js";', ""))).toBe("module");
  });

  it("auto-wires a top-level-await .js loader that dynamically imports fs", () => {
    const dir = tempDir();
    const wasm = put(dir, "core.wasm", wasmWithScore(9));
    const pin = put(dir, "pin.bin", "pin");
    const loader = put(dir, "loader.js", `
      const { readFileSync } = await import("node:fs");
      const { instance } = await WebAssembly.instantiate(readFileSync("./core.wasm"));
      console.log(instance.exports.score());
    `);
    const report = protectTarget({
      inputPath: wasm, inPlace: true, intensity: "balanced", seed: "wasm-tla",
      sidecarEntangle: true, sidecarEntanglePaths: [pin],
    });
    expect(report.wasmSidecarLoaderHookApplied).toBe(true);
    expect(readFileSync(loader, "utf8")).toContain("import.meta.url");
    const intact = run(process.execPath, [loader], dir);
    expect(intact.status, intact.stderr).toBe(0);
    expect(intact.stdout.trim()).toBe("9");
    rmSync(pin);
    const failure = run(process.execPath, [loader], dir);
    expect(failure.status).not.toBe(0);
    expect(failure.stderr).toContain("integrity binding mismatch");
  });

  it("preserves native constructor, subclass, streaming, and unrelated-module behavior", () => {
    const dir = tempDir();
    const pinned = bindWasmSidecarEntanglement({
      entryPath: "app.wasm", entryBytes: wasmWithScore(9),
      sidecarPaths: ["pin.bin"], sidecarBytes: [Buffer.from("pin")],
    });
    put(dir, "pin.bin", "pin");
    put(dir, "app.wasm", pinned.bytes);
    put(dir, "stripped.wasm", wasmWithScore(9));
    put(dir, "unrelated.wasm", wasmWithScore(10));

    const loader = entangleWasmLoaderWithSidecars({
      wasmBytes: pinned.bytes,
      loaderSource: `
        "custom loader pragma"
        const assert = (await import("node:assert/strict")).default;
        const { readFileSync } = await import("node:fs");
        const bound = readFileSync("app.wasm");
        const unrelated = readFileSync("unrelated.wasm");
        const stripped = readFileSync("stripped.wasm");
        assert.throws(() => WebAssembly.Module(bound), TypeError);
        class Derived extends WebAssembly.Module {}
        const derived = new Derived(bound);
        assert.ok(derived instanceof Derived);
        assert.ok(derived instanceof WebAssembly.Module);
        assert.equal(new WebAssembly.Instance(derived).exports.score(), 9);
        assert.equal(WebAssembly.Module.exports(derived)[0].name, "score");
        const { runInNewContext } = await import("node:vm");
        assert.throws(() => new WebAssembly.Module(runInNewContext(
          "Uint8Array.from(bytes).buffer", { bytes: [...stripped] },
        )), /section missing/);
        assert.equal((await WebAssembly.instantiate(unrelated)).instance.exports.score(), 10);
        const response = (bytes, type = "application/wasm", status = 200) =>
          new Response(bytes, { headers: { "Content-Type": type }, status });
        await assert.rejects(WebAssembly.instantiateStreaming(response(bound, "text/plain")), /unsupported MIME type/);
        await assert.rejects(WebAssembly.compileStreaming(response(bound, "text/plain")), /unsupported MIME type/);
        await assert.rejects(WebAssembly.compileStreaming(response(bound, "application/wasm", 404)), /status code 404/);
        const used = response(bound);
        await used.arrayBuffer();
        await assert.rejects(WebAssembly.compileStreaming(used), /body has already been used/);
        await assert.rejects(WebAssembly.compileStreaming({ arrayBuffer: async () => bound }), TypeError);
        const valid = response(bound);
        assert.equal((await WebAssembly.instantiateStreaming(Promise.resolve(valid))).instance.exports.score(), 9);
        assert.equal(valid.bodyUsed, true);
        assert.ok(await WebAssembly.compileStreaming(response(unrelated)) instanceof WebAssembly.Module);
        await assert.rejects(WebAssembly.compileStreaming(response(stripped)), /section missing/);
        console.log("native WASM contracts preserved");
      `,
    });
    expect(loader.code).toContain("import.meta.url");
    const result = run(process.execPath, [put(dir, "loader.js", loader.code)], dir);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("native WASM contracts preserved");
  });
});

describe.skipIf(!pythonAvailable)("Python runtime safety", () => {
  const identity = "a".repeat(64);
  it.each([
    ["pyc", generateSidecarPycLoaderSnippet({ codeIdentityHex: identity, pycRelPaths: ["missing.pyc"] }).preamble],
    ["gguf", generateSidecarGgufLoaderSnippet({ codeIdentityHex: identity, ggufRelPaths: ["missing.gguf"] }).preamble],
    ["safetensors", generateSidecarSafetensorsLoaderSnippet({ codeIdentityHex: identity, safetensorsRelPaths: ["missing.safetensors"] }).preamble],
    ["sqlite", generateSidecarSqliteLoaderSnippet({ codeIdentityHex: identity, sqliteRelPaths: ["missing.sqlite"] }).preamble],
  ])("fails closed on a missing pinned %s before running the body", (_format, preamble) => {
    const dir = tempDir();
    put(dir, "loader.py", `${preamble}\nprint("entry ran")\n`);
    const result = run("python3", ["loader.py"], dir);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("integrity binding mismatch");
    expect(result.stdout).toBe("");
  });

  it.each([
    "import sys; sys.frozen = True",
    "__compiled__ = object()",
  ])("keeps pinned sibling checks active in frozen mode (%s)", (setup) => {
    const dir = tempDir();
    const entry = bindPythonSidecarEntanglement({
      entryPath: "loader.py", entryBytes: Buffer.from('print("entry ran")\n'),
      sidecarPaths: ["sibling.py"], sidecarBytes: [Buffer.from("pass\n")],
    });
    put(dir, "loader.py", `${setup}\n${entry.code}`);
    put(dir, "sibling.py", "pass\n");
    const success = run("python3", ["loader.py"], dir);
    expect(success.status, success.stderr).toBe(0);
    expect(success.stdout.trim()).toBe("entry ran");
    rmSync(join(dir, "sibling.py"));
    const failure = run("python3", ["loader.py"], dir);
    expect(failure.status).not.toBe(0);
    expect(failure.stderr).toContain("integrity binding mismatch");
    expect(failure.stdout).toBe("");
  });

  it.each(["terminal \"", "terminal '", "terminal \\", "triple \"\"\" quote", undefined])(
    "executes the tarpit with chaff %j without adding a module annotation",
    (rawText) => {
      const dir = tempDir();
      const table: readonly ChaffPayload[] = rawText === undefined ? [] : [{
        id: "chaff", symbolName: "manifest", category: "enclave-delegation",
        encodedBase64: "", encodedHex: "", rawText,
      }];
      const tarpit = generatePythonTarpit(new SeededPrng("tarpit"), "stealth", table);
      const checks = [
        'assert (globals()["__annotate__"](1) if "__annotate__" in globals() else globals().get("__annotations__", {})) == {"original": int}',
        rawText === undefined ? "" : `assert ${tarpit.decoyFunctionNames[0]}.__doc__ == ${JSON.stringify(rawText)}`,
        'print("entry ran")',
      ];
      put(dir, "entry.py", `original: int = 5\n${tarpit.code}\n${checks.join("\n")}`);
      const result = run("python3", ["entry.py"], dir);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout.trim()).toBe("entry ran");
    },
  );
});

it("samples absolutely aligned bigint addresses in half-open ranges", () => {
  const high = 0x20_0000_0000_0000n;
  const sample = (codeStart: bigint, codeEnd: bigint, seed: number) => generateChaffPayloads(
    new SeededPrng(seed), "stealth", {
      addressContext: {
        codeStart, codeEnd, rodataStart: high + 3n, rodataEnd: high + 8n,
        dataStart: high + 24n, dataEnd: high + 8n, hexWidth: 16,
      },
    },
  ).find((payload) => payload.category === "decoy-offset-table")!.rawText;
  expect(sample(high + 1n, high + 17n, 0)).toMatch(/\.text\.enclave_entry=0x0020000000000010\b/);
  expect(sample(high + 16n, high + 16n, 0)).not.toContain("=0x");
  expect(sample(high + 1n, high + 16n, 0)).not.toContain("=0x");
  const addresses = new Set(Array.from({ length: 32 }, (_, seed) => {
    const raw = sample(high + 1n, high + 33n, seed);
    expect(raw).not.toMatch(/\.rodata|\.data/);
    return BigInt(/=0x([\da-f]+)/.exec(raw)![0].slice(1));
  }));
  expect(addresses).toEqual(new Set([high + 16n, high + 32n]));
});
