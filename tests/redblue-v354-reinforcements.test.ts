import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { classifyBrowserBundles } from "../src/engine/browser-bundle.js";
import { hardenProject } from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import {
  injectWasmBytecodeFlowerInstructions,
  protectWasmBinary,
} from "../src/shields/formats/wasm.js";
import { protectPythonSource } from "../src/shields/formats/python.js";
import { protectSqliteBuffer } from "../src/shields/formats/sqlite.js";
import { getDatabaseSyncClass } from "../src/core/sqlite-runtime.js";
import {
  bindSidecarEntanglement,
  entangleWasmEntryWithSidecars,
  entangleWasmLoaderWithSidecars,
  stripWasmSidecarCustomSection,
} from "../src/shields/runtime/sidecar-entangle.js";
import { generateSelfSealSnippet } from "../src/shields/runtime/self-seal.js";
import { SeededPrng } from "../src/core/prng.js";

const PY3 = spawnSync("python3", ["--version"], { encoding: "utf8" }).status === 0;
const tempDirs: string[] = [];

function makeDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

/** Valid 2-function WASM module: arxMix(a,b) = ((a+b)*7)^90, checkKey(k) = ((k^19)+5)&255. */
function buildTwoFnWasm(): Buffer {
  const buf = Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    // Type section: (i32, i32)->i32 and (i32)->i32
    0x01, 0x0c, 0x02,
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    0x60, 0x01, 0x7f, 0x01, 0x7f,
    // Function section
    0x03, 0x03, 0x02, 0x00, 0x01,
    // Export section
    0x07, 0x15, 0x02,
    0x06, ...Buffer.from("arxMix"), 0x00, 0x00,
    0x08, ...Buffer.from("checkKey"), 0x00, 0x01,
    // Code section
    0x0a, 0x1f, 0x02,
    0x0e, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x41, 0x07, 0x6c, 0x41, 0xda, 0x00, 0x73, 0x0b,
    0x0e, 0x00, 0x20, 0x00, 0x41, 0x13, 0x73, 0x41, 0x05, 0x6a, 0x41, 0xff, 0x01, 0x71, 0x0b,
  ]);
  expect(WebAssembly.validate(buf)).toBe(true);
  return buf;
}

describe("Red-Blue v3.5.4 Reinforcements", () => {
  it("JS AST rename preserves for-of/for-in destructuring and duplicate assignment targets", () => {
    const src = [
      '"use strict";',
      "function computeAll(pairs, items, obj, arr) {",
      "  let k = '', v = 0, sum = 0;",
      "  for ([k, v] of pairs) sum += k.length * v;",
      "  let a = 0, b = 0;",
      "  for ({ a, b } of items) sum += a * 3 + b;",
      "  let ch = '';",
      "  for ([ch] in obj) sum += ch.charCodeAt(0);",
      "  let skip = 0, keep = 0;",
      "  [skip, skip, keep] = arr;",
      "  let tmp = 0;",
      "  ({ x: tmp, y: tmp } = { x: 11, y: 29 });",
      "  return { sum, skip, keep, tmp };",
      "}",
      "module.exports = { computeAll };",
      "",
    ].join("\n");

    const runCjs = (code: string): unknown => {
      const mod = { exports: {} as { computeAll?: (...args: unknown[]) => unknown } };
      new Function("exports", "require", "module", "__filename", "__dirname", code)(
        mod.exports,
        require,
        mod,
        "/virtual/forx.cjs",
        "/virtual",
      );
      return mod.exports.computeAll!(
        [["ab", 3], ["cde", 5]],
        [{ a: 2, b: 7 }, { a: 4, b: 1 }],
        { hello: 1, world: 2 },
        [10, 20, 30],
      );
    };

    const expected = runCjs(src);
    for (const intensity of ["maximum", "bankrupt"] as const) {
      const shielded = transformJavaScriptWithBlaShield(src, {
        intensity,
        seed: `forx-rename-${intensity}`,
        filename: "forx.cjs",
      });
      expect(runCjs(shielded.code)).toEqual(expected);
    }
  });

  it("8-bit seed coupling breaks `runtimeSeed = 1` collapse while preserving intact & detached execution", () => {
    const secret = "acme-enterprise-billing-v4-endpoint";
    const src = [
      '"use strict";',
      `function getEndpoint() { return ${JSON.stringify(secret)}; }`,
      "module.exports = { getEndpoint, text: getEndpoint.toString() };",
      "",
    ].join("\n");
    const shielded = transformJavaScriptWithBlaShield(src, {
      intensity: "bankrupt",
      seed: "seed-low-byte-coupling-1",
      filename: "endpoint.cjs",
    });

    const evalCjs = (code: string) => {
      const mod = { exports: {} as { getEndpoint?: () => string; text?: string } };
      new Function("exports", "require", "module", "__filename", "__dirname", code)(
        mod.exports,
        require,
        mod,
        "/virtual/endpoint.cjs",
        "/virtual",
      );
      return mod.exports;
    };

    // 1. Intact module returns exact plaintext and detached fn.toString() works.
    const intact = evalCjs(shielded.code);
    expect(intact.getEndpoint!()).toBe(secret);
    const detached = vm.runInNewContext(`(${intact.text})`) as () => string;
    expect(detached()).toBe(secret);

    // 2. Red-team universal bypass: forcing module seed + hoisted epoch to `1`
    //    must corrupt every masked string instead of evaluating cleanly.
    const forced = shielded.code.replace(
      /(const\s+(runtimeSeed\w+)\s*=\s*)[\s\S]*?;\s*\n(\s*var\s+(runtimeEpoch\w+)\s*=\s*\2;)/,
      "$1 1;\n$3",
    );
    expect(forced).not.toBe(shielded.code);
    const collapsed = evalCjs(forced);
    expect(collapsed.getEndpoint!()).not.toBe(secret);
  });

  it("self-seal hard-fail enforces 1-char selfExpected tamper, --inspect env tamper, and site-1 openSync", () => {
    const dir = makeDir("bla-selfseal-hardfail-");
    const sib = join(dir, "sib.bin");
    writeFileSync(sib, Buffer.from("sibling-payload-v1"));
    const entry = join(dir, "entry.cjs");
    writeFileSync(
      entry,
      'const fs = require("node:fs"); console.log("OK:" + fs.readFileSync(__dirname + "/sib.bin", "utf8"));\n',
      "utf8",
    );
    const out = join(dir, "entry.out.cjs");
    protectTarget({
      inputPath: entry,
      outputPath: out,
      intensity: "balanced",
      seed: "selfseal-fixes-1",
      selfSeal: true,
      selfSealSiblingPaths: ["sib.bin"],
    });

    // Intact run succeeds.
    const ok = spawnSync(process.execPath, [out], { encoding: "utf8" });
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout.trim()).toBe("OK:sibling-payload-v1");

    // Attack 1: --inspect / NODE_OPTIONS env tamper now fails closed (previously dead `_tampered`!).
    const debugged = spawnSync(process.execPath, [out], {
      encoding: "utf8",
      env: { ...process.env, NODE_OPTIONS: "--inspect=0" },
    });
    expect(debugged.status).not.toBe(0);
    expect(debugged.stderr + debugged.stdout).toMatch(/integrity check failed/);

    // Attack 2: 1-char mutation of `selfExpected` (hex -> 'z') now fails closed (previously skipped!).
    const origCode = readFileSync(out, "utf8");
    const oneCharMutated = origCode.replace(
      /(var\s+selfExpected\s*=\s*")[0-9a-f]([0-9a-f]{63}")/g,
      '$1z$2',
    );
    expect(oneCharMutated).not.toBe(origCode);
    const badPath = join(dir, "entry.bad.cjs");
    writeFileSync(badPath, oneCharMutated, "utf8");
    const bad = spawnSync(process.execPath, [badPath], { encoding: "utf8" });
    expect(bad.status).not.toBe(0);
    expect(bad.stderr + bad.stdout).toMatch(/integrity check failed/);

    // Structural check: site 1 uses openSync/readSync to resist readFileSync-only hooks.
    const snip = generateSelfSealSnippet(new SeededPrng("site1-fd"), {
      siblingPaths: ["sib.bin"],
      expectedSiblingSha256: { "sib.bin": "a".repeat(64) },
      hardFailOnSiblingMismatch: true,
    });
    expect(snip.code).toContain("_fs.openSync");
    expect(snip.code).toContain("_fs.readSync");
  });

  it("closes ESM hoisted-import fs.readFileSync + syncBuiltinESMExports() integrity bypass", () => {
    const dir = makeDir("bla-esm-hoist-fix-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "esm-hoist-test", version: "1.0.0", type: "module", exports: { ".": "./dist/entry.mjs" } }),
    );
    writeFileSync(
      join(dir, "dist/quota.mjs"),
      "export function cap() { return 25; }\n",
      "utf8",
    );
    writeFileSync(
      join(dir, "dist/entry.mjs"),
      'import { cap } from "./quota.mjs";\nconsole.log("CAP:" + cap());\n',
      "utf8",
    );

    const rep = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "esm-hoist-defense-1",
      selfSeal: true,
      sidecarEntangle: true,
    });
    expect(rep.overallSuccess).toBe(true);

    const outEntry = join(rep.outputDirectory, "dist/entry.mjs");
    const outQuota = join(rep.outputDirectory, "dist/quota.mjs");
    const intact = spawnSync(process.execPath, [outEntry], { encoding: "utf8" });
    expect(intact.status, intact.stderr).toBe(0);
    expect(intact.stdout.trim()).toBe("CAP:25");

    // Live exploit: replace quota.mjs with an attacker module that patches
    // `fs.readFileSync` + calls `module.syncBuiltinESMExports()` before entry.mjs body runs.
    const origHardenedQuota = readFileSync(outQuota);
    const pocDir = makeDir("bla-esm-hoist-poc-");
    cpSync(rep.outputDirectory, pocDir, { recursive: true });
    writeFileSync(
      join(pocDir, "dist/quota.mjs"),
      [
        'import fs from "node:fs";',
        'import mod from "node:module";',
        `const origBytes = Buffer.from(${JSON.stringify(origHardenedQuota.toString("base64"))}, "base64");`,
        "const realRead = fs.readFileSync;",
        'fs.readFileSync = function (p, ...rest) { if (String(p).endsWith("quota.mjs")) return origBytes; return realRead.call(this, p, ...rest); };',
        "mod.syncBuiltinESMExports();",
        "export function cap() { return 999999; }",
        "",
      ].join("\n"),
      "utf8",
    );
    const exploited = spawnSync(process.execPath, [join(pocDir, "dist/entry.mjs")], {
      encoding: "utf8",
    });
    expect(exploited.status).not.toBe(0);
    expect(exploited.stderr + exploited.stdout).toMatch(/integrity/i);
  });

  it("WASM loader hook fails closed on 1-byte tamper, WebAssembly.Module bypass, and harden --apply repinning", async () => {
    const dir = makeDir("bla-wasm-hook-fixes-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "wasm-apply-test", version: "1.0.0", main: "dist/index.cjs" }),
    );
    writeFileSync(join(dir, "dist/crypto_core.wasm"), buildTwoFnWasm());
    writeFileSync(join(dir, "dist/helper.cjs"), "module.exports = { bonus: () => 7 };\n", "utf8");
    writeFileSync(
      join(dir, "dist/index.cjs"),
      [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        'const { bonus } = require("./helper.cjs");',
        "async function run() {",
        '  const bytes = fs.readFileSync(path.join(__dirname, "crypto_core.wasm"));',
        "  const { instance } = await WebAssembly.instantiate(bytes);",
        "  const mod = new WebAssembly.Module(bytes);",
        "  const syncInst = new WebAssembly.Instance(mod);",
        "  console.log(JSON.stringify({ a: instance.exports.arxMix(12, 3), b: syncInst.exports.checkKey(51), c: bonus() }));",
        "}",
        "run().catch((e) => { console.error(e.message); process.exit(1); });",
        "",
      ].join("\n"),
      "utf8",
    );

    // 1. harden --apply with BOTH --self-seal and --sidecar-entangle must NOT clobber WASM __ids!
    const rep = hardenProject({
      directory: dir,
      apply: true,
      intensity: "maximum",
      seed: "wasm-apply-repin-1",
      selfSeal: true,
      sidecarEntangle: true,
      wasmPreserveExports: ["arxMix", "checkKey"],
    });
    expect(rep.overallSuccess).toBe(true);
    const okRun = spawnSync(process.execPath, [join(dir, "dist/index.cjs")], { encoding: "utf8" });
    expect(okRun.status, okRun.stderr).toBe(0);
    expect(JSON.parse(okRun.stdout.trim())).toEqual({ a: 51, b: 37, c: 7 });

    // 2. Direct loader hook unit test: new WebAssembly.Module(stripped) AND 1-byte patched WASM fail closed,
    //    while unrelated third-party WASM still instantiates cleanly.
    const hookDir = makeDir("bla-wasm-hook-direct-");
    const rawWasm = buildTwoFnWasm();
    const sidecar = Buffer.from("sidecar-data");
    const bound = entangleWasmEntryWithSidecars({
      entryPath: "core.wasm",
      entryBytes: rawWasm,
      sidecars: [{ pathLabel: "sib.bin", bytes: sidecar }],
      seedTag: "wasm-hook-unit",
    });
    expect(bound).not.toBeNull();
    writeFileSync(join(hookDir, "sib.bin"), sidecar);
    writeFileSync(join(hookDir, "core.wasm"), bound!.bytes);
    writeFileSync(
      join(hookDir, "other.wasm"),
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    );
    const loader = entangleWasmLoaderWithSidecars({
      loaderSource: [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        'const target = process.argv[2];',
        'const bytes = fs.readFileSync(path.join(__dirname, target));',
        'const mod = new WebAssembly.Module(bytes);',
        'console.log("MOD_OK:" + WebAssembly.Module.exports(mod).length);',
        "",
      ].join("\n"),
      wasmBytes: bound!.bytes,
      carrier: "commonjs",
    });
    writeFileSync(join(hookDir, "loader.cjs"), loader.code, "utf8");

    // Intact protected WASM via new WebAssembly.Module passes.
    const modOk = spawnSync(process.execPath, [join(hookDir, "loader.cjs"), "core.wasm"], {
      encoding: "utf8",
    });
    expect(modOk.status, modOk.stderr).toBe(0);
    expect(modOk.stdout.trim()).toBe("MOD_OK:2");

    // Unrelated empty WASM still passes.
    const otherOk = spawnSync(process.execPath, [join(hookDir, "loader.cjs"), "other.wasm"], {
      encoding: "utf8",
    });
    expect(otherOk.status, otherOk.stderr).toBe(0);

    // Stripped bla.sidecar.v1 via new WebAssembly.Module fails closed!
    writeFileSync(join(hookDir, "stripped.wasm"), stripWasmSidecarCustomSection(bound!.bytes));
    const modStripped = spawnSync(
      process.execPath,
      [join(hookDir, "loader.cjs"), "stripped.wasm"],
      { encoding: "utf8" },
    );
    expect(modStripped.status).not.toBe(0);
    expect(modStripped.stderr + modStripped.stdout).toMatch(/bla\.sidecar\.v1|integrity binding mismatch/);

    // 1-byte patched code + stripped section (matches protectedExportNames) fails closed!
    const patched = Buffer.from(rawWasm);
    patched[patched.length - 2] = 0x72; // change xor/and byte while keeping valid wasm
    writeFileSync(join(hookDir, "patched.wasm"), patched);
    const modPatched = spawnSync(
      process.execPath,
      [join(hookDir, "loader.cjs"), "patched.wasm"],
      { encoding: "utf8" },
    );
    expect(modPatched.status).not.toBe(0);
    expect(modPatched.stderr + modPatched.stdout).toMatch(/integrity binding mismatch/);
  });

  it("polymorphic multi-point WASM flowers sandwich real bytecode and eliminate repeated-e / canary-honeypot tells", async () => {
    const raw = buildTwoFnWasm();
    const flowered = injectWasmBytecodeFlowerInstructions(raw, {
      intensity: "bankrupt",
      seed: "poly-wasm-flower-1",
    });
    expect(flowered.functionsHardened).toBe(2);
    expect(flowered.flowerBlocksInjected).toBe(8);
    const floweredBytes = new Uint8Array(flowered.buffer);
    expect(WebAssembly.validate(floweredBytes)).toBe(true);

    // Real original 10-byte tail must NOT sit directly before final 0x0b end (epilogue flower follows it).
    const origTail0 = Buffer.from([0x20, 0x00, 0x20, 0x01, 0x6a, 0x41, 0x07, 0x6c, 0x41, 0xda, 0x00, 0x73, 0x0b]);
    expect(flowered.buffer.indexOf(origTail0)).toBe(-1);

    // Runtime equivalence across negative, zero, and boundary inputs.
    const { instance } = await WebAssembly.instantiate(floweredBytes);
    const exports = instance.exports as { arxMix: (a: number, b: number) => number; checkKey: (k: number) => number };
    for (const [a, b] of [[12, 3], [0, 0], [-7, 19], [0x7fff, -1234]]) {
      expect(exports.arxMix(a, b)).toBe((((a + b) * 7) ^ 90) | 0);
      expect(exports.checkKey(a)).toBe((((a ^ 19) + 5) & 255) | 0);
    }

    // Protected WASM must not contain 1000+ consecutive 'e' padding or self-snitching classification strings.
    const prot = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "poly-wasm-prot-1",
      preserveExports: ["arxMix", "checkKey"],
    });
    const text = prot.buffer.toString("latin1");
    expect(text).not.toContain("e".repeat(1000));
    expect(text).not.toContain("SYNTHETIC_CANARY_CREDENTIAL_HONEYPOT");
    expect(text).not.toContain("SYSTEM_DIAGNOSTIC_AND_COGNITIVE_ARMOR_DECOY");
  });

  it.skipIf(!PY3)("Python hardening selects loader.py, enforces self-seal on engine.py, uses per-file seeds, and blocks PYTHONPATH hashlib spoofing", () => {
    const dir = makeDir("bla-py-reinforce-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(
      join(dir, "dist/engine.py"),
      "def score(x: int) -> int:\n    return (x * 13) ^ 7\n",
      "utf8",
    );
    writeFileSync(
      join(dir, "dist/loader.py"),
      'from engine import score\nif __name__ == "__main__":\n    print("SCORE:" + str(score(10)))\n',
      "utf8",
    );

    const rep = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "py-reinforce-1",
      selfSeal: true,
      sidecarEntangle: true,
      weaveDecoys: true,
    });
    expect(rep.overallSuccess).toBe(true);

    const outEngine = join(rep.outputDirectory, "dist/engine.py");
    const outLoader = join(rep.outputDirectory, "dist/loader.py");
    const engineSrc = readFileSync(outEngine, "utf8");
    const loaderSrc = readFileSync(outLoader, "utf8");

    // 1. Per-file seeding: decoy preambles must NOT be identical across files.
    expect(engineSrc.slice(0, 800)).not.toBe(loaderSrc.slice(0, 800));
    expect(engineSrc).not.toContain("(inert)");
    expect(loaderSrc).not.toContain("(inert)");

    // 2. Intact execution matches baseline.
    const ok = spawnSync("python3", [outLoader], { encoding: "utf8" });
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout.trim()).toBe("SCORE:133");

    // 3. Tampering engine.py OR replacing engine.py with unhardened original BOTH fail closed!
    const tmp1 = makeDir("bla-py-tamper-");
    cpSync(rep.outputDirectory, tmp1, { recursive: true });
    writeFileSync(join(tmp1, "dist/engine.py"), engineSrc + "\n# patched\n", "utf8");
    const tampered = spawnSync("python3", [join(tmp1, "dist/loader.py")], { encoding: "utf8" });
    expect(tampered.status).not.toBe(0);

    writeFileSync(join(tmp1, "dist/engine.py"), readFileSync(join(dir, "dist/engine.py")));
    const replaced = spawnSync("python3", [join(tmp1, "dist/loader.py")], { encoding: "utf8" });
    expect(replaced.status).not.toBe(0);

    // 4. PYTHONPATH fake hashlib.py spoofing must NOT bypass tampered engine.py!
    const spoofDir = makeDir("bla-py-spoof-");
    const expectedMatch = loaderSrc.match(/_sc_expected_[0-9a-f]{8}\s*=\s*"([0-9a-f]{64})"/);
    expect(expectedMatch).not.toBeNull();
    writeFileSync(
      join(spoofDir, "hashlib.py"),
      `class _Fake:\n    def update(self, b): pass\n    def hexdigest(self): return ${JSON.stringify(expectedMatch![1])}\ndef sha256(b=b""): return _Fake()\n`,
      "utf8",
    );
    const spoofed = spawnSync("python3", [join(tmp1, "dist/loader.py")], {
      encoding: "utf8",
      env: { ...process.env, PYTHONPATH: spoofDir },
    });
    expect(spoofed.status).not.toBe(0);

    // 5. Python sibling auto-detection in `bla verify` & stale `__pycache__` nextSteps warning.
    const verifiedEngine = verifyTarget(outEngine, join(dir, "dist/engine.py"), {
      autoDetectBindings: true,
    });
    expect(verifiedEngine.overallPassed).toBe(true);
    expect((verifiedEngine.defenseScoreGaps ?? []).map((g) => g.id)).toEqual([]);

    const cacheDir = join(dir, "dist/__pycache__");
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(join(cacheDir, "engine.cpython-312.pyc"), Buffer.from([0xcb, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    const repWithCache = hardenProject({
      directory: dir,
      outputDirectory: join(dir, ".bla-hardened-2"),
      intensity: "balanced",
      seed: "py-cache-warn-1",
    });
    expect((repWithCache.nextSteps ?? []).some((s) => s.includes("__pycache__"))).toBe(true);

    // 6. Python single-file self-seal works standalone with builtins shadowed on reload.
    const pySingle = protectPythonSource('len = 99\nVALUE = 42\n', {
      intensity: "balanced",
      seed: "py-selfseal-reload",
      selfSeal: true,
    });
    expect(pySingle.code).not.toContain("(inert)");
    expect(pySingle.code).toContain("self_expected =");
  });

  it("detects typeof-window browser widgets, preserves JS directives/license comments, auto-detects bla verify bindings, and removes self-snitching tells", () => {
    const dir = makeDir("bla-ux-fixes-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    const widgetPath = join(dir, "dist/web-widget.js");
    writeFileSync(
      widgetPath,
      '(() => { if (typeof window !== "undefined" && typeof document !== "undefined") { window.__W__ = { render(el, v) { el.textContent = "Hi " + v; } }; } })();\n',
      "utf8",
    );
    const verdicts = classifyBrowserBundles(
      [{ path: widgetPath, relativePath: "dist/web-widget.js" }],
      dir,
    );
    expect(verdicts.has(widgetPath)).toBe(true);

    // Directive + license banner preservation in bindSidecarEntanglement (CJS & ESM).
    const cjsSrc = '/*! Copyright 2026 Acme */\n"use strict";module.exports = 1;\n';
    const cjsBound = bindSidecarEntanglement({
      entryPath: "a.cjs",
      sidecarPaths: ["b.bin"],
      entryBytes: Buffer.from(cjsSrc),
      sidecarBytes: [Buffer.from("b")],
      carrier: "commonjs",
    });
    expect(cjsBound.code.startsWith('/*! Copyright 2026 Acme */\n"use strict";\n')).toBe(true);

    const rscSrc = '"use client";\nexport const X = 1;\n';
    const rscBound = bindSidecarEntanglement({
      entryPath: "a.mjs",
      sidecarPaths: ["b.bin"],
      entryBytes: Buffer.from(rscSrc),
      sidecarBytes: [Buffer.from("b")],
      carrier: "module",
    });
    expect(rscBound.code.startsWith('"use client";\n')).toBe(true);

    // bla verify autoDetectBindings + reversed-argument diagnostic.
    const vDir = makeDir("bla-verify-auto-");
    mkdirSync(join(vDir, "dist"), { recursive: true });
    writeFileSync(join(vDir, "package.json"), JSON.stringify({ name: "v-test", version: "1.0.0", main: "dist/a.cjs" }));
    writeFileSync(join(vDir, "dist/a.cjs"), 'const b = require("./b.cjs"); module.exports = { x: b.y + 1 };\n');
    writeFileSync(join(vDir, "dist/b.cjs"), "module.exports = { y: 41 };\n");
    const h = hardenProject({
      directory: vDir,
      intensity: "bankrupt",
      seed: "verify-auto-1",
      selfSeal: true,
      sidecarEntangle: true,
    });
    const outA = join(h.outputDirectory, "dist/a.cjs");
    const origA = join(vDir, "dist/a.cjs");
    const verified = verifyTarget(outA, origA, { autoDetectBindings: true });
    expect(verified.overallPassed).toBe(true);
    expect((verified.defenseScoreGaps ?? []).map((g) => g.id)).toEqual([]);

    const reversed = verifyTarget(origA, outA, { autoDetectBindings: true });
    expect((reversed.agentActions ?? []).some((a) => a.id === "reversed-verify-arguments")).toBe(true);

    // harden --apply --dry-run after a prior --apply plans cleanly instead of refusing.
    const applyDir = makeDir("bla-apply-dryrun-");
    mkdirSync(join(applyDir, "dist"), { recursive: true });
    writeFileSync(join(applyDir, "dist/app.cjs"), "module.exports = { ok: 1 };\n");
    const firstApply = hardenProject({
      directory: applyDir,
      apply: true,
      intensity: "balanced",
      seed: "apply-dry-1",
    });
    expect(firstApply.overallSuccess).toBe(true);
    const secondPreview = hardenProject({
      directory: applyDir,
      apply: true,
      dryRun: true,
      intensity: "balanced",
      seed: "apply-dry-1",
    });
    expect(secondPreview.apply?.status).toBe("planned");
    expect(secondPreview.discoveredCount).toBe(1);

    // Global tell scrubbing: no 0x424c4103, apparent decompiler constant, state_diff_frontier_, or remediation_rabbit_hole.
    const jsOut = readFileSync(outA, "utf8");
    expect(jsOut).not.toContain("0x424c4103");
    expect(jsOut).not.toContain("apparent decompiler constant");
    expect(jsOut).not.toContain("aliased overwrite via shared ArrayBuffer");
    expect(jsOut).not.toContain("state_diff_frontier_");

    const DatabaseSync = getDatabaseSyncClass();
    const dbPath = join(dir, "t.sqlite");
    const db = new DatabaseSync(dbPath);
    db.exec("CREATE TABLE items (id INTEGER PRIMARY KEY, val TEXT); INSERT INTO items VALUES (1, 'ok');");
    db.close();
    const protDb = protectSqliteBuffer(readFileSync(dbPath), { intensity: "balanced", seed: "sql-tell-1" });
    expect(protDb.buffer.toString("latin1")).not.toContain("remediation_rabbit_hole");
  });
});
