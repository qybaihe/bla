import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import {
  bindWasmSidecarEntanglement,
  computeWasmSidecarCodeIdentity,
  entangleWasmLoaderWithSidecars,
  generateSidecarWasmLoaderSnippet,
  isSafeNodeWasmJsLoader,
  isWasmSidecarLoaderHookWired,
  prependWasmSidecarLoaderHook,
  selectNodeWasmJsLoader,
  detectWasmJsLoaderCarrier,
  esmStaticImportsAreNodeBuiltinsOnly,
  SIDECAR_ENTANGLE_SCHEMA,
  stripWasmSidecarCustomSection,
  WASM_SIDECAR_LOADER_MARKER,
  WASM_SIDECAR_SECTION_NAME,
} from "../src/shields/runtime/sidecar-entangle.js";
import { inspectWasmBinary } from "../src/shields/formats/wasm.js";
import { collectDefenseScoreGaps } from "../src/engine/defense-score-honesty.js";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifyTarget } from "../src/engine/verifier.js";

/** Minimal WASM exporting compute_score(i32)->i32 = x*42+7 */
function fixtureComputeScore(): Buffer {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60,
    0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x11, 0x01, 0x0d,
    0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x5f, 0x73, 0x63, 0x6f, 0x72,
    0x65, 0x00, 0x00, 0x0a, 0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x41, 0x2a,
    0x6c, 0x41, 0x07, 0x6a, 0x0b,
  ]);
}

/** Empty WASM module (valid magic + version, no exports). */
function fixtureEmptyModule(): Buffer {
  return Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
}

function runLoader(
  dir: string,
  source: string,
): { status: number; stdout: string; stderr: string } {
  writeFileSync(join(dir, "loader.cjs"), source, "utf8");
  try {
    const stdout = execFileSync(process.execPath, ["loader.cjs"], {
      cwd: dir,
      encoding: "utf8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: string; stderr?: string };
    return {
      status: typeof err.status === "number" ? err.status : 1,
      stdout: String(err.stdout ?? ""),
      stderr: String(err.stderr ?? ""),
    };
  }
}

function runEsmLoader(
  dir: string,
  source: string,
  filename = "loader.mjs",
): { status: number; stdout: string; stderr: string } {
  writeFileSync(join(dir, filename), source, "utf8");
  try {
    const stdout = execFileSync(process.execPath, [filename], {
      cwd: dir,
      encoding: "utf8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: string; stderr?: string };
    return {
      status: typeof err.status === "number" ? err.status : 1,
      stdout: String(err.stdout ?? ""),
      stderr: String(err.stderr ?? ""),
    };
  }
}

const LOADER_BODY = `
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const bytes = fs.readFileSync(path.join(__dirname, "core.wasm"));
WebAssembly.instantiate(bytes).then(({ instance }) => {
  const fn = instance.exports.compute_score;
  if (typeof fn !== "function") {
    console.error("missing export");
    process.exit(2);
  }
  const value = fn(1);
  if (value !== 49) {
    console.error("unexpected result", value);
    process.exit(3);
  }
  console.log("ok", value);
}).catch((err) => {
  console.error(err && err.message ? err.message : String(err));
  process.exit(1);
});
`;


const ESM_LOADER_BODY = `
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bytes = fs.readFileSync(path.join(__dirname, "core.wasm"));
WebAssembly.instantiate(bytes).then(({ instance }) => {
  const fn = instance.exports.compute_score;
  if (typeof fn !== "function") {
    console.error("missing export");
    process.exit(2);
  }
  const result = fn(1);
  console.log("ok " + result);
}).catch((err) => {
  console.error(err && err.message ? err.message : String(err));
  process.exit(1);
});
`;

const EMPTY_LOADER_BODY = `
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const bytes = fs.readFileSync(path.join(__dirname, "other.wasm"));
WebAssembly.instantiate(bytes).then(({ instance }) => {
  if (instance.exports.compute_score) {
    console.error("unexpected export");
    process.exit(2);
  }
  console.log("passthrough");
}).catch((err) => {
  console.error(err && err.message ? err.message : String(err));
  process.exit(1);
});
`;

describe("sidecar WASM JS-loader hook", () => {
  it("generateSidecarWasmLoaderSnippet rejects non-hex identities", () => {
    expect(() =>
      generateSidecarWasmLoaderSnippet({ codeIdentityHex: "deadbeef" }),
    ).toThrow(/64-char/);
  });

  it("computeWasmSidecarCodeIdentity is stable across planting the note", () => {
    const entry = fixtureComputeScore();
    const unbound = computeWasmSidecarCodeIdentity(entry);
    const bound = bindWasmSidecarEntanglement({
      entryPath: "core.wasm",
      sidecarPaths: ["sib.bin"],
      seedTag: "loader-id-v1",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode("sidecar-payload\n")],
    });
    expect(computeWasmSidecarCodeIdentity(bound.bytes)).toBe(unbound);
    expect(unbound).toMatch(/^[0-9a-f]{64}$/);
    const stripped = stripWasmSidecarCustomSection(bound.bytes);
    expect(computeWasmSidecarCodeIdentity(stripped)).toBe(unbound);
  });

  it("prepend is idempotent and preserves shebang / use strict", () => {
    const inject = generateSidecarWasmLoaderSnippet({
      codeIdentityHex: computeWasmSidecarCodeIdentity(fixtureComputeScore()),
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.preamble).toContain(WASM_SIDECAR_LOADER_MARKER);
    const once = prependWasmSidecarLoaderHook(
      '#!/usr/bin/env node\n"use strict";\nconsole.log(1);\n',
      inject.preamble,
    );
    expect(once.startsWith("#!/usr/bin/env node\n")).toBe(true);
    expect(once).toContain('"use strict";');
    const twice = prependWasmSidecarLoaderHook(once, inject.preamble);
    expect(twice).toBe(once);
  });

  it("load-time hook: intact module instantiates and keeps the export", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-ok-"));
    try {
      const entry = fixtureComputeScore();
      const sibSrc = "sidecar-payload\n";
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
      const bound = bindWasmSidecarEntanglement({
        entryPath: "core.wasm",
        sidecarPaths: ["sib.bin"],
        seedTag: "loader-rt-v1",
        entryBytes: entry,
        sidecarBytes: [new TextEncoder().encode(sibSrc)],
      });
      writeFileSync(join(dir, "core.wasm"), bound.bytes);
      const inspected = inspectWasmBinary(bound.bytes);
      expect(inspected.validMagic).toBe(true);
      expect(inspected.customSectionNames).toContain(WASM_SIDECAR_SECTION_NAME);
      expect(inspected.exportNames).toEqual(["compute_score"]);

      const entangled = entangleWasmLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        wasmBytes: bound.bytes,
        baseDir: dir,
      });
      expect(entangled.codeIdentityHex).toBe(
        computeWasmSidecarCodeIdentity(bound.bytes),
      );
      const ran = runLoader(dir, entangled.code);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 49/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("load-time hook: stripping the custom section fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-strip-"));
    try {
      const entry = fixtureComputeScore();
      const sibSrc = "sidecar-payload\n";
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
      const bound = bindWasmSidecarEntanglement({
        entryPath: "core.wasm",
        sidecarPaths: ["sib.bin"],
        seedTag: "loader-strip-v1",
        entryBytes: entry,
        sidecarBytes: [new TextEncoder().encode(sibSrc)],
      });
      const stripped = stripWasmSidecarCustomSection(bound.bytes);
      writeFileSync(join(dir, "core.wasm"), stripped);
      const inspected = inspectWasmBinary(stripped);
      expect(inspected.validMagic).toBe(true);
      expect(inspected.customSectionNames).not.toContain(WASM_SIDECAR_SECTION_NAME);
      expect(inspected.exportNames).toContain("compute_score");

      const entangled = entangleWasmLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        wasmBytes: bound.bytes,
        baseDir: dir,
      });
      const ran = runLoader(dir, entangled.code);
      expect(ran.status).toBe(1);
      expect(ran.stderr + ran.stdout).toMatch(/missing or unreadable|integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("load-time hook: mutated sibling sidecar fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-sib-"));
    try {
      const entry = fixtureComputeScore();
      const sibSrc = "sidecar-payload\n";
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
      const bound = bindWasmSidecarEntanglement({
        entryPath: "core.wasm",
        sidecarPaths: ["sib.bin"],
        seedTag: "loader-sib-v1",
        entryBytes: entry,
        sidecarBytes: [new TextEncoder().encode(sibSrc)],
      });
      writeFileSync(join(dir, "core.wasm"), bound.bytes);
      writeFileSync(join(dir, "sib.bin"), "tampered\n", "utf8");

      const entangled = entangleWasmLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        wasmBytes: bound.bytes,
        baseDir: dir,
      });
      const ran = runLoader(dir, entangled.code);
      expect(ran.status).toBe(1);
      expect(ran.stderr + ran.stdout).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("load-time hook: unrelated WASM still instantiates", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-pass-"));
    try {
      const entry = fixtureComputeScore();
      const sibSrc = "sidecar-payload\n";
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
      const bound = bindWasmSidecarEntanglement({
        entryPath: "core.wasm",
        sidecarPaths: ["sib.bin"],
        seedTag: "loader-pass-v1",
        entryBytes: entry,
        sidecarBytes: [new TextEncoder().encode(sibSrc)],
      });
      writeFileSync(join(dir, "other.wasm"), fixtureEmptyModule());

      const entangled = entangleWasmLoaderWithSidecars({
        loaderSource: EMPTY_LOADER_BODY,
        wasmBytes: bound.bytes,
        baseDir: dir,
      });
      const ran = runLoader(dir, entangled.code);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/passthrough/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("honesty: shipping the snippet without wiring keeps the host-verify-only gap", () => {
    const gaps = collectDefenseScoreGaps({
      detectedFormat: "wasm",
      sidecarEntangleEnabled: true,
    });
    expect(gaps.map((g) => g.id)).toContain("wasm-sidecar-host-verify-only");
  });
  it("honesty: auto-wired loader hook clears wasm-sidecar-host-verify-only", () => {
    const gaps = collectDefenseScoreGaps({
      detectedFormat: "wasm",
      sidecarEntangleEnabled: true,
      wasmSidecarLoaderHookApplied: true,
    });
    expect(gaps.map((g) => g.id)).not.toContain("wasm-sidecar-host-verify-only");
  });

  it("selectNodeWasmJsLoader prefers stem/loader/index and refuses unsafe files", () => {
    const nodeLoader = `
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const bytes = fs.readFileSync(path.join(__dirname, "core.wasm"));
WebAssembly.instantiate(bytes);
`;
    const browserLoader = `
fetch("./core.wasm").then((r) => WebAssembly.instantiateStreaming(r));
`;
    const esmLoader = `
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const dir = path.dirname(fileURLToPath(import.meta.url));
const bytes = fs.readFileSync(path.join(dir, "core.wasm"));
WebAssembly.instantiate(bytes);
`;
    const esmUserImport = `
import fs from "node:fs";
import { helper } from "./util.js";
const bytes = fs.readFileSync(new URL("./core.wasm", import.meta.url));
WebAssembly.instantiate(bytes);
`;
    const esmWasmImport = `
import fs from "node:fs";
import wasm from "./core.wasm";
WebAssembly.instantiate(wasm);
`;
    const otherWasm = `
"use strict";
const fs = require("node:fs");
WebAssembly.instantiate(fs.readFileSync("./other.wasm"));
`;
    expect(
      isSafeNodeWasmJsLoader({
        source: nodeLoader,
        filename: "loader.cjs",
        wasmBasename: "core.wasm",
      }),
    ).toBe(true);
    expect(
      isSafeNodeWasmJsLoader({
        source: browserLoader,
        filename: "loader.js",
        wasmBasename: "core.wasm",
      }),
    ).toBe(false);
    expect(
      isSafeNodeWasmJsLoader({
        source: esmLoader,
        filename: "loader.mjs",
        wasmBasename: "core.wasm",
      }),
    ).toBe(true);
    expect(detectWasmJsLoaderCarrier("loader.mjs", esmLoader)).toBe("module");
    expect(esmStaticImportsAreNodeBuiltinsOnly(esmLoader)).toBe(true);
    expect(
      isSafeNodeWasmJsLoader({
        source: esmUserImport,
        filename: "loader.mjs",
        wasmBasename: "core.wasm",
      }),
    ).toBe(false);
    expect(
      isSafeNodeWasmJsLoader({
        source: esmWasmImport,
        filename: "loader.mjs",
        wasmBasename: "core.wasm",
      }),
    ).toBe(false);
    expect(
      isSafeNodeWasmJsLoader({
        source: otherWasm,
        filename: "loader.cjs",
        wasmBasename: "core.wasm",
      }),
    ).toBe(false);

    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "helper.cjs", source: nodeLoader },
        { name: "loader.cjs", source: nodeLoader },
        { name: "index.cjs", source: nodeLoader },
      ]),
    ).toBe("loader.cjs");
    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "core.cjs", source: nodeLoader },
        { name: "loader.cjs", source: nodeLoader },
      ]),
    ).toBe("core.cjs");
    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "a.cjs", source: nodeLoader },
        { name: "b.cjs", source: nodeLoader },
      ]),
    ).toBeNull();
    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "license.cjs", source: nodeLoader },
      ]),
    ).toBeNull();
    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "helper.cjs", source: nodeLoader },
      ]),
    ).toBeNull();
    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "loader.cjs", source: nodeLoader },
        { name: "loader.mjs", source: esmLoader },
      ]),
    ).toBe("loader.cjs");
    expect(
      selectNodeWasmJsLoader("core.wasm", [
        { name: "loader.mjs", source: esmLoader },
      ]),
    ).toBe("loader.mjs");
  });

  it("protectTarget auto-wires a same-directory Node CJS loader and records wasm-sidecar-entangle", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-protect-"));
    try {
      const entry = join(dir, "core.wasm");
      const sibSrc = "sidecar-payload\n";
      writeFileSync(entry, fixtureComputeScore());
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
      writeFileSync(join(dir, "loader.cjs"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-wasm-loader-hook",
        wasmPreserveExports: ["compute_score"],
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.wasmSidecarLoaderHookApplied).toBe(true);
      expect(res.counteredReaVectors).toContain("wasm-sidecar-entangle");

      const hooked = readFileSync(join(dir, "loader.cjs"), "utf8");
      expect(hooked).toContain(WASM_SIDECAR_LOADER_MARKER);
      expect(
        isWasmSidecarLoaderHookWired({
          wasmBytes: readFileSync(entry),
          wasmPath: entry,
        }),
      ).toBe(true);

      const inspected = inspectWasmBinary(readFileSync(entry));
      expect(inspected.validMagic).toBe(true);
      expect(inspected.customSectionNames).toContain(WASM_SIDECAR_SECTION_NAME);
      expect(inspected.exportNames).toContain("compute_score");

      const ran = runLoader(dir, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 49/);

      const verification = verifyTarget(entry, undefined, {
        sidecarEntangleEnabled: true,
      });
      const gapIds = (verification.defenseScoreGaps ?? []).map((g) => g.id);
      expect(gapIds).not.toContain("wasm-sidecar-host-verify-only");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget does not rewrite a browser fetch loader or record the vector", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-browser-"));
    try {
      const entry = join(dir, "core.wasm");
      writeFileSync(entry, fixtureComputeScore());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n", "utf8");
      const browser = `fetch("./core.wasm").then((r) => WebAssembly.instantiateStreaming(r));\n`;
      writeFileSync(join(dir, "loader.js"), browser, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-wasm-loader-browser",
        wasmPreserveExports: ["compute_score"],
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.wasmSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("wasm-sidecar-entangle");
      expect(readFileSync(join(dir, "loader.js"), "utf8")).toBe(browser);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("hardenProject auto-wires dist/loader.cjs beside core.wasm", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-harden-"));
    try {
      const dist = join(dir, "dist");
      mkdirSync(dist, { recursive: true });
      writeFileSync(join(dist, "core.wasm"), fixtureComputeScore());
      writeFileSync(join(dist, "sib.bin"), "sidecar-payload\n", "utf8");
      writeFileSync(join(dist, "loader.cjs"), LOADER_BODY, "utf8");

      const report = hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "harden-wasm-loader-hook",
        sidecarEntangle: true,
        wasmPreserveExports: ["compute_score"],
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.sidecarEntangleError).toBeUndefined();

      const outDist = join(report.outputDirectory, "dist");
      const hooked = readFileSync(join(outDist, "loader.cjs"), "utf8");
      expect(hooked).toContain(WASM_SIDECAR_LOADER_MARKER);
      const wasmBytes = readFileSync(join(outDist, "core.wasm"));
      expect(inspectWasmBinary(wasmBytes).customSectionNames).toContain(
        WASM_SIDECAR_SECTION_NAME,
      );
      expect(
        isWasmSidecarLoaderHookWired({
          wasmBytes,
          wasmPath: join(outDist, "core.wasm"),
        }),
      ).toBe(true);

      const ran = runLoader(outDist, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 49/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget auto-wires a same-directory Node ESM loader and records wasm-sidecar-entangle", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-protect-esm-"));
    try {
      const entry = join(dir, "core.wasm");
      const sibSrc = "sidecar-payload\n";
      writeFileSync(entry, fixtureComputeScore());
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
      writeFileSync(join(dir, "loader.mjs"), ESM_LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-wasm-loader-hook-esm",
        wasmPreserveExports: ["compute_score"],
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.wasmSidecarLoaderHookApplied).toBe(true);
      expect(res.counteredReaVectors).toContain("wasm-sidecar-entangle");

      const hooked = readFileSync(join(dir, "loader.mjs"), "utf8");
      expect(hooked).toContain(WASM_SIDECAR_LOADER_MARKER);
      expect(hooked).toMatch(/import \{ createRequire as /);
      expect(hooked).toContain("import.meta.url");
      expect(
        isWasmSidecarLoaderHookWired({
          wasmBytes: readFileSync(entry),
          wasmPath: entry,
        }),
      ).toBe(true);

      const inspected = inspectWasmBinary(readFileSync(entry));
      expect(inspected.validMagic).toBe(true);
      expect(inspected.customSectionNames).toContain(WASM_SIDECAR_SECTION_NAME);
      expect(inspected.exportNames).toContain("compute_score");

      const ran = runEsmLoader(dir, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 49/);

      const verification = verifyTarget(entry, undefined, {
        sidecarEntangleEnabled: true,
      });
      const gapIds = (verification.defenseScoreGaps ?? []).map((g) => g.id);
      expect(gapIds).not.toContain("wasm-sidecar-host-verify-only");
      expect(gapIds).not.toContain("esm-import-hoist-before-hooks");

      const bound = readFileSync(entry);
      writeFileSync(entry, stripWasmSidecarCustomSection(bound));
      const failed = runEsmLoader(dir, hooked);
      expect(failed.status).not.toBe(0);
      expect(failed.stderr + failed.stdout).toMatch(
        /bla\.sidecar\.v1 custom section missing|integrity binding mismatch/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget does not rewrite an ESM loader that statically imports a user module", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-esm-user-"));
    try {
      const entry = join(dir, "core.wasm");
      writeFileSync(entry, fixtureComputeScore());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n", "utf8");
      const esm =
        'import fs from "node:fs";\nimport { helper } from "./util.js";\nWebAssembly.instantiate(fs.readFileSync(new URL("./core.wasm", import.meta.url)));\n';
      writeFileSync(join(dir, "loader.mjs"), esm, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-wasm-loader-esm-user",
        wasmPreserveExports: ["compute_score"],
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.wasmSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("wasm-sidecar-entangle");
      expect(readFileSync(join(dir, "loader.mjs"), "utf8")).toBe(esm);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("hardenProject auto-wires dist/loader.mjs beside core.wasm", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-loader-harden-esm-"));
    try {
      const dist = join(dir, "dist");
      mkdirSync(dist, { recursive: true });
      writeFileSync(join(dist, "core.wasm"), fixtureComputeScore());
      writeFileSync(join(dist, "sib.bin"), "sidecar-payload\n", "utf8");
      writeFileSync(join(dist, "loader.mjs"), ESM_LOADER_BODY, "utf8");

      const report = hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "harden-wasm-loader-hook-esm",
        sidecarEntangle: true,
        wasmPreserveExports: ["compute_score"],
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.sidecarEntangleError).toBeUndefined();

      const outDist = join(report.outputDirectory, "dist");
      const hooked = readFileSync(join(outDist, "loader.mjs"), "utf8");
      expect(hooked).toContain(WASM_SIDECAR_LOADER_MARKER);
      expect(hooked).toMatch(/import \{ createRequire as /);
      const wasmBytes = readFileSync(join(outDist, "core.wasm"));
      expect(inspectWasmBinary(wasmBytes).customSectionNames).toContain(
        WASM_SIDECAR_SECTION_NAME,
      );
      expect(
        isWasmSidecarLoaderHookWired({
          wasmBytes,
          wasmPath: join(outDist, "core.wasm"),
        }),
      ).toBe(true);

      const ran = runEsmLoader(outDist, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 49/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

});
