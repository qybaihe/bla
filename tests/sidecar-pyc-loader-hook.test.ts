import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  readFileSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  bindPycSidecarEntanglement,
  computePycSidecarCodeIdentity,
  entanglePycLoaderWithSidecars,
  extractPycSidecarMarshalNote,
  generateSidecarPycLoaderSnippet,
  isPycSidecarLoaderHookWired,
  isSafePythonPycLoader,
  prependPycSidecarLoaderHook,
  PYC_SIDECAR_LOADER_MARKER,
  PYC_SIDECAR_MARSHAL_MARKER,
  selectPythonPycLoader,
  SIDECAR_ENTANGLE_SCHEMA,
  sourceMentionsPycModule,
  stripPycSidecarMarshalNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import { collectDefenseScoreGaps } from "../src/engine/defense-score-honesty.js";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifyTarget } from "../src/engine/verifier.js";

const PY3 = (() => {
  const r = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();

function compileSamplePyc(): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-compile-"));
  try {
    const srcPath = join(dir, "sample.py");
    const pycPath = join(dir, "sample.pyc");
    writeFileSync(srcPath, "def add(a, b):\n    return a + b\n\nRESULT = add(2, 3)\n");
    const r = spawnSync(
      "python3",
      [
        "-c",
        `import py_compile; py_compile.compile(${JSON.stringify(srcPath)}, cfile=${JSON.stringify(pycPath)}, doraise=True)`,
      ],
      { encoding: "utf8" },
    );
    if (r.status !== 0) {
      throw new Error(`py_compile failed: ${r.stderr || r.stdout}`);
    }
    return readFileSync(pycPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const LOADER_BODY = `import importlib.util
import pathlib
_pyc = pathlib.Path(__file__).resolve().parent / "sample.pyc"
_spec = importlib.util.spec_from_file_location("sample", _pyc)
_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_mod)
print("ok", _mod.RESULT)
`;

const FUTURE_LOADER_BODY = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loader docstring."""
from __future__ import annotations
import importlib.util
import pathlib
_pyc = pathlib.Path(__file__).resolve().parent / "sample.pyc"
_spec = importlib.util.spec_from_file_location("sample", _pyc)
_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_mod)
print("ok", _mod.RESULT)
`;

function runLoader(
  dir: string,
  source: string,
  filename = "loader.py",
): { status: number; stdout: string; stderr: string } {
  writeFileSync(join(dir, filename), source, "utf8");
  const r = spawnSync("python3", [filename], {
    cwd: dir,
    encoding: "utf8",
    timeout: 15_000,
  });
  return {
    status: r.status ?? 1,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  };
}

describe("sidecar .pyc import-time hook", () => {
  it("generateSidecarPycLoaderSnippet rejects non-hex identities", () => {
    expect(() =>
      generateSidecarPycLoaderSnippet({
        codeIdentityHex: "deadbeef",
        pycRelPaths: ["sample.pyc"],
      }),
    ).toThrow(/64-char/);
  });

  it.skipIf(!PY3)("computePycSidecarCodeIdentity is stable across planting the note", () => {
    const entry = compileSamplePyc();
    const unbound = computePycSidecarCodeIdentity(entry);
    const bound = bindPycSidecarEntanglement({
      entryPath: "sample.pyc",
      sidecarPaths: ["sib.bin"],
      seedTag: "loader-id-v1",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode("sidecar-payload\n")],
    });
    expect(computePycSidecarCodeIdentity(bound.bytes)).toBe(unbound);
    expect(unbound).toMatch(/^[0-9a-f]{64}$/);
    const stripped = stripPycSidecarMarshalNote(bound.bytes);
    expect(computePycSidecarCodeIdentity(stripped)).toBe(unbound);
  });

  it("prepend is idempotent and preserves shebang / encoding / docstring / futures", () => {
    const inject = generateSidecarPycLoaderSnippet({
      codeIdentityHex: "a".repeat(64),
      pycRelPaths: ["sample.pyc"],
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.preamble).toContain(PYC_SIDECAR_LOADER_MARKER);
    const once = prependPycSidecarLoaderHook(FUTURE_LOADER_BODY, inject.preamble);
    expect(once.startsWith("#!/usr/bin/env python3\n")).toBe(true);
    expect(once).toContain("# -*- coding: utf-8 -*-");
    expect(once).toContain('"""Loader docstring."""');
    expect(once).toContain("from __future__ import annotations");
    const hookAt = once.indexOf(PYC_SIDECAR_LOADER_MARKER);
    const futureAt = once.indexOf("from __future__ import annotations");
    expect(hookAt).toBeGreaterThan(futureAt);
    const twice = prependPycSidecarLoaderHook(once, inject.preamble);
    expect(twice).toBe(once);
  });

  it("isSafe / select only admit known loaders that mention the module", () => {
    const loader = LOADER_BODY;
    const noMention = "print('hello')\n";
    const helper = 'import importlib.util\nimport pathlib\n_pyc = pathlib.Path("sample.pyc")\n';
    const stemSource = "RESULT = 5\n";
    const testLoader =
      'import importlib.util\nimport pathlib\n_pyc = pathlib.Path(__file__).parent / "sample.pyc"\n';
    const already = `${loader}\n# _verify_sibling_digest_deadbeef\n`;

    expect(
      sourceMentionsPycModule(loader, "sample.pyc"),
    ).toBe(true);
    expect(sourceMentionsPycModule(noMention, "sample.pyc")).toBe(false);

    expect(
      isSafePythonPycLoader({
        source: loader,
        filename: "loader.py",
        pycBasename: "sample.pyc",
      }),
    ).toBe(true);
    expect(
      isSafePythonPycLoader({
        source: stemSource,
        filename: "sample.py",
        pycBasename: "sample.pyc",
      }),
    ).toBe(false);
    expect(
      isSafePythonPycLoader({
        source: testLoader,
        filename: "test_loader.py",
        pycBasename: "sample.pyc",
      }),
    ).toBe(false);
    expect(
      isSafePythonPycLoader({
        source: already,
        filename: "loader.py",
        pycBasename: "sample.pyc",
      }),
    ).toBe(false);
    expect(
      isSafePythonPycLoader({
        source: helper,
        filename: "helper.py",
        pycBasename: "sample.pyc",
      }),
    ).toBe(true);
    expect(
      isSafePythonPycLoader({
        source: noMention,
        filename: "loader.py",
        pycBasename: "sample.pyc",
      }),
    ).toBe(false);

    expect(
      selectPythonPycLoader("sample.pyc", [
        { name: "helper.py", source: helper },
        { name: "loader.py", source: loader },
        { name: "__init__.py", source: loader },
      ]),
    ).toBe("loader.py");
    expect(
      selectPythonPycLoader("sample.pyc", [
        { name: "__init__.py", source: loader },
        { name: "__main__.py", source: loader },
      ]),
    ).toBe("__init__.py");
    expect(
      selectPythonPycLoader("sample.pyc", [
        { name: "helper.py", source: helper },
      ]),
    ).toBeNull();
    expect(
      selectPythonPycLoader("sample.pyc", [
        { name: "sample.py", source: loader },
      ]),
    ).toBeNull();
  });

  it.skipIf(!PY3)("load-time hook: intact module imports and keeps RESULT", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-ok-"));
    try {
      const entry = compileSamplePyc();
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindPycSidecarEntanglement({
        entryPath: "sample.pyc",
        sidecarPaths: ["sib.bin"],
        seedTag: "pyc-loader-ok",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "sample.pyc"), bound.bytes);
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entanglePycLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        pycBytes: bound.bytes,
        pycRelPath: "sample.pyc",
      });
      expect(hooked.code).toContain(PYC_SIDECAR_LOADER_MARKER);
      const ran = runLoader(dir, hooked.code);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 5/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("load-time hook fails closed on trailer strip or sibling delete", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-fail-"));
    try {
      const entry = compileSamplePyc();
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindPycSidecarEntanglement({
        entryPath: "sample.pyc",
        sidecarPaths: ["sib.bin"],
        seedTag: "pyc-loader-fail",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entanglePycLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        pycBytes: bound.bytes,
        pycRelPath: "sample.pyc",
      });

      writeFileSync(join(dir, "sample.pyc"), bound.bytes);
      const ok = runLoader(dir, hooked.code);
      expect(ok.status, ok.stderr || ok.stdout).toBe(0);

      writeFileSync(join(dir, "sample.pyc"), stripPycSidecarMarshalNote(bound.bytes));
      const stripped = runLoader(dir, hooked.code);
      expect(stripped.status).not.toBe(0);
      expect(stripped.stderr + stripped.stdout).toMatch(/integrity binding mismatch/);

      writeFileSync(join(dir, "sample.pyc"), bound.bytes);
      unlinkSync(join(dir, "sib.bin"));
      const deleted = runLoader(dir, hooked.code);
      expect(deleted.status).not.toBe(0);
      expect(deleted.stderr + deleted.stdout).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget auto-wires a same-directory loader and records pyc-sidecar-entangle", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-protect-"));
    try {
      const entry = join(dir, "sample.pyc");
      writeFileSync(entry, compileSamplePyc());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-pyc-loader-hook",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.pycSidecarLoaderHookApplied).toBe(true);
      expect(res.counteredReaVectors).toContain("pyc-sidecar-entangle");

      const hooked = readFileSync(join(dir, "loader.py"), "utf8");
      expect(hooked).toContain(PYC_SIDECAR_LOADER_MARKER);
      expect(
        isPycSidecarLoaderHookWired({
          pycBytes: readFileSync(entry),
          pycPath: entry,
        }),
      ).toBe(true);
      expect(extractPycSidecarMarshalNote(readFileSync(entry))).not.toBeNull();

      const ran = runLoader(dir, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 5/);

      const verification = verifyTarget(entry, undefined, {
        sidecarEntangleEnabled: true,
      });
      const gapIds = (verification.defenseScoreGaps ?? []).map((g) => g.id);
      expect(gapIds).not.toContain("pyc-sidecar-host-verify-only");

      const gaps = collectDefenseScoreGaps({
        detectedFormat: "python-pyc",
        sidecarEntangleEnabled: true,
        pycSidecarLoaderHookApplied: true,
      });
      expect(gaps.map((g) => g.id)).not.toContain("pyc-sidecar-host-verify-only");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite when sidecarEntangle is off", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-off-"));
    try {
      const entry = join(dir, "sample.pyc");
      writeFileSync(entry, compileSamplePyc());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-pyc-loader-off",
        inPlace: true,
      });
      expect(res.sidecarEntangle).not.toBe(true);
      expect(res.pycSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("pyc-sidecar-entangle");
      expect(readFileSync(join(dir, "loader.py"), "utf8")).toBe(LOADER_BODY);
      expect(extractPycSidecarMarshalNote(readFileSync(entry))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite an unknown or source-counterpart file", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-unsafe-"));
    try {
      const entry = join(dir, "sample.pyc");
      writeFileSync(entry, compileSamplePyc());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      const helper = LOADER_BODY;
      writeFileSync(join(dir, "helper.py"), helper, "utf8");
      writeFileSync(join(dir, "sample.py"), "RESULT = 5\n", "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-pyc-loader-unsafe",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.pycSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("pyc-sidecar-entangle");
      expect(readFileSync(join(dir, "helper.py"), "utf8")).toBe(helper);
      expect(readFileSync(join(dir, "sample.py"), "utf8")).toBe("RESULT = 5\n");
      // Note is still planted (host-verify); direct import still works.
      expect(extractPycSidecarMarshalNote(readFileSync(entry))).not.toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("hardenProject auto-wires dist/loader.py beside sample.pyc", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-loader-harden-"));
    try {
      const dist = join(dir, "dist");
      mkdirSync(dist, { recursive: true });
      writeFileSync(join(dist, "sample.pyc"), compileSamplePyc());
      writeFileSync(join(dist, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dist, "loader.py"), LOADER_BODY, "utf8");

      const report = hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "harden-pyc-loader-hook",
        sidecarEntangle: true,
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.sidecarEntangleError).toBeUndefined();

      const outDist = join(report.outputDirectory, "dist");
      const hooked = readFileSync(join(outDist, "loader.py"), "utf8");
      expect(hooked).toContain(PYC_SIDECAR_LOADER_MARKER);
      const pycBytes = readFileSync(join(outDist, "sample.pyc"));
      expect(extractPycSidecarMarshalNote(pycBytes)).not.toBeNull();
      expect(pycBytes.includes(Buffer.from(PYC_SIDECAR_MARSHAL_MARKER))).toBe(true);
      expect(
        isPycSidecarLoaderHookWired({
          pycBytes,
          pycPath: join(outDist, "sample.pyc"),
        }),
      ).toBe(true);

      const ran = runLoader(outDist, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok 5/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
