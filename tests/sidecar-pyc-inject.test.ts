import { describe, expect, it } from "vitest";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  PYC_SIDECAR_MARSHAL_KIND,
  PYC_SIDECAR_MARSHAL_MARKER,
  SIDECAR_ENTANGLE_SCHEMA,
  bindPycSidecarEntanglement,
  computeSidecarBindingDigest,
  entanglePycEntryWithSidecars,
  extractPycSidecarMarshalNote,
  generateSidecarPycMarshalNote,
  planSidecarEntanglement,
  stripPycSidecarMarshalNote,
  verifyPycSidecarMarshalNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import { protectTarget } from "../src/engine/protector.js";
import { protectPythonPycBuffer } from "../src/shields/formats/python.js";

const PY3 = (() => {
  const r = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();

function compileSamplePyc(): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "bla-pyc-sidecar-"));
  try {
    const srcPath = join(dir, "sample.py");
    const pycPath = join(dir, "sample.pyc");
    writeFileSync(
      srcPath,
      "def add(a, b):\n    return a + b\n\nRESULT = add(2, 3)\n",
    );
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

function importPycResult(pyc: Buffer): number {
  const dir = mkdtempSync(join(tmpdir(), "bla-pyc-run-"));
  try {
    const pycPath = join(dir, "sample.pyc");
    writeFileSync(pycPath, pyc);
    const r = spawnSync(
      "python3",
      [
        "-c",
        `import importlib.util\nspec = importlib.util.spec_from_file_location("sample", ${JSON.stringify(pycPath)})\nmod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)\nprint(mod.RESULT)\n`,
      ],
      { encoding: "utf8" },
    );
    if (r.status !== 0) {
      throw new Error(`import failed: ${r.stderr || r.stdout}`);
    }
    return Number(r.stdout.trim());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("sidecar .pyc marshal-note strip⇒fail", () => {
  it("planSidecarEntanglement guesses pyc-marshal-note for .pyc entries", () => {
    const plan = planSidecarEntanglement({
      entryPath: "app.pyc",
      sidecarPaths: ["decoy.bin"],
    });
    expect(plan.entryHookKind).toBe("pyc-marshal-note");
  });

  it("generateSidecarPycMarshalNote rejects non-hex expected digests", () => {
    expect(() =>
      generateSidecarPycMarshalNote({
        entryPath: "app.pyc",
        sidecarPaths: ["sidecar.dat"],
        expectedHex: "deadbeef",
      }),
    ).toThrow(/64-char/);
  });

  it.skipIf(!PY3)("bind leaves root marshal intact and plants TYPE_ASCII trailer", () => {
    const entry = compileSamplePyc();
    const sidecar = Buffer.from("decoy-sidecar-bytes\n");
    const beforeResult = importPycResult(entry);
    expect(beforeResult).toBe(5);

    const bound = bindPycSidecarEntanglement({
      entryPath: "sample.pyc",
      sidecarPaths: ["sidecar.dat"],
      seedTag: "pyc-inject-v1",
      entryBytes: entry,
      sidecarBytes: [sidecar],
    });
    expect(bound.plan.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("pyc-marshal-note");
    expect(bound.inject.kind).toBe(PYC_SIDECAR_MARSHAL_KIND);
    expect(bound.inject.payload.startsWith(PYC_SIDECAR_MARSHAL_MARKER)).toBe(true);
    expect(bound.inject.expectedHex).toBe(bound.digest.hex);

    // Trailer present; root still imports with same RESULT.
    expect(bound.bytes.includes(Buffer.from(PYC_SIDECAR_MARSHAL_MARKER))).toBe(true);
    expect(importPycResult(bound.bytes)).toBe(5);

    const note = extractPycSidecarMarshalNote(bound.bytes);
    expect(note?.digest).toBe(bound.digest.hex);
    expect(note?.sidecarPaths).toEqual(["sidecar.dat"]);
  });

  it.skipIf(!PY3)("digest matches computeSidecarBindingDigest sidecars-mode", () => {
    const entry = compileSamplePyc();
    const snap = Buffer.from("sidecar-payload\n");
    const bound = bindPycSidecarEntanglement({
      entryPath: "sample.pyc",
      sidecarPaths: ["sidecar.dat"],
      seedTag: "pyc-digest-v1",
      entryBytes: entry,
      sidecarBytes: [snap],
    });
    const expected = computeSidecarBindingDigest(
      { pathLabel: "sample.pyc", bytes: entry },
      [{ pathLabel: "sidecar.dat", bytes: snap }],
      "pyc-digest-v1",
      "sidecars",
    );
    expect(bound.digest.hex).toBe(expected.hex);
  });

  it.skipIf(!PY3)("verifyPycSidecarMarshalNote ok on intact, fail on strip/alter", () => {
    const entry = compileSamplePyc();
    const snap = Buffer.from("sidecar-A\n");
    const bound = entanglePycEntryWithSidecars({
      entryPath: "sample.pyc",
      entryBytes: entry,
      sidecars: [{ pathLabel: "sidecar.dat", bytes: snap }],
      seedTag: "pyc-verify-v1",
    });
    expect(bound).not.toBeNull();

    const ok = verifyPycSidecarMarshalNote({
      entryBytes: bound!.bytes,
      sidecarBytes: { "sidecar.dat": snap },
    });
    expect(ok.ok).toBe(true);

    const stripped = stripPycSidecarMarshalNote(bound!.bytes);
    expect(extractPycSidecarMarshalNote(stripped)).toBeNull();
    expect(
      verifyPycSidecarMarshalNote({
        entryBytes: stripped,
        sidecarBytes: { "sidecar.dat": snap },
      }).ok,
    ).toBe(false);

    const altered = verifyPycSidecarMarshalNote({
      entryBytes: bound!.bytes,
      sidecarBytes: { "sidecar.dat": Buffer.from("tampered\n") },
    });
    expect(altered.ok).toBe(false);
    expect(altered.reason).toMatch(/mismatch|missing/i);
  });

  it.skipIf(!PY3)("protectTarget with sidecarEntangle plants note (default remains OFF)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-protect-"));
    try {
      const entry = compileSamplePyc();
      const inPyc = join(dir, "app.pyc");
      const outPyc = join(dir, "app.out.pyc");
      const sidecar = join(dir, "honey.txt");
      writeFileSync(inPyc, entry);
      writeFileSync(sidecar, "honey-sidecar\n");

      const off = protectTarget({
        inputPath: inPyc,
        outputPath: join(dir, "app.off.pyc"),
        intensity: "balanced",
        seed: "pyc-protect-off",
      });
      expect(off.sidecarEntangle).not.toBe(true);
      expect(
        extractPycSidecarMarshalNote(readFileSync(join(dir, "app.off.pyc"))),
      ).toBeNull();

      const on = protectTarget({
        inputPath: inPyc,
        outputPath: outPyc,
        intensity: "balanced",
        seed: "pyc-protect-on",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["honey.txt"],
      });
      expect(on.sidecarEntangle).toBe(true);
      expect(on.counteredReaVectors).toContain("pyc-sidecar-entangle");
      const outBytes = readFileSync(outPyc);
      const note = extractPycSidecarMarshalNote(outBytes);
      expect(note).not.toBeNull();
      expect(importPycResult(outBytes)).toBe(5);

      const verified = verifyPycSidecarMarshalNote({
        entryBytes: outBytes,
        baseDir: dir,
      });
      expect(verified.ok).toBe(true);

      // Honey from protectPythonPycBuffer still present alongside the note.
      const honey = protectPythonPycBuffer(entry, {
        intensity: "balanced",
        seed: "pyc-protect-on",
      });
      expect(outBytes.length).toBeGreaterThan(honey.buffer.length);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("re-bind is idempotent (strip prior note first)", () => {
    const entry = compileSamplePyc();
    const snap = Buffer.from("sidecar\n");
    const once = bindPycSidecarEntanglement({
      entryPath: "sample.pyc",
      sidecarPaths: ["sidecar.dat"],
      seedTag: "idem",
      entryBytes: entry,
      sidecarBytes: [snap],
    });
    const twice = bindPycSidecarEntanglement({
      entryPath: "sample.pyc",
      sidecarPaths: ["sidecar.dat"],
      seedTag: "idem",
      entryBytes: once.bytes,
      sidecarBytes: [snap],
    });
    expect(once.digest.hex).toBe(twice.digest.hex);
    // Only one marker occurrence.
    const text = twice.bytes.toString("latin1");
    const first = text.indexOf(PYC_SIDECAR_MARSHAL_MARKER);
    const last = text.lastIndexOf(PYC_SIDECAR_MARSHAL_MARKER);
    expect(first).toBe(last);
    expect(importPycResult(twice.bytes)).toBe(5);
  });
});
