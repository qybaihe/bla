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
import { createHash } from "node:crypto";
import {
  bindSafetensorsSidecarEntanglement,
  computeSafetensorsSidecarCodeIdentity,
  entangleSafetensorsLoaderWithSidecars,
  extractSafetensorsSidecarMetadataNote,
  generateSidecarSafetensorsLoaderSnippet,
  isSafetensorsSidecarLoaderHookWired,
  isSafePythonSafetensorsLoader,
  prependSafetensorsSidecarLoaderHook,
  SAFETENSORS_SIDECAR_LOADER_MARKER,
  SAFETENSORS_SIDECAR_METADATA_KEY,
  selectPythonSafetensorsLoader,
  SIDECAR_ENTANGLE_SCHEMA,
  sourceMentionsSafetensorsFile,
  stripSafetensorsSidecarMetadataNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  buildSafetensorsBuffer,
  validateSafetensorsBuffer,
} from "../src/shields/formats/model.js";
import { collectDefenseScoreGaps } from "../src/engine/defense-score-honesty.js";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifyTarget } from "../src/engine/verifier.js";

const PY3 = (() => {
  const r = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();

function buildMinimalSafetensors(): Buffer {
  const weights = Buffer.alloc(16);
  [1.5, -2.25, 3.75, 8.0].forEach((v, idx) => weights.writeFloatLE(v, idx * 4));
  return buildSafetensorsBuffer(
    {
      weight: {
        dtype: "F32",
        shape: [2, 2],
        data_offsets: [0, 16],
      },
    },
    weights,
  );
}

function tensorDataDigest(bytes: Buffer): string {
  const { tensorData } = validateSafetensorsBuffer(bytes);
  return createHash("sha256").update(tensorData).digest("hex");
}

const LOADER_BODY = `import pathlib
_st = pathlib.Path(__file__).resolve().parent / "model.safetensors"
_raw = _st.read_bytes()
assert len(_raw) >= 10
assert _raw[8:9] == b"{"
print("ok", len(_raw))
`;

const FUTURE_LOADER_BODY = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loader docstring."""
from __future__ import annotations
import pathlib
_st = pathlib.Path(__file__).resolve().parent / "model.safetensors"
_raw = _st.read_bytes()
assert len(_raw) >= 10
assert _raw[8:9] == b"{"
print("ok", len(_raw))
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

describe("sidecar Safetensors load-time hook", () => {
  it("generateSidecarSafetensorsLoaderSnippet rejects non-hex identities", () => {
    expect(() =>
      generateSidecarSafetensorsLoaderSnippet({
        codeIdentityHex: "deadbeef",
        safetensorsRelPaths: ["model.safetensors"],
      }),
    ).toThrow(/64-char/);
  });

  it("computeSafetensorsSidecarCodeIdentity is stable across planting the note", () => {
    const entry = buildMinimalSafetensors();
    const unbound = computeSafetensorsSidecarCodeIdentity(entry);
    const bound = bindSafetensorsSidecarEntanglement({
      entryPath: "model.safetensors",
      sidecarPaths: ["sib.bin"],
      seedTag: "loader-id-v1",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode("sidecar-payload\n")],
    });
    expect(computeSafetensorsSidecarCodeIdentity(bound.bytes)).toBe(unbound);
    expect(unbound).toMatch(/^[0-9a-f]{64}$/);
    const stripped = stripSafetensorsSidecarMetadataNote(bound.bytes);
    expect(computeSafetensorsSidecarCodeIdentity(stripped)).toBe(unbound);
    expect(Buffer.compare(stripped, entry)).toBe(0);
    expect(tensorDataDigest(bound.bytes)).toBe(tensorDataDigest(entry));
  });

  it("prepend is idempotent and preserves shebang / encoding / docstring / futures", () => {
    const inject = generateSidecarSafetensorsLoaderSnippet({
      codeIdentityHex: "a".repeat(64),
      safetensorsRelPaths: ["model.safetensors"],
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.preamble).toContain(SAFETENSORS_SIDECAR_LOADER_MARKER);
    const once = prependSafetensorsSidecarLoaderHook(FUTURE_LOADER_BODY, inject.preamble);
    expect(once.startsWith("#!/usr/bin/env python3\n")).toBe(true);
    expect(once).toContain("# -*- coding: utf-8 -*-");
    expect(once).toContain('"""Loader docstring."""');
    expect(once).toContain("from __future__ import annotations");
    const hookAt = once.indexOf(SAFETENSORS_SIDECAR_LOADER_MARKER);
    const futureAt = once.indexOf("from __future__ import annotations");
    expect(hookAt).toBeGreaterThan(futureAt);
    const twice = prependSafetensorsSidecarLoaderHook(once, inject.preamble);
    expect(twice).toBe(once);
  });

  it("isSafe / select only admit known loaders that mention the .safetensors", () => {
    const loader = LOADER_BODY;
    const noMention = "print('hello')\n";
    const helper =
      'import pathlib\n_st = pathlib.Path("model.safetensors")\n';
    const testLoader =
      'import pathlib\n_st = pathlib.Path(__file__).parent / "model.safetensors"\n';
    const already = `${loader}\n# _verify_sibling_digest_deadbeef\n`;

    expect(sourceMentionsSafetensorsFile(loader, "model.safetensors")).toBe(true);
    expect(sourceMentionsSafetensorsFile(noMention, "model.safetensors")).toBe(false);

    expect(
      isSafePythonSafetensorsLoader({
        source: loader,
        filename: "loader.py",
        safetensorsBasename: "model.safetensors",
      }),
    ).toBe(true);
    expect(
      isSafePythonSafetensorsLoader({
        source: testLoader,
        filename: "test_loader.py",
        safetensorsBasename: "model.safetensors",
      }),
    ).toBe(false);
    expect(
      isSafePythonSafetensorsLoader({
        source: already,
        filename: "loader.py",
        safetensorsBasename: "model.safetensors",
      }),
    ).toBe(false);
    expect(
      isSafePythonSafetensorsLoader({
        source: helper,
        filename: "helper.py",
        safetensorsBasename: "model.safetensors",
      }),
    ).toBe(true);
    expect(
      isSafePythonSafetensorsLoader({
        source: noMention,
        filename: "loader.py",
        safetensorsBasename: "model.safetensors",
      }),
    ).toBe(false);

    expect(
      selectPythonSafetensorsLoader("model.safetensors", [
        { name: "helper.py", source: helper },
        { name: "loader.py", source: loader },
        { name: "__init__.py", source: loader },
      ]),
    ).toBe("loader.py");
    expect(
      selectPythonSafetensorsLoader("model.safetensors", [
        { name: "__init__.py", source: loader },
        { name: "__main__.py", source: loader },
      ]),
    ).toBe("__init__.py");
    expect(
      selectPythonSafetensorsLoader("model.safetensors", [
        { name: "helper.py", source: helper },
      ]),
    ).toBeNull();
  });

  it.skipIf(!PY3)("load-time hook: intact model opens and keeps tensor bytes", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-st-loader-ok-"));
    try {
      const entry = buildMinimalSafetensors();
      const data0 = tensorDataDigest(entry);
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindSafetensorsSidecarEntanglement({
        entryPath: "model.safetensors",
        sidecarPaths: ["sib.bin"],
        seedTag: "st-loader-ok",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "model.safetensors"), bound.bytes);
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entangleSafetensorsLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        safetensorsBytes: bound.bytes,
        safetensorsRelPath: "model.safetensors",
      });
      expect(hooked.code).toContain(SAFETENSORS_SIDECAR_LOADER_MARKER);
      expect(tensorDataDigest(bound.bytes)).toBe(data0);
      const ran = runLoader(dir, hooked.code);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("load-time hook fails closed on metadata strip or sibling delete", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-st-loader-fail-"));
    try {
      const entry = buildMinimalSafetensors();
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindSafetensorsSidecarEntanglement({
        entryPath: "model.safetensors",
        sidecarPaths: ["sib.bin"],
        seedTag: "st-loader-fail",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entangleSafetensorsLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        safetensorsBytes: bound.bytes,
        safetensorsRelPath: "model.safetensors",
      });

      writeFileSync(join(dir, "model.safetensors"), bound.bytes);
      const ok = runLoader(dir, hooked.code);
      expect(ok.status, ok.stderr || ok.stdout).toBe(0);

      writeFileSync(join(dir, "model.safetensors"), stripSafetensorsSidecarMetadataNote(bound.bytes));
      const stripped = runLoader(dir, hooked.code);
      expect(stripped.status).not.toBe(0);
      expect(stripped.stderr + stripped.stdout).toMatch(/integrity binding mismatch/);

      writeFileSync(join(dir, "model.safetensors"), bound.bytes);
      unlinkSync(join(dir, "sib.bin"));
      const deleted = runLoader(dir, hooked.code);
      expect(deleted.status).not.toBe(0);
      expect(deleted.stderr + deleted.stdout).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget auto-wires a same-directory loader and records safetensors-sidecar-entangle", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-st-loader-protect-"));
    try {
      const entry = join(dir, "model.safetensors");
      writeFileSync(entry, buildMinimalSafetensors());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-st-loader-hook",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.safetensorsSidecarLoaderHookApplied).toBe(true);
      expect(res.counteredReaVectors).toContain("safetensors-sidecar-entangle");

      const hooked = readFileSync(join(dir, "loader.py"), "utf8");
      expect(hooked).toContain(SAFETENSORS_SIDECAR_LOADER_MARKER);
      const stBytes = readFileSync(entry);
      expect(
        isSafetensorsSidecarLoaderHookWired({
          safetensorsBytes: stBytes,
          safetensorsPath: entry,
        }),
      ).toBe(true);
      expect(extractSafetensorsSidecarMetadataNote(stBytes)).not.toBeNull();
      expect(stBytes.includes(Buffer.from(SAFETENSORS_SIDECAR_METADATA_KEY))).toBe(true);

      const ran = runLoader(dir, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok /);

      const verification = verifyTarget(entry, undefined, {
        sidecarEntangleEnabled: true,
      });
      const gapIds = (verification.defenseScoreGaps ?? []).map((g) => g.id);
      expect(gapIds).not.toContain("safetensors-sidecar-host-verify-only");

      const gaps = collectDefenseScoreGaps({
        detectedFormat: "model-safetensors",
        sidecarEntangleEnabled: true,
        safetensorsSidecarLoaderHookApplied: true,
      });
      expect(gaps.map((g) => g.id)).not.toContain("safetensors-sidecar-host-verify-only");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite when sidecarEntangle is off", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-st-loader-off-"));
    try {
      const entry = join(dir, "model.safetensors");
      writeFileSync(entry, buildMinimalSafetensors());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-st-loader-off",
        inPlace: true,
      });
      expect(res.sidecarEntangle).not.toBe(true);
      expect(res.safetensorsSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("safetensors-sidecar-entangle");
      expect(readFileSync(join(dir, "loader.py"), "utf8")).toBe(LOADER_BODY);
      expect(extractSafetensorsSidecarMetadataNote(readFileSync(entry))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite an unknown helper file", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-st-loader-unsafe-"));
    try {
      const entry = join(dir, "model.safetensors");
      writeFileSync(entry, buildMinimalSafetensors());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      const helper = LOADER_BODY;
      writeFileSync(join(dir, "helper.py"), helper, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-st-loader-unsafe",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.safetensorsSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("safetensors-sidecar-entangle");
      expect(readFileSync(join(dir, "helper.py"), "utf8")).toBe(helper);
      expect(extractSafetensorsSidecarMetadataNote(readFileSync(entry))).not.toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("hardenProject auto-wires dist/loader.py beside model.safetensors", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-st-loader-harden-"));
    try {
      const dist = join(dir, "dist");
      mkdirSync(dist, { recursive: true });
      writeFileSync(join(dist, "model.safetensors"), buildMinimalSafetensors());
      writeFileSync(join(dist, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dist, "loader.py"), LOADER_BODY, "utf8");

      const report = hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "harden-st-loader-hook",
        sidecarEntangle: true,
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.sidecarEntangleError).toBeUndefined();

      const outDist = join(report.outputDirectory, "dist");
      const hooked = readFileSync(join(outDist, "loader.py"), "utf8");
      expect(hooked).toContain(SAFETENSORS_SIDECAR_LOADER_MARKER);
      const stBytes = readFileSync(join(outDist, "model.safetensors"));
      expect(extractSafetensorsSidecarMetadataNote(stBytes)).not.toBeNull();
      expect(stBytes.includes(Buffer.from(SAFETENSORS_SIDECAR_METADATA_KEY))).toBe(true);
      expect(
        isSafetensorsSidecarLoaderHookWired({
          safetensorsBytes: stBytes,
          safetensorsPath: join(outDist, "model.safetensors"),
        }),
      ).toBe(true);

      const ran = runLoader(outDist, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
