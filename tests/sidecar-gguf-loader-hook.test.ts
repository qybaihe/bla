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
  bindGgufSidecarEntanglement,
  computeGgufSidecarCodeIdentity,
  entangleGgufLoaderWithSidecars,
  extractGgufSidecarMetadataNote,
  generateSidecarGgufLoaderSnippet,
  isGgufSidecarLoaderHookWired,
  isSafePythonGgufLoader,
  prependGgufSidecarLoaderHook,
  GGUF_SIDECAR_LOADER_MARKER,
  GGUF_SIDECAR_METADATA_KEY,
  selectPythonGgufLoader,
  SIDECAR_ENTANGLE_SCHEMA,
  sourceMentionsGgufFile,
  stripGgufSidecarMetadataNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  encodeGgufString,
  encodeGgufStringKv,
  parseGgufLayout,
} from "../src/shields/formats/gguf-layout.js";
import { collectDefenseScoreGaps } from "../src/engine/defense-score-honesty.js";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifyTarget } from "../src/engine/verifier.js";

const PY3 = (() => {
  const r = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();

function buildMinimalGguf(): Buffer {
  const kv = encodeGgufStringKv("general.architecture", "llama");
  const name = encodeGgufString("w");
  const rest = Buffer.alloc(4 + 8 + 4 + 8);
  rest.writeUInt32LE(1, 0);
  rest.writeBigUInt64LE(1n, 4);
  rest.writeUInt32LE(0, 12);
  rest.writeBigUInt64LE(0n, 16);
  const header = Buffer.alloc(24);
  header.write("GGUF", 0, "ascii");
  header.writeUInt32LE(3, 4);
  header.writeBigUInt64LE(1n, 8);
  header.writeBigUInt64LE(1n, 16);
  const metaAndInfos = Buffer.concat([header, kv, name, rest]);
  const align = 32;
  const rem = metaAndInfos.length % align;
  const pad = rem === 0 ? Buffer.alloc(0) : Buffer.alloc(align - rem, 0);
  const data = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  return Buffer.concat([metaAndInfos, pad, data]);
}

function tensorDataDigest(bytes: Buffer): string {
  const layout = parseGgufLayout(bytes)!;
  return createHash("sha256")
    .update(bytes.subarray(layout.dataStart))
    .digest("hex");
}

const LOADER_BODY = `import pathlib
_gguf = pathlib.Path(__file__).resolve().parent / "model.gguf"
_raw = _gguf.read_bytes()
assert _raw[0:4] == b"GGUF"
print("ok", len(_raw))
`;

const FUTURE_LOADER_BODY = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loader docstring."""
from __future__ import annotations
import pathlib
_gguf = pathlib.Path(__file__).resolve().parent / "model.gguf"
_raw = _gguf.read_bytes()
assert _raw[0:4] == b"GGUF"
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

describe("sidecar GGUF load-time hook", () => {
  it("generateSidecarGgufLoaderSnippet rejects non-hex identities", () => {
    expect(() =>
      generateSidecarGgufLoaderSnippet({
        codeIdentityHex: "deadbeef",
        ggufRelPaths: ["model.gguf"],
      }),
    ).toThrow(/64-char/);
  });

  it("computeGgufSidecarCodeIdentity is stable across planting the note", () => {
    const entry = buildMinimalGguf();
    const unbound = computeGgufSidecarCodeIdentity(entry);
    const bound = bindGgufSidecarEntanglement({
      entryPath: "model.gguf",
      sidecarPaths: ["sib.bin"],
      seedTag: "loader-id-v1",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode("sidecar-payload\n")],
    });
    expect(computeGgufSidecarCodeIdentity(bound.bytes)).toBe(unbound);
    expect(unbound).toMatch(/^[0-9a-f]{64}$/);
    const stripped = stripGgufSidecarMetadataNote(bound.bytes);
    expect(computeGgufSidecarCodeIdentity(stripped)).toBe(unbound);
    expect(Buffer.compare(stripped, entry)).toBe(0);
    expect(tensorDataDigest(bound.bytes)).toBe(tensorDataDigest(entry));
  });

  it("prepend is idempotent and preserves shebang / encoding / docstring / futures", () => {
    const inject = generateSidecarGgufLoaderSnippet({
      codeIdentityHex: "a".repeat(64),
      ggufRelPaths: ["model.gguf"],
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.preamble).toContain(GGUF_SIDECAR_LOADER_MARKER);
    const once = prependGgufSidecarLoaderHook(FUTURE_LOADER_BODY, inject.preamble);
    expect(once.startsWith("#!/usr/bin/env python3\n")).toBe(true);
    expect(once).toContain("# -*- coding: utf-8 -*-");
    expect(once).toContain('"""Loader docstring."""');
    expect(once).toContain("from __future__ import annotations");
    const hookAt = once.indexOf(GGUF_SIDECAR_LOADER_MARKER);
    const futureAt = once.indexOf("from __future__ import annotations");
    expect(hookAt).toBeGreaterThan(futureAt);
    const twice = prependGgufSidecarLoaderHook(once, inject.preamble);
    expect(twice).toBe(once);
  });

  it("isSafe / select only admit known loaders that mention the .gguf", () => {
    const loader = LOADER_BODY;
    const noMention = "print('hello')\n";
    const helper =
      'import pathlib\n_gguf = pathlib.Path("model.gguf")\n';
    const testLoader =
      'import pathlib\n_gguf = pathlib.Path(__file__).parent / "model.gguf"\n';
    const already = `${loader}\n# _verify_sibling_digest_deadbeef\n`;

    expect(sourceMentionsGgufFile(loader, "model.gguf")).toBe(true);
    expect(sourceMentionsGgufFile(noMention, "model.gguf")).toBe(false);

    expect(
      isSafePythonGgufLoader({
        source: loader,
        filename: "loader.py",
        ggufBasename: "model.gguf",
      }),
    ).toBe(true);
    expect(
      isSafePythonGgufLoader({
        source: testLoader,
        filename: "test_loader.py",
        ggufBasename: "model.gguf",
      }),
    ).toBe(false);
    expect(
      isSafePythonGgufLoader({
        source: already,
        filename: "loader.py",
        ggufBasename: "model.gguf",
      }),
    ).toBe(false);
    expect(
      isSafePythonGgufLoader({
        source: helper,
        filename: "helper.py",
        ggufBasename: "model.gguf",
      }),
    ).toBe(true);
    expect(
      isSafePythonGgufLoader({
        source: noMention,
        filename: "loader.py",
        ggufBasename: "model.gguf",
      }),
    ).toBe(false);

    expect(
      selectPythonGgufLoader("model.gguf", [
        { name: "helper.py", source: helper },
        { name: "loader.py", source: loader },
        { name: "__init__.py", source: loader },
      ]),
    ).toBe("loader.py");
    expect(
      selectPythonGgufLoader("model.gguf", [
        { name: "__init__.py", source: loader },
        { name: "__main__.py", source: loader },
      ]),
    ).toBe("__init__.py");
    expect(
      selectPythonGgufLoader("model.gguf", [
        { name: "helper.py", source: helper },
      ]),
    ).toBeNull();
  });

  it.skipIf(!PY3)("load-time hook: intact model opens and keeps tensor bytes", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-loader-ok-"));
    try {
      const entry = buildMinimalGguf();
      const data0 = tensorDataDigest(entry);
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindGgufSidecarEntanglement({
        entryPath: "model.gguf",
        sidecarPaths: ["sib.bin"],
        seedTag: "gguf-loader-ok",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "model.gguf"), bound.bytes);
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entangleGgufLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        ggufBytes: bound.bytes,
        ggufRelPath: "model.gguf",
      });
      expect(hooked.code).toContain(GGUF_SIDECAR_LOADER_MARKER);
      expect(tensorDataDigest(bound.bytes)).toBe(data0);
      const ran = runLoader(dir, hooked.code);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("load-time hook fails closed on metadata strip or sibling delete", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-loader-fail-"));
    try {
      const entry = buildMinimalGguf();
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindGgufSidecarEntanglement({
        entryPath: "model.gguf",
        sidecarPaths: ["sib.bin"],
        seedTag: "gguf-loader-fail",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entangleGgufLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        ggufBytes: bound.bytes,
        ggufRelPath: "model.gguf",
      });

      writeFileSync(join(dir, "model.gguf"), bound.bytes);
      const ok = runLoader(dir, hooked.code);
      expect(ok.status, ok.stderr || ok.stdout).toBe(0);

      writeFileSync(join(dir, "model.gguf"), stripGgufSidecarMetadataNote(bound.bytes));
      const stripped = runLoader(dir, hooked.code);
      expect(stripped.status).not.toBe(0);
      expect(stripped.stderr + stripped.stdout).toMatch(/integrity binding mismatch/);

      writeFileSync(join(dir, "model.gguf"), bound.bytes);
      unlinkSync(join(dir, "sib.bin"));
      const deleted = runLoader(dir, hooked.code);
      expect(deleted.status).not.toBe(0);
      expect(deleted.stderr + deleted.stdout).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget auto-wires a same-directory loader and records gguf-sidecar-entangle", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-loader-protect-"));
    try {
      const entry = join(dir, "model.gguf");
      writeFileSync(entry, buildMinimalGguf());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-gguf-loader-hook",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.ggufSidecarLoaderHookApplied).toBe(true);
      expect(res.counteredReaVectors).toContain("gguf-sidecar-entangle");

      const hooked = readFileSync(join(dir, "loader.py"), "utf8");
      expect(hooked).toContain(GGUF_SIDECAR_LOADER_MARKER);
      const ggufBytes = readFileSync(entry);
      expect(
        isGgufSidecarLoaderHookWired({
          ggufBytes,
          ggufPath: entry,
        }),
      ).toBe(true);
      expect(extractGgufSidecarMetadataNote(ggufBytes)).not.toBeNull();
      expect(ggufBytes.includes(Buffer.from(GGUF_SIDECAR_METADATA_KEY))).toBe(true);

      const ran = runLoader(dir, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok /);

      const verification = verifyTarget(entry, undefined, {
        sidecarEntangleEnabled: true,
      });
      const gapIds = (verification.defenseScoreGaps ?? []).map((g) => g.id);
      expect(gapIds).not.toContain("gguf-sidecar-host-verify-only");

      const gaps = collectDefenseScoreGaps({
        detectedFormat: "model-gguf",
        sidecarEntangleEnabled: true,
        ggufSidecarLoaderHookApplied: true,
      });
      expect(gaps.map((g) => g.id)).not.toContain("gguf-sidecar-host-verify-only");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite when sidecarEntangle is off", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-loader-off-"));
    try {
      const entry = join(dir, "model.gguf");
      writeFileSync(entry, buildMinimalGguf());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-gguf-loader-off",
        inPlace: true,
      });
      expect(res.sidecarEntangle).not.toBe(true);
      expect(res.ggufSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("gguf-sidecar-entangle");
      expect(readFileSync(join(dir, "loader.py"), "utf8")).toBe(LOADER_BODY);
      expect(extractGgufSidecarMetadataNote(readFileSync(entry))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite an unknown helper file", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-loader-unsafe-"));
    try {
      const entry = join(dir, "model.gguf");
      writeFileSync(entry, buildMinimalGguf());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      const helper = LOADER_BODY;
      writeFileSync(join(dir, "helper.py"), helper, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-gguf-loader-unsafe",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.ggufSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("gguf-sidecar-entangle");
      expect(readFileSync(join(dir, "helper.py"), "utf8")).toBe(helper);
      expect(extractGgufSidecarMetadataNote(readFileSync(entry))).not.toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("hardenProject auto-wires dist/loader.py beside model.gguf", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-loader-harden-"));
    try {
      const dist = join(dir, "dist");
      mkdirSync(dist, { recursive: true });
      writeFileSync(join(dist, "model.gguf"), buildMinimalGguf());
      writeFileSync(join(dist, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dist, "loader.py"), LOADER_BODY, "utf8");

      const report = hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "harden-gguf-loader-hook",
        sidecarEntangle: true,
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.sidecarEntangleError).toBeUndefined();

      const outDist = join(report.outputDirectory, "dist");
      const hooked = readFileSync(join(outDist, "loader.py"), "utf8");
      expect(hooked).toContain(GGUF_SIDECAR_LOADER_MARKER);
      const ggufBytes = readFileSync(join(outDist, "model.gguf"));
      expect(extractGgufSidecarMetadataNote(ggufBytes)).not.toBeNull();
      expect(ggufBytes.includes(Buffer.from(GGUF_SIDECAR_METADATA_KEY))).toBe(true);
      expect(
        isGgufSidecarLoaderHookWired({
          ggufBytes,
          ggufPath: join(outDist, "model.gguf"),
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
