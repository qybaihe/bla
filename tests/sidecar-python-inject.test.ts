import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  bindPythonSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarPythonPreamble,
  SIDECAR_ENTANGLE_SCHEMA,
} from "../src/shields/runtime/sidecar-entangle.js";

function runPython(entryAbs: string): {
  status: number | null;
  out: string;
} {
  const r = spawnSync("python3", [entryAbs], { encoding: "utf8" });
  return {
    status: r.status,
    out: `${r.stderr || ""}${r.stdout || ""}`,
  };
}

describe("sidecar Python inject strip⇒fail", () => {
  it("generateSidecarPythonPreamble rejects non-hex expected digests", () => {
    expect(() =>
      generateSidecarPythonPreamble({
        entryPath: "main.py",
        sidecarPaths: ["sib.py"],
        expectedHex: "deadbeef",
      }),
    ).toThrow(/64-char/);
  });

  it("bindPythonSidecarEntanglement returns status bound and preserves docstring/futures", () => {
    const entrySrc =
      '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"""module doc"""\nfrom __future__ import annotations\n\nVALUE = 42\n';
    const sibBytes = new TextEncoder().encode("sidecar-payload\n");
    const bound = bindPythonSidecarEntanglement({
      entryPath: "main.py",
      sidecarPaths: ["sib.py"],
      seedTag: "py-inject-v1",
      entryBytes: new TextEncoder().encode(entrySrc),
      sidecarBytes: [sibBytes],
      entrySource: entrySrc,
    });
    expect(bound.plan.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("python-preamble");
    expect(bound.inject.preamble).toContain("hashlib");
    expect(bound.inject.expectedHex).toBe(bound.digest.hex);
    expect(bound.code.startsWith("#!/usr/bin/env python3")).toBe(true);
    expect(bound.code).toContain('"""module doc"""');
    expect(bound.code).toContain("from __future__ import annotations");
    // Preamble must land AFTER futures, not before.
    const futureIdx = bound.code.indexOf("from __future__ import annotations");
    const hashIdx = bound.code.indexOf("import hashlib");
    expect(hashIdx).toBeGreaterThan(futureIdx);
    expect(bound.code).toContain("VALUE = 42");
  });

  it("digest matches computeSidecarBindingDigest sidecars-mode", () => {
    const entrySrc = "print(1)\n";
    const sibSrc = "sidecar-payload\n";
    const digest = computeSidecarBindingDigest(
      { pathLabel: "main.py", bytes: new TextEncoder().encode(entrySrc) },
      [{ pathLabel: "sib.py", bytes: new TextEncoder().encode(sibSrc) }],
      "parity-v1",
    );
    const inject = generateSidecarPythonPreamble({
      entryPath: "main.py",
      sidecarPaths: ["sib.py"],
      seedTag: "parity-v1",
      expectedHex: digest.hex,
    });
    expect(inject.expectedHex).toBe(digest.hex);
    expect(inject.expectedU32).toBe(digest.u32);
  });

  it("runtime: intact sidecars pass; stripped sidecar fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-py-inject-"));
    try {
      const entryPath = "main.py";
      const sibName = "sib.py";
      const entrySrc = "print('ok-value')\n";
      const sibSrc = "sidecar-payload\n";
      writeFileSync(join(dir, sibName), sibSrc, "utf8");

      const digest = computeSidecarBindingDigest(
        { pathLabel: entryPath, bytes: new TextEncoder().encode(entrySrc) },
        [{ pathLabel: sibName, bytes: new TextEncoder().encode(sibSrc) }],
        "rt-py-v1",
      );
      const inject = generateSidecarPythonPreamble({
        entryPath,
        sidecarPaths: [sibName],
        seedTag: "rt-py-v1",
        expectedHex: digest.hex,
        softFold: false,
      });
      writeFileSync(join(dir, entryPath), `${inject.preamble}\n${entrySrc}`, "utf8");

      const intact = runPython(join(dir, entryPath));
      expect(intact.status, intact.out).toBe(0);
      expect(intact.out).toContain("ok-value");

      unlinkSync(join(dir, sibName));
      const stripped = runPython(join(dir, entryPath));
      expect(stripped.status, stripped.out).not.toBe(0);
      expect(stripped.out).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runtime: altered sidecar fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-py-alter-"));
    try {
      const entryPath = "main.py";
      const sibName = "sib.bin";
      const entrySrc = "print(7)\n";
      const sibSrc = "original-sidecar\n";
      writeFileSync(join(dir, sibName), sibSrc, "utf8");

      const digest = computeSidecarBindingDigest(
        { pathLabel: entryPath, bytes: new TextEncoder().encode(entrySrc) },
        [{ pathLabel: sibName, bytes: new TextEncoder().encode(sibSrc) }],
        "alter-py-v1",
      );
      const inject = generateSidecarPythonPreamble({
        entryPath,
        sidecarPaths: [sibName],
        seedTag: "alter-py-v1",
        expectedHex: digest.hex,
      });
      writeFileSync(join(dir, entryPath), `${inject.preamble}\n${entrySrc}`, "utf8");

      const intact = runPython(join(dir, entryPath));
      expect(intact.status, intact.out).toBe(0);

      writeFileSync(join(dir, sibName), "TAMPERED\n", "utf8");
      const altered = runPython(join(dir, entryPath));
      expect(altered.status, altered.out).not.toBe(0);
      expect(altered.out).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("softFold flips digest u32 instead of raising when sidecar missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-py-soft-"));
    try {
      const entryPath = "main.py";
      const sibName = "sib.py";
      const digest = computeSidecarBindingDigest(
        { pathLabel: entryPath, bytes: new TextEncoder().encode("x") },
        [{ pathLabel: sibName, bytes: new TextEncoder().encode("y") }],
        "soft-py-v1",
      );
      const inject = generateSidecarPythonPreamble({
        entryPath,
        sidecarPaths: [sibName],
        seedTag: "soft-py-v1",
        expectedHex: digest.hex,
        softFold: true,
        bindingName: "__bla_sidecar_digest",
      });
      writeFileSync(
        join(dir, entryPath),
        `${inject.preamble}\nprint(__bla_sidecar_digest)\n`,
        "utf8",
      );
      const out = runPython(join(dir, entryPath));
      expect(out.status, out.out).toBe(0);
      const printed = Number((out.out || "").trim().split(/\s+/).pop());
      expect(Number.isFinite(printed)).toBe(true);
      expect(printed).not.toBe(digest.u32);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
