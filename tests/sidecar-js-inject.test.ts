import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import {
  bindSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarJsPreamble,
  SIDECAR_ENTANGLE_SCHEMA,
} from "../src/shields/runtime/sidecar-entangle.js";

describe("sidecar JS inject strip⇒fail (vertical slice)", () => {
  it("generateSidecarJsPreamble rejects non-hex expected digests", () => {
    expect(() =>
      generateSidecarJsPreamble({
        entryPath: "main.js",
        sidecarPaths: ["sib.js"],
        expectedHex: "deadbeef",
      }),
    ).toThrow(/64-char/);
  });

  it("bindSidecarEntanglement returns status bound with inject + digest", () => {
    const entryBytes = new TextEncoder().encode("module.exports = { ok: true };\n");
    const sibBytes = new TextEncoder().encode("sidecar-payload\n");
    const bound = bindSidecarEntanglement({
      entryPath: "main.js",
      sidecarPaths: ["sib.js"],
      seedTag: "inject-test-v1",
      entryBytes,
      sidecarBytes: [sibBytes],
    });
    expect(bound.plan.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(bound.plan.status).toBe("bound");
    expect(bound.inject.preamble).toContain("node:crypto");
    expect(bound.inject.expectedHex).toBe(bound.digest.hex);
    expect(bound.inject.softFold).toBe(false);
    expect(bound.code.startsWith(bound.inject.preamble)).toBe(true);
  });

  it("runtime: intact sidecars pass; stripped sidecar fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-inject-"));
    try {
      const entryPath = "main.js";
      const sibName = "sib.js";
      const entrySrc = "module.exports = { value: 42 };\n";
      const sibSrc = "module.exports = 'sidecar';\n";
      writeFileSync(join(dir, sibName), sibSrc, "utf8");

      const digest = computeSidecarBindingDigest(
        { pathLabel: entryPath, bytes: new TextEncoder().encode(entrySrc) },
        [{ pathLabel: sibName, bytes: new TextEncoder().encode(sibSrc) }],
        "rt-v1",
      );
      const inject = generateSidecarJsPreamble({
        entryPath,
        sidecarPaths: [sibName],
        seedTag: "rt-v1",
        expectedHex: digest.hex,
        softFold: false,
      });

      // Write entry WITH preamble prepended — sidecars-mode digest still matches.
      const protectedEntry = `${inject.preamble}\n${entrySrc}`;
      writeFileSync(join(dir, entryPath), protectedEntry, "utf8");

      const req = createRequire(join(dir, "pkg.json"));
      const loaded = req(join(dir, entryPath)) as { value: number };
      expect(loaded.value).toBe(42);

      // Strip sidecar → next load must throw.
      rmSync(join(dir, sibName));
      expect(() => {
        // Bust require cache
        const abs = join(dir, entryPath);
        delete req.cache[abs];
        req(abs);
      }).toThrow(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runtime: altered sidecar fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-alter-"));
    try {
      const entryPath = "main.js";
      const sibName = "sib.js";
      const entrySrc = "module.exports = { value: 7 };\n";
      const sibSrc = "original-sidecar\n";
      writeFileSync(join(dir, sibName), sibSrc, "utf8");

      const digest = computeSidecarBindingDigest(
        { pathLabel: entryPath, bytes: new TextEncoder().encode(entrySrc) },
        [{ pathLabel: sibName, bytes: new TextEncoder().encode(sibSrc) }],
        "alter-v1",
      );
      const inject = generateSidecarJsPreamble({
        entryPath,
        sidecarPaths: [sibName],
        seedTag: "alter-v1",
        expectedHex: digest.hex,
      });
      writeFileSync(join(dir, entryPath), `${inject.preamble}\n${entrySrc}`, "utf8");

      const req = createRequire(join(dir, "pkg.json"));
      expect((req(join(dir, entryPath)) as { value: number }).value).toBe(7);

      writeFileSync(join(dir, sibName), "TAMPERED\n", "utf8");
      const abs = join(dir, entryPath);
      delete req.cache[abs];
      expect(() => req(abs)).toThrow(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("softFold flips digest u32 instead of throwing when sidecar missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-soft-"));
    try {
      const entryPath = "main.js";
      const sibName = "sib.js";
      const entrySrc =
        "module.exports = { d: (typeof __blaSidecarDigest === 'number' ? __blaSidecarDigest : 0) };\n";
      // softFold preamble assigns binding as IIFE return — capture via rewrite:
      const digest = computeSidecarBindingDigest(
        { pathLabel: entryPath, bytes: new TextEncoder().encode("x") },
        [{ pathLabel: sibName, bytes: new TextEncoder().encode("y") }],
        "soft-v1",
      );
      const inject = generateSidecarJsPreamble({
        entryPath,
        sidecarPaths: [sibName],
        seedTag: "soft-v1",
        expectedHex: digest.hex,
        softFold: true,
        bindingName: "__blaSidecarDigest",
      });
      // Capture IIFE return into the binding name for the module scope.
      const preambleAssign = `var __blaSidecarDigest = ${inject.preamble}\n`;
      writeFileSync(
        join(dir, entryPath),
        `${preambleAssign}module.exports = { d: __blaSidecarDigest };\n`,
        "utf8",
      );
      // No sidecar written → softFold should set flipped/zero digest, not throw.
      const req = createRequire(join(dir, "pkg.json"));
      const out = req(join(dir, entryPath)) as { d: number };
      expect(typeof out.d).toBe("number");
      expect(out.d).not.toBe(digest.u32);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
