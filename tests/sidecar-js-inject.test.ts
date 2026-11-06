import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  realpathSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import {
  bindSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarJsPreamble,
  SIDECAR_ENTANGLE_SCHEMA,
} from "../src/shields/runtime/sidecar-entangle.js";

/** macOS tmpdir is often /var → /private/var; require.cache keys use realpath. */
function bustRequireCache(req: NodeRequire, target: string): string {
  let abs: string;
  try {
    abs = realpathSync(target);
  } catch {
    abs = target;
  }
  for (const k of Object.keys(req.cache)) {
    let rk = k;
    try {
      rk = realpathSync(k);
    } catch {
      /* keep raw key */
    }
    if (rk === abs || k === target || k === abs) delete req.cache[k];
  }
  return abs;
}

function runFresh(entryAbs: string): {
  status: number | null;
  out: string;
} {
  const r = spawnSync(process.execPath, [entryAbs], { encoding: "utf8" });
  return {
    status: r.status,
    out: `${r.stderr || ""}${r.stdout || ""}`,
  };
}

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

      const protectedEntry = `${inject.preamble}\n${entrySrc}`;
      writeFileSync(join(dir, entryPath), protectedEntry, "utf8");

      const req = createRequire(join(dir, "pkg.json"));
      const entryAbs = bustRequireCache(req, join(dir, entryPath));
      const loaded = req(entryAbs) as { value: number };
      expect(loaded.value).toBe(42);

      // Strip sidecar → fresh process must hard-fail (avoid require.cache realpath traps).
      rmSync(join(dir, sibName));
      const stripped = runFresh(entryAbs);
      expect(stripped.status, stripped.out).not.toBe(0);
      expect(stripped.out).toMatch(/integrity binding mismatch/);
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
      const entryAbs = bustRequireCache(req, join(dir, entryPath));
      expect((req(entryAbs) as { value: number }).value).toBe(7);

      writeFileSync(join(dir, sibName), "TAMPERED\n", "utf8");
      const altered = runFresh(entryAbs);
      expect(altered.status, altered.out).not.toBe(0);
      expect(altered.out).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("softFold flips digest u32 instead of throwing when sidecar missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-soft-"));
    try {
      const entryPath = "main.js";
      const sibName = "sib.js";
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
      const preambleAssign = `var __blaSidecarDigest = ${inject.preamble}\n`;
      writeFileSync(
        join(dir, entryPath),
        `${preambleAssign}module.exports = { d: __blaSidecarDigest };\n`,
        "utf8",
      );
      const req = createRequire(join(dir, "pkg.json"));
      const entryAbs = bustRequireCache(req, join(dir, entryPath));
      const out = req(entryAbs) as { d: number };
      expect(typeof out.d).toBe("number");
      expect(out.d).not.toBe(digest.u32);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
