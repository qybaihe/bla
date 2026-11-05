import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { protectTarget } from "../src/engine/protector.js";
import { computeSidecarBindingDigest } from "../src/shields/runtime/sidecar-entangle.js";

const enc = (s: string) => new TextEncoder().encode(s);

describe("sidecar entangle protectTarget wiring", () => {
  it("flag off leaves entry free of strip⇒fail preamble", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-off-"));
    try {
      const entry = join(dir, "main.js");
      const sib = join(dir, "sib.js");
      writeFileSync(entry, "module.exports = { v: 1 };\n", "utf8");
      writeFileSync(sib, "sidecar\n", "utf8");
      const out = join(dir, "main.out.js");
      const res = protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "off-test",
        honeySourceMaps: false,
        sidecarEntangle: false,
        sidecarEntanglePaths: ["sib.js"],
      });
      expect(res.sidecarEntangle).toBeUndefined();
      const code = readFileSync(out, "utf8");
      expect(code).not.toContain("integrity binding mismatch");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flag on writes binding; intact load works; strip fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-on-"));
    try {
      const entry = join(dir, "main.js");
      const sib = join(dir, "sib.js");
      const entrySrc = "module.exports = { v: 99 };\n";
      const sibSrc = "sidecar-bytes-v1\n";
      writeFileSync(entry, entrySrc, "utf8");
      writeFileSync(sib, sibSrc, "utf8");
      const out = join(dir, "main.out.js");
      // protect writes next to output; sidecar path resolved from output dir
      writeFileSync(join(dir, "sib-for-out.js"), sibSrc, "utf8");
      const res = protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "on-test-seed",
        honeySourceMaps: false,
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib-for-out.js"],
      });
      expect(res.sidecarEntangle).toBe(true);
      const code = readFileSync(out, "utf8");
      expect(code).toContain("node:crypto");
      expect(code).toContain("integrity binding mismatch");

      const req = createRequire(join(dir, "pkg.json"));
      const loaded = req(out) as { v: number };
      expect(loaded.v).toBe(99);

      rmSync(join(dir, "sib-for-out.js"));
      delete req.cache[out];
      expect(() => req(out)).toThrow(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("digest is order-sensitive across sidecars", () => {
    const entry = { pathLabel: "main.js", bytes: enc("x") };
    const fwd = computeSidecarBindingDigest(entry, [
      { pathLabel: "a", bytes: enc("A") },
      { pathLabel: "b", bytes: enc("B") },
    ]).hex;
    const rev = computeSidecarBindingDigest(entry, [
      { pathLabel: "b", bytes: enc("B") },
      { pathLabel: "a", bytes: enc("A") },
    ]).hex;
    expect(fwd).not.toBe(rev);
  });
});
