import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  readFileSync,
  realpathSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
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
      const entrySrc = "module.exports = { v: 99 };\n";
      const sibSrc = "sidecar-bytes-v1\n";
      writeFileSync(entry, entrySrc, "utf8");
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

      const outAbs = realpathSync(out);
      const intact = spawnSync(process.execPath, ["-e", `console.log(require(${JSON.stringify(outAbs)}).v)`], {
        encoding: "utf8",
      });
      expect(intact.status, intact.stderr).toBe(0);
      expect((intact.stdout || "").trim()).toBe("99");

      rmSync(join(dir, "sib-for-out.js"));
      const stripped = spawnSync(process.execPath, [outAbs], { encoding: "utf8" });
      const strippedOut = `${stripped.stderr || ""}${stripped.stdout || ""}`;
      expect(stripped.status, strippedOut).not.toBe(0);
      expect(strippedOut).toMatch(/integrity binding mismatch/);
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

describe("sidecar entangle protectTarget Python wiring", () => {
  it("flag off leaves Python entry free of strip⇒fail preamble", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-py-off-"));
    try {
      const entry = join(dir, "main.py");
      const sib = join(dir, "sib.bin");
      writeFileSync(entry, "print(1)\n", "utf8");
      writeFileSync(sib, "sidecar\n", "utf8");
      const out = join(dir, "main.out.py");
      const res = protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "py-off-test",
        sidecarEntangle: false,
        sidecarEntanglePaths: ["sib.bin"],
      });
      expect(res.sidecarEntangle).toBeUndefined();
      const code = readFileSync(out, "utf8");
      expect(code).not.toContain("integrity binding mismatch");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flag on writes Python binding; intact runs; strip fails closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-py-on-"));
    try {
      const entry = join(dir, "main.py");
      const entrySrc = "print('py-ok')\n";
      const sibSrc = "sidecar-bytes-py-v1\n";
      writeFileSync(entry, entrySrc, "utf8");
      const out = join(dir, "main.out.py");
      writeFileSync(join(dir, "sib-for-out.bin"), sibSrc, "utf8");
      const res = protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "py-on-test-seed",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib-for-out.bin"],
      });
      expect(res.sidecarEntangle).toBe(true);
      const code = readFileSync(out, "utf8");
      expect(code).toContain("hashlib");
      expect(code).toContain("integrity binding mismatch");

      const intact = spawnSync("python3", [out], { encoding: "utf8" });
      expect(intact.status, `${intact.stderr || ""}${intact.stdout || ""}`).toBe(0);
      expect((intact.stdout || "")).toContain("py-ok");

      rmSync(join(dir, "sib-for-out.bin"));
      const stripped = spawnSync("python3", [out], { encoding: "utf8" });
      const strippedOut = `${stripped.stderr || ""}${stripped.stdout || ""}`;
      expect(stripped.status, strippedOut).not.toBe(0);
      expect(strippedOut).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("sidecar entangle hardenProject Python-only post-pass", () => {
  it("Python-only project binds entry; strip of sibling fails closed", async () => {
    const { hardenProject } = await import("../src/engine/harden.js");
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-py-harden-"));
    try {
      writeFileSync(
        join(dir, "policy.py"),
        "def check():\n    return 7\n\nif __name__ == '__main__':\n    print(check())\n",
        "utf8",
      );
      // Second discovered Python artifact becomes the measured sibling.
      writeFileSync(join(dir, "helper.py"), "HELPER = 1\n", "utf8");
      const report = await hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "py-harden-seed",
        sidecarEntangle: true,
        dryRun: false,
      });
      expect(report.overallSuccess).toBe(true);
      const policyOut = report.artifacts.find(
        (a) => a.relativePath.replaceAll("\\", "/").endsWith("policy.py") && a.success,
      );
      expect(policyOut).toBeTruthy();
      const code = readFileSync(policyOut!.outputPath, "utf8");
      expect(code).toContain("hashlib");
      expect(code).toContain("integrity binding mismatch");

      const intact = spawnSync("python3", [policyOut!.outputPath], { encoding: "utf8" });
      expect(intact.status, `${intact.stderr || ""}${intact.stdout || ""}`).toBe(0);
      expect((intact.stdout || "").trim()).toContain("7");

      const helperOut = report.artifacts.find(
        (a) => a.relativePath.replaceAll("\\", "/").endsWith("helper.py") && a.success,
      );
      expect(helperOut).toBeTruthy();
      rmSync(helperOut!.outputPath);
      const stripped = spawnSync("python3", [policyOut!.outputPath], { encoding: "utf8" });
      const strippedOut = `${stripped.stderr || ""}${stripped.stdout || ""}`;
      expect(stripped.status, strippedOut).not.toBe(0);
      expect(strippedOut).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

