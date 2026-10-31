import { createHash } from "node:crypto";
import { readFileSync, existsSync, mkdtempSync, copyFileSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const ROOT = join(__dirname, "..");
const V7 = join(ROOT, "challenge", "v7");
const DIST = join(V7, "hardened");
const SEAL_PATH = join(V7, "SEAL.json");
const MODULES = ["cli/meridian.cjs", "core/expr.cjs", "core/units.cjs", "core/stats.cjs", "core/license.cjs"] as const;
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

function run(args: string[], cwd = DIST) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return spawnSync(process.execPath, [join(cwd, "cli", "meridian.cjs"), ...args], {
    env,
    encoding: "utf8",
  });
}

describe("CrackMe v7 Meridian", () => {
  it("publishes SEAL with knobs, digests, no plaintext secrets", () => {
    const seal = JSON.parse(readFileSync(SEAL_PATH, "utf8"));
    expect(seal.schema).toBe("bla-crackme-v7-seal/v1");
    expect(seal.product).toBe("Meridian");
    expect(seal.intensity).toBe("bankrupt");
    expect(seal.llmDirectives).toBe(false);
    expect(seal.emitManifest).toBe(false);
    expect(seal.keySha256).toMatch(/^[0-9a-f]{64}$/);
    expect(seal.certSha256).toMatch(/^[0-9a-f]{64}$/);
    const blob = readFileSync(SEAL_PATH, "utf8") + readFileSync(join(DIST, "data", "catalog.json"), "utf8");
    expect(blob.toLowerCase()).not.toMatch(/flag\{/);
    expect(blob).not.toMatch(/CRACKME_V7_KEY|CRACKME_V7_CERT/);
  });

  it("git hygiene: hardened modules match SEAL digests and integrity", () => {
    const seal = JSON.parse(readFileSync(SEAL_PATH, "utf8"));
    for (const rel of [...MODULES, "data/catalog.json"]) {
      const buf = readFileSync(join(DIST, rel));
      expect(seal.files[rel].sha256).toBe(sha(buf));
      expect(seal.files[rel].bytes).toBe(buf.length);
    }
    const h = createHash("sha256");
    for (const rel of MODULES) {
      h.update(rel);
      h.update(readFileSync(join(DIST, rel)));
    }
    expect(h.digest("hex")).toBe(seal.integrity);
  });

  it("product surface: calc / convert / stats / units", () => {
    expect(run(["calc", "6!/(2^3)"]).stdout.trim()).toBe("90");
    expect(run(["convert", "1", "mi", "km"]).status).toBe(0);
    expect(run(["stats", "1", "2", "3"]).stdout).toMatch(/mean/);
    expect(run(["units"]).stdout).toMatch(/length/);
  });

  it("license deny is uniform; format errors are distinct", () => {
    expect(run(["license", "activate", "AAAAA-AAAAA-AAAAA-AAAAA"]).status).toBe(1);
    expect(run(["license", "activate", "AAAAA-AAAAA-AAAAA-AAAAA"]).stderr).toMatch(/License rejected/);
    expect(run(["license", "activate", "nope"]).status).toBe(2);
  });

  it("self-integrity: flipping a module byte denies activation", () => {
    const dir = mkdtempSync(join(tmpdir(), "meridian-t-"));
    try {
      for (const rel of [...MODULES, "data/catalog.json"]) {
        mkdirSync(dirname(join(dir, rel)), { recursive: true });
        copyFileSync(join(DIST, rel), join(dir, rel));
      }
      const p = join(dir, "core", "stats.cjs");
      const buf = Buffer.from(readFileSync(p));
      buf[Math.min(100, buf.length - 1)] ^= 0x5a;
      writeFileSync(p, buf);
      expect(run(["license", "activate", "AAAAA-AAAAA-AAAAA-AAAAA"], dir).status).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("DESIGN.md exists and states the v6 supersession + chained ARX", () => {
    const d = readFileSync(join(V7, "DESIGN.md"), "utf8");
    expect(d).toMatch(/successor to CrackMe v6/i);
    expect(d).toMatch(/Chained|ARX/i);
    expect(d).toMatch(/self-integrity/i);
  });

  it.skipIf(!process.env.CRACKME_V7_KEY || !process.env.CRACKME_V7_CERT)(
    "release unlock when secrets match SEAL",
    () => {
      const seal = JSON.parse(readFileSync(SEAL_PATH, "utf8"));
      const key = process.env.CRACKME_V7_KEY!;
      const cert = process.env.CRACKME_V7_CERT!;
      expect(sha(key)).toBe(seal.keySha256);
      expect(sha(cert)).toBe(seal.certSha256);
      const r = run(["license", "activate", key]);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain("Activation certificate: " + cert);
    },
  );
});
