import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const v6 = join(root, "challenge", "v6");
const artifactsDir = join(v6, "artifacts");
const commitmentPath = join(v6, "commitment.json");
const profilesPath = join(v6, "profiles.json");
const templatePath = join(v6, "clean", "target.template.cjs");
const buildScript = join(root, "scripts", "crackme", "build.mjs");
const sealScript = join(root, "scripts", "crackme", "seal.mjs");

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function runNode(args: string[], envExtra: Record<string, string | undefined> = {}) {
  const env = { ...process.env, ...envExtra };
  delete env.NODE_OPTIONS;
  return execFileSync(process.execPath, args, {
    cwd: root,
    encoding: "utf8",
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

describe("CrackMe v6 — BLA-generated tiered challenge", () => {
  it("ships template, profiles, commitment, and L1/L2/L3 artifacts without plaintext secrets", () => {
    expect(existsSync(templatePath)).toBe(true);
    expect(existsSync(profilesPath)).toBe(true);
    expect(existsSync(commitmentPath)).toBe(true);

    const commitment = JSON.parse(readFileSync(commitmentPath, "utf8")) as {
      version: number;
      flagSha256: string;
      keySha256: string;
      artifactSha256: Record<string, string>;
    };
    expect(commitment.version).toBe(6);
    expect(commitment.flagSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(commitment.keySha256).toMatch(/^[0-9a-f]{64}$/);

    const template = readFileSync(templatePath, "utf8");
    expect(template).toContain("%%KEY_SHA256%%");
    expect(template).toContain("%%FLAG_CIPHER_HEX%%");
    expect(template).not.toMatch(/FLAG\{[A-Za-z0-9_]{16,}\}/);
    expect(template).toContain("%%FLAG_SHA256%%");

    for (const tier of ["L1", "L2", "L3"] as const) {
      const path = join(artifactsDir, `${tier}.cjs`);
      expect(existsSync(path)).toBe(true);
      const raw = readFileSync(path);
      const digest = createHash("sha256").update(raw).digest("hex");
      expect(digest).toBe(commitment.artifactSha256[tier]);
      const text = raw.toString("utf8");
      expect(text).not.toMatch(/FLAG\{[A-Za-z0-9_]{16,}\}/);
      expect(text).not.toContain("%%KEY_SHA256%%");
      // BLA honey / decoy surface should be present on hardened output
      expect(text.length).toBeGreaterThan(20_000);
    }
  });

  it("denies wrong keys on every published tier", () => {
    for (const tier of ["L1", "L2", "L3"]) {
      const artifact = join(artifactsDir, `${tier}.cjs`);
      let denied = false;
      try {
        runNode([artifact, "wrong-key-not-it"]);
      } catch {
        denied = true;
      }
      expect(denied).toBe(true);
    }
  });

  it("rebuilds fixture tiers via real bla protect and unlocks the demo secret only", () => {
    runNode([buildScript, "--fixture"], { CRACKME_V6_MODE: "fixture" });
    const fixtureL3 = join(artifactsDir, ".fixture", "L3.cjs");
    expect(existsSync(fixtureL3)).toBe(true);

    const out = runNode([fixtureL3, "DemoKey-CrackMe-V6-FIXTURE!"]);
    expect(out).toContain("FLAG{bla_v6_demo_fixture_not_the_real_prize}");
    expect(sha256Hex("FLAG{bla_v6_demo_fixture_not_the_real_prize}")).not.toBe(
      JSON.parse(readFileSync(commitmentPath, "utf8")).flagSha256,
    );

    let denied = false;
    try {
      runNode([fixtureL3, "DemoKey-CrackMe-V6!"]);
    } catch {
      denied = true;
    }
    expect(denied).toBe(true);
  });

  it("passes crackme:seal (digest + deny + fixture)", () => {
    runNode([sealScript]);
  });
});
