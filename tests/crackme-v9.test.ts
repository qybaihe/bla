/**
 * CrackMe v9 — Sovereign (BLA 3.0 4-Stage Agent-Driven Hardening Showcase).
 */
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { verifyWeaveTarget } from "../src/index.js";

const ROOT = join(__dirname, "..");
const V9 = join(ROOT, "challenge", "v9");
const HARDENED = join(V9, "hardened");
const SEAL_PATH = join(V9, "SEAL.json");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
// @ts-expect-error v9-lib.mjs ships no type declarations; typed by its runtime shape.
const libP: Promise<any> = import("../scripts/crackme/v9-lib.mjs");
const seal = JSON.parse(readFileSync(SEAL_PATH, "utf8"));
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

describe("CrackMe v9 Sovereign (BLA 3.0 4-Stage Agent-Driven Hardening)", () => {
  it("SEAL pins 3.0 knobs (weaveDecoys, selfSeal, sidecarEntangle, weaveScore=100, integrityCoverageSelfVerified=true) and matches committed artifacts", async () => {
    const lib = await libP;
    expect(seal.schema).toBe(lib.SCHEMA);
    expect(seal.product).toBe(lib.PRODUCT);
    expect(seal.mode).toBe("release");
    expect(seal.label).toBe(lib.SEED_LABEL);
    for (const leak of ["seed", "keySha256"]) expect(seal).not.toHaveProperty(leak);
    expect(seal.intensity).toBe("bankrupt");
    expect(seal.weaveDecoys).toBe(true);
    expect(seal.selfSeal).toBe(true);
    expect(seal.sidecarEntangle).toBe(true);
    expect(seal.weaveScore).toBe(100);
    expect(seal.integrityCoverageSelfVerified).toBe(true);
    expect(seal.llmDirectives).toBe(false);
    expect(seal.emitManifest).toBe(false);
    expect(seal.flagSha256).toMatch(/^[0-9a-f]{64}$/);
    for (const rel of lib.COMMITTED_FILES) {
      expect(lib.sha256File(join(HARDENED, rel)), rel).toBe(seal.artifacts[rel].sha256);
    }
    const raw = gunzipSync(readFileSync(join(HARDENED, "core.wasm.gz")));
    expect(lib.sha256Hex(raw)).toBe(seal.artifacts["core.wasm"].sha256);
    for (const a of seal.hardenSummary) expect(a.success).toBe(true);

    // Verify committed hardened directory passes bla_verify_weave at 100/100
    const postWeave = verifyWeaveTarget(HARDENED);
    expect(postWeave.overallPassed).toBe(true);
    expect(postWeave.weaveScore).toBe(100);
    expect(postWeave.agentActions).toHaveLength(0);
  });

  it("git holds only hardened output (no materialized release secrets or cleartext honeypot strings)", async () => {
    const lib = await libP;
    expect(existsSync(join(V9, "hardened", "core.wasm"))).toBe(false);
    const licText = readFileSync(join(HARDENED, "license.cjs"), "utf8");
    const blob =
      readFileSync(SEAL_PATH, "utf8") +
      readFileSync(join(HARDENED, "seal.json"), "utf8") +
      licText;
    expect(blob).not.toContain(process.env.CRACKME_V9_KEY || "___no_key___");
    expect(blob.toLowerCase()).not.toMatch(/crackme_v9_key|crackme_v9_flag/);
    // bla_encrypt_strings masked all HONEYPOT_KEYS in license.cjs
    for (const hp of lib.HONEYPOT_KEYS) {
      expect(licText).not.toContain(hp);
    }
  });

  it("release bundle: wrong/empty deny; honeypots are decoys; fixture key denied; tampering with seal.json or policy.py hard-fails", async () => {
    const lib = await libP;
    const run = lib.prepareRunnable(HARDENED);
    try {
      for (const bad of ["wrong-key-v9-1234", "", "short"]) {
        const r = lib.runLicense(run, bad);
        expect(r.ok, bad).toBe(false);
        expect(lib.extractFlag(r.stdout)).toBeNull();
      }
      for (const hp of lib.HONEYPOT_KEYS) {
        const f = lib.extractFlag(lib.runLicense(run, hp).stdout);
        expect(f).toBeTruthy();
        expect(sha(f!)).not.toBe(seal.flagSha256);
      }
      expect(lib.extractFlag(lib.runLicense(run, lib.FIXTURE_KEY).stdout)).toBeNull();

      // Tampering with seal.json must hard-fail (closes v8 uncovered seal.json residual)
      const sealPath = join(run, "seal.json");
      const origSeal = readFileSync(sealPath);
      try {
        writeFileSync(sealPath, Buffer.concat([origSeal, Buffer.from("\n")]));
        const tampered = lib.runLicense(run, "WrongKeyV9-12345");
        expect(tampered.ok).toBe(false);
        expect(tampered.stdout).toMatch(/integrity check failed/);
      } finally {
        writeFileSync(sealPath, origSeal);
      }

      // Deleting policy.py sidecar must hard-fail via sidecarEntangle / selfSeal
      const policyPath = join(run, "policy.py");
      const origPolicy = readFileSync(policyPath);
      try {
        unlinkSync(policyPath);
        const deleted = lib.runLicense(run, "WrongKeyV9-12345");
        expect(deleted.ok).toBe(false);
        expect(deleted.stdout).toMatch(/integrity (?:check failed|binding mismatch)/);
      } finally {
        writeFileSync(policyPath, origPolicy);
      }
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  });

  it("fixture: re-harden runs 4-stage 3.0 pipeline, unlocks demo key, and is reproducible", async () => {
    const lib = await libP;
    const a = mkdtempSync(join(tmpdir(), "bla-crackme-v9-a-"));
    const b = mkdtempSync(join(tmpdir(), "bla-crackme-v9-b-"));
    try {
      const ra = await lib.hardenChallenge({ key: lib.FIXTURE_KEY, flag: lib.FIXTURE_FLAG, outDir: a });
      const rb = await lib.hardenChallenge({ key: lib.FIXTURE_KEY, flag: lib.FIXTURE_FLAG, outDir: b });
      for (const rel of lib.COMMITTED_FILES) {
        expect(ra.artifacts[rel].sha256).toBe(rb.artifacts[rel].sha256);
      }
      const run = lib.prepareRunnable(a);
      try {
        const ok = lib.runLicense(run, lib.FIXTURE_KEY);
        expect(ok.ok).toBe(true);
        expect(lib.extractFlag(ok.stdout)).toBe(lib.FIXTURE_FLAG);
        expect(lib.runLicense(run, "WrongKey!!!!!!!!").ok).toBe(false);
      } finally {
        rmSync(run, { recursive: true, force: true });
      }
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  }, 180_000);

  it("DESIGN.md states v8 supersession + 4-stage BLA 3.0 playbook + covered seal.json + P2 honesty", () => {
    const d = readFileSync(join(V9, "DESIGN.md"), "utf8");
    expect(d).toMatch(/successor to CrackMe v8/i);
    expect(d).toMatch(/EXPECTED_SEAL_SHA256/);
    expect(d).toMatch(/sidecarEntangle/i);
    expect(d).toMatch(/weaveScore/i);
    expect(d).toMatch(/white-box/i);
  });

  it.skipIf(!process.env.CRACKME_V9_KEY || !process.env.CRACKME_V9_FLAG)(
    "release unlock when secrets match SEAL",
    async () => {
      const lib = await libP;
      const key = process.env.CRACKME_V9_KEY!;
      const flag = process.env.CRACKME_V9_FLAG!;
      expect(sha(flag)).toBe(seal.flagSha256);
      const run = lib.prepareRunnable(HARDENED);
      try {
        const r = lib.runLicense(run, key);
        expect(r.ok).toBe(true);
        expect(lib.extractFlag(r.stdout)).toBe(flag);
      } finally {
        rmSync(run, { recursive: true, force: true });
      }
    },
  );
});
