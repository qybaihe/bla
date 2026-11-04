/**
 * CrackMe v8 — Aegis (2.0 harden-native + R1–R12 recipes).
 */
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";

const ROOT = join(__dirname, "..");
const V8 = join(ROOT, "challenge", "v8");
const HARDENED = join(V8, "hardened");
const SEAL_PATH = join(V8, "SEAL.json");

// Relative specifier (not file://): Vite/vitest space-safe; no .d.ts for the mjs helper.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
// @ts-expect-error v8-lib.mjs ships no type declarations; typed by its runtime shape.
const libP: Promise<any> = import("../scripts/crackme/v8-lib.mjs");
const seal = JSON.parse(readFileSync(SEAL_PATH, "utf8"));
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

describe("CrackMe v8 Aegis (harden-native + R1–R12)", () => {
  it("SEAL pins 2.0 knobs, self-seal, and matches committed artifacts", async () => {
    const lib = await libP;
    expect(seal.schema).toBe(lib.SCHEMA);
    expect(seal.product).toBe(lib.PRODUCT);
    expect(seal.mode).toBe("release");
    expect(seal.label).toBe(lib.SEED_LABEL);
    for (const leak of ["seed", "keySha256"]) expect(seal).not.toHaveProperty(leak);
    expect(seal.intensity).toBe("bankrupt");
    expect(seal.selfSeal).toBe(true);
    expect(seal.llmDirectives).toBe(false);
    expect(seal.emitManifest).toBe(false);
    expect(seal.flagSha256).toMatch(/^[0-9a-f]{64}$/);
    for (const rel of lib.COMMITTED_FILES) {
      expect(lib.sha256File(join(HARDENED, rel)), rel).toBe(seal.artifacts[rel].sha256);
    }
    const raw = gunzipSync(readFileSync(join(HARDENED, "core.wasm.gz")));
    expect(lib.sha256Hex(raw)).toBe(seal.artifacts["core.wasm"].sha256);
    for (const a of seal.hardenSummary) expect(a.success).toBe(true);
  });

  it("git holds only hardened output (no materialized release secrets)", async () => {
    expect(existsSync(join(V8, "hardened", "core.wasm"))).toBe(false);
    const blob =
      readFileSync(SEAL_PATH, "utf8") +
      readFileSync(join(HARDENED, "seal.json"), "utf8") +
      readFileSync(join(HARDENED, "license.cjs"), "utf8");
    expect(blob).not.toContain(process.env.CRACKME_V8_KEY || "___no_key___");
    expect(blob.toLowerCase()).not.toMatch(/crackme_v8_key|crackme_v8_flag/);
  });

  it("release bundle: wrong/empty deny; honeypots are decoys; fixture key denied", async () => {
    const lib = await libP;
    const run = lib.prepareRunnable(HARDENED);
    try {
      for (const bad of ["wrong-key-v8-1234", "", "short"]) {
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
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  });

  it("fixture: re-harden unlocks demo key and is reproducible", async () => {
    const lib = await libP;
    const a = mkdtempSync(join(tmpdir(), "bla-crackme-v8-a-"));
    const b = mkdtempSync(join(tmpdir(), "bla-crackme-v8-b-"));
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

  it("DESIGN.md states v7 supersession + R1–R12 recipes + P2 honesty", () => {
    const d = readFileSync(join(V8, "DESIGN.md"), "utf8");
    expect(d).toMatch(/successor to CrackMe v7/i);
    expect(d).toMatch(/SHA-256\(key\)|mask KDF/i);
    expect(d).toMatch(/self-seal/i);
    expect(d).toMatch(/Honest residual|white-box/i);
  });

  it.skipIf(!process.env.CRACKME_V8_KEY || !process.env.CRACKME_V8_FLAG)(
    "release unlock when secrets match SEAL",
    async () => {
      const lib = await libP;
      const key = process.env.CRACKME_V8_KEY!;
      const flag = process.env.CRACKME_V8_FLAG!;
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
