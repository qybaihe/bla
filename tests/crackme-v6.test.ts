/**
 * CrackMe v6 — harden-native edition.
 * The published challenge is `hardenProject()` (== `bla harden`) output over a
 * public template; no plaintext key/flag lives in git. CI exercises the public
 * demo fixture end-to-end and only digests for the release bundle.
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { assertNoForbiddenMarkers } from "../src/core/identifiers.js";
import { inspectWasmBinary } from "../src/shields/formats/wasm.js";

const ROOT = resolve(process.cwd());
const V6 = join(ROOT, "challenge", "v6");
const HARDENED = join(V6, "hardened");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const libP: Promise<any> = import(pathToFileURL(join(ROOT, "scripts", "crackme", "lib.mjs")).href);
const seal = JSON.parse(readFileSync(join(V6, "SEAL.json"), "utf8"));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function withFixture<T>(fn: (lib: any, bundle: string, run: string) => Promise<T> | T): Promise<T> {
  const lib = await libP;
  const bundle = mkdtempSync(join(tmpdir(), "bla-crackme-v6-test-"));
  let run = "";
  try {
    await lib.hardenChallenge({ key: lib.FIXTURE_KEY, flag: lib.FIXTURE_FLAG, outDir: bundle });
    run = lib.prepareRunnable(bundle);
    return await fn(lib, bundle, run);
  } finally {
    rmSync(bundle, { recursive: true, force: true });
    if (run) rmSync(run, { recursive: true, force: true });
  }
}

describe("CrackMe v6 (harden-native)", () => {
  it("SEAL pins P0-safe harden knobs and matches committed artifacts + templates", async () => {
    const lib = await libP;
    expect(seal.schema).toBe(lib.SCHEMA);
    expect(seal.mode).toBe("release");
    expect(seal.seed).toBe(lib.SEED);
    expect(seal.intensity).toBe("bankrupt");
    expect(seal.llmDirectives).toBe(false);
    expect(seal.emitManifest).toBe(false);
    expect(seal.flagSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(seal.keySha256).toMatch(/^[0-9a-f]{64}$/);
    for (const rel of lib.COMMITTED_FILES) {
      expect(lib.sha256File(join(HARDENED, rel)), rel).toBe(seal.artifacts[rel].sha256);
    }
    const raw = gunzipSync(readFileSync(join(HARDENED, "core.wasm.gz")));
    expect(lib.sha256Hex(raw)).toBe(seal.artifacts["core.wasm"].sha256);
    expect(lib.templateDigests()).toEqual(seal.templates);
    for (const a of seal.hardenSummary) expect(a.success).toBe(true);
  });

  it("git holds only the template + hardened output (no materialized secrets)", () => {
    const tpl = readFileSync(join(V6, "src", "vault.template.cjs"), "utf8");
    for (const p of ["%%LANE_TARGETS_HEX%%", "%%PANEL_TOKEN%%", "%%FLAG_CIPHER_HEX%%", "%%FLAG_SHA256%%"]) {
      expect(tpl).toContain(p);
    }
    expect(existsSync(join(V6, "hardened", "core.wasm"))).toBe(false);
    for (const rel of ["vault.cjs", "panel.html"]) {
      const src = readFileSync(join(HARDENED, rel), "utf8");
      assertNoForbiddenMarkers(src, `crackme-v6/${rel}`);
      expect(src).not.toMatch(/FLAG\{[A-Za-z0-9_\-]{12,}\}/);
      expect(src).not.toContain(seal.flagSha256);
    }
  });

  it("release bundle denies wrong/empty/fixture keys without a per-stage oracle; honeypots stay decoys", async () => {
    const lib = await libP;
    const run = lib.prepareRunnable(HARDENED);
    try {
      for (const bad of ["wrong-key-v6-123", lib.FIXTURE_KEY]) {
        const r = lib.runVault(run, bad);
        expect(r.ok).toBe(false);
        expect(r.stdout.trim()).toBe("[vault] DENIED");
      }
      expect(lib.extractFlag(lib.runVault(run, "").stdout)).toBeNull();
      for (const hp of lib.HONEYPOT_KEYS) {
        const f = lib.extractFlag(lib.runVault(run, hp).stdout);
        expect(f).not.toBeNull();
        expect(lib.sha256Hex(f)).not.toBe(seal.flagSha256);
      }
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  }, 120_000);

  it("fixture: real re-harden of the public template unlocks with the demo key and hides its constants", async () => {
    await withFixture(async (lib, bundle, run) => {
      const ok = lib.runVault(run, lib.FIXTURE_KEY);
      expect(ok.ok).toBe(true);
      expect(lib.extractFlag(ok.stdout)).toBe(lib.FIXTURE_FLAG);
      expect(lib.runVault(run, "Demo-V6-Fixture?").stdout.trim()).toBe("[vault] DENIED");

      const vault = readFileSync(join(bundle, "vault.cjs"), "utf8");
      const targets = lib.laneTargets(lib.FIXTURE_KEY, lib.laneSalt()).map((n: number) => n.toString(16).padStart(8, "0"));
      expect(vault).not.toContain(targets.join(""));
      expect(vault).not.toContain(lib.panelToken(lib.FIXTURE_KEY));
      expect(vault).not.toContain(lib.flagCipherHex(lib.FIXTURE_KEY, lib.FIXTURE_FLAG));
      expect(vault).not.toContain(lib.FIXTURE_FLAG);
    });
  }, 180_000);

  it("fixture: seeded harden is byte-for-byte reproducible", async () => {
    const lib = await libP;
    const a = mkdtempSync(join(tmpdir(), "bla-crackme-v6-a-"));
    const b = mkdtempSync(join(tmpdir(), "bla-crackme-v6-b-"));
    try {
      const ra = await lib.hardenChallenge({ key: lib.FIXTURE_KEY, flag: lib.FIXTURE_FLAG, outDir: a });
      const rb = await lib.hardenChallenge({ key: lib.FIXTURE_KEY, flag: lib.FIXTURE_FLAG, outDir: b });
      expect(ra.artifacts).toEqual(rb.artifacts);
      // Same public template + panel + wasm as the release → identical panel/wasm digests.
      expect(ra.artifacts["panel.html"].sha256).toBe(seal.artifacts["panel.html"].sha256);
      expect(ra.artifacts["core.wasm"].sha256).toBe(seal.artifacts["core.wasm"].sha256);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  }, 180_000);

  it("fixture: stripping BLA's cognitive-armor corpus breaks the unlock (anti-strip)", async () => {
    await withFixture(async (lib, _bundle, run) => {
      const path = join(run, "vault.cjs");
      const src = readFileSync(path, "utf8");
      const stripped = src.replace(/const (_interlockSafetyCorpus_[0-9a-f]{4}) = \[[\s\S]*?\];/, "const $1 = [];");
      expect(stripped).not.toEqual(src);
      writeFileSync(path, stripped);
      const r = lib.runVault(run, lib.FIXTURE_KEY);
      expect(r.ok).toBe(false);
      expect(r.stdout).not.toContain(lib.FIXTURE_FLAG);
    });
  }, 180_000);

  it("hardened WASM keeps mix/seal semantics behind decoy exports; hardened panel drives stage B", async () => {
    const lib = await libP;
    const bytes = gunzipSync(readFileSync(join(HARDENED, "core.wasm.gz")));
    expect(WebAssembly.validate(bytes)).toBe(true);
    const summary = inspectWasmBinary(bytes);
    expect(summary.exportNames).toContain("mix");
    expect(summary.exportNames).toContain("seal");
    expect(summary.exportNames.length).toBeGreaterThan(2);
    const { instance } = await WebAssembly.instantiate(bytes);
    const ex = instance.exports as Record<string, (a: number, b?: number) => number>;
    for (const [a, b] of [[1, 2], [65, 0x1234], [-7, 99]]) expect(ex.mix(a, b)).toBe(lib.wasmMix(a, b));
    expect(ex.seal(42)).toBe(lib.wasmSeal(42));

    const html = readFileSync(join(HARDENED, "panel.html"), "utf8");
    expect(html.length).toBeGreaterThan(readFileSync(join(V6, "src", "panel.html"), "utf8").length * 10);
  });

  const key = process.env.CRACKME_V6_KEY;
  const flag = process.env.CRACKME_V6_FLAG;
  const h = (s: string) => createHash("sha256").update(s).digest("hex");
  const secretsMatch = !!key && !!flag && h(key) === seal.keySha256 && h(flag) === seal.flagSha256;
  it.skipIf(!secretsMatch)("release (secret-gated): key unlocks the committed bundle to the committed flag", async () => {
    const lib = await libP;
    const run = lib.prepareRunnable(HARDENED);
    try {
      expect(lib.extractFlag(lib.runVault(run, key).stdout)).toBe(flag);
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  }, 120_000);
});
