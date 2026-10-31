/**
 * CrackMe v6 (harden-native) shared helpers.
 *
 * Secrets model: the authorization key + FLAG come from CRACKME_V6_KEY /
 * CRACKME_V6_FLAG (maintainer env or GitHub Actions secrets). Without them only
 * the public demo fixture can be built. Plaintext key/flag never enter git:
 * the repo holds the public template, the hardened output and SHA-256 digests.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

export const ROOT = resolve(fileURLToPath(new URL("../..", import.meta.url)));
export const V6_DIR = join(ROOT, "challenge", "v6");
export const SRC_DIR = join(V6_DIR, "src");
export const HARDENED_DIR = join(V6_DIR, "hardened");
export const SEAL_PATH = join(V6_DIR, "SEAL.json");
export const FIXTURE_DIR = join(V6_DIR, ".fixture");

export const SCHEMA = "bla-crackme-v6-seal/v2";
export const SEED = "bla-crackme-v6-harden-native-2026-11";
export const INTENSITY = "bankrupt";
/** Files handed to hardenProject() — the same tree `bla harden <dir>` sees. */
export const STAGE_FILES = ["vault.cjs", "panel.html", "core.wasm"];
/** Committed outputs (core.wasm is gzipped: bankrupt WASM is ~7 MB raw). */
export const COMMITTED_FILES = ["vault.cjs", "panel.html", "core.wasm.gz"];

/** Public demo secret — exercised by CI; NOT the published prize. */
export const FIXTURE_KEY = "Demo-V6-Fixture!";
export const FIXTURE_FLAG = "FLAG{bla_v6_demo_fixture_not_the_real_prize}";
export const HONEYPOT_KEYS = ["P4#kR9$vM2@xL7!q", "W9$mK3#pT7!vQ2@z", "A1!bC2@dE3#fG4$h"];
export const KEY_LENGTH = 16;

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}
export function sha256File(path) {
  return sha256Hex(readFileSync(path));
}

export function resolveSecrets({ fixture = false } = {}) {
  if (fixture) return { mode: "fixture", key: FIXTURE_KEY, flag: FIXTURE_FLAG };
  const key = process.env.CRACKME_V6_KEY;
  const flag = process.env.CRACKME_V6_FLAG;
  if (!key || !flag) {
    throw new Error(
      "Missing CRACKME_V6_KEY / CRACKME_V6_FLAG. Export them, or pass --fixture for the public demo secret.",
    );
  }
  validateSecrets(key, flag);
  return { mode: "release", key, flag };
}

export function validateSecrets(key, flag) {
  if (key.length !== KEY_LENGTH || !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error(`CRACKME_V6_KEY must be ${KEY_LENGTH} printable ASCII chars (no spaces)`);
  }
  if (HONEYPOT_KEYS.includes(key)) throw new Error("CRACKME_V6_KEY collides with a honeypot key");
  if (!/^FLAG\{[A-Za-z0-9_\-]{12,64}\}$/.test(flag)) throw new Error("CRACKME_V6_FLAG must look like FLAG{...}");
}

// ── Reference implementations of the public template logic ───────────────
function rotl(x, r) {
  return ((x << r) | (x >>> (32 - r))) | 0;
}
export function wasmMix(a, b) {
  return rotl(Math.imul(a, 0x9e3779b1) ^ Math.imul(b, 0x85ebca6b) ^ ((a + b) | 0), 13);
}
export function wasmSeal(x) {
  return wasmMix(wasmMix(x, 0xc0ffee01 | 0), 0xbadc0ffe | 0);
}
export function laneSalt(seed = SEED) {
  return createHash("sha256").update(`${seed}|lane-salt`).digest().readInt32LE(0);
}
export function laneTweak(i, salt) {
  return (Math.imul(i + 1, 0x01000193) ^ salt) | 0;
}
export function laneTargets(key, salt) {
  return [...key].map((ch, i) => wasmSeal(wasmMix(ch.charCodeAt(0), laneTweak(i, salt))) >>> 0);
}
function fnvLane(text, basis, prime) {
  let h = basis >>> 0;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, prime) >>> 0;
    h ^= h >>> 15;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}
export function panelToken(key) {
  const text = `panel|${key}`;
  return fnvLane(text, 0x811c9dc5, 0x01000193) + fnvLane([...text].reverse().join(""), 0x9e3779b9, 0x85ebca6b);
}
export function flagCipherHex(key, flag) {
  const mask = createHash("sha256").update(`bla-crackme-v6|${key}`).digest();
  const plain = Buffer.from(flag, "utf8");
  return Buffer.from(plain.map((b, i) => b ^ mask[i % mask.length])).toString("hex");
}

/** Fill the public template; returns the cleartext vault source (never committed). */
export function materializeVault({ key, flag, seed = SEED }) {
  const salt = laneSalt(seed);
  const hex8 = (n) => (n >>> 0).toString(16).padStart(8, "0");
  const template = readFileSync(join(SRC_DIR, "vault.template.cjs"), "utf8");
  const out = template
    .replaceAll("%%LANE_SALT%%", String(salt))
    .replaceAll("%%LANE_TARGETS_HEX%%", laneTargets(key, salt).map(hex8).join(""))
    .replaceAll("%%PANEL_TOKEN%%", panelToken(key))
    .replaceAll("%%FLAG_CIPHER_HEX%%", flagCipherHex(key, flag))
    .replaceAll("%%FLAG_SHA256%%", sha256Hex(flag));
  if (out.includes("%%")) throw new Error("unfilled placeholder in vault template");
  return out;
}

export function ensureDistBuilt() {
  if (!existsSync(join(ROOT, "dist", "engine", "harden.js"))) {
    execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build"], {
      cwd: ROOT,
      stdio: "inherit",
      shell: process.platform === "win32",
    });
  }
}

/**
 * Stage cleartext in a temp dir and run the real harden pipeline over it.
 * Writes vault.cjs / panel.html / core.wasm.gz to outDir; returns digests.
 */
export async function hardenChallenge({ key, flag, outDir, seed = SEED }) {
  ensureDistBuilt();
  const { hardenProject } = await import(pathToFileURL(join(ROOT, "dist", "engine", "harden.js")).href);
  const { BLA_IDENTITY } = await import(pathToFileURL(join(ROOT, "dist", "identity.js")).href);
  const work = mkdtempSync(join(tmpdir(), "bla-crackme-v6-"));
  try {
    const stage = join(work, "app");
    const hardened = join(work, "out");
    mkdirSync(stage, { recursive: true });
    writeFileSync(join(stage, "vault.cjs"), materializeVault({ key, flag, seed }), "utf8");
    copyFileSync(join(SRC_DIR, "panel.html"), join(stage, "panel.html"));
    copyFileSync(join(SRC_DIR, "core.wasm"), join(stage, "core.wasm"));

    const report = hardenProject({
      directory: stage,
      intensity: INTENSITY,
      seed,
      llmDirectives: false,
      emitManifest: false,
      outputDirectory: hardened,
    });
    if (!report.overallSuccess) {
      throw new Error(`hardenProject failed: ${JSON.stringify(report.artifacts?.map((a) => [a.relativePath, a.success, a.error]))}`);
    }

    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    copyFileSync(join(hardened, "vault.cjs"), join(outDir, "vault.cjs"));
    copyFileSync(join(hardened, "panel.html"), join(outDir, "panel.html"));
    const rawWasm = readFileSync(join(hardened, "core.wasm"));
    // Fixed mtime/OS-free gzip header → byte-stable across platforms.
    const gz = gzipSync(rawWasm, { level: 9 });
    gz[9] = 0xff; // OS = unknown
    writeFileSync(join(outDir, "core.wasm.gz"), gz);

    const artifacts = {};
    for (const rel of COMMITTED_FILES) {
      const buf = readFileSync(join(outDir, rel));
      artifacts[rel] = { sha256: sha256Hex(buf), bytes: buf.length };
    }
    artifacts["core.wasm"] = { sha256: sha256Hex(rawWasm), bytes: rawWasm.length, note: "raw harden output; committed gzipped" };

    return {
      blaVersion: BLA_IDENTITY.version,
      artifacts,
      hardenSummary: report.artifacts.map((a) => ({
        relativePath: a.relativePath.replaceAll("\\", "/"),
        format: a.format,
        defenseScore: a.defenseScore,
        success: a.success,
      })),
    };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** Copy a hardened bundle to a temp dir, gunzip core.wasm, return the dir. */
export function prepareRunnable(bundleDir) {
  const dir = mkdtempSync(join(tmpdir(), "bla-crackme-v6-run-"));
  copyFileSync(join(bundleDir, "vault.cjs"), join(dir, "vault.cjs"));
  copyFileSync(join(bundleDir, "panel.html"), join(dir, "panel.html"));
  writeFileSync(join(dir, "core.wasm"), gunzipSync(readFileSync(join(bundleDir, "core.wasm.gz"))));
  return dir;
}

export function runVault(runDir, key) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  try {
    const stdout = execFileSync(process.execPath, [join(runDir, "vault.cjs"), key], {
      encoding: "utf8",
      env,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000,
    });
    return { ok: true, status: 0, stdout };
  } catch (err) {
    return { ok: false, status: err.status ?? 1, stdout: String(err.stdout ?? "") + String(err.stderr ?? "") };
  }
}

export function extractFlag(text) {
  const m = String(text).match(/FLAG\{[A-Za-z0-9_\-]{12,64}\}/);
  return m ? m[0] : null;
}

export function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export function templateDigests() {
  const out = {};
  for (const rel of ["vault.template.cjs", "panel.html", "core.wasm"]) out[`src/${rel}`] = sha256File(join(SRC_DIR, rel));
  return out;
}
