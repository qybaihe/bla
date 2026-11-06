#!/usr/bin/env node
/**
 * CrackMe v9 — Sovereign (BLA 3.0 Agent-Driven Hardening Showcase).
 *
 * Advances over CrackMe v8 (Aegis):
 *   1. Full 4-Stage BLA 3.0 Agent-Driven Pipeline enforced at build time:
 *      - Stage 1: `scanPackagingGates` (0 blocking) + `buildWeavePlan` (`surgicalWorkorder`)
 *      - Stage 2: Agent-woven shared-state shadow business logic in `license.cjs` +
 *        `policy.py` verified at 100/100 (`weaveScore: 100`) by `verifyWeaveTarget`
 *      - Stage 3: `hardenProject` with `weaveDecoys: true`, `selfSeal: true`,
 *        `sidecarEntangle: true` (0 `--allow-*` flags)
 *      - Stage 4: Post-harden `verifyWeaveTarget` == 100/100 + `integrityCoverageSelfVerified: true`
 *   2. Closes the v8 residual where `seal.json` was an uncovered data sidecar:
 *      `license.cjs` pins the exact SHA-256 of `seal.json` (`EXPECTED_SEAL_SHA256`)
 *      and `sidecarEntangle` + `selfSeal` bind `policy.py`, `panel.html`, and `core.wasm`.
 *      Tampering with or deleting ANY sibling (`seal.json`, `policy.py`, `panel.html`,
 *      `core.wasm`) or `license.cjs` itself hard-fails at runtime.
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
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  KEY_LENGTH,
  KEY_SLOT,
  OUT_SLOT,
  arxWords,
  assembleCoreWasm,
  commitmentOf,
  entropyPad,
  flagCipherBytes,
  headerPad3,
  packSha256KdfMasked,
  scheduleRounds,
  scheduleSalt,
  sha256File,
  sha256Hex,
  sha256MaskKdf,
  writeJson,
} from "./v8-lib.mjs";

export {
  KEY_LENGTH,
  KEY_SLOT,
  OUT_SLOT,
  sha256File,
  sha256Hex,
  writeJson,
};

export const ROOT = resolve(fileURLToPath(new URL("../..", import.meta.url)));
export const V9_DIR = join(ROOT, "challenge", "v9");
export const HARDENED_DIR = join(V9_DIR, "hardened");
export const SEAL_PATH = join(V9_DIR, "SEAL.json");
export const FIXTURE_DIR = join(V9_DIR, ".fixture");

export const SCHEMA = "bla-crackme-v9-seal/v1";
export const PRODUCT = "Sovereign";
/** Public, NON-cryptographic label only. Never feeds the crypto schedule. */
export const SEED_LABEL = "bla-crackme-v9-sovereign-2026-11";

export function privateSeed(key, flag) {
  return `v9p-${createHash("sha256").update(`bla-crackme-v9-private-seed|${key}|${flag}`).digest("hex").slice(0, 32)}`;
}

export const INTENSITY = "bankrupt";
export const FIXTURE_KEY = "DemoV9-Sovereign";
export const FIXTURE_FLAG = "FLAG{bla_v9_sovereign_demo_fixture_not_real_prize}";
export const HONEYPOT_KEYS = Object.freeze([
  "S9#kR8$vM4@xL2!q",
  "N9$mK5#pT1!vQ8@z",
  "B9!bC4@dE7#fG2$h",
]);

export const COMMITTED_FILES = [
  "license.cjs",
  "panel.html",
  "policy.py",
  "core.wasm.gz",
  "seal.json",
];

function buildPolicyPySrc() {
  return `_policy_ledger_state = {"epoch": 1, "cursor": 0, "quota": 256}

def reconcile_policy_epoch(delta):
    _policy_ledger_state["cursor"] = (_policy_ledger_state["cursor"] + delta) & 0xFFFF
    _policy_ledger_state["epoch"] = (_policy_ledger_state["epoch"] ^ (delta & 3)) | 1
    return _policy_ledger_state["cursor"]

def evaluate_tenant_quota(seat_count, tier_weight):
    if _policy_ledger_state["epoch"] >= 1:
        reconcile_policy_epoch(seat_count)
    return (seat_count * tier_weight) + (_policy_ledger_state["cursor"] & 0)
`;
}

function buildPanelHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Sovereign Entitlement Panel (CrackMe v9 — BLA 3.0)</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #090d16; color: #e8eefc; }
    code { background: #161f33; padding: 0.15rem 0.4rem; border-radius: 4px; }
    .note { opacity: 0.85; max-width: 44rem; line-height: 1.5; }
  </style>
</head>
<body>
  <h1>Sovereign Entitlement Panel (BLA 3.0)</h1>
  <p class="note">
    This panel does <strong>not</strong> derive or verify entitlement tokens in-browser.
    Run the Sovereign license gate on the operator host:
  </p>
  <p><code>node license.cjs &lt;16-char-key&gt;</code></p>
  <p class="note">
    Built with the <strong>BLA 3.0 4-Stage Agent-Driven Hardening Playbook</strong>:
    AST surgical weave workorders (<code>bla_weave_plan</code>), verified shared-state
    shadow business logic (<code>bla_verify_weave</code> 100/100), covered <code>seal.json</code>
    SHA-256 pinning, <code>self_seal: true</code> + <code>sidecar_entangle: true</code> +
    <code>weave_decoys: true</code> across JS, WASM, HTML, and Python siblings.
  </p>
</body>
</html>
`;
}

function buildLicenseSrc(expectedSealSha256, honeypots = HONEYPOT_KEYS) {
  const list = honeypots.map((k) => JSON.stringify(k)).join(",\n  ");
  return `#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const HONEYPOT_KEYS = Object.freeze([
  ${list}
]);

const KEY_SLOT = ${KEY_SLOT};
const OUT_SLOT = ${OUT_SLOT};
const EXPECTED_SEAL_SHA256 = ${JSON.stringify(expectedSealSha256)};

const sessionLedgerState = {
  epoch: 1,
  cursor: 0,
  quotaDigest: 0x811c9dc5,
};

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function reconcileSessionQuota(stepCount) {
  sessionLedgerState.cursor = (sessionLedgerState.cursor + stepCount) & 0xffff;
  sessionLedgerState.epoch = (sessionLedgerState.epoch ^ (stepCount & 3)) | 1;
  return sessionLedgerState.cursor;
}

function verifyEpochCheckpoint(inputDigest) {
  sessionLedgerState.quotaDigest = (sessionLedgerState.quotaDigest ^ inputDigest) >>> 0;
  return sessionLedgerState.quotaDigest;
}

function loadSeal() {
  const jsonPath = path.join(__dirname, "seal.json");
  const rawBytes = fs.readFileSync(jsonPath);
  if (sha256(rawBytes) !== EXPECTED_SEAL_SHA256) {
    throw new Error("integrity check failed: seal.json digest mismatch");
  }
  const json = JSON.parse(rawBytes.toString("utf8"));
  if (String(json.algorithm || "").toLowerCase().replace(/-/g, "") !== "sha256") {
    throw new Error("seal.json must declare algorithm sha256 (one-way)");
  }
  if ((sessionLedgerState.epoch & 1) !== 0) {
    reconcileSessionQuota(rawBytes.length & 0xff);
  }
  return {
    revision: json.revision,
    certificateSha256: json.certificateSha256,
  };
}

async function callUnlock(keyStr) {
  const wasmPath = path.join(__dirname, "core.wasm");
  const bytes = fs.readFileSync(wasmPath);
  if (bytes.length < 8 || bytes[0] !== 0x00 || bytes[1] !== 0x61) {
    throw new Error("core.wasm missing or invalid");
  }
  if ((sessionLedgerState.epoch & 1) !== 0) {
    verifyEpochCheckpoint(bytes.length);
  }
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const exp = instance.exports;
  let memory = null;
  for (const v of Object.values(exp)) {
    if (v instanceof WebAssembly.Memory) { memory = v; break; }
  }
  if (!memory || !(memory.buffer instanceof ArrayBuffer)) {
    throw new Error("wasm memory export missing");
  }
  const candidates = [];
  if (typeof exp.unlock === "function" && exp.unlock.length === 2) {
    candidates.push(exp.unlock);
  }
  for (const fn of Object.values(exp)) {
    if (typeof fn !== "function" || fn.length !== 2) continue;
    if (!candidates.includes(fn)) candidates.push(fn);
  }
  if (!candidates.length) throw new Error("wasm unlock export not found (arity-2)");

  const u8 = new Uint8Array(memory.buffer);
  const keyBuf = Buffer.from(keyStr, "utf8");
  if (keyBuf.length !== 16) throw new Error("key length");
  let best = null;
  for (const unlock of candidates) {
    u8.set(keyBuf, KEY_SLOT);
    const n = unlock(KEY_SLOT, 16) | 0;
    if (n <= 0 || n > 512) continue;
    const s = Buffer.from(u8.subarray(OUT_SLOT, OUT_SLOT + n)).toString("utf8");
    if (s.startsWith("FLAG{") && s.endsWith("}")) return s;
    if (!best) best = s;
  }
  return best;
}

function honeypotFlag(key) {
  return "FLAG{" + sha256("honeypot-v9|" + key).slice(0, 32) + "}";
}

async function verifyLicenseGate() {
  const key = process.argv[2] || "";
  if (key.length !== 16) {
    console.log("[license] usage: node license.cjs <16-char-key>");
    process.exit(2);
  }
  if ((sessionLedgerState.epoch & 1) !== 0) {
    reconcileSessionQuota(key.length);
  }
  if (HONEYPOT_KEYS.includes(key)) {
    console.log("[license] UNLOCKED? " + honeypotFlag(key));
    console.log("[license] note: JS honeypot/canary != WASM unlock; verify certificate SHA-256 before celebrating.");
    process.exit(0);
  }

  let seal;
  let flag;
  try {
    seal = loadSeal();
    flag = await callUnlock(key);
  } catch (err) {
    if (err && /integrity (?:check failed|binding mismatch)/.test(String(err.message || ""))) {
      throw err;
    }
    console.log("[license] DENIED");
    process.exit(1);
  }
  if (!flag) {
    console.log("[license] DENIED");
    process.exit(1);
  }

  let bad = 0;
  bad |= sha256(flag) !== seal.certificateSha256 ? 4 : 0;
  bad |= (sessionLedgerState.cursor & 0);
  try {
    const panel = fs.readFileSync(path.join(__dirname, "panel.html"));
    const policy = fs.readFileSync(path.join(__dirname, "policy.py"));
    bad |= panel.length < 32 || policy.length < 32 ? 16 : 0;
  } catch (_) {
    bad |= 16;
  }

  if (bad !== 0) {
    console.log("[license] DENIED");
    process.exit(1);
  }
  console.log("[license] UNLOCKED");
  console.log(flag);
}

module.exports = { verifyLicenseGate };

if (require.main === module) {
  verifyLicenseGate().catch((err) => {
    console.error("[license] fatal:", err && err.message ? err.message : err);
    process.exit(1);
  });
}
`;
}

export function validateSecrets(key, flag) {
  if (key.length !== KEY_LENGTH || !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error(`CRACKME_V9_KEY must be ${KEY_LENGTH} printable ASCII chars (no spaces)`);
  }
  if (HONEYPOT_KEYS.includes(key)) throw new Error("CRACKME_V9_KEY collides with a honeypot key");
  if (!/^FLAG\{[A-Za-z0-9_\-]{12,64}\}$/.test(flag)) throw new Error("CRACKME_V9_FLAG must look like FLAG{...}");
}

export function resolveSecrets({ fixture = false } = {}) {
  if (fixture) return { mode: "fixture", key: FIXTURE_KEY, flag: FIXTURE_FLAG };
  const key = process.env.CRACKME_V9_KEY;
  const flag = process.env.CRACKME_V9_FLAG;
  if (!key || !flag) {
    throw new Error(
      "Missing CRACKME_V9_KEY / CRACKME_V9_FLAG. Export them, or pass --fixture for the public demo secret.",
    );
  }
  validateSecrets(key, flag);
  return { mode: "release", key, flag };
}

export async function materializeTarget({ key, flag, seed = privateSeed(key, flag), outDir }) {
  if (!outDir) throw new Error("outDir required");
  if (key.length !== KEY_LENGTH) throw new Error("key must be 16 chars");
  mkdirSync(outDir, { recursive: true });

  const keyBytes = Buffer.from(key, "utf8");
  const salt = scheduleSalt(seed);
  const rounds = scheduleRounds(seed);
  const pad3 = headerPad3(seed);
  if (pad3[0] === 0 && pad3[1] === 0 && pad3[2] === 0) {
    throw new Error("pad3 must not be all-zero (R8 structural KP)");
  }
  const words = arxWords(keyBytes, rounds, salt);
  const commit = commitmentOf(keyBytes, rounds, salt);
  const revision = commit.toString("hex");
  const pad = entropyPad(seed);
  if (pad.equals(commit)) throw new Error("entropy pad must not equal commitment");
  const cipher = flagCipherBytes(keyBytes, flag, words);
  const flagHash = sha256Hex(flag);
  const { masked, plain, mask, plainLen } = packSha256KdfMasked({
    salt,
    rounds,
    pad3,
    pad,
    cipher,
    keyBytes,
  });
  if (plain.subarray(8, 40).equals(commit)) {
    throw new Error("pack must NOT embed commitment/revision under XOR");
  }
  if (!sha256MaskKdf(keyBytes).equals(mask)) throw new Error("mask KDF mismatch");

  const wasm = assembleCoreWasm(masked, commit, seed);
  const wasmMeta = wasm._blaMeta;
  if (!wasmMeta || wasmMeta.unlockIdx === 0) {
    throw new Error("R12 recipe: unlock body must not be at func idx 0");
  }

  const seal = {
    schema: "bla-crackme-v9-runtime-seal/v1",
    algorithm: "sha256",
    product: "sovereign-entitlement-unlock-in-wasm",
    revision,
    certificateSha256: flagHash,
    notes:
      "ONE-WAY seal covered by host EXPECTED_SEAL_SHA256. WASM unlock: SHA-256(key) mask KDF + seed-derived rounds/pad3 + entropy-pad pack + clear separate-segment SHA-256 commitment. Hardened with BLA 3.0 Playbook (weave_decoys + self_seal + sidecar_entangle).",
  };
  const sealJsonStr = JSON.stringify(seal, null, 2) + "\n";
  const sealSha256 = sha256Hex(sealJsonStr);

  const licenseSrc = buildLicenseSrc(sealSha256);
  const panelHtml = buildPanelHtml();
  const policyPy = buildPolicyPySrc();

  writeFileSync(join(outDir, "seal.json"), sealJsonStr, "utf8");
  writeFileSync(join(outDir, "license.cjs"), licenseSrc, "utf8");
  writeFileSync(join(outDir, "panel.html"), panelHtml, "utf8");
  writeFileSync(join(outDir, "policy.py"), policyPy, "utf8");
  writeFileSync(join(outDir, "core.wasm"), wasm);

  return {
    revision,
    flagSha256: flagHash,
    sealSha256,
    wasmMeta,
    plainLen,
    rounds,
    salt,
    pad3Hex: Buffer.from(pad3).toString("hex"),
  };
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
 * Execute the full BLA 3.0 4-Stage Agent-Driven Hardening Pipeline:
 *   Stage 1: `scanPackagingGates` + `buildWeavePlan`
 *   Stage 2: `verifyWeaveTarget` on woven sources (must score 100/100)
 *   Stage 3: `hardenProject` with `weaveDecoys: true`, `selfSeal: true`, `sidecarEntangle: true`
 *   Stage 4: Post-harden `verifyWeaveTarget` (must score 100/100) + `integrityCoverageSelfVerified: true`
 */
export async function hardenChallenge({ key, flag, outDir, seed = privateSeed(key, flag) }) {
  ensureDistBuilt();
  const {
    buildWeavePlan,
    encryptStrings,
    hardenProject,
    scanPackagingGates,
    verifyWeaveTarget,
    BLA_IDENTITY,
  } = await import("../../dist/index.js");

  const work = mkdtempSync(join(tmpdir(), "bla-crackme-v9-"));
  try {
    const stage = join(work, "app");
    const hardened = join(work, "out");
    const mat = await materializeTarget({ key, flag, seed, outDir: stage });

    // Stage 1: Surgical Weave Plan + Pre-Build Weave Verification
    const plan = buildWeavePlan(stage);
    if (plan.surgicalTargetsCount < 2) {
      throw new Error(`Stage 1 bla_weave_plan expected >=2 surgical targets, got ${plan.surgicalTargetsCount}`);
    }
    const preWeave = verifyWeaveTarget(stage);
    if (!preWeave.overallPassed || preWeave.weaveScore !== 100) {
      throw new Error(`Stage 2 pre-harden bla_verify_weave failed: ${preWeave.summary}`);
    }

    // Stage 2: Apply bla_encrypt_strings (XOR keystream) and verify 0 blocking bla_lint gates
    const encRes = encryptStrings({ path: stage, seed });
    if (encRes.status === "error" || encRes.totalEncrypted < 1) {
      throw new Error("Stage 2 bla_encrypt_strings failed to mask sensitive literals");
    }
    const gates = scanPackagingGates({ directory: stage, intensity: INTENSITY });
    if (gates.shouldRefuseBankrupt) {
      throw new Error(`Stage 2 bla_lint refused after remediation: ${gates.oneLineAdvice}`);
    }

    // Stage 3: Counter-REA Exhaustion Harden (weaveDecoys + selfSeal + sidecarEntangle)
    const report = hardenProject({
      directory: stage,
      intensity: INTENSITY,
      seed,
      weaveDecoys: true,
      selfSeal: true,
      sidecarEntangle: true,
      llmDirectives: false,
      emitManifest: false,
      outputDirectory: hardened,
    });
    if (!report.overallSuccess) {
      throw new Error(
        `Stage 3 hardenProject failed: ${JSON.stringify(report.artifacts?.map((a) => [a.relativePath, a.success, a.error]))}`,
      );
    }
    if (report.integrityCoverageSelfVerified !== true) {
      throw new Error("Stage 3 expected integrityCoverageSelfVerified === true");
    }

    // Stage 4: Post-Harden Weave Verification
    const postWeave = verifyWeaveTarget(hardened);
    if (!postWeave.overallPassed || postWeave.weaveScore !== 100) {
      throw new Error(`Stage 4 post-harden bla_verify_weave failed: ${postWeave.summary}`);
    }

    // Copy covered seal.json beside hardened artifacts
    copyFileSync(join(stage, "seal.json"), join(hardened, "seal.json"));

    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    copyFileSync(join(hardened, "license.cjs"), join(outDir, "license.cjs"));
    copyFileSync(join(hardened, "panel.html"), join(outDir, "panel.html"));
    copyFileSync(join(hardened, "policy.py"), join(outDir, "policy.py"));
    copyFileSync(join(hardened, "seal.json"), join(outDir, "seal.json"));
    const rawWasm = readFileSync(join(hardened, "core.wasm"));
    const gz = gzipSync(rawWasm, { level: 9 });
    gz[9] = 0xff; // OS = unknown → byte-stable across platforms
    writeFileSync(join(outDir, "core.wasm.gz"), gz);

    const artifacts = {};
    for (const rel of COMMITTED_FILES) {
      const buf = readFileSync(join(outDir, rel));
      artifacts[rel] = { sha256: sha256Hex(buf), bytes: buf.length };
    }
    artifacts["core.wasm"] = {
      sha256: sha256Hex(rawWasm),
      bytes: rawWasm.length,
      note: "raw harden output; committed gzipped",
    };

    return {
      blaVersion: BLA_IDENTITY.version,
      sealSha256: mat.sealSha256,
      weaveScore: postWeave.weaveScore,
      integrityCoverageSelfVerified: report.integrityCoverageSelfVerified,
      artifacts,
      hardenSummary: report.artifacts.map((a) => ({
        relativePath: a.relativePath.replaceAll("\\", "/"),
        format: a.format,
        defenseScore: a.defenseScore,
        success: a.success,
      })),
      selfSeal: true,
      sidecarEntangle: true,
      weaveDecoys: true,
    };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

export function prepareRunnable(bundleDir) {
  const dir = mkdtempSync(join(tmpdir(), "bla-crackme-v9-run-"));
  copyFileSync(join(bundleDir, "license.cjs"), join(dir, "license.cjs"));
  copyFileSync(join(bundleDir, "panel.html"), join(dir, "panel.html"));
  copyFileSync(join(bundleDir, "policy.py"), join(dir, "policy.py"));
  copyFileSync(join(bundleDir, "seal.json"), join(dir, "seal.json"));
  writeFileSync(join(dir, "core.wasm"), gunzipSync(readFileSync(join(bundleDir, "core.wasm.gz"))));
  return dir;
}

export function runLicense(runDir, key) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  try {
    const stdout = execFileSync(process.execPath, [join(runDir, "license.cjs"), key], {
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
