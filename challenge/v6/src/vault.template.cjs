#!/usr/bin/env node
"use strict";
/**
 * BLA CrackMe v6 — cleartext vault TEMPLATE (license entitlement gate).
 *
 * Public on purpose: the challenge is NOT "guess the algorithm", it is
 * "recover the constants and the logic from the BLA-hardened build".
 * `npm run crackme:build` fills the placeholders from maintainer secrets
 * (or the public demo fixture), then runs `hardenProject()` (== `bla harden`)
 * over vault.cjs + panel.html + core.wasm. Only the hardened output and
 * SHA-256 digests are committed; the materialized cleartext never is.
 *
 * Solve path (by design): find the 16 lane targets + panel token inside the
 * hardened vault, understand core.wasm's mix/seal, invert each lane (one key
 * byte per lane), then the flag decrypts itself.
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");

const LANE_SALT = %%LANE_SALT%%;
const LANE_TARGETS_HEX = "%%LANE_TARGETS_HEX%%";
const LANE_TARGETS = Object.freeze(
  (LANE_TARGETS_HEX.match(/.{8}/g) || []).map((h) => parseInt(h, 16) >>> 0),
);
const PANEL_TOKEN = "%%PANEL_TOKEN%%";
const FLAG_CIPHER_HEX = "%%FLAG_CIPHER_HEX%%";
const FLAG_SHA256 = "%%FLAG_SHA256%%";

/** Retired keys that print honeypot flags — punish "first greppable string" solvers. */
const HONEYPOT_KEYS = Object.freeze([
  "P4#kR9$vM2@xL7!q",
  "W9$mK3#pT7!vQ2@z",
  "A1!bC2@dE3#fG4$h",
]);

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function loadCore() {
  const bytes = fs.readFileSync(path.join(__dirname, "core.wasm"));
  return WebAssembly.instantiate(bytes).then((r) => r.instance.exports);
}

/** Stage B lives in panel.html: run its inline scripts and borrow derive(). */
function loadPanelDerive() {
  const html = fs.readFileSync(path.join(__dirname, "panel.html"), "utf8");
  const sandbox = { console: { log() {}, warn() {}, error() {} } };
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    const attrs = m[1] || "";
    if (/\bsrc\s*=/.test(attrs)) continue;
    if (/\btype\s*=\s*["']?(?!text\/javascript|module|application\/javascript)/i.test(attrs)) continue;
    try {
      vm.runInContext(m[2], sandbox, { timeout: 2000 });
    } catch (_) {
      /* hardened decoy scripts may throw outside a browser */
    }
  }
  return sandbox.__vaultPanelDerive_v6;
}

function laneTweak(i) {
  return (Math.imul(i + 1, 0x01000193) ^ LANE_SALT) | 0;
}

function decryptFlag(key) {
  const mask = crypto.createHash("sha256").update("bla-crackme-v6|" + key).digest();
  const cipher = Buffer.from(FLAG_CIPHER_HEX, "hex");
  const out = Buffer.alloc(cipher.length);
  for (let i = 0; i < cipher.length; i++) out[i] = cipher[i] ^ mask[i % mask.length];
  return out.toString("utf8");
}

function honeypotFlag(key) {
  return "FLAG{" + sha256("honeypot|" + key).slice(0, 32) + "}";
}

async function main() {
  const key = process.argv[2] || "";
  if (key.length !== LANE_TARGETS.length) {
    console.log("[vault] usage: node vault.cjs <" + LANE_TARGETS.length + "-char-key>");
    process.exit(2);
  }

  if (HONEYPOT_KEYS.includes(key)) {
    console.log("[vault] UNLOCKED? " + honeypotFlag(key));
    console.log("[vault] note: verify against the published flag SHA-256 before celebrating.");
    process.exit(0);
  }

  const { mix, seal } = await loadCore();
  if (typeof mix !== "function" || typeof seal !== "function") {
    console.log("[vault] core.wasm exports missing — refusing.");
    process.exit(1);
  }

  // Every stage runs to completion and failures fold into one bit: no
  // per-lane / per-stage oracle (a solve must come from reversing, not probing).
  let bad = 0;

  // Stage A: every key byte is sealed in its own WASM lane.
  for (let i = 0; i < key.length; i++) {
    const lane = seal(mix(key.charCodeAt(i), laneTweak(i))) >>> 0;
    bad |= (lane ^ (LANE_TARGETS[i] >>> 0)) !== 0 ? 1 : 0;
  }

  // Stage B: the hardened HTML panel must derive the entitlement token.
  const derive = loadPanelDerive();
  bad |= typeof derive !== "function" || derive(key) !== PANEL_TOKEN ? 2 : 0;

  // Stage C: the key decrypts the flag; the digest binds it to the public SEAL.
  const flag = decryptFlag(key);
  bad |= sha256(flag) !== FLAG_SHA256 ? 4 : 0;

  if (bad !== 0) {
    console.log("[vault] DENIED");
    process.exit(1);
  }
  console.log("[vault] UNLOCKED");
  console.log(flag);
}

main().catch((err) => {
  console.error("[vault] fatal:", err && err.message ? err.message : err);
  process.exit(1);
});
