#!/usr/bin/env node
/**
 * Round-12 blue: keep R8–R11 crypto + arity-2 spread + export-order shuffle;
 * scatter unlock **function body index** so it is not stably func idx 0.
 *
 * Design (no --allow-* / --wasm-preserve-exports):
 *   - unlock(keyPtr,keyLen)->outLen still runs entirely inside WASM.
 *   - Mask = SHA-256(key[16]) (one-way KDF) — NOT algebraically invertible byte mix.
 *   - Pack plain: salt||rounds||pad3||entropyPad[32]||clen||cipher
 *     entropyPad is seed-derived random — NOT seal.revision / commitment.
 *   - pad3 is seed-derived random (not zero); rounds is seed-derived in 32..63.
 *   - Commitment SHA-256(ARX_state) lives in a **separate clear data segment**
 *     (not under the XOR mask). seal.revision = hex(commitment).
 *   - No plaintext XOR-mask sidecar; no JS AES / hydrate / panel derive / lanes.
 *   - Arity-2 hygiene (R10/R12): engine spreads bankrupt decoy aliases across
 *     exported **arity-2** indices (arity-1 seal does not burn alias budget).
 *   - Export-order shuffle (R11): cleartext + bankrupt shuffle; host resolves by
 *     arity + FLAG{…} + certificateSha256 — never by export order / bare name.
 *   - Unlock body index scatter (R12): seed-derived pad funcs prepended so real
 *     unlock is NOT at func idx 0 (body index, not just export order).
 *   - JS honeypot keys are host-only canaries (UNLOCKED? decoy); they do NOT
 *     call WASM unlock and do NOT match seal.certificateSha256.
 *
 * Rebuild: node materialize.mjs
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

export const ROOT = resolve(fileURLToPath(new URL("../..", import.meta.url)));
export const V8_DIR = join(ROOT, "challenge", "v8");
export const HARDENED_DIR = join(V8_DIR, "hardened");
export const SEAL_PATH = join(V8_DIR, "SEAL.json");
export const FIXTURE_DIR = join(V8_DIR, ".fixture");

export const SCHEMA = "bla-crackme-v8-seal/v2";
export const PRODUCT = "Aegis";
/** Public, NON-cryptographic label only. Never feeds the crypto schedule. */
export const SEED_LABEL = "bla-crackme-v8-aegis-2026-11";

/**
 * Private materialization + harden seed, derived from release secrets so it is
 * never published (CrackMe v8 red team: a public seed re-derives salt/rounds/
 * pad3/entropy pad and strips the XOR mask without reversing WASM).
 */
export function privateSeed(key, flag) {
  return `v8p-${createHash("sha256").update(`bla-crackme-v8-private-seed|${key}|${flag}`).digest("hex").slice(0, 32)}`;
}
export const INTENSITY = "bankrupt";
export const FIXTURE_KEY = "DemoV8-AegisKey!";
export const FIXTURE_FLAG = "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}";
export const HONEYPOT_KEYS = Object.freeze([
  "P8#kR9$vM2@xL7!q",
  "W8$mK3#pT7!vQ2@z",
  "A8!bC2@dE3#fG4$h",
]);
export const KEY_LENGTH = 16;
/** Committed outputs (core.wasm is gzipped: bankrupt WASM is ~7 MB raw). */
export const COMMITTED_FILES = ["license.cjs", "panel.html", "core.wasm.gz", "seal.json"];

/** Fallback only — prefer scheduleRounds(seed). */
export const ROUNDS = 40;
export const KEY_SLOT = 2048;
export const OUT_SLOT = 4096;
export const WORK = 8192;
export const MASK_TMP = 8600;
export const HASH_IN = 8700;
export const HASH_OUT = 8800;
export const SHA_BLK = 14000;
export const SHA_W = 14064;
export const SHA_ST = 14400;
/** Clear commitment (not XOR-masked) — separate from data@0 pack. */
export const COMMIT_CLEAR = 12288;
export const K_OFF = 16384;
export const IV_OFF = K_OFF + 256;

export function sha256Hex(v) {
  return createHash("sha256").update(v).digest("hex");
}
function sha256Buf(v) {
  return createHash("sha256").update(v).digest();
}
function rotl(x, r) {
  return ((x << r) | (x >>> (32 - r))) | 0;
}
function packWordBuf(buf, start) {
  let w = 0;
  for (let i = 0; i < 4; i++) w = (w << 8) | buf[start + i];
  return w | 0;
}

export function scheduleSalt(seed) {
  return sha256Buf(`${seed}|v8-schedule`).readInt32LE(0);
}

/** Seed-derived rounds in 32..63 — avoids fixed rounds=40 structural KP on mask[4]. */
export function scheduleRounds(seed) {
  return 32 + (sha256Buf(`${seed}|v8-rounds`)[0] & 31);
}

/** Seed-derived 3-byte header pad — closes R8 zero-pad3 KP on mask[5..7]. */
export function headerPad3(seed) {
  return sha256Buf(`${seed}|v8-header-pad3`).subarray(0, 3);
}

/** Seed-derived entropy pad — public-looking bytes that are NOT the commitment. */
export function entropyPad(seed) {
  return sha256Buf(`${seed}|v8-entropy-pad-not-revision`);
}

/**
 * One-way mask KDF: SHA-256(key[16]) → 32 bytes.
 * Closes R7 algebraic invert of keyDependentMask.
 */
export function sha256MaskKdf(keyBytes) {
  if (keyBytes.length !== 16) throw new Error("key must be 16 bytes");
  return sha256Buf(keyBytes);
}

export function arxWords(keyBytes, rounds = ROUNDS, salt = scheduleSalt()) {
  if (keyBytes.length !== 16) throw new Error("key must be 16 bytes");
  let a = packWordBuf(keyBytes, 0);
  let b = packWordBuf(keyBytes, 4);
  let c = packWordBuf(keyBytes, 8);
  let d = packWordBuf(keyBytes, 12);
  for (let r = 0; r < rounds; r++) {
    const k = (Math.imul(r + 1, 0x9e3779b9) ^ salt) | 0;
    a = (a + b + k) | 0;
    b = rotl(b ^ a, 7);
    c = (c + d + rotl(k, 11)) | 0;
    d = rotl(d ^ c, 9);
    a ^= c;
    b ^= d;
    const t = a;
    a = b;
    b = c;
    c = d;
    d = t;
  }
  return [a | 0, b | 0, c | 0, d | 0];
}

export function arxStateBytes(keyBytes, rounds = ROUNDS, salt = scheduleSalt()) {
  const words = arxWords(keyBytes, rounds, salt);
  const out = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) out.writeUInt32BE(words[i] >>> 0, i * 4);
  return out;
}

export function commitmentOf(keyBytes, rounds = ROUNDS, salt = scheduleSalt()) {
  return sha256Buf(arxStateBytes(keyBytes, rounds, salt));
}

export function flagCipherBytes(keyBytes, flag, words) {
  const plain = Buffer.from(flag, "utf8");
  const out = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) {
    const w = words[i % 4] >>> 0;
    const ks = ((w >>> (8 * ((i >> 2) % 4))) & 0xff) ^ keyBytes[i % 16];
    out[i] = plain[i] ^ ks;
  }
  return out;
}

/** Pack: salt||rounds||pad3||entropyPad[32]||clen||cipher — commitment NOT in pack. */
export function packSha256KdfMasked({ salt, rounds, pad3, pad, cipher, keyBytes }) {
  if (pad.length !== 32) throw new Error("entropy pad must be 32 bytes");
  if (!pad3 || pad3.length !== 3) throw new Error("pad3 must be 3 bytes");
  const plain = Buffer.alloc(42 + cipher.length);
  plain.writeInt32LE(salt | 0, 0);
  plain[4] = rounds & 0xff;
  plain[5] = pad3[0];
  plain[6] = pad3[1];
  plain[7] = pad3[2];
  pad.copy(plain, 8);
  plain.writeUInt16LE(cipher.length, 40);
  cipher.copy(plain, 42);
  const mask = sha256MaskKdf(keyBytes);
  const masked = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) masked[i] = plain[i] ^ mask[i % 32];
  return { masked, plain, mask, plainLen: plain.length };
}

function uleb(v) {
  const out = [];
  v >>>= 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return out;
}
function section(id, body) {
  return [id, ...uleb(body.length), ...body];
}
function name(s) {
  const u = [...Buffer.from(s)];
  return [...uleb(u.length), ...u];
}
function iconst(v) {
  v |= 0;
  const out = [0x41];
  while (true) {
    let b = v & 0x7f;
    v >>= 7;
    if ((v === 0 && (b & 0x40) === 0) || (v === -1 && (b & 0x40) !== 0)) {
      out.push(b);
      break;
    }
    out.push(b | 0x80);
  }
  return out;
}

const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const SHA_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/** Internal sha256_16(inPtr, outPtr) — hashes exactly 16 bytes → 32. */
function buildSha256Body() {
  const L = {
    i: 2, t1: 3, t2: 4, a: 5, b: 6, c: 7, d: 8, e: 9, f: 10, g: 11, h: 12,
    s0: 13, s1: 14, maj: 15, ch: 16, tmp: 17, w: 18,
  };
  const nLocals = 17;
  const b = [];
  b.push(1, nLocals, 0x7f);

  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(64), 0x4f, 0x0d, 1);
  b.push(...iconst(SHA_BLK), 0x20, L.i, 0x6a, ...iconst(0), 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(16), 0x4f, 0x0d, 1);
  b.push(...iconst(SHA_BLK), 0x20, L.i, 0x6a);
  b.push(0x20, 0, 0x20, L.i, 0x6a, 0x2d, 0x00, 0x00);
  b.push(0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  b.push(...iconst(SHA_BLK + 16), ...iconst(0x80), 0x3a, 0x00, 0x00);
  b.push(...iconst(SHA_BLK + 63), ...iconst(0x80), 0x3a, 0x00, 0x00);

  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(16), 0x4f, 0x0d, 1);
  b.push(...iconst(0), 0x21, L.w);
  for (let j = 0; j < 4; j++) {
    b.push(0x20, L.w, ...iconst(8), 0x74);
    b.push(...iconst(SHA_BLK), 0x20, L.i, ...iconst(4), 0x6c, ...iconst(j), 0x6a, 0x6a, 0x2d, 0x00, 0x00);
    b.push(0x72, 0x21, L.w);
  }
  b.push(...iconst(SHA_W), 0x20, L.i, ...iconst(2), 0x74, 0x6a, 0x20, L.w, 0x36, 0x02, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  b.push(...iconst(16), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(64), 0x4f, 0x0d, 1);
  const loadW = (immOff, dest) => {
    b.push(
      ...iconst(SHA_W), 0x20, L.i, ...iconst(immOff), 0x6a, ...iconst(2), 0x74, 0x6a,
      0x28, 0x02, 0x00, 0x21, dest,
    );
  };
  loadW(-15, L.tmp);
  b.push(0x20, L.tmp, ...iconst(7), 0x76, 0x20, L.tmp, ...iconst(25), 0x74, 0x72);
  b.push(0x20, L.tmp, ...iconst(18), 0x76, 0x20, L.tmp, ...iconst(14), 0x74, 0x72);
  b.push(0x73);
  b.push(0x20, L.tmp, ...iconst(3), 0x76, 0x73, 0x21, L.s0);
  loadW(-2, L.tmp);
  b.push(0x20, L.tmp, ...iconst(17), 0x76, 0x20, L.tmp, ...iconst(15), 0x74, 0x72);
  b.push(0x20, L.tmp, ...iconst(19), 0x76, 0x20, L.tmp, ...iconst(13), 0x74, 0x72);
  b.push(0x73);
  b.push(0x20, L.tmp, ...iconst(10), 0x76, 0x73, 0x21, L.s1);
  loadW(-16, L.w);
  loadW(-7, L.tmp);
  b.push(0x20, L.w, 0x20, L.s0, 0x6a, 0x20, L.tmp, 0x6a, 0x20, L.s1, 0x6a, 0x21, L.w);
  b.push(...iconst(SHA_W), 0x20, L.i, ...iconst(2), 0x74, 0x6a, 0x20, L.w, 0x36, 0x02, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  for (let i = 0; i < 8; i++) {
    b.push(...iconst(SHA_ST + i * 4), ...iconst(IV_OFF + i * 4), 0x28, 0x02, 0x00, 0x36, 0x02, 0x00);
  }
  const regs = [L.a, L.b, L.c, L.d, L.e, L.f, L.g, L.h];
  for (let i = 0; i < 8; i++) {
    b.push(...iconst(SHA_ST + i * 4), 0x28, 0x02, 0x00, 0x21, regs[i]);
  }

  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(64), 0x4f, 0x0d, 1);
  b.push(0x20, L.e, ...iconst(6), 0x76, 0x20, L.e, ...iconst(26), 0x74, 0x72);
  b.push(0x20, L.e, ...iconst(11), 0x76, 0x20, L.e, ...iconst(21), 0x74, 0x72);
  b.push(0x73);
  b.push(0x20, L.e, ...iconst(25), 0x76, 0x20, L.e, ...iconst(7), 0x74, 0x72);
  b.push(0x73, 0x21, L.s1);
  b.push(0x20, L.e, 0x20, L.f, 0x71);
  b.push(0x20, L.e, ...iconst(-1), 0x73, 0x20, L.g, 0x71);
  b.push(0x73, 0x21, L.ch);
  b.push(0x20, L.h, 0x20, L.s1, 0x6a, 0x20, L.ch, 0x6a);
  b.push(...iconst(K_OFF), 0x20, L.i, ...iconst(2), 0x74, 0x6a, 0x28, 0x02, 0x00, 0x6a);
  b.push(...iconst(SHA_W), 0x20, L.i, ...iconst(2), 0x74, 0x6a, 0x28, 0x02, 0x00, 0x6a);
  b.push(0x21, L.t1);
  b.push(0x20, L.a, ...iconst(2), 0x76, 0x20, L.a, ...iconst(30), 0x74, 0x72);
  b.push(0x20, L.a, ...iconst(13), 0x76, 0x20, L.a, ...iconst(19), 0x74, 0x72);
  b.push(0x73);
  b.push(0x20, L.a, ...iconst(22), 0x76, 0x20, L.a, ...iconst(10), 0x74, 0x72);
  b.push(0x73, 0x21, L.s0);
  b.push(0x20, L.a, 0x20, L.b, 0x71);
  b.push(0x20, L.a, 0x20, L.c, 0x71, 0x73);
  b.push(0x20, L.b, 0x20, L.c, 0x71, 0x73, 0x21, L.maj);
  b.push(0x20, L.s0, 0x20, L.maj, 0x6a, 0x21, L.t2);
  b.push(0x20, L.g, 0x21, L.h);
  b.push(0x20, L.f, 0x21, L.g);
  b.push(0x20, L.e, 0x21, L.f);
  b.push(0x20, L.d, 0x20, L.t1, 0x6a, 0x21, L.e);
  b.push(0x20, L.c, 0x21, L.d);
  b.push(0x20, L.b, 0x21, L.c);
  b.push(0x20, L.a, 0x21, L.b);
  b.push(0x20, L.t1, 0x20, L.t2, 0x6a, 0x21, L.a);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  for (let i = 0; i < 8; i++) {
    b.push(0x20, regs[i], ...iconst(IV_OFF + i * 4), 0x28, 0x02, 0x00, 0x6a, 0x21, regs[i]);
  }
  for (let i = 0; i < 8; i++) {
    b.push(0x20, 1, ...iconst(i * 4), 0x6a, 0x20, regs[i], ...iconst(24), 0x76, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
    b.push(0x20, 1, ...iconst(i * 4 + 1), 0x6a, 0x20, regs[i], ...iconst(16), 0x76, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
    b.push(0x20, 1, ...iconst(i * 4 + 2), 0x6a, 0x20, regs[i], ...iconst(8), 0x76, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
    b.push(0x20, 1, ...iconst(i * 4 + 3), 0x6a, 0x20, regs[i], ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
  }
  b.push(0x0b);
  return b;
}

function buildUnlockBody(blobLen, shaFuncIdx) {
  const L = {
    a: 2, b: 3, c: 4, d: 5, r: 6, k: 7, t: 8, i: 9, tmp: 10,
    salt: 11, rounds: 12, clen: 13, ptr: 14, acc: 15,
  };
  const nLocals = 14;
  const b = [];
  b.push(1, nLocals, 0x7f);

  // keyLen != 16 → 0
  b.push(0x20, 1, ...iconst(16), 0x47, 0x04, 0x40, ...iconst(0), 0x0f, 0x0b);

  // mask = SHA-256(key[16]) → MASK_TMP (one-way KDF; closes R7 algebraic invert)
  b.push(0x20, 0, ...iconst(MASK_TMP), 0x10, ...uleb(shaFuncIdx));

  // unmask data@0 → WORK using MASK_TMP
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(blobLen), 0x4f, 0x0d, 1);
  b.push(0x20, L.i, 0x2d, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(31), 0x71, ...iconst(MASK_TMP), 0x6a, 0x2d, 0x00, 0x00);
  b.push(0x73, 0x21, L.tmp);
  b.push(...iconst(WORK), 0x20, L.i, 0x6a, 0x20, L.tmp, 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  // parse header (entropy pad at +8 is ignored for auth)
  b.push(...iconst(WORK), 0x28, 0x02, 0x00, 0x21, L.salt);
  b.push(...iconst(WORK + 4), 0x2d, 0x00, 0x00, 0x21, L.rounds);
  b.push(...iconst(WORK + 40), 0x2d, 0x00, 0x00);
  b.push(...iconst(WORK + 41), 0x2d, 0x00, 0x00, ...iconst(8), 0x74, 0x72);
  b.push(0x21, L.clen);

  const packAt = (localId, off) => {
    b.push(...iconst(0), 0x21, localId);
    for (let j = 0; j < 4; j++) {
      b.push(0x20, localId, ...iconst(8), 0x74);
      b.push(0x20, 0, ...iconst(off + j), 0x6a, 0x2d, 0x00, 0x00);
      b.push(0x72, 0x21, localId);
    }
  };
  packAt(L.a, 0); packAt(L.b, 4); packAt(L.c, 8); packAt(L.d, 12);

  // ARX rounds
  b.push(...iconst(0), 0x21, L.r);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.r, 0x20, L.rounds, 0x4f, 0x0d, 1);
  b.push(0x20, L.r, ...iconst(1), 0x6a, ...iconst(0x9e3779b9 | 0), 0x6c);
  b.push(0x20, L.salt, 0x73, 0x21, L.k);
  b.push(0x20, L.a, 0x20, L.b, 0x6a, 0x20, L.k, 0x6a, 0x21, L.a);
  b.push(0x20, L.b, 0x20, L.a, 0x73, ...iconst(7), 0x77, 0x21, L.b);
  b.push(0x20, L.c, 0x20, L.d, 0x6a, 0x20, L.k, ...iconst(11), 0x77, 0x6a, 0x21, L.c);
  b.push(0x20, L.d, 0x20, L.c, 0x73, ...iconst(9), 0x77, 0x21, L.d);
  b.push(0x20, L.a, 0x20, L.c, 0x73, 0x21, L.a);
  b.push(0x20, L.b, 0x20, L.d, 0x73, 0x21, L.b);
  b.push(0x20, L.a, 0x21, L.t);
  b.push(0x20, L.b, 0x21, L.a);
  b.push(0x20, L.c, 0x21, L.b);
  b.push(0x20, L.d, 0x21, L.c);
  b.push(0x20, L.t, 0x21, L.d);
  b.push(0x20, L.r, ...iconst(1), 0x6a, 0x21, L.r, 0x0c, 0, 0x0b, 0x0b);

  const storeBe = (localId, baseOff) => {
    b.push(...iconst(HASH_IN + baseOff), 0x20, localId, ...iconst(24), 0x76, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
    b.push(...iconst(HASH_IN + baseOff + 1), 0x20, localId, ...iconst(16), 0x76, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
    b.push(...iconst(HASH_IN + baseOff + 2), 0x20, localId, ...iconst(8), 0x76, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
    b.push(...iconst(HASH_IN + baseOff + 3), 0x20, localId, ...iconst(0xff), 0x71, 0x3a, 0x00, 0x00);
  };
  storeBe(L.a, 0); storeBe(L.b, 4); storeBe(L.c, 8); storeBe(L.d, 12);

  // sha256_16(HASH_IN, HASH_OUT)
  b.push(...iconst(HASH_IN), ...iconst(HASH_OUT), 0x10, ...uleb(shaFuncIdx));

  // compare HASH_OUT[32] to COMMIT_CLEAR (NOT under XOR / not seal-revision-in-pack)
  b.push(...iconst(0), 0x21, L.acc);
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(32), 0x4f, 0x0d, 1);
  b.push(...iconst(HASH_OUT), 0x20, L.i, 0x6a, 0x2d, 0x00, 0x00);
  b.push(...iconst(COMMIT_CLEAR), 0x20, L.i, 0x6a, 0x2d, 0x00, 0x00);
  b.push(0x73, 0x20, L.acc, 0x72, 0x21, L.acc);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  // mismatch → wipe + deny
  b.push(0x20, L.acc, ...iconst(0), 0x47, 0x04, 0x40);
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(blobLen), 0x4f, 0x0d, 1);
  b.push(...iconst(WORK), 0x20, L.i, 0x6a, ...iconst(0), 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(160), 0x4f, 0x0d, 1);
  b.push(...iconst(MASK_TMP), 0x20, L.i, 0x6a, ...iconst(0), 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);
  b.push(...iconst(0), 0x0f, 0x0b);

  // decrypt cipher → OUT_SLOT
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, 0x20, L.clen, 0x4f, 0x0d, 1);
  b.push(0x20, L.i, ...iconst(3), 0x71, 0x21, L.tmp);
  b.push(0x20, L.tmp, ...iconst(0), 0x46, 0x04, 0x7f, 0x20, L.a, 0x05);
  b.push(0x20, L.tmp, ...iconst(1), 0x46, 0x04, 0x7f, 0x20, L.b, 0x05);
  b.push(0x20, L.tmp, ...iconst(2), 0x46, 0x04, 0x7f, 0x20, L.c, 0x05, 0x20, L.d, 0x0b, 0x0b, 0x0b);
  b.push(0x21, L.k);
  b.push(0x20, L.i, ...iconst(2), 0x76, ...iconst(3), 0x71, ...iconst(3), 0x74, 0x21, L.t);
  b.push(0x20, L.k, 0x20, L.t, 0x76, ...iconst(0xff), 0x71, 0x21, L.tmp);
  b.push(0x20, 0, 0x20, L.i, ...iconst(15), 0x71, 0x6a, 0x2d, 0x00, 0x00);
  b.push(0x20, L.tmp, 0x73, 0x21, L.tmp);
  b.push(...iconst(WORK + 42), 0x20, L.i, 0x6a, 0x2d, 0x00, 0x00);
  b.push(0x20, L.tmp, 0x73, 0x21, L.tmp);
  b.push(...iconst(OUT_SLOT), 0x20, L.i, 0x6a, 0x20, L.tmp, 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  // wipe scratch
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(blobLen), 0x4f, 0x0d, 1);
  b.push(...iconst(WORK), 0x20, L.i, 0x6a, ...iconst(0), 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);
  b.push(...iconst(0), 0x21, L.i);
  b.push(0x02, 0x40, 0x03, 0x40);
  b.push(0x20, L.i, ...iconst(160), 0x4f, 0x0d, 1);
  b.push(...iconst(MASK_TMP), 0x20, L.i, 0x6a, ...iconst(0), 0x3a, 0x00, 0x00);
  b.push(0x20, L.i, ...iconst(1), 0x6a, 0x21, L.i, 0x0c, 0, 0x0b, 0x0b);

  b.push(0x20, L.clen, 0x0b);
  return b;
}

export function schedulePadCount(seed) {
  // 3..7 pad funcs before core — unlock body index is never 0.
  return 3 + (sha256Buf(`${seed}|v8-func-pad-count`)[0] % 5);
}

export function assembleCoreWasm(masked, commitClear, seed) {
  const blob = Buffer.from(masked);
  const N = blob.length;
  if (commitClear.length !== 32) throw new Error("commitClear must be 32 bytes");

  const kPayload = Buffer.alloc(256 + 32);
  for (let i = 0; i < 64; i++) kPayload.writeInt32LE(SHA_K[i] | 0, i * 4);
  for (let i = 0; i < 8; i++) kPayload.writeInt32LE(SHA_IV[i] | 0, 256 + i * 4);

  const padCount = schedulePadCount(seed);
  // Type indices (stable):
  //   0 = arity-2 (i32,i32)->i32  — pads / unlock / mix / decoyA / decoyB
  //   1 = arity-1 (i32)->i32      — seal
  //   2 = arity-2 void (i32,i32)  — sha256_16
  const typeSec = section(1, [
    3,
    0x60, 2, 0x7f, 0x7f, 1, 0x7f, // 0 arity-2
    0x60, 1, 0x7f, 1, 0x7f,       // 1 seal
    0x60, 2, 0x7f, 0x7f, 0,       // 2 sha256_16
  ]);

  // Func layout: [pad0..padN-1][unlock][mix][seal][sha][decoyA][decoyB]
  const unlockIdx = padCount;
  const mixIdx = padCount + 1;
  const sealIdx = padCount + 2;
  const shaIdx = padCount + 3;
  const decoyAIdx = padCount + 4;
  const decoyBIdx = padCount + 5;
  const totalFuncs = padCount + 6;
  if (unlockIdx === 0) throw new Error("unlock must not be at func idx 0");

  const funcTypeIds = [];
  for (let i = 0; i < padCount; i++) funcTypeIds.push(0); // arity-2 pads
  funcTypeIds.push(0, 0, 1, 2, 0, 0); // unlock, mix, seal, sha, decoyA, decoyB
  const funcSec = section(3, [totalFuncs, ...funcTypeIds]);
  const memSec = section(5, [1, 0, 2]);

  // Export a few pads (host-visible arity-2 noise) + unlock/mix/decoys/seal/memory.
  // R11: seed-shuffle export order so unlock is NOT first among arity-2.
  // Host must resolve by arity + FLAG shape + certificateSha256 (not order/name).
  const exportEntries = [];
  // Export min(3, padCount) pads so alias spread / first-hit noise includes them.
  const exportedPads = Math.min(3, padCount);
  for (let i = 0; i < exportedPads; i++) {
    exportEntries.push([...name(`pad${i}`), 0x00, ...uleb(i)]);
  }
  exportEntries.push(
    [...name("unlock"), 0x00, ...uleb(unlockIdx)],
    [...name("mix"), 0x00, ...uleb(mixIdx)],
    [...name("decoyA"), 0x00, ...uleb(decoyAIdx)],
    [...name("decoyB"), 0x00, ...uleb(decoyBIdx)],
    [...name("seal"), 0x00, ...uleb(sealIdx)],
    [...name("memory"), 0x02, 0],
  );
  const exportCount = exportEntries.length;
  // Deterministic Fisher–Yates from seed (independent of func indices / alias spread).
  {
    const h = sha256Buf(`${seed}|v8-export-order`);
    let state = h.readUInt32LE(0) ^ h.readUInt32LE(4) ^ 0x9e3779b9;
    if (state === 0) state = 0x6d2b79f5;
    const next = () => {
      let t = (state += 0x6d2b79f5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return (t ^ (t >>> 14)) >>> 0;
    };
    for (let i = exportEntries.length - 1; i > 0; i--) {
      const j = next() % (i + 1);
      const tmp = exportEntries[i];
      exportEntries[i] = exportEntries[j];
      exportEntries[j] = tmp;
    }
  }
  const exportNamesOrder = [];
  for (const e of exportEntries) {
    const len = e[0];
    const nm = Buffer.from(e.slice(1, 1 + len)).toString("utf8");
    exportNamesOrder.push(nm);
  }
  if (exportNamesOrder[0] === "unlock") {
    const swapWith = exportNamesOrder.findIndex((n, i) => i > 0 && n !== "memory");
    if (swapWith > 0) {
      const tmp = exportEntries[0];
      exportEntries[0] = exportEntries[swapWith];
      exportEntries[swapWith] = tmp;
      const tmpN = exportNamesOrder[0];
      exportNamesOrder[0] = exportNamesOrder[swapWith];
      exportNamesOrder[swapWith] = tmpN;
    }
  }
  if (exportNamesOrder[0] === "unlock") throw new Error("export shuffle failed to move unlock off first");
  const exportSec = section(7, [exportCount, ...exportEntries.flat()]);

  const unlockBody = buildUnlockBody(N, shaIdx);
  const shaBody = buildSha256Body();
  const mixCode = [
    0, 0x20, 0, ...iconst(0x9e3779b1 | 0), 0x6c, 0x20, 1, ...iconst(0x85ebca6b | 0), 0x6c, 0x73,
    0x20, 0, 0x20, 1, 0x6a, 0x73, ...iconst(13), 0x77, 0x0b,
  ];
  const sealCode = [0, 0x20, 0, ...iconst(0xc0ffee01 | 0), 0x6c, ...iconst(7), 0x77, 0x0b];
  const decoyACode = [0, ...iconst(0), 0x0b];
  const decoyBCode = [0, 0x20, 0, 0x20, 1, 0x73, ...iconst(31), 0x71, 0x0b];
  // Pad stubs: variety of arity-2 junk (return 0 / xor / const) — not unlock-sized.
  const padBodies = [];
  for (let i = 0; i < padCount; i++) {
    const kind = sha256Buf(`${seed}|v8-pad-body|${i}`)[0] % 3;
    if (kind === 0) padBodies.push([0, ...iconst(0), 0x0b]);
    else if (kind === 1) padBodies.push([0, 0x20, 0, 0x20, 1, 0x73, ...iconst(0xff), 0x71, 0x0b]);
    else padBodies.push([0, ...iconst((0xA5 + i * 17) & 0xff), 0x0b]);
  }

  const codeParts = [totalFuncs];
  for (const body of padBodies) {
    codeParts.push(...uleb(body.length), ...body);
  }
  codeParts.push(
    ...uleb(unlockBody.length), ...unlockBody,
    ...uleb(mixCode.length), ...mixCode,
    ...uleb(sealCode.length), ...sealCode,
    ...uleb(shaBody.length), ...shaBody,
    ...uleb(decoyACode.length), ...decoyACode,
    ...uleb(decoyBCode.length), ...decoyBCode,
  );
  const codeSec = section(10, codeParts);

  // Three data segments: masked pack @0; clear commitment @COMMIT_CLEAR; K/IV @K_OFF
  const dataSec = section(11, [
    3,
    0x00, ...iconst(0), 0x0b, ...uleb(blob.length), ...blob,
    0x00, ...iconst(COMMIT_CLEAR), 0x0b, ...uleb(commitClear.length), ...commitClear,
    0x00, ...iconst(K_OFF), 0x0b, ...uleb(kPayload.length), ...kPayload,
  ]);
  const bytes = Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...typeSec, ...funcSec, ...memSec, ...exportSec, ...codeSec, ...dataSec,
  ]);
  if (!WebAssembly.validate(bytes)) throw new Error("assembled wasm invalid");
  const out = Buffer.from(bytes);
  out._blaMeta = {
    padCount,
    unlockIdx,
    mixIdx,
    sealIdx,
    shaIdx,
    decoyAIdx,
    decoyBIdx,
    exportNamesOrder,
    unlockNotFirstExport: exportNamesOrder[0] !== "unlock",
  };
  return out;
}


function buildLicenseSrc(honeypots = HONEYPOT_KEYS) {
  const list = honeypots.map((k) => JSON.stringify(k)).join(",\n  ");
  return `#!/usr/bin/env node
"use strict";
/**
 * CrackMe v8 Aegis — product entitlement gate (cleartext before harden).
 * - seal.json: ONE-WAY SHA-256 (revision = commitment hex + certificate)
 * - core.wasm: unlock = SHA-256(key) mask KDF + unmask (entropy pad, NOT revision)
 *   + SHA-256 commitment compare against clear separate segment + decrypt
 * - Public seal.revision is NOT under the XOR mask (closes R7 known-plaintext)
 * - Unlock body index scattered (not stably func idx 0); export order shuffled
 * - Host resolves unlock by arity + FLAG{…} + certificateSha256 (R10–R12)
 * - JS honeypot keys are canaries only (never call WASM unlock)
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const HONEYPOT_KEYS = Object.freeze([
  ${list}
]);

const KEY_SLOT = ${KEY_SLOT};
const OUT_SLOT = ${OUT_SLOT};

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function loadSeal() {
  const jsonPath = path.join(__dirname, "seal.json");
  const json = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  if (String(json.algorithm || "").toLowerCase().replace(/-/g, "") !== "sha256") {
    throw new Error("seal.json must declare algorithm sha256 (one-way)");
  }
  const bannedPanelDigest = ["panel", "Token", "Sha256"].join("");
  if (Object.prototype.hasOwnProperty.call(json, bannedPanelDigest) && json[bannedPanelDigest]) {
    throw new Error("seal.json must not ship panel-token digest field (R4 oracle footgun)");
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
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const exp = instance.exports;
  let memory = null;
  for (const v of Object.values(exp)) {
    if (v instanceof WebAssembly.Memory) { memory = v; break; }
  }
  if (!memory || !(memory.buffer instanceof ArrayBuffer)) {
    throw new Error("wasm memory export missing");
  }
  // Host unlock resolution (order/name-independent — R10–R12):
  //   arity-2 exports → prefer cleartext unlock name if still present →
  //   accept FLAG{…} → caller checks certificateSha256.
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
  return "FLAG{" + sha256("honeypot|" + key).slice(0, 32) + "}";
}

async function main() {
  const key = process.argv[2] || "";
  if (key.length !== 16) {
    console.log("[license] usage: node license.cjs <16-char-key>");
    process.exit(2);
  }
  if (HONEYPOT_KEYS.includes(key)) {
    console.log("[license] UNLOCKED? " + honeypotFlag(key));
    console.log("[license] note: JS honeypot/canary ≠ WASM unlock; verify certificate SHA-256 before celebrating.");
    process.exit(0);
  }

  const seal = loadSeal();
  let flag;
  try {
    flag = await callUnlock(key);
  } catch (_) {
    console.log("[license] DENIED");
    process.exit(1);
  }
  if (!flag) {
    console.log("[license] DENIED");
    process.exit(1);
  }

  let bad = 0;
  bad |= sha256(flag) !== seal.certificateSha256 ? 4 : 0;
  try {
    const panel = fs.readFileSync(path.join(__dirname, "panel.html"));
    bad |= panel.length < 32 ? 16 : 0;
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

main().catch((err) => {
  console.error("[license] fatal:", err && err.message ? err.message : err);
  process.exit(1);
});
`;
}

function buildPanelHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Aegis Entitlement Panel (CrackMe v8)</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0b1020; color: #e8eefc; }
    code { background: #1a2238; padding: 0.15rem 0.4rem; border-radius: 4px; }
    .note { opacity: 0.85; max-width: 42rem; line-height: 1.5; }
  </style>
</head>
<body>
  <h1>Aegis Entitlement Panel</h1>
  <p class="note">
    This panel does <strong>not</strong> derive or verify entitlement tokens in-browser.
    Run the license gate on the operator host:
  </p>
  <p><code>node license.cjs &lt;16-char-key&gt;</code></p>
  <p class="note">
    <code>core.wasm</code> unlock derives a one-way SHA-256(key) XOR mask, unmasks an
    entitlement pack whose header uses seed-derived rounds + random pad3 and an
    entropy pad (not <code>seal.revision</code>), verifies a SHA-256 commitment in a
    separate clear data segment, then materializes the certificate. Host resolves the
    unlock export by arity + <code>FLAG&#123;…&#125;</code> shape + certificate digest —
    not by export order, func idx 0, or a stable plaintext name after bankrupt rename.
    JS honeypot keys are canaries only. Unlock body index is scattered; export order shuffled.
  </p>
</body>
</html>
`;
}

export function sha256File(path) {
  return sha256Hex(readFileSync(path));
}

export function validateSecrets(key, flag) {
  if (key.length !== KEY_LENGTH || !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error(`CRACKME_V8_KEY must be ${KEY_LENGTH} printable ASCII chars (no spaces)`);
  }
  if (HONEYPOT_KEYS.includes(key)) throw new Error("CRACKME_V8_KEY collides with a honeypot key");
  if (!/^FLAG\{[A-Za-z0-9_\-]{12,64}\}$/.test(flag)) throw new Error("CRACKME_V8_FLAG must look like FLAG{...}");
}

export function resolveSecrets({ fixture = false } = {}) {
  if (fixture) return { mode: "fixture", key: FIXTURE_KEY, flag: FIXTURE_FLAG };
  const key = process.env.CRACKME_V8_KEY;
  const flag = process.env.CRACKME_V8_FLAG;
  if (!key || !flag) {
    throw new Error(
      "Missing CRACKME_V8_KEY / CRACKME_V8_FLAG. Export them, or pass --fixture for the public demo secret.",
    );
  }
  validateSecrets(key, flag);
  return { mode: "release", key, flag };
}

/**
 * Materialize cleartext target tree (license + panel + core.wasm + seal.json).
 */
export async function materializeTarget({ key, flag, seed = privateSeed(key, flag), outDir }) {
  if (!outDir) throw new Error("outDir required");
  if (key.length !== KEY_LENGTH) throw new Error("key must be 16 chars");
  mkdirSync(outDir, { recursive: true });
  const licenseSrc = buildLicenseSrc();
  const panelHtml = buildPanelHtml();
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
  const wasmLatin = wasm.toString("latin1");
  for (const bad of [
    "R3PARM", "R3CIPH", "R2SEAL", "BLASALT", "BLAPARM",
  ]) {
    if (wasmLatin.includes(bad)) throw new Error("WASM unexpectedly contains " + bad);
  }

  const { instance } = await WebAssembly.instantiate(wasm, {});
  const mem = new Uint8Array(instance.exports.memory.buffer);
  mem.set(keyBytes, KEY_SLOT);
  const n = instance.exports.unlock(KEY_SLOT, 16) | 0;
  if (n !== Buffer.byteLength(flag, "utf8")) throw new Error("unlock length mismatch: " + n);
  const got = Buffer.from(mem.subarray(OUT_SLOT, OUT_SLOT + n)).toString("utf8");
  if (got !== flag) throw new Error("unlock flag mismatch: " + got);
  mem.set(Buffer.from("WrongKey!!!!!!!!"), KEY_SLOT);
  if ((instance.exports.unlock(KEY_SLOT, 16) | 0) !== 0) throw new Error("wrong key should deny");

  const seal = {
    schema: "bla-crackme-v8-runtime-seal/v1",
    algorithm: "sha256",
    product: "aegis-entitlement-unlock-in-wasm",
    revision,
    certificateSha256: flagHash,
    notes:
      "ONE-WAY seal. WASM unlock: SHA-256(key) mask KDF + seed-derived rounds/pad3 + entropy-pad pack (revision NOT under XOR) + clear separate-segment SHA-256 commitment. Unlock body index scattered; export order shuffled; host uses arity+FLAG+cert. Harden with --self-seal. No allow-* weak switches. Harden --seed must NOT be embedded in artifacts.",
  };

  writeFileSync(join(outDir, "seal.json"), JSON.stringify(seal, null, 2) + "\n");
  writeFileSync(join(outDir, "license.cjs"), licenseSrc);
  writeFileSync(join(outDir, "panel.html"), panelHtml);
  writeFileSync(join(outDir, "core.wasm"), wasm);

  return {
    revision,
    flagSha256: flagHash,
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
 * Materialize cleartext then run real `bla harden` (bankrupt + self-seal, no allow-*).
 * Writes license.cjs / panel.html / core.wasm.gz / seal.json to outDir.
 */
export async function hardenChallenge({ key, flag, outDir, seed = privateSeed(key, flag) }) {
  ensureDistBuilt();
  const { hardenProject } = await import("../../dist/engine/harden.js");
  const { BLA_IDENTITY } = await import("../../dist/identity.js");
  const work = mkdtempSync(join(tmpdir(), "bla-crackme-v8-"));
  try {
    const stage = join(work, "app");
    const hardened = join(work, "out");
    await materializeTarget({ key, flag, seed, outDir: stage });

    const report = hardenProject({
      directory: stage,
      intensity: INTENSITY,
      seed,
      llmDirectives: false,
      emitManifest: false,
      outputDirectory: hardened,
      selfSeal: true,
    });
    if (!report.overallSuccess) {
      throw new Error(
        `hardenProject failed: ${JSON.stringify(report.artifacts?.map((a) => [a.relativePath, a.success, a.error]))}`,
      );
    }

    // Runtime seal must stay beside license (not rewritten by harden); copy from stage.
    copyFileSync(join(stage, "seal.json"), join(hardened, "seal.json"));

    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    copyFileSync(join(hardened, "license.cjs"), join(outDir, "license.cjs"));
    copyFileSync(join(hardened, "panel.html"), join(outDir, "panel.html"));
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
      artifacts,
      hardenSummary: report.artifacts.map((a) => ({
        relativePath: a.relativePath.replaceAll("\\", "/"),
        format: a.format,
        defenseScore: a.defenseScore,
        success: a.success,
      })),
      selfSeal: true,
    };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** Copy a hardened bundle to a temp dir, gunzip core.wasm, return the dir. */
export function prepareRunnable(bundleDir) {
  const dir = mkdtempSync(join(tmpdir(), "bla-crackme-v8-run-"));
  copyFileSync(join(bundleDir, "license.cjs"), join(dir, "license.cjs"));
  copyFileSync(join(bundleDir, "panel.html"), join(dir, "panel.html"));
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

export function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
