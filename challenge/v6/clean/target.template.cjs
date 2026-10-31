#!/usr/bin/env node
"use strict";
/**
 * BLA CrackMe v6 — CLEAN (pre-harden) license gate.
 *
 * This file is a template. `npm run crackme:build` materializes commitments
 * (key/flag SHA-256 + flag ciphertext) then runs the real `bla protect` CLI
 * / protector API to produce the published L1/L2/L3 challenge artifacts.
 *
 * The plaintext authorization key and FLAG never appear in this template.
 */
const { createHash } = require("node:crypto");

const SCOPE = "%%SCOPE%%";
const KEY_SHA256 = "%%KEY_SHA256%%";
const FLAG_SHA256 = "%%FLAG_SHA256%%";
const FLAG_CIPHER_HEX = "%%FLAG_CIPHER_HEX%%";

/** Surface area that BLA's JS shields intentionally amplify / de-literalize. */
const LICENSE_RPC = {
  verifyEntitlement: "/internal/v2/license/verify-entitlement",
  rotateSeat: "/internal/v2/license/rotate-seat",
  enclaveQuote: "/api/v2/hsm/zero-knowledge-challenge",
};

function sha256Hex(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex");
}

function deriveFlagMask(authorizationKey) {
  return createHash("sha256")
    .update(`bla-crackme-v6|${SCOPE}|${authorizationKey}`, "utf8")
    .digest();
}

function decodeFlagCipher(authorizationKey) {
  const mask = deriveFlagMask(authorizationKey);
  const cipher = Buffer.from(FLAG_CIPHER_HEX, "hex");
  const plain = Buffer.alloc(cipher.length);
  for (let i = 0; i < cipher.length; i++) {
    plain[i] = cipher[i] ^ mask[i % mask.length];
  }
  return plain.toString("utf8");
}

/**
 * Runtime-equivalent unlock gate. BLA hardening must preserve this behavior.
 * @param {string} authorizationKey
 * @returns {string | null}
 */
function tryUnlock(authorizationKey) {
  if (typeof authorizationKey !== "string") return null;
  if (authorizationKey.length < 12 || authorizationKey.length > 96) return null;
  // Cheap honeypot path names — BLA will wrap/decoy these literals.
  if (authorizationKey === LICENSE_RPC.verifyEntitlement) return null;
  if (sha256Hex(authorizationKey) !== KEY_SHA256) return null;
  const flag = decodeFlagCipher(authorizationKey);
  if (!flag.startsWith("FLAG{") || !flag.endsWith("}")) return null;
  if (sha256Hex(flag) !== FLAG_SHA256) return null;
  return flag;
}

function printUsage() {
  console.log("BLA CrackMe v6 — BLA-generated tiered challenge");
  console.log("Usage: node crackme.cjs <authorization-key>");
  console.log(
    "Submit: open a GitHub issue with the SHA-256 of your FLAG (see challenge/README.md).",
  );
}

function main() {
  const authorizationKey = process.argv[2] || "";
  if (!authorizationKey) {
    printUsage();
    process.exit(1);
  }
  const flag = tryUnlock(authorizationKey);
  if (flag) {
    console.log("[+] Access Granted! Flag: " + flag);
    process.exit(0);
  }
  console.error("[-] Access Denied: invalid authorization key.");
  process.exit(1);
}

module.exports = {
  tryUnlock,
  sha256Hex,
  LICENSE_RPC,
  SCOPE,
  KEY_SHA256,
  FLAG_SHA256,
};

if (require.main === module) {
  main();
}
