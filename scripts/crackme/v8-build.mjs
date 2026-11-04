#!/usr/bin/env node
/**
 * CrackMe v8 (Aegis) build — published challenge IS `bla harden` output
 * (bankrupt + --self-seal, no --allow-*).
 *
 *   CRACKME_V8_KEY=… CRACKME_V8_FLAG=FLAG{…} npm run crackme:v8:build
 *   npm run crackme:v8:build -- --fixture [--out <dir>]
 */
import { join, resolve } from "node:path";
import {
  FIXTURE_DIR,
  HARDENED_DIR,
  INTENSITY,
  PRODUCT,
  SCHEMA,
  SEAL_PATH,
  SEED_LABEL,
  hardenChallenge,
  resolveSecrets,
  sha256Hex,
  writeJson,
} from "./v8-lib.mjs";

const argv = process.argv.slice(2);
const fixture = argv.includes("--fixture");
const outIdx = argv.indexOf("--out");
const secrets = resolveSecrets({ fixture });
const outDir = outIdx >= 0 ? resolve(argv[outIdx + 1]) : secrets.mode === "release" ? HARDENED_DIR : FIXTURE_DIR;

const result = await hardenChallenge({ key: secrets.key, flag: secrets.flag, outDir });
const seal = {
  schema: SCHEMA,
  mode: secrets.mode,
  product: PRODUCT,
  blaVersion: result.blaVersion,
  recipe:
    "npm run crackme:v8:build (hardenProject == `bla harden <dir> --intensity bankrupt --seed <private> --self-seal`); harden/schedule seed is private (derived from release secrets) and NOT published",
  label: SEED_LABEL,
  intensity: INTENSITY,
  selfSeal: true,
  llmDirectives: false,
  emitManifest: false,
  flagSha256: sha256Hex(secrets.flag),
  artifacts: result.artifacts,
  hardenSummary: result.hardenSummary,
  recipesAbsorbed: [
    "R7/R8 SHA-256(key) mask KDF + commitment outside XOR",
    "R9 seed-derived rounds + pad3 (private seed — v8 red-team public-seed KP closed)",
    "R10–R12 arity-2 hygiene + export-order shuffle + unlock body-index scatter",
    "bankrupt packaging gates + --self-seal (no --allow-*)",
  ],
  honestyResidual:
    "P2 full WASM RE + online/SMT vs clear commitment remains possible — gates do not claim white-box secrecy.",
  note: "Public commitment: prove a solve by publishing SHA-256(FLAG{...}) matching flagSha256. Plaintext key/flag/seed are not in git; no key digest is published (no offline key oracle).",
};
const sealPath = secrets.mode === "release" && outIdx < 0 ? SEAL_PATH : join(outDir, "SEAL.json");
writeJson(sealPath, seal);
console.log(`[crackme:v8:build] ${secrets.mode} bundle → ${outDir}`);
for (const [rel, meta] of Object.entries(result.artifacts)) {
  console.log(`  ${rel.padEnd(14)} ${String(meta.bytes).padStart(9)} B  ${meta.sha256}`);
}
console.log(`  SEAL → ${sealPath}`);
