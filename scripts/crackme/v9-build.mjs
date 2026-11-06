#!/usr/bin/env node
/**
 * CrackMe v9 (Sovereign) build — published challenge IS `bla harden` 3.0 output
 * (bankrupt + --weave-decoys + --self-seal + --sidecar-entangle, no --allow-*).
 *
 *   CRACKME_V9_KEY=… CRACKME_V9_FLAG=FLAG{…} npm run crackme:v9:build
 *   npm run crackme:v9:build -- --fixture [--out <dir>]
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
} from "./v9-lib.mjs";

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
    "npm run crackme:v9:build (4-Stage BLA 3.0 Playbook: bla_lint -> bla_weave_plan -> bla_verify_weave -> bla_harden --intensity bankrupt --weave-decoys --self-seal --sidecar-entangle); harden/schedule seed is private",
  label: SEED_LABEL,
  intensity: INTENSITY,
  weaveDecoys: true,
  selfSeal: true,
  sidecarEntangle: true,
  weaveScore: result.weaveScore,
  integrityCoverageSelfVerified: result.integrityCoverageSelfVerified,
  llmDirectives: false,
  emitManifest: false,
  flagSha256: sha256Hex(secrets.flag),
  artifacts: result.artifacts,
  hardenSummary: result.hardenSummary,
  recipesAbsorbed: [
    "BLA 3.0 4-Stage Playbook: AST surgicalWorkorder + pre/post bla_verify_weave (100/100)",
    "Closes v8 seal.json sidecar residual: license.cjs pins EXPECTED_SEAL_SHA256 at runtime",
    "Multi-format sibling entanglement: self_seal + sidecar_entangle across license.cjs, panel.html, policy.py, core.wasm",
    "R7–R12 SHA-256(key) mask KDF + commitment outside XOR + private seed + arity-2/export-order/body-index scatter",
  ],
  honestyResidual:
    "P2 full WASM RE + online/SMT vs clear commitment remains possible — gates do not claim white-box secrecy.",
  note: "Public commitment: prove a solve by publishing SHA-256(FLAG{...}) matching flagSha256. Plaintext key/flag/seed are not in git; no key digest is published (no offline key oracle).",
};
const sealPath = secrets.mode === "release" && outIdx < 0 ? SEAL_PATH : join(outDir, "SEAL.json");
writeJson(sealPath, seal);
console.log(`[crackme:v9:build] ${secrets.mode} bundle → ${outDir}`);
for (const [rel, meta] of Object.entries(result.artifacts)) {
  console.log(`  ${rel.padEnd(14)} ${String(meta.bytes).padStart(9)} B  ${meta.sha256}`);
}
console.log(`  SEAL → ${sealPath}`);
