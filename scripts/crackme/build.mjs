#!/usr/bin/env node
/**
 * CrackMe v6 (harden-native) build — the published challenge IS `bla harden` output.
 *
 *   CRACKME_V6_KEY=… CRACKME_V6_FLAG=FLAG{…} npm run crackme:build   # release → challenge/v6/hardened + SEAL.json
 *   npm run crackme:build -- --fixture [--out <dir>]                  # public demo secret → challenge/v6/.fixture (gitignored)
 *
 * Knobs are pinned and P0-safe: intensity=bankrupt, llmDirectives=false,
 * emitManifest=false, fixed seed (seeded harden is bit-for-bit reproducible).
 */
import { join, resolve } from "node:path";
import {
  FIXTURE_DIR,
  HARDENED_DIR,
  INTENSITY,
  SCHEMA,
  SEAL_PATH,
  SEED,
  hardenChallenge,
  resolveSecrets,
  sha256Hex,
  templateDigests,
  writeJson,
} from "./lib.mjs";

const argv = process.argv.slice(2);
const fixture = argv.includes("--fixture");
const outIdx = argv.indexOf("--out");
const secrets = resolveSecrets({ fixture });
const outDir = outIdx >= 0 ? resolve(argv[outIdx + 1]) : secrets.mode === "release" ? HARDENED_DIR : FIXTURE_DIR;

const result = await hardenChallenge({ key: secrets.key, flag: secrets.flag, outDir });
const seal = {
  schema: SCHEMA,
  mode: secrets.mode,
  blaVersion: result.blaVersion,
  recipe: "npm run crackme:build (hardenProject == `bla harden <dir> --intensity bankrupt --seed <seed>`)",
  seed: SEED,
  intensity: INTENSITY,
  llmDirectives: false,
  emitManifest: false,
  keySha256: sha256Hex(secrets.key),
  flagSha256: sha256Hex(secrets.flag),
  templates: templateDigests(),
  artifacts: result.artifacts,
  hardenSummary: result.hardenSummary,
  note: "Public commitment: prove a solve by publishing SHA-256(FLAG{...}) matching flagSha256. Plaintext key/flag are not in git.",
};
const sealPath = secrets.mode === "release" && outIdx < 0 ? SEAL_PATH : join(outDir, "SEAL.json");
writeJson(sealPath, seal);
console.log(`[crackme:build] ${secrets.mode} bundle → ${outDir}`);
for (const [rel, meta] of Object.entries(result.artifacts)) console.log(`  ${rel.padEnd(14)} ${String(meta.bytes).padStart(9)} B  ${meta.sha256}`);
console.log(`  SEAL → ${sealPath}`);
