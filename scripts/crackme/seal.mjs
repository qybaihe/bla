#!/usr/bin/env node
/**
 * CrackMe v6 CI seal:
 * 1) Always: published artifacts deny wrong keys; digests match commitment.json;
 *    fixture pipeline rebuilds and unlocks with the demo secret.
 * 2) If CRACKME_V6_KEY/FLAG are set: published artifacts unlock and FLAG SHA-256
 *    matches the public commitment (runtime equivalence to the committed prize).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import {
  ARTIFACTS_DIR,
  COMMITMENT_PATH,
  ROOT,
  extractFlag,
  loadProfiles,
  runCrackme,
  sha256File,
  sha256Hex,
} from "./lib.mjs";

function fail(msg) {
  console.error(`[crackme:seal] FAIL: ${msg}`);
  process.exit(1);
}

function ok(msg) {
  console.log(`[crackme:seal] OK: ${msg}`);
}

const profiles = loadProfiles();
if (!existsSync(COMMITMENT_PATH)) fail(`missing ${COMMITMENT_PATH}`);
const commitment = JSON.parse(readFileSync(COMMITMENT_PATH, "utf8"));

if (commitment.version !== 6) fail("commitment.version must be 6");
if (commitment.scope !== profiles.scope) fail("commitment.scope drift");
if (commitment.seed !== profiles.seed) fail("commitment.seed drift");
if (!commitment.flagSha256 || !commitment.keySha256) fail("commitment missing hashes");

for (const tierId of Object.keys(profiles.tiers)) {
  const artifact = join(ARTIFACTS_DIR, `${tierId}.cjs`);
  if (!existsSync(artifact)) fail(`missing artifact ${artifact}`);
  const digest = sha256File(artifact);
  if (commitment.artifactSha256?.[tierId] !== digest) {
    fail(`${tierId} digest mismatch: commitment=${commitment.artifactSha256?.[tierId]} actual=${digest}`);
  }
  const denied = runCrackme(artifact, "wrong-key-for-seal");
  if (denied.ok || extractFlag(denied.stdout)) fail(`${tierId} accepted wrong key`);
  const empty = runCrackme(artifact, "");
  // empty key → usage / deny, never a flag
  if (extractFlag(empty.stdout) || extractFlag(empty.stderr)) fail(`${tierId} leaked flag on empty key`);
  ok(`${tierId} digest + deny-wrong-key`);
}

// Fixture pipeline must stay green without repo secrets.
console.log("[crackme:seal] running fixture rebuild…");
execFileSync(process.execPath, [join(ROOT, "scripts/crackme/build.mjs"), "--fixture"], {
  cwd: ROOT,
  stdio: "inherit",
  env: { ...process.env, CRACKME_V6_MODE: "fixture" },
});
ok("fixture rebuild");

const key = process.env.CRACKME_V6_KEY;
const flag = process.env.CRACKME_V6_FLAG;
if (key && flag) {
  if (sha256Hex(key) !== commitment.keySha256) fail("CRACKME_V6_KEY does not match commitment.keySha256");
  if (sha256Hex(flag) !== commitment.flagSha256) fail("CRACKME_V6_FLAG does not match commitment.flagSha256");
  for (const tierId of Object.keys(profiles.tiers)) {
    const artifact = join(ARTIFACTS_DIR, `${tierId}.cjs`);
    const unlocked = runCrackme(artifact, key);
    const got = extractFlag(unlocked.stdout);
    if (!unlocked.ok || got !== flag) fail(`${tierId} failed release unlock`);
    ok(`${tierId} release unlock matches commitment`);
  }
} else {
  console.log(
    "[crackme:seal] NOTE: CRACKME_V6_KEY/FLAG not set — skipped release unlock check (digest + fixture still enforced).",
  );
}

ok("CrackMe v6 seal passed");
