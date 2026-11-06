#!/usr/bin/env node
/**
 * CI gate for CrackMe v9 (Sovereign — BLA 3.0). No plaintext secrets required.
 * If CRACKME_V9_KEY/FLAG match SEAL digests, also verifies unlock + byte rebuild.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import {
  COMMITTED_FILES,
  FIXTURE_FLAG,
  FIXTURE_KEY,
  HARDENED_DIR,
  HONEYPOT_KEYS,
  INTENSITY,
  PRODUCT,
  ROOT,
  SCHEMA,
  SEAL_PATH,
  SEED_LABEL,
  extractFlag,
  hardenChallenge,
  prepareRunnable,
  runLicense,
  sha256File,
  sha256Hex,
  validateSecrets,
} from "./v9-lib.mjs";

const fail = (m) => {
  console.error(`[crackme:v9:seal] FAIL: ${m}`);
  process.exit(1);
};
const ok = (m) => console.log(`[crackme:v9:seal] OK: ${m}`);
const tmpRoots = [];
const tmp = (p) => {
  const d = mkdtempSync(join(tmpdir(), p));
  tmpRoots.push(d);
  return d;
};

try {
  if (!existsSync(SEAL_PATH)) fail(`missing ${SEAL_PATH}`);
  const seal = JSON.parse(readFileSync(SEAL_PATH, "utf8"));
  if (seal.schema !== SCHEMA || seal.mode !== "release") fail("SEAL schema/mode drift");
  if (seal.product !== PRODUCT) fail("SEAL product drift");
  if (seal.label !== SEED_LABEL || seal.intensity !== INTENSITY) fail("SEAL label/intensity drift");
  for (const leak of ["seed", "materializationSeed", "hardenSeed", "keySha256", "keyDigest"]) {
    if (leak in seal) fail(`SEAL must not publish ${leak} (public-seed KP / offline key oracle)`);
  }
  if (seal.selfSeal !== true || seal.sidecarEntangle !== true || seal.weaveDecoys !== true) {
    fail("SEAL must pin selfSeal=true, sidecarEntangle=true, weaveDecoys=true");
  }
  if (seal.weaveScore !== 100 || seal.integrityCoverageSelfVerified !== true) {
    fail("SEAL must pin weaveScore=100 and integrityCoverageSelfVerified=true");
  }
  if (seal.llmDirectives !== false || seal.emitManifest !== false) {
    fail("SEAL must pin llmDirectives=false, emitManifest=false");
  }
  const pkgVersion = String(JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version);
  if (seal.blaVersion !== pkgVersion) fail(`SEAL blaVersion ${seal.blaVersion} != package.json ${pkgVersion}`);
  if (!/^[0-9a-f]{64}$/.test(seal.flagSha256)) fail("SEAL flagSha256 missing");

  for (const rel of COMMITTED_FILES) {
    const got = sha256File(join(HARDENED_DIR, rel));
    if (got !== seal.artifacts[rel]?.sha256) fail(`${rel} digest ${got} != SEAL ${seal.artifacts[rel]?.sha256}`);
  }
  const raw = sha256Hex(gunzipSync(readFileSync(join(HARDENED_DIR, "core.wasm.gz"))));
  if (raw !== seal.artifacts["core.wasm"]?.sha256) fail("gunzip(core.wasm.gz) != SEAL raw core.wasm digest");
  ok("SEAL knobs + artifact digests");

  const run = prepareRunnable(HARDENED_DIR);
  tmpRoots.push(run);
  for (const bad of ["wrong-key-v9-1234", "", "short"]) {
    const r = runLicense(run, bad);
    if (r.ok || extractFlag(r.stdout)) fail(`release bundle accepted ${JSON.stringify(bad)}`);
  }
  for (const hp of HONEYPOT_KEYS) {
    const f = extractFlag(runLicense(run, hp).stdout);
    if (!f || sha256Hex(f) === seal.flagSha256) fail(`honeypot ${hp} misbehaved`);
  }
  if (extractFlag(runLicense(run, FIXTURE_KEY).stdout)) fail("release bundle accepts the public fixture key");
  ok("release bundle denies wrong/empty/fixture keys; honeypots stay decoys");

  const fxA = tmp("bla-crackme-v9-fxA-");
  const fxB = tmp("bla-crackme-v9-fxB-");
  const a = await hardenChallenge({ key: FIXTURE_KEY, flag: FIXTURE_FLAG, outDir: fxA });
  const b = await hardenChallenge({ key: FIXTURE_KEY, flag: FIXTURE_FLAG, outDir: fxB });
  for (const rel of COMMITTED_FILES) {
    if (a.artifacts[rel].sha256 !== b.artifacts[rel].sha256) fail(`fixture re-harden not reproducible on ${rel}`);
  }
  const fxRun = prepareRunnable(fxA);
  tmpRoots.push(fxRun);
  const unlocked = runLicense(fxRun, FIXTURE_KEY);
  if (!unlocked.ok || extractFlag(unlocked.stdout) !== FIXTURE_FLAG) fail("fixture unlock failed");
  if (runLicense(fxRun, "WrongKey!!!!!!!!").ok) fail("fixture accepted wrong key");
  ok("fixture re-harden reproducible + unlock/deny");

  const key = process.env.CRACKME_V9_KEY;
  const flag = process.env.CRACKME_V9_FLAG;
  if (key && flag) {
    if (sha256Hex(flag) === seal.flagSha256) {
      validateSecrets(key, flag);
      const r = runLicense(run, key);
      if (!r.ok || extractFlag(r.stdout) !== flag) fail("release unlock failed: " + r.stdout);
      ok("release unlock (secrets present)");
    } else {
      console.log("[crackme:v9:seal] NOTE: CRACKME_V9_KEY/FLAG set but digests do not match SEAL — release unlock skipped");
    }
  } else {
    console.log("[crackme:v9:seal] NOTE: CRACKME_V9_KEY/FLAG unset — release unlock skipped");
  }

  console.log("[crackme:v9:seal] OK: CrackMe v9 seal passed");
} finally {
  for (const d of tmpRoots) rmSync(d, { recursive: true, force: true });
}
