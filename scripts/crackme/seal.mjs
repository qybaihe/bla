#!/usr/bin/env node
/**
 * CrackMe v6 CI seal (runs on every matrix job, no secrets required):
 *  1. SEAL.json pins P0-safe knobs and matches committed artifact + template digests.
 *  2. Published bundle denies wrong / empty keys; honeypot keys never yield the committed flag.
 *  3. Fixture pipeline: re-harden the public template with the demo secret, unlock it,
 *     and confirm the build is reproducible (two runs → identical bytes).
 *  4. If CRACKME_V6_KEY/FLAG are present AND match SEAL's digests: release unlock +
 *     re-harden must reproduce the committed artifacts byte-for-byte.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import {
  COMMITTED_FILES,
  HARDENED_DIR,
  HONEYPOT_KEYS,
  FIXTURE_FLAG,
  FIXTURE_KEY,
  INTENSITY,
  SCHEMA,
  SEAL_PATH,
  SEED,
  extractFlag,
  hardenChallenge,
  prepareRunnable,
  runVault,
  sha256File,
  sha256Hex,
  templateDigests,
  validateSecrets,
} from "./lib.mjs";

const fail = (m) => {
  console.error(`[crackme:seal] FAIL: ${m}`);
  process.exit(1);
};
const ok = (m) => console.log(`[crackme:seal] OK: ${m}`);
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
  if (seal.seed !== SEED || seal.intensity !== INTENSITY) fail("SEAL seed/intensity drift");
  if (seal.llmDirectives !== false || seal.emitManifest !== false) fail("SEAL must pin llmDirectives=false, emitManifest=false");
  if (!/^[0-9a-f]{64}$/.test(seal.flagSha256) || !/^[0-9a-f]{64}$/.test(seal.keySha256)) fail("SEAL digests missing");
  for (const rel of COMMITTED_FILES) {
    const got = sha256File(join(HARDENED_DIR, rel));
    if (got !== seal.artifacts[rel]?.sha256) fail(`${rel} digest ${got} != SEAL ${seal.artifacts[rel]?.sha256}`);
  }
  const raw = sha256Hex(gunzipSync(readFileSync(join(HARDENED_DIR, "core.wasm.gz"))));
  if (raw !== seal.artifacts["core.wasm"]?.sha256) fail("gunzip(core.wasm.gz) != SEAL raw core.wasm digest");
  const tpl = templateDigests();
  for (const [rel, digest] of Object.entries(tpl)) if (seal.templates?.[rel] !== digest) fail(`template ${rel} drifted from SEAL (rebuild required)`);
  ok("SEAL knobs + artifact/template digests");

  const run = prepareRunnable(HARDENED_DIR);
  tmpRoots.push(run);
  for (const bad of ["wrong-key-v6-123", "", "short"]) {
    const r = runVault(run, bad);
    if (r.ok || extractFlag(r.stdout)) fail(`release bundle accepted ${JSON.stringify(bad)}`);
  }
  for (const hp of HONEYPOT_KEYS) {
    const f = extractFlag(runVault(run, hp).stdout);
    if (!f || sha256Hex(f) === seal.flagSha256) fail(`honeypot ${hp} misbehaved`);
  }
  if (extractFlag(runVault(run, FIXTURE_KEY).stdout)) fail("release bundle accepts the public fixture key");
  ok("release bundle denies wrong/empty/fixture keys; honeypots stay decoys");

  const fxA = tmp("bla-crackme-v6-fxA-");
  const fxB = tmp("bla-crackme-v6-fxB-");
  const a = await hardenChallenge({ key: FIXTURE_KEY, flag: FIXTURE_FLAG, outDir: fxA });
  const b = await hardenChallenge({ key: FIXTURE_KEY, flag: FIXTURE_FLAG, outDir: fxB });
  for (const rel of [...COMMITTED_FILES, "core.wasm"]) {
    if (a.artifacts[rel].sha256 !== b.artifacts[rel].sha256) fail(`fixture harden not reproducible for ${rel}`);
  }
  const fxRun = prepareRunnable(fxA);
  tmpRoots.push(fxRun);
  const fxOut = runVault(fxRun, FIXTURE_KEY);
  if (!fxOut.ok || extractFlag(fxOut.stdout) !== FIXTURE_FLAG) fail(`fixture unlock failed: ${fxOut.stdout}`);
  ok("fixture re-harden is reproducible and unlocks with the demo key");

  const key = process.env.CRACKME_V6_KEY;
  const flag = process.env.CRACKME_V6_FLAG;
  if (key && flag && sha256Hex(key) === seal.keySha256 && sha256Hex(flag) === seal.flagSha256) {
    validateSecrets(key, flag);
    const got = extractFlag(runVault(run, key).stdout);
    if (got !== flag) fail("release bundle did not unlock with CRACKME_V6_KEY");
    const rel = tmp("bla-crackme-v6-rel-");
    const r = await hardenChallenge({ key, flag, outDir: rel });
    for (const f of [...COMMITTED_FILES, "core.wasm"]) {
      if (r.artifacts[f].sha256 !== seal.artifacts[f].sha256) fail(`release re-harden drift on ${f}`);
    }
    ok("release unlock + byte-for-byte re-harden reproduction (secrets present)");
  } else if (key || flag) {
    console.log("[crackme:seal] NOTE: CRACKME_V6_KEY/FLAG set but do not match SEAL digests (rotate the repo secrets) — release reproduction skipped.");
  } else {
    console.log("[crackme:seal] NOTE: no CRACKME_V6_KEY/FLAG — release reproduction skipped (digests + fixture still enforced).");
  }
  ok("CrackMe v6 seal passed");
} finally {
  for (const d of tmpRoots) rmSync(d, { recursive: true, force: true });
}
