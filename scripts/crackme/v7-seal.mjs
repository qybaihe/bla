#!/usr/bin/env node
/**
 * CI gate for CrackMe v7 (Meridian). No plaintext secrets required.
 * If CRACKME_V7_KEY/CERT are set and match SEAL digests, also verifies unlock.
 */
import { createHash, createHmac } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const V7 = join(ROOT, "challenge", "v7");
const DIST = join(V7, "dist");
const SEAL = join(V7, "SEAL.json");
const MODULES = ["cli/meridian.cjs", "core/expr.cjs", "core/units.cjs", "core/stats.cjs", "core/license.cjs"];
const sha = (b) => createHash("sha256").update(b).digest("hex");

function run(args, envExtra = {}) {
  const env = { ...process.env, ...envExtra };
  delete env.NODE_OPTIONS;
  return spawnSync(process.execPath, [join(DIST, "cli", "meridian.cjs"), ...args], {
    env,
    encoding: "utf8",
    cwd: DIST, // so relative data/ resolves the same as product use via run.mjs from v7 root — actually cli uses __dirname/../data
  });
}

function must(cond, msg) {
  if (!cond) throw new Error(msg);
}

const seal = JSON.parse(readFileSync(SEAL, "utf8"));
must(seal.schema === "bla-crackme-v7-seal/v1", "bad schema");
must(seal.intensity === "bankrupt" && seal.llmDirectives === false && seal.emitManifest === false, "knobs");
must(seal.product === "Meridian", "product");

for (const rel of [...MODULES, "data/catalog.json"]) {
  const buf = readFileSync(join(DIST, rel));
  const meta = seal.files[rel];
  must(meta && meta.sha256 === sha(buf) && meta.bytes === buf.length, `digest mismatch ${rel}`);
}
const h = createHash("sha256");
for (const rel of MODULES) {
  h.update(rel);
  h.update(readFileSync(join(DIST, rel)));
}
must(h.digest("hex") === seal.integrity, "integrity mismatch");
console.log("[v7-seal] OK: SEAL knobs + file digests + integrity");

// Functional surface still works.
must(run(["calc", "(3+4)*5"]).stdout.trim() === "35", "calc");
must(run(["convert", "212", "degF", "degC"]).stdout.trim().startsWith("100"), "convert");
must(run(["stats", "4", "8", "15", "16", "23", "42"]).status === 0, "stats");
console.log("[v7-seal] OK: calc/convert/stats");

// Deny paths.
must(run(["license", "activate", "AAAAA-AAAAA-AAAAA-AAAAA"]).status === 1, "wrong key should deny");
must(run(["license", "activate", "short"]).status === 2, "short key format");
console.log("[v7-seal] OK: deny + format");

// Anti-tamper: flip one byte in a copy and expect deny even with (possibly correct) env key.
{
  const dir = mkdtempSync(join(tmpdir(), "meridian-tamper-"));
  for (const rel of [...MODULES, "data/catalog.json"]) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    copyFileSync(join(DIST, rel), join(dir, rel));
  }
  const target = join(dir, "core", "expr.cjs");
  const buf = Buffer.from(readFileSync(target));
  buf[buf.length >> 1] ^= 0x01;
  writeFileSync(target, buf);
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, [join(dir, "cli", "meridian.cjs"), "license", "activate", process.env.CRACKME_V7_KEY || "AAAAA-AAAAA-AAAAA-AAAAA"], { env, encoding: "utf8" });
  must(r.status === 1, "tampered module must deny");
  rmSync(dir, { recursive: true, force: true });
  console.log("[v7-seal] OK: self-integrity rejects tamper");
}

const key = process.env.CRACKME_V7_KEY;
const cert = process.env.CRACKME_V7_CERT;
if (key && cert) {
  if (sha(key) === seal.keySha256 && sha(cert) === seal.certSha256) {
    const r = run(["license", "activate", key]);
    must(r.status === 0, "release unlock failed: " + (r.stderr || r.stdout));
    must(r.stdout.includes("Activation certificate: " + cert), "certificate mismatch");
    console.log("[v7-seal] OK: release unlock (secrets present)");
  } else {
    console.log("[v7-seal] NOTE: CRACKME_V7_KEY/CERT set but digests do not match SEAL — release unlock skipped");
  }
} else {
  console.log("[v7-seal] NOTE: CRACKME_V7_KEY/CERT unset — release unlock skipped");
}

console.log("[v7-seal] OK: CrackMe v7 seal passed");
