#!/usr/bin/env node
/**
 * CrackMe v6 reproducible build:
 *   CRACKME_V6_KEY=... CRACKME_V6_FLAG=... npm run crackme:build
 *   npm run crackme:build -- --fixture   # demo secret (not the published prize)
 *
 * Runs the real BLA protector API (same engine as `bla protect` / `bla harden`)
 * for L1/L2/L3 and writes challenge/v6/artifacts + commitment.json.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ARTIFACTS_DIR,
  BUILD_REPORT_PATH,
  COMMITMENT_PATH,
  V6_DIR,
  extractFlag,
  loadProfiles,
  materializeCleanTarget,
  protectTier,
  resolveSecrets,
  runCrackme,
  sha256File,
  sha256Hex,
  writeJson,
} from "./lib.mjs";

const fixture = process.argv.includes("--fixture");
const secrets = resolveSecrets({ fixture });
const profiles = loadProfiles();

const work = mkdtempSync(join(tmpdir(), "bla-crackme-v6-build-"));
const cleanPath = join(work, "target.cjs");

try {
  materializeCleanTarget({
    scope: profiles.scope,
    key: secrets.key,
    flag: secrets.flag,
    outputPath: cleanPath,
  });

  // Also materialize a gitignored local clean for debugging (release builds only).
  if (secrets.mode === "release") {
    materializeCleanTarget({
      scope: profiles.scope,
      key: secrets.key,
      flag: secrets.flag,
      outputPath: join(V6_DIR, "clean", "target.materialized.cjs"),
    });
  }

  const tierReports = {};
  const artifactDigests = {};
  const outDir = secrets.mode === "release" ? ARTIFACTS_DIR : join(ARTIFACTS_DIR, ".fixture");

  for (const [tierId, tier] of Object.entries(profiles.tiers)) {
    const outPath = join(outDir, `${tierId}.cjs`);
    const result = await protectTier({
      cleanPath,
      outPath,
      tier: { ...tier, id: tierId },
      seed: profiles.seed,
    });

    const unlocked = runCrackme(outPath, secrets.key);
    const denied = runCrackme(outPath, "definitely-not-the-key");
    const flag = extractFlag(unlocked.stdout);
    if (!unlocked.ok || flag !== secrets.flag) {
      throw new Error(
        `${tierId}: hardened artifact failed runtime unlock (status=${unlocked.status}).\n${unlocked.stdout}\n${unlocked.stderr}`,
      );
    }
    if (denied.ok || extractFlag(denied.stdout)) {
      throw new Error(`${tierId}: hardened artifact accepted a wrong key`);
    }

    artifactDigests[tierId] = sha256File(outPath);
    tierReports[tierId] = {
      intensity: tier.intensity,
      llmDirectives: tier.llmDirectives === true,
      honeySourceMaps: tier.honeySourceMaps !== false,
      originalBytes: result.metrics.originalBytes,
      protectedBytes: result.metrics.protectedBytes,
      decoyFunctionsInjected: result.metrics.decoyFunctionsInjected,
      counteredVectors: result.counteredVectors,
      artifactSha256: artifactDigests[tierId],
      seedUsed: `${profiles.seed}:${tier.intensity}:${tier.llmDirectives ? "llm" : "std"}`,
    };
    console.log(
      `[crackme:build] ${tierId} ok — ${result.metrics.originalBytes} → ${result.metrics.protectedBytes} bytes (${tier.intensity})`,
    );
  }

  const commitment = {
    version: 6,
    scope: profiles.scope,
    seed: profiles.seed,
    mode: secrets.mode,
    keySha256: sha256Hex(secrets.key),
    flagSha256: sha256Hex(secrets.flag),
    artifactSha256: artifactDigests,
    builtAt: new Date().toISOString(),
    note:
      secrets.mode === "fixture"
        ? "FIXTURE build — do not publish these digests as the public challenge commitment."
        : "Public commitment: prove a break by publishing SHA-256(FLAG{...}) matching flagSha256.",
  };

  const reportPath = secrets.mode === "release" ? BUILD_REPORT_PATH : join(outDir, "build-report.json");
  const commitmentOut = secrets.mode === "release" ? COMMITMENT_PATH : join(outDir, "commitment.json");
  writeJson(commitmentOut, commitment);
  writeJson(reportPath, {
    version: 6,
    mode: secrets.mode,
    tiers: tierReports,
    commitmentPath: commitmentOut,
  });

  console.log(`[crackme:build] done (${secrets.mode}) → ${outDir}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
