#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const pkgPath = resolve(root, "package.json");
const identityPath = resolve(root, "src/identity.ts");
const lockPath = resolve(root, "package-lock.json");

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
const version = String(pkg.version);

const identityText = readFileSync(identityPath, "utf8");
const updated = identityText.replace(
  /version:\s*"[^"]+"/,
  `version: "${version}"`,
);

if (updated !== identityText) {
  writeFileSync(identityPath, updated, "utf8");
  console.log(`Synced BLA_IDENTITY.version -> ${version}`);
} else {
  console.log(`BLA_IDENTITY.version already at ${version}`);
}

// Keep package-lock.json's root version in lockstep — `npm version` normally
// does this, but manual bumps / partial releases leave the lockfile behind and
// the drift silently passes CI (npm ci tolerates a root-version mismatch).
try {
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const rootEntry = lock.packages?.[""];
  const stale =
    lock.version !== version || (rootEntry && rootEntry.version !== version);
  if (stale) {
    lock.version = version;
    if (rootEntry) rootEntry.version = version;
    writeFileSync(lockPath, JSON.stringify(lock, null, 2) + "\n", "utf8");
    console.log(`Synced package-lock.json version -> ${version}`);
  } else {
    console.log(`package-lock.json already at ${version}`);
  }
} catch (err) {
  console.warn(`Skipped package-lock.json sync: ${err instanceof Error ? err.message : String(err)}`);
}
