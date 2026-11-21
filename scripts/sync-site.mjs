#!/usr/bin/env node
/**
 * Syncs ./website/* from qybaihe/bla to https://github.com/qybaihe/bla-site
 * Usage: npm run sync:site  |  node scripts/sync-site.mjs --dry-run
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseSiteSyncArgs, planSiteSync } from "./site-sync-plan.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const websiteDir = path.join(rootDir, "website");
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-site-sync-"));
const { dryRun } = parseSiteSyncArgs(process.argv);

/**
 * Run git with an argv array and no shell.
 *
 * `tmpDir` is derived from `os.tmpdir()`, so interpolating it into a shell
 * command string let any metacharacter in `TMPDIR`/`TEMP` — a `"` in particular —
 * escape the quoting and execute arbitrary commands with the release engineer's
 * or CI job's privileges. `release-plan.ts` already refuses a shell for the same
 * reason; every argument stays an opaque argv entry here too.
 */
function git(args, options = {}) {
  return execFileSync("git", args, { stdio: "inherit", ...options });
}

try {
  console.log("Cloning qybaihe/bla-site...");
  git(["clone", "--depth", "1", "https://github.com/qybaihe/bla-site.git", tmpDir]);

  // Copy all files from website/ to tmpDir
  fs.cpSync(websiteDir, tmpDir, { recursive: true, force: true });

  const status = git(["status", "--porcelain"], { stdio: "pipe", encoding: "utf8" });
  const plan = planSiteSync(status);
  if (plan.upToDate) {
    console.log("qybaihe/bla-site is already up to date with ./website.");
  } else if (dryRun) {
    console.log(`Dry-run: ${plan.changedPaths.length} path(s) would be synced:`);
    for (const changed of plan.changedPaths) {
      console.log(`  ${changed}`);
    }
    console.log("Dry-run: no commit or push performed.");
  } else {
    git(["add", "-A"], { cwd: tmpDir });
    git(["commit", "-m", "chore(site): sync website from qybaihe/bla"], { cwd: tmpDir });
    git(["push", "origin", "main"], { cwd: tmpDir });
    console.log("Successfully synced ./website to https://github.com/qybaihe/bla-site");
  }
} finally {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
