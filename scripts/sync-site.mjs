#!/usr/bin/env node
/**
 * Syncs ./website/* from qybaihe/bla to https://github.com/qybaihe/bla-site
 * Usage: npm run sync:site  |  node scripts/sync-site.mjs --dry-run
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseSiteSyncArgs, planSiteSync } from "./site-sync-plan.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const defaultWebsiteDir = path.join(rootDir, "website");
const defaultRepoUrl = "https://github.com/qybaihe/bla-site.git";

/**
 * Invoke git directly without a shell so paths (e.g. from TMPDIR/TEMP) are
 * never subject to shell quoting or command substitution.
 */
function runGit(args, options = {}) {
  return execFileSync("git", args, { stdio: "inherit", ...options });
}

export function syncSite(options = {}) {
  const {
    websiteDir = defaultWebsiteDir,
    repoUrl = defaultRepoUrl,
    tmpBaseDir = os.tmpdir(),
    dryRun = false,
    quiet = false,
    gitEnv,
  } = options;
  const tmpDir = fs.mkdtempSync(path.join(tmpBaseDir, "bla-site-sync-"));
  const defaultStdio = quiet ? "pipe" : "inherit";
  const git = (args, opts = {}) =>
    runGit(args, {
      stdio: defaultStdio,
      ...(gitEnv ? { env: gitEnv } : {}),
      ...opts,
    });

  try {
    if (!quiet) {
      console.log("Cloning qybaihe/bla-site...");
    }
    git(["clone", "--depth", "1", repoUrl, tmpDir]);

    // Only copy website content into the clone. Never overlay Git metadata or
    // import links that point outside the website tree.
    fs.cpSync(websiteDir, tmpDir, {
      recursive: true,
      force: true,
      filter: (source) => path.basename(source).toLowerCase() !== ".git" &&
        !fs.lstatSync(source).isSymbolicLink(),
    });

    // Stage in the throwaway clone before checking status so Git applies
    // line-ending normalization (e.g. core.autocrlf=true on Windows) and
    // `git status --porcelain` matches what `git commit` will actually commit.
    git(["add", "-A"], { cwd: tmpDir });

    const status = git(["status", "--porcelain"], {
      cwd: tmpDir,
      stdio: "pipe",
      encoding: "utf8",
    });
    const plan = planSiteSync(status);
    if (plan.upToDate) {
      if (!quiet) {
        console.log("qybaihe/bla-site is already up to date with ./website.");
      }
      return { action: "up-to-date", changedPaths: plan.changedPaths };
    }
    if (dryRun) {
      if (!quiet) {
        console.log(`Dry-run: ${plan.changedPaths.length} path(s) would be synced:`);
        for (const changed of plan.changedPaths) {
          console.log(`  ${changed}`);
        }
        console.log("Dry-run: no commit or push performed.");
      }
      return { action: "dry-run", changedPaths: plan.changedPaths };
    }
    git(["commit", "-m", "chore(site): sync website from qybaihe/bla"], {
      cwd: tmpDir,
    });
    git(["push", "origin", "main"], { cwd: tmpDir });
    if (!quiet) {
      console.log("Successfully synced ./website to https://github.com/qybaihe/bla-site");
    }
    return { action: "pushed", changedPaths: plan.changedPaths };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href;
  } catch {
    return import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
  }
}

if (isMainModule()) {
  const { dryRun } = parseSiteSyncArgs(process.argv);
  syncSite({ dryRun });
}
