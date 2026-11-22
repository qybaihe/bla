import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { parseSiteSyncArgs, planSiteSync } from "../scripts/site-sync-plan.mjs";
import { syncSite } from "../scripts/sync-site.mjs";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("site sync dry-run planning", () => {
  it("parses --dry-run from argv", () => {
    expect(parseSiteSyncArgs(["node", "sync-site.mjs", "--dry-run"]).dryRun).toBe(
      true,
    );
    expect(parseSiteSyncArgs(["node", "sync-site.mjs"]).dryRun).toBe(false);
  });

  it("treats an empty porcelain status as up to date", () => {
    const plan = planSiteSync("");
    expect(plan.upToDate).toBe(true);
    expect(plan.changedPaths).toEqual([]);
  });

  it("extracts changed paths from porcelain status lines", () => {
    const plan = planSiteSync(" M website/index.html\n?? website/new.md\n");
    expect(plan.upToDate).toBe(false);
    expect(plan.changedPaths).toEqual(["website/index.html", "website/new.md"]);
  });

  it("runs git via execFileSync without a shell", () => {
    const source = fs.readFileSync(
      path.resolve(process.cwd(), "scripts/sync-site.mjs"),
      "utf8",
    );
    expect(source).toContain("execFileSync");
    expect(source).not.toMatch(/\bexecSync\b/);
    expect(source).not.toMatch(/\bshell\s*:\s*true\b/);
  });

  it("checks git status inside the cloned tmpDir, syncs changes, and ignores shell metacharacters in tmpBaseDir", () => {
    const sandbox = makeTempDir("bla-sync-site-test-");
    const bareRepo = path.join(sandbox, "origin.git");
    const seedWorktree = path.join(sandbox, "seed");
    const websiteDir = path.join(sandbox, "website");
    // Directory name containing spaces and shell metacharacters legal on POSIX & NTFS.
    // Under a shell-interpolated double-quoted string, `$(echo expanded)` would be
    // substituted into a different path and break clone/status; execFileSync passes it verbatim.
    const hostileTmpBase = path.join(sandbox, "tmp dir & $(echo expanded)");
    fs.mkdirSync(websiteDir, { recursive: true });
    fs.mkdirSync(hostileTmpBase, { recursive: true });

    const gitEnv: NodeJS.ProcessEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: "BLA Test",
      GIT_AUTHOR_EMAIL: "test@bla.local",
      GIT_COMMITTER_NAME: "BLA Test",
      GIT_COMMITTER_EMAIL: "test@bla.local",
      // Exercise Windows-style CRLF checkout normalization on every OS so a
      // line-ending-only mismatch never triggers a spurious `git commit`.
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.autocrlf",
      GIT_CONFIG_VALUE_0: "true",
    };
    const git = (args: string[], cwd?: string): string =>
      execFileSync("git", args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        stdio: "pipe",
      });

    git(["init", "--bare", bareRepo]);
    git(["--git-dir", bareRepo, "symbolic-ref", "HEAD", "refs/heads/main"]);
    git(["clone", pathToFileURL(bareRepo).href, seedWorktree]);
    git(["checkout", "-b", "main"], seedWorktree);
    fs.writeFileSync(path.join(seedWorktree, "index.html"), "<h1>v1</h1>\n");
    git(["add", "-A"], seedWorktree);
    git(["commit", "-m", "initial"], seedWorktree);
    git(["push", "origin", "main"], seedWorktree);

    fs.writeFileSync(path.join(websiteDir, "index.html"), "<h1>v2</h1>\n");
    fs.writeFileSync(path.join(websiteDir, "changelog.html"), "<p>new</p>\n");

    const repoUrl = pathToFileURL(bareRepo).href;

    // 1. Dry-run must inspect the cloned tmpDir (not process.cwd()) and report changes without pushing.
    const dryResult = syncSite({
      websiteDir,
      repoUrl,
      tmpBaseDir: hostileTmpBase,
      dryRun: true,
      quiet: true,
      gitEnv,
    });
    expect(dryResult.action).toBe("dry-run");
    expect([...dryResult.changedPaths].sort()).toEqual([
      "changelog.html",
      "index.html",
    ]);
    expect(
      git(["--git-dir", bareRepo, "rev-list", "--count", "refs/heads/main"]).trim(),
    ).toBe("1");

    // 2. Live sync must commit and push changes to main, and clean up its temp checkout.
    const pushResult = syncSite({
      websiteDir,
      repoUrl,
      tmpBaseDir: hostileTmpBase,
      dryRun: false,
      quiet: true,
      gitEnv,
    });
    expect(pushResult.action).toBe("pushed");
    expect(
      git(["--git-dir", bareRepo, "rev-list", "--count", "refs/heads/main"]).trim(),
    ).toBe("2");
    expect(
      git(["--git-dir", bareRepo, "show", "refs/heads/main:index.html"]),
    ).toBe("<h1>v2</h1>\n");
    expect(fs.readdirSync(hostileTmpBase)).toEqual([]);

    // 3. Re-running with identical website contents must report up-to-date and make no new commit.
    const upToDateResult = syncSite({
      websiteDir,
      repoUrl,
      tmpBaseDir: hostileTmpBase,
      dryRun: false,
      quiet: true,
      gitEnv,
    });
    expect(upToDateResult.action).toBe("up-to-date");
    expect(upToDateResult.changedPaths).toEqual([]);
    expect(
      git(["--git-dir", bareRepo, "rev-list", "--count", "refs/heads/main"]).trim(),
    ).toBe("2");
  });
});
