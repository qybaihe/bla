import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withApplyTransaction } from "../src/engine/harden-apply.js";

const LOCK = "transaction.lock";
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-apply-lock-"));
  tempDirs.push(dir);
  return dir;
}

function writeLock(stateDir: string, owner?: { pid: number }): string {
  const lock = join(stateDir, LOCK);
  mkdirSync(lock);
  if (owner) {
    writeFileSync(
      join(lock, "owner.json"),
      JSON.stringify({ pid: owner.pid, startedAt: new Date().toISOString() }),
      "utf8",
    );
  }
  return lock;
}

function deadPid(): number {
  const child = spawnSync(process.execPath, ["-e", "0"]);
  return child.pid!;
}

describe("apply/restore transaction lock", () => {
  it("removes the lock after a successful action", () => {
    const stateDir = scratch();
    const result = withApplyTransaction(stateDir, () => {
      expect(existsSync(join(stateDir, LOCK))).toBe(true);
      return "done";
    });
    expect(result).toBe("done");
    expect(existsSync(join(stateDir, LOCK))).toBe(false);
  });

  it("refuses a lock owned by a live process even with clearStaleLock", () => {
    const stateDir = scratch();
    const lock = writeLock(stateDir, { pid: process.pid });
    expect(() =>
      withApplyTransaction(stateDir, () => "never", { clearStaleLock: true }),
    ).toThrow(/live process/i);
    expect(existsSync(lock)).toBe(true);
  });

  it("refuses a lock without an owner record", () => {
    const stateDir = scratch();
    const lock = writeLock(stateDir);
    expect(() =>
      withApplyTransaction(stateDir, () => "never", { clearStaleLock: true }),
    ).toThrow(/no owner record/i);
    expect(existsSync(lock)).toBe(true);
  });

  it("clears a lock whose recorded owner has exited", () => {
    const stateDir = scratch();
    const lock = writeLock(stateDir, { pid: deadPid() });
    const result = withApplyTransaction(stateDir, () => "recovered", {
      clearStaleLock: true,
    });
    expect(result).toBe("recovered");
    expect(existsSync(lock)).toBe(false);
  });

  it("keeps a dead owner's lock without the explicit flag", () => {
    const stateDir = scratch();
    const lock = writeLock(stateDir, { pid: deadPid() });
    expect(() => withApplyTransaction(stateDir, () => "never")).toThrow(
      /re-run with --clear-stale-lock/i,
    );
    expect(existsSync(lock)).toBe(true);
  });
});