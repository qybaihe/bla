import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  getDatabaseSyncClass,
  isNodeSqliteAvailable,
} from "../src/core/sqlite-runtime.js";

const repoRoot = resolve(import.meta.dirname, "..");
const SQLITE_AVAILABLE = isNodeSqliteAvailable();
/** `--no-experimental-sqlite` exists only on Node 22+; Node 20 rejects it as a bad option. */
const SUPPORTS_NO_EXPERIMENTAL_SQLITE_FLAG =
  Number(process.versions.node.split(".")[0]!) >= 22;

describe("SQLite runtime floor", () => {
  it("declares only Node versions where node:sqlite DatabaseSync.function is unflagged", () => {
    const pkg = JSON.parse(
      readFileSync(resolve(repoRoot, "package.json"), "utf8"),
    ) as {
      engines?: { node?: string };
    };
    expect(pkg.engines?.node).toBe("^22.23.4 || >=24.0.0");
  });

  it("exposes an availability probe that matches getDatabaseSyncClass success", () => {
    expect(typeof isNodeSqliteAvailable()).toBe("boolean");
    if (SQLITE_AVAILABLE) {
      expect(() => getDatabaseSyncClass()).not.toThrow();
    } else {
      expect(() => getDatabaseSyncClass()).toThrow(/BLA SQLite support requires Node/);
    }
  });

  it.skipIf(!SQLITE_AVAILABLE)(
    "loads DatabaseSync with custom scalar function support on the supported runtime",
    () => {
      const DatabaseSync = getDatabaseSyncClass();
      expect(typeof DatabaseSync.prototype.function).toBe("function");
    },
  );

  it.skipIf(!SUPPORTS_NO_EXPERIMENTAL_SQLITE_FLAG)(
    "Allows non-SQLite CLI commands when node:sqlite is disabled",
    () => {
      const cli = resolve(repoRoot, "src/cli.ts");
      const result = spawnSync(
        process.execPath,
        ["--no-experimental-sqlite", "--import", "tsx", cli, "--version"],
        { cwd: repoRoot, encoding: "utf8" },
      );
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    },
  );

  it.skipIf(!SUPPORTS_NO_EXPERIMENTAL_SQLITE_FLAG)(
    "Reports a clear Node runtime requirement when SQLite protection runs without node:sqlite",
    () => {
      const script =
        "import { buildSampleSqliteDatabase } from './src/shields/formats/sqlite.ts'; buildSampleSqliteDatabase();";
      const result = spawnSync(
        process.execPath,
        [
          "--no-experimental-sqlite",
          "--import",
          "tsx",
          "--input-type=module",
          "-e",
          script,
        ],
        { cwd: repoRoot, encoding: "utf8" },
      );
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        "BLA SQLite support requires Node.js 22.x >=22.13.0 or Node.js >=24.0.0",
      );
    },
  );
});
