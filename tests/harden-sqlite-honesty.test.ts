import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getDatabaseSyncClass, isNodeSqliteAvailable } from "../src/core/sqlite-runtime.js";
import { auditTarget } from "../src/engine/auditor.js";
import { hardenProject, type HardenProjectReport } from "../src/engine/harden.js";
import { handleMcpRequest } from "../src/mcp/server.js";

/**
 * What hardening a SQLite database is, and is not.
 *
 * The shield adds decoy tables. It does not hide the application's own rows,
 * and by default it must not break the application's own maintenance commands.
 * The form that makes an inspector's read of a decoy table fail also breaks
 * `PRAGMA integrity_check` and `VACUUM` for everyone, so it is opt-in — and
 * the report has to spell out both facts.
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const ROW = { account_id: "acct_prod_01", plan_tier: "enterprise", offline_token: "tok_live_9988776655" };

function project(config?: Record<string, unknown>): string {
  const dir = tempDir("bla-sqlite-honesty-");
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "ships-a-db", version: "1.0.0" }));
  if (config !== undefined) writeFileSync(join(dir, "bla.config.json"), JSON.stringify(config));
  const DatabaseSync = getDatabaseSyncClass();
  const db = new DatabaseSync(join(dir, "dist", "app.sqlite"));
  try {
    db.exec(
      `CREATE TABLE license_cache(account_id TEXT PRIMARY KEY, plan_tier TEXT NOT NULL, offline_token TEXT NOT NULL);
       INSERT INTO license_cache VALUES ('${ROW.account_id}', '${ROW.plan_tier}', '${ROW.offline_token}');
       PRAGMA user_version = 7;`,
    );
  } finally {
    db.close();
  }
  return dir;
}

function harden(dir: string, extra: Record<string, unknown> = {}): HardenProjectReport {
  return hardenProject({
    directory: dir,
    seed: "sqlite-honesty",
    applyStateRoot: tempDir("bla-sqlite-state-"),
    ...extra,
  });
}

/** What a client that registers nothing — the application, an inspector — gets. */
function onStockConnection(file: string): Record<string, string> {
  const DatabaseSync = getDatabaseSyncClass();
  const db = new DatabaseSync(file);
  const attempt = (run: () => unknown): string => {
    try {
      return JSON.stringify(run());
    } catch (err) {
      return `ERROR ${(err as Error).message}`;
    }
  };
  try {
    return {
      business: attempt(() => db.prepare("SELECT * FROM license_cache").all()),
      honey: attempt(() => db.prepare("SELECT * FROM enclave_key_hierarchy LIMIT 1").all().length),
      integrity: attempt(() => db.prepare("PRAGMA integrity_check").all()),
      vacuum: attempt(() => (db.exec("VACUUM"), "done")),
    };
  } finally {
    db.close();
  }
}

describe.skipIf(!isNodeSqliteAvailable())("hardening a SQLite database", () => {
  it("by default leaves a database every client can still check, vacuum and read — and says the rows are not hidden", () => {
    const dir = project();
    const report = harden(dir);
    expect(report.overallSuccess).toBe(true);
    const artifact = report.artifacts[0]!;
    expect(artifact).toMatchObject({ relativePath: "dist/app.sqlite", format: "sqlite", success: true });
    expect(report.sqliteEvalTrapArtifacts).toBeUndefined();

    expect(onStockConnection(artifact.outputPath)).toEqual({
      business: JSON.stringify([ROW]),
      honey: "1",
      integrity: JSON.stringify([{ integrity_check: "ok" }]),
      vacuum: JSON.stringify("done"),
    });

    // Decoys are not confidentiality: the score is capped and the report says why.
    expect(artifact.defenseScore).toBeLessThanOrEqual(68);
    const steps = report.nextSteps?.join("\n") ?? "";
    expect(steps).toMatch(
      /dist\/app\.sqlite now holds decoy tables beside the application's own tables, which are stored exactly as before: anyone who opens the file reads them\. BLA does not encrypt a database/,
    );
    expect(steps).not.toMatch(/evaluation-trap columns/);

    // The audit of the hardened file does not claim a failure that cannot happen.
    const audit = auditTarget(artifact.outputPath);
    expect(audit.reaSimulation.triggeredResourceLimits.join(" ")).not.toMatch(/SqliteColumnEvaluationFailure/);
    expect(audit.reaSimulation.triggeredResourceLimits).toContain("sqlite-enclave-honey-tables");
    const business = audit.exposedItems.find((item) => item.id.startsWith("sqlite_business_"))!;
    expect(business.riskLevel).toBe("critical");
    expect(business.name).toContain("license_cache");
    expect(business.reason).toMatch(/does not encrypt a database/);
  }, 120000);

  it("with sqliteEvalTrap stops a row read of the decoy tables, and reports what else stops", () => {
    const dir = project();
    const report = harden(dir, { sqliteEvalTrap: true });
    expect(report.overallSuccess).toBe(true);
    const artifact = report.artifacts[0]!;
    expect(report.sqliteEvalTrapArtifacts).toEqual(["dist/app.sqlite"]);

    const stock = onStockConnection(artifact.outputPath);
    expect(stock.business).toBe(JSON.stringify([ROW]));
    expect(stock.honey).toMatch(/^ERROR .*enclave_unseal_payload/);
    expect(stock.integrity).toMatch(/^ERROR .*enclave_unseal_payload/);
    expect(stock.vacuum).toMatch(/^ERROR .*enclave_unseal_payload/);

    const steps = report.nextSteps?.join("\n") ?? "";
    expect(steps).toMatch(/now holds decoy tables beside the application's own tables/);
    expect(steps).toMatch(
      /dist\/app\.sqlite carries evaluation-trap columns \(sqlite_eval_trap\)\. .* PRAGMA integrity_check, PRAGMA quick_check, VACUUM and a dump\/restore fail\./,
    );
    expect(steps).toMatch(/register a deterministic one-argument SQL function named enclave_unseal_payload/);
    expect(artifact.defenseScore).toBeLessThanOrEqual(78);
    expect(artifact.defenseScore).toBeGreaterThan(68);
    expect(
      auditTarget(artifact.outputPath).reaSimulation.triggeredResourceLimits.join(" "),
    ).toMatch(/SqliteColumnEvaluationFailure/);

    // The way out the report names: the application registers the function itself.
    const DatabaseSync = getDatabaseSyncClass();
    const db = new DatabaseSync(artifact.outputPath);
    try {
      db.function("enclave_unseal_payload", { deterministic: true }, (value: unknown) => `x:${String(value ?? "")}`);
      expect(db.prepare("PRAGMA integrity_check").all()).toEqual([{ integrity_check: "ok" }]);
      db.exec("VACUUM");
      expect(db.prepare("SELECT * FROM license_cache").all()).toEqual([ROW]);
    } finally {
      db.close();
    }
  }, 120000);

  it("takes the opt-in from the project config, and a dry run promises nothing", () => {
    const dir = project({ sqliteEvalTrap: true });
    const preview = harden(dir, { dryRun: true });
    expect(preview.sqliteEvalTrapArtifacts).toBeUndefined();
    expect(preview.nextSteps?.join("\n") ?? "").not.toMatch(/evaluation-trap columns|decoy tables beside/);

    const report = harden(dir);
    expect(report.sqliteEvalTrapArtifacts).toEqual(["dist/app.sqlite"]);
    expect(onStockConnection(report.artifacts[0]!.outputPath).honey).toMatch(/^ERROR/);
  }, 120000);

  it("MCP: sqlite_eval_trap reaches the shield, and is off unless asked for", async () => {
    const call = async (args: Record<string, unknown>) => {
      const res = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "bla_harden", arguments: args },
      });
      expect(res?.error).toBeUndefined();
      return (res!.result as { structuredContent: Record<string, any> }).structuredContent;
    };
    const plain = await call({ directory: project(), seed: "sqlite-honesty" });
    expect(plain.sqliteEvalTrapArtifacts).toBeUndefined();
    expect(onStockConnection(plain.artifacts[0].outputPath).integrity).toBe(
      JSON.stringify([{ integrity_check: "ok" }]),
    );

    const trapped = await call({ directory: project(), seed: "sqlite-honesty", sqlite_eval_trap: true });
    expect(trapped.sqliteEvalTrapArtifacts).toEqual(["dist/app.sqlite"]);
    expect(trapped.nextSteps.join("\n")).toMatch(/evaluation-trap columns \(sqlite_eval_trap\)/);
    expect(onStockConnection(trapped.artifacts[0].outputPath).integrity).toMatch(/^ERROR/);
  }, 120000);
});
