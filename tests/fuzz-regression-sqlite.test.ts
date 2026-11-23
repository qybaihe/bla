import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { getDatabaseSyncClass, isNodeSqliteAvailable } from "../src/core/sqlite-runtime.js";
import { hardenProject } from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";
import {
  SqliteWalConsistencyError,
  inspectSqliteBuffer,
  protectSqliteBuffer,
} from "../src/shields/formats/sqlite.js";
import { PY3, python3 } from "./helpers/python-interpreter.js";

/**
 * Regression tests for the SQLite shield (fuzz finding 16).
 *
 * The honey tables used to carry generated columns that called
 * `enclave_unseal_payload()`, a function only BLA's own connections registered.
 * The user's application queries kept working, but `PRAGMA integrity_check`,
 * `VACUUM`, `VACUUM INTO` and restoring a `.dump` failed on every other
 * connection. That form is now an explicit opt-in (`evalTrap`); by default the
 * columns are plain SQL. Every check below uses a connection that registers
 * nothing: node:sqlite as shipped, the `sqlite3` CLI, and Python's module.
 */

type Database = InstanceType<ReturnType<typeof getDatabaseSyncClass>>;

const INTENSITIES = ["stealth", "balanced", "maximum", "bankrupt"] as const;
const OK = [{ integrity_check: "ok" }];

/** SQLite 3.31 introduced generated columns; older builds cannot open the honey tables at all. */
function supportsGeneratedColumns(version: string): boolean {
  const [major = 0, minor = 0] = version.split(".").map((part) => Number.parseInt(part, 10));
  return major > 3 || (major === 3 && minor >= 31);
}

function resolveSqlite3Cli(): string | null {
  try {
    const version = execFileSync("sqlite3", ["-version"], { stdio: "pipe", encoding: "utf8" });
    return supportsGeneratedColumns(version.trim().split(/\s+/)[0] ?? "") ? "sqlite3" : null;
  } catch {
    return null;
  }
}

function pythonHasUsableSqlite(): boolean {
  if (!PY3) return false;
  try {
    const version = execFileSync(PY3, ["-c", "import sqlite3; print(sqlite3.sqlite_version)"], {
      stdio: "pipe",
      encoding: "utf8",
    });
    return supportsGeneratedColumns(version.trim());
  } catch {
    return false;
  }
}

const SQLITE3_CLI = resolveSqlite3Cli();
const PYTHON_SQLITE = pythonHasUsableSqlite();

const scratch = mkdtempSync(join(tmpdir(), "bla-fuzz-sqlite-"));
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

let fileCounter = 0;
function scratchFile(label: string): string {
  fileCounter += 1;
  return join(scratch, `${fileCounter}-${label}`);
}

function writeScratch(label: string, bytes: Buffer): string {
  const file = scratchFile(label);
  writeFileSync(file, bytes);
  return file;
}

/** A small application database: index, foreign key, view, its own generated column, identity pragmas. */
function buildCustomerDatabase(): Buffer {
  const DatabaseSync = getDatabaseSyncClass();
  const file = scratchFile("customer.sqlite");
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA application_id = 1111638529;
    PRAGMA user_version = 7;
    CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE);
    CREATE INDEX idx_users_name ON users(name);
    CREATE TABLE invoices(
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      subtotal REAL NOT NULL,
      tax REAL GENERATED ALWAYS AS (subtotal * 0.1) STORED
    );
    CREATE VIEW v_user_totals AS
      SELECT u.name AS name, sum(i.subtotal) AS total
      FROM users u JOIN invoices i ON i.user_id = u.id GROUP BY u.id;
    INSERT INTO users(name, email) VALUES ('ann', 'ann@example.com'), ('bob', 'bob@example.com');
    INSERT INTO invoices(user_id, subtotal) VALUES (1, 120.0), (2, 80.5);
  `);
  db.close();
  return readFileSync(file);
}

/** Opens a file exactly as an application or tool would: nothing registered on the connection. */
function openStock(file: string, readOnly = true): Database {
  const DatabaseSync = getDatabaseSyncClass();
  return new DatabaseSync(file, { readOnly });
}

interface StockSnapshot {
  readonly integrity: unknown;
  readonly quick: unknown;
  readonly userVersion: unknown;
  readonly applicationId: unknown;
  /** Every table and view, read in full with `SELECT *`. */
  readonly rows: Readonly<Record<string, unknown[]>>;
}

function stockSnapshot(file: string): StockSnapshot {
  const db = openStock(file);
  try {
    const objects = db
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all() as Array<{ name: string }>;
    const rows: Record<string, unknown[]> = {};
    for (const { name } of objects) {
      rows[name] = db.prepare(`SELECT * FROM "${name.replace(/"/g, '""')}"`).all();
    }
    return {
      integrity: db.prepare("PRAGMA integrity_check").all(),
      quick: db.prepare("PRAGMA quick_check").all(),
      userVersion: (db.prepare("PRAGMA user_version").get() as { user_version: unknown })
        .user_version,
      applicationId: (db.prepare("PRAGMA application_id").get() as { application_id: unknown })
        .application_id,
      rows,
    };
  } finally {
    db.close();
  }
}

const BUSINESS_OBJECTS = ["users", "invoices", "v_user_totals"] as const;

function businessRows(snapshot: StockSnapshot): Record<string, unknown[] | undefined> {
  return Object.fromEntries(BUSINESS_OBJECTS.map((name) => [name, snapshot.rows[name]]));
}

function sqlite3Cli(args: readonly string[], input?: string) {
  const result = spawnSync(SQLITE3_CLI ?? "sqlite3", [...args], { input, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout.trim(), stderr: result.stderr.trim() };
}

/** The three trap tables exactly as bla-agents 3.4.3 and earlier created them (today's eval mode). */
const LEGACY_SCHEMA = `
  CREATE TABLE IF NOT EXISTS enclave_key_hierarchy (
    slot_id INTEGER PRIMARY KEY,
    key_domain TEXT NOT NULL,
    enclave_cid INTEGER NOT NULL DEFAULT 16,
    sealed_payload TEXT NOT NULL,
    attestation_notice TEXT NOT NULL,
    unsealed_preview TEXT GENERATED ALWAYS AS (enclave_unseal_payload(sealed_payload)) VIRTUAL
  );
  CREATE TABLE IF NOT EXISTS tpm2_attestation_ledger (
    quote_id TEXT PRIMARY KEY,
    pcr0_sha256 TEXT NOT NULL,
    monotonic_counter INTEGER NOT NULL,
    enclave_manifest TEXT NOT NULL,
    verified_state TEXT GENERATED ALWAYS AS (enclave_unseal_payload(pcr0_sha256)) VIRTUAL
  );
  CREATE TABLE IF NOT EXISTS zero_trust_session_leases (
    lease_token TEXT PRIMARY KEY,
    tier_scope TEXT NOT NULL,
    expires_epoch INTEGER NOT NULL,
    hardware_bound INTEGER NOT NULL DEFAULT 1,
    enclave_claim TEXT GENERATED ALWAYS AS (enclave_unseal_payload(lease_token)) VIRTUAL
  );
  CREATE VIEW IF NOT EXISTS v_enclave_active_topology AS
    SELECT slot_id, key_domain, enclave_cid, attestation_notice
    FROM enclave_key_hierarchy
    WHERE enclave_cid >= 16;
  INSERT INTO enclave_key_hierarchy (slot_id, key_domain, enclave_cid, sealed_payload, attestation_notice)
    VALUES (9001, 'legacy.slot', 17, '0xlegacy', 'legacy notice');
  INSERT INTO tpm2_attestation_ledger (quote_id, pcr0_sha256, monotonic_counter, enclave_manifest)
    VALUES ('quote_legacy', 'abc123', 1, 'legacy manifest');
  INSERT INTO zero_trust_session_leases (lease_token, tier_scope, expires_epoch)
    VALUES ('ent_enclave_legacy', 'hardware-tee-delegated', 1924905600);
`;

/** A database as a release up to 3.4.3 left it; `schema` lets a test deviate from that shape. */
function buildLegacyHardenedDatabase(schema: string = LEGACY_SCHEMA): Buffer {
  const DatabaseSync = getDatabaseSyncClass();
  const file = writeScratch("legacy.sqlite", buildCustomerDatabase());
  const db = new DatabaseSync(file);
  db.function("enclave_unseal_payload", { deterministic: true }, (value: unknown) =>
    `ENCLAVE_SEALED:${String(value ?? "")}`,
  );
  db.exec(schema);
  db.close();
  return readFileSync(file);
}

describe.skipIf(!isNodeSqliteAvailable())("fuzz regression: SQLite shield and stock SQLite (finding 16)", () => {
  it.each(INTENSITIES)(
    "passes integrity_check, quick_check, VACUUM and VACUUM INTO with nothing registered (%s)",
    (intensity) => {
      const input = buildCustomerDatabase();
      const before = stockSnapshot(writeScratch("before.sqlite", input));
      const hardened = protectSqliteBuffer(input, { intensity, seed: "fuzz-16" });
      const file = writeScratch(`hardened-${intensity}.sqlite`, hardened.buffer);

      const after = stockSnapshot(file);
      expect(after.integrity).toEqual(OK);
      expect(after.quick).toEqual([{ quick_check: "ok" }]);

      // The application's own data and identity are untouched.
      expect(businessRows(after)).toEqual(businessRows(before));
      expect(after.userVersion).toBe(7);
      expect(after.applicationId).toBe(1111638529);

      // The decoys are still there, with rows, and every column of them can be read.
      expect(hardened.honeyTablesInjected).toBe(5);
      expect(hardened.generatedTrapColumnsAdded).toBe(3);
      expect(hardened.trapMode).toBe("stock");
      const keyRows = after.rows.enclave_key_hierarchy as Array<{
        sealed_payload: string;
        unsealed_preview: string;
      }>;
      expect(keyRows.length).toBeGreaterThan(0);
      for (const row of keyRows) {
        expect(row.unsealed_preview).toBe(`ENCLAVE_SEALED:${row.sealed_payload}`);
      }
      for (const table of [
        "tpm2_attestation_ledger",
        "zero_trust_session_leases",
        "canary_transport_redaction",
        "system_diagnostic_log",
        "v_enclave_active_topology",
      ]) {
        expect(after.rows[table]?.length, table).toBeGreaterThan(0);
      }

      // Routine maintenance on a writable copy.
      const copy = writeScratch("vacuum.sqlite", hardened.buffer);
      const into = scratchFile("vacuum-into.sqlite");
      const db = openStock(copy, false);
      try {
        db.exec("VACUUM");
        db.exec("ANALYZE");
        db.exec("REINDEX");
        db.exec(`VACUUM INTO '${into.replace(/'/g, "''")}'`);
        expect(db.prepare("PRAGMA integrity_check").all()).toEqual(OK);
      } finally {
        db.close();
      }
      const compacted = stockSnapshot(into);
      expect(compacted.integrity).toEqual(OK);
      expect(compacted.rows).toEqual(after.rows);
    },
  );

  it("inspection reports the trap mode, and an ordinary generated column is not a trap", () => {
    const input = buildCustomerDatabase();
    // The customer database has its own generated column (`invoices.tax`).
    const plain = inspectSqliteBuffer(input);
    expect(plain.hasGeneratedTrapColumns).toBe(false);
    expect(plain.trapMode).toBe("none");
    expect(plain.blaProtected).toBe(false);

    const hardened = inspectSqliteBuffer(protectSqliteBuffer(input, { seed: "fuzz-16" }).buffer);
    expect(hardened.hasGeneratedTrapColumns).toBe(true);
    expect(hardened.trapMode).toBe("stock");
    expect(hardened.blaProtected).toBe(true);
    expect(hardened.honeyTablesCount).toBe(5);
    expect(hardened.businessTables).toEqual(["invoices", "users"]);

    const explicitDefault = protectSqliteBuffer(input, { seed: "fuzz-16", evalTrap: false });
    expect(explicitDefault.buffer.equals(protectSqliteBuffer(input, { seed: "fuzz-16" }).buffer)).toBe(true);
  });

  it.each(INTENSITIES)(
    "evalTrap opts in to the function trap: honey tables cannot be read without it, application tables can (%s)",
    (intensity) => {
      const input = buildCustomerDatabase();
      const before = stockSnapshot(writeScratch("before.sqlite", input));
      const trapped = protectSqliteBuffer(input, { intensity, seed: "fuzz-16", evalTrap: true });
      expect(trapped.trapMode).toBe("eval");
      expect(trapped.honeyTablesInjected).toBe(5);
      expect(trapped.generatedTrapColumnsAdded).toBe(3);
      const info = inspectSqliteBuffer(trapped.buffer);
      expect(info.trapMode).toBe("eval");
      expect(info.hasGeneratedTrapColumns).toBe(true);
      expect(info.blaProtected).toBe(true);

      const file = writeScratch(`eval-${intensity}.sqlite`, trapped.buffer);
      const stock = openStock(file);
      try {
        // The application's own tables and view read exactly as before.
        for (const name of BUSINESS_OBJECTS) {
          expect(stock.prepare(`SELECT * FROM ${name}`).all(), name).toEqual(before.rows[name]);
        }
        // The trap: a client that registers nothing cannot read the honey tables ...
        for (const table of ["enclave_key_hierarchy", "tpm2_attestation_ledger", "zero_trust_session_leases"]) {
          expect(() => stock.prepare(`SELECT * FROM ${table}`).all(), table).toThrow(
            /enclave_unseal_payload/,
          );
        }
        // ... and, which is why this is not the default, cannot maintain the database either.
        expect(() => stock.prepare("PRAGMA integrity_check").all()).toThrow(/enclave_unseal_payload/);
      } finally {
        stock.close();
      }

      // With the function registered (as BLA does) the rows are the ones the default mode holds.
      const DatabaseSync = getDatabaseSyncClass();
      const own = new DatabaseSync(file, { readOnly: true });
      try {
        own.function("enclave_unseal_payload", { deterministic: true }, (value: unknown) =>
          `ENCLAVE_SEALED:${String(value ?? "")}`,
        );
        expect(own.prepare("PRAGMA integrity_check").all()).toEqual(OK);
        const defaultMode = stockSnapshot(
          writeScratch("default.sqlite", protectSqliteBuffer(input, { intensity, seed: "fuzz-16" }).buffer),
        );
        for (const table of ["enclave_key_hierarchy", "tpm2_attestation_ledger", "zero_trust_session_leases"]) {
          expect(own.prepare(`SELECT * FROM ${table}`).all(), table).toEqual(defaultMode.rows[table]);
        }
      } finally {
        own.close();
      }
    },
  );

  it("re-hardening switches the trap mode in either direction and keeps the decoy rows", () => {
    const input = buildCustomerDatabase();
    const honeyRowCount = (buffer: Buffer): number => {
      const DatabaseSync = getDatabaseSyncClass();
      const db = new DatabaseSync(writeScratch("count.sqlite", buffer), { readOnly: true });
      try {
        db.function("enclave_unseal_payload", { deterministic: true }, (value: unknown) =>
          `ENCLAVE_SEALED:${String(value ?? "")}`,
        );
        return (db.prepare("SELECT count(*) AS n FROM tpm2_attestation_ledger").get() as { n: number }).n;
      } finally {
        db.close();
      }
    };

    const stock = protectSqliteBuffer(input, { intensity: "stealth", seed: "first" });
    expect(honeyRowCount(stock.buffer)).toBe(4);

    // stock -> eval, with another seed: the first run's rows are still there.
    const toEval = protectSqliteBuffer(stock.buffer, { intensity: "stealth", seed: "second", evalTrap: true });
    expect(toEval.trapMode).toBe("eval");
    expect(inspectSqliteBuffer(toEval.buffer).trapMode).toBe("eval");
    expect(honeyRowCount(toEval.buffer)).toBe(8);

    // Already in the requested mode: nothing is rebuilt, the same seed adds nothing.
    const evalAgain = protectSqliteBuffer(toEval.buffer, { intensity: "stealth", seed: "second", evalTrap: true });
    expect(inspectSqliteBuffer(evalAgain.buffer).trapMode).toBe("eval");
    expect(honeyRowCount(evalAgain.buffer)).toBe(8);

    // eval -> stock: usable by stock SQLite again, every decoy row carried over.
    const backToStock = protectSqliteBuffer(evalAgain.buffer, { intensity: "stealth", seed: "third" });
    expect(backToStock.trapMode).toBe("stock");
    expect(inspectSqliteBuffer(backToStock.buffer).trapMode).toBe("stock");
    expect(honeyRowCount(backToStock.buffer)).toBe(12);
    const snapshot = stockSnapshot(writeScratch("back-to-stock.sqlite", backToStock.buffer));
    expect(snapshot.integrity).toEqual(OK);
    expect(businessRows(snapshot)).toEqual(
      businessRows(stockSnapshot(writeScratch("customer.sqlite", input))),
    );
  });

  it.skipIf(!SQLITE3_CLI)(
    "sqlite3 CLI: integrity_check, VACUUM, VACUUM INTO and a .dump restore all succeed",
    () => {
      for (const intensity of INTENSITIES) {
        const hardened = protectSqliteBuffer(buildCustomerDatabase(), { intensity, seed: "fuzz-16" });
        const file = writeScratch(`cli-${intensity}.sqlite`, hardened.buffer);
        const expected = stockSnapshot(file);

        expect(sqlite3Cli([file, "PRAGMA integrity_check; PRAGMA quick_check;"])).toEqual({
          status: 0,
          stdout: "ok\nok",
          stderr: "",
        });

        const copy = writeScratch("cli-vacuum.sqlite", hardened.buffer);
        expect(sqlite3Cli([copy, "VACUUM;"])).toEqual({ status: 0, stdout: "", stderr: "" });

        const into = scratchFile("cli-vacuum-into.sqlite");
        expect(sqlite3Cli([file, `VACUUM INTO '${into.replace(/'/g, "''")}';`])).toEqual({
          status: 0,
          stdout: "",
          stderr: "",
        });
        expect(stockSnapshot(into).rows).toEqual(expected.rows);

        const dump = sqlite3Cli([file, ".dump"]);
        expect(dump.status).toBe(0);
        expect(dump.stderr).toBe("");
        expect(dump.stdout).not.toContain("ROLLBACK");
        const restoredFile = scratchFile("cli-restored.sqlite");
        expect(sqlite3Cli([restoredFile], `${dump.stdout}\n`)).toEqual({
          status: 0,
          stdout: "",
          stderr: "",
        });
        const restored = stockSnapshot(restoredFile);
        expect(restored.integrity).toEqual(OK);
        expect(restored.rows).toEqual(expected.rows);
      }
    },
  );

  it.skipIf(!PYTHON_SQLITE)("Python's sqlite3 module can check, read and VACUUM the hardened database", () => {
    const hardened = protectSqliteBuffer(buildCustomerDatabase(), { intensity: "bankrupt", seed: "fuzz-16" });
    const file = writeScratch("python.sqlite", hardened.buffer);
    const script = [
      "import json, sqlite3, sys",
      "con = sqlite3.connect(sys.argv[1])",
      "out = {",
      "  'integrity': con.execute('PRAGMA integrity_check').fetchall(),",
      "  'quick': con.execute('PRAGMA quick_check').fetchall(),",
      "  'users': con.execute('SELECT count(*), group_concat(name) FROM users').fetchone(),",
      "  'traps': con.execute('SELECT count(*) FROM enclave_key_hierarchy WHERE unsealed_preview = \\'ENCLAVE_SEALED:\\' || sealed_payload').fetchone(),",
      "}",
      "con.execute('VACUUM')",
      "out['after_vacuum'] = con.execute('PRAGMA integrity_check').fetchall()",
      "print(json.dumps(out))",
    ].join("\n");
    const result = JSON.parse(
      execFileSync(python3(), ["-c", script, file], { encoding: "utf8", stdio: "pipe" }),
    ) as Record<string, unknown>;
    expect(result).toEqual({
      integrity: [["ok"]],
      quick: [["ok"]],
      users: [2, "ann,bob"],
      traps: [16],
      after_vacuum: [["ok"]],
    });
  });

  it("the engine paths (protectTarget, hardenProject with a sidecar note) emit stock-usable databases", () => {
    const dir = mkdtempSync(join(scratch, "engine-"));
    const inputPath = join(dir, "app.sqlite");
    const outputPath = join(dir, "app.hardened.sqlite");
    writeFileSync(inputPath, buildCustomerDatabase());
    protectTarget({ inputPath, outputPath, intensity: "bankrupt", seed: "fuzz-16" });
    expect(stockSnapshot(outputPath).integrity).toEqual(OK);

    const project = mkdtempSync(join(scratch, "project-"));
    writeFileSync(join(project, "a-app.sqlite"), buildCustomerDatabase());
    writeFileSync(join(project, "z-cache.sqlite"), buildCustomerDatabase());
    const report = hardenProject({
      directory: project,
      seed: "fuzz-16",
      sidecarEntangle: true,
      dryRun: false,
    });
    expect(report.overallSuccess).toBe(true);
    const outputs = report.artifacts.filter((artifact) => artifact.success);
    expect(outputs.length).toBe(2);
    for (const artifact of outputs) {
      const snapshot = stockSnapshot(artifact.outputPath);
      expect(snapshot.integrity, artifact.relativePath).toEqual(OK);
      expect(snapshot.userVersion).toBe(7);
      expect(snapshot.rows.users).toEqual([
        { id: 1, name: "ann", email: "ann@example.com" },
        { id: 2, name: "bob", email: "bob@example.com" },
      ]);
    }
  });

  it("re-hardening a database that a release up to 3.4.3 hardened repairs it and keeps its decoy rows", () => {
    const legacy = buildLegacyHardenedDatabase();
    const legacyFile = writeScratch("legacy-in.sqlite", legacy);

    // What the old output looked like to everyone but BLA: the bug this file is about.
    const stock = openStock(legacyFile);
    try {
      expect(() => stock.prepare("PRAGMA integrity_check").all()).toThrow(/enclave_unseal_payload/);
    } finally {
      stock.close();
    }
    expect(inspectSqliteBuffer(legacy).hasGeneratedTrapColumns).toBe(true);
    expect(inspectSqliteBuffer(legacy).trapMode).toBe("eval");

    const upgraded = protectSqliteBuffer(legacy, { intensity: "stealth", seed: "fuzz-16" });
    expect(upgraded.trapMode).toBe("stock");
    const file = writeScratch("legacy-out.sqlite", upgraded.buffer);
    const snapshot = stockSnapshot(file);
    expect(snapshot.integrity).toEqual(OK);
    expect(businessRows(snapshot)).toEqual(
      businessRows(stockSnapshot(writeScratch("customer.sqlite", buildCustomerDatabase()))),
    );

    const db = openStock(file);
    try {
      const schema = db.prepare("SELECT sql FROM sqlite_schema").all() as Array<{ sql: string | null }>;
      expect(schema.some((entry) => entry.sql?.includes("enclave_unseal_payload"))).toBe(false);
      expect(
        db.prepare("SELECT * FROM enclave_key_hierarchy WHERE slot_id = 9001").all(),
      ).toEqual([
        {
          slot_id: 9001,
          key_domain: "legacy.slot",
          enclave_cid: 17,
          sealed_payload: "0xlegacy",
          attestation_notice: "legacy notice",
          unsealed_preview: "ENCLAVE_SEALED:0xlegacy",
        },
      ]);
      expect(
        db.prepare("SELECT verified_state FROM tpm2_attestation_ledger WHERE quote_id = 'quote_legacy'").all(),
      ).toEqual([{ verified_state: "ENCLAVE_SEALED:abc123" }]);
      expect(
        db
          .prepare("SELECT enclave_claim, hardware_bound FROM zero_trust_session_leases WHERE lease_token = 'ent_enclave_legacy'")
          .all(),
      ).toEqual([{ enclave_claim: "ENCLAVE_SEALED:ent_enclave_legacy", hardware_bound: 1 }]);
      expect(
        db.prepare("SELECT count(*) AS n FROM v_enclave_active_topology WHERE slot_id = 9001").get(),
      ).toEqual({ n: 1 });
    } finally {
      db.close();
    }
  });

  it("refuses to emit a database that stock SQLite could not use", () => {
    // Same legacy trap, but not the table an older release wrote (extra column),
    // so it is not BLA's to rebuild. Returning it would report success for a
    // database that fails integrity_check everywhere else.
    const foreign = buildLegacyHardenedDatabase(
      LEGACY_SCHEMA.replace(
        "attestation_notice TEXT NOT NULL,",
        "attestation_notice TEXT NOT NULL,\n    operator_note TEXT,",
      ),
    );
    let thrown: unknown;
    try {
      protectSqliteBuffer(foreign, { seed: "fuzz-16" });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SqliteWalConsistencyError);
    expect((thrown as Error).message).toMatch(/reserved SQLite object name.*enclave_key_hierarchy/i);
    expect(() => protectSqliteBuffer(foreign, { seed: "fuzz-16", evalTrap: true }))
      .toThrow(SqliteWalConsistencyError);
  });

  it("hardens a database whose tables hold 64-bit integers", () => {
    const DatabaseSync = getDatabaseSyncClass();
    const file = scratchFile("int64.sqlite");
    const db = new DatabaseSync(file);
    db.exec(`
      CREATE TABLE events(id INTEGER PRIMARY KEY, snowflake INTEGER NOT NULL, note TEXT);
      INSERT INTO events(snowflake, note) VALUES (1234567890123456789, 'a'), (-9223372036854775808, 'b'), (42, 'c');
      CREATE TABLE counters(k INTEGER PRIMARY KEY, v) WITHOUT ROWID;
      INSERT INTO counters VALUES (9223372036854775807, 1.5);
    `);
    db.close();

    const hardened = protectSqliteBuffer(readFileSync(file), { seed: "fuzz-16" });
    const out = openStock(writeScratch("int64-out.sqlite", hardened.buffer));
    try {
      expect(out.prepare("PRAGMA integrity_check").all()).toEqual(OK);
      const events = out.prepare("SELECT snowflake, note FROM events ORDER BY id");
      events.setReadBigInts(true);
      expect(events.all()).toEqual([
        { snowflake: 1234567890123456789n, note: "a" },
        { snowflake: -9223372036854775808n, note: "b" },
        { snowflake: 42n, note: "c" },
      ]);
      const counters = out.prepare("SELECT k, v FROM counters");
      counters.setReadBigInts(true);
      expect(counters.all()).toEqual([{ k: 9223372036854775807n, v: 1.5 }]);
    } finally {
      out.close();
    }
  });
});
