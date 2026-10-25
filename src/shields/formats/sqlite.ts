import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getDatabaseSyncClass } from "../../core/sqlite-runtime.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";

export interface SqliteInspectionSummary {
  readonly validSqlite: boolean;
  readonly tableNames: readonly string[];
  readonly honeyTablesCount: number;
  readonly hasGeneratedTrapColumns: boolean;
  readonly blaProtected: boolean;
}

/**
 * Inspects a SQLite 3 database file or buffer using `node:sqlite`.
 */
export function inspectSqliteBuffer(bytes: Buffer): SqliteInspectionSummary {
  if (
    bytes.length < 100 ||
    bytes.subarray(0, 16).toString("latin1") !== "SQLite format 3\0"
  ) {
    return {
      validSqlite: false,
      tableNames: [],
      honeyTablesCount: 0,
      hasGeneratedTrapColumns: false,
      blaProtected: false,
    };
  }

  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-inspect-"));
  const dbPath = join(tempDir, "inspect.sqlite");
  try {
    writeFileSync(dbPath, bytes);
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const rows = db
        .prepare(
          "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all() as Array<{ name: string; sql: string | null }>;

      const tableNames = rows.map((r) => r.name);
      const honeyTablesCount = tableNames.filter(
        (n) => n.startsWith("_bla_") || n.includes("enclave_"),
      ).length;
      const hasGeneratedTrapColumns = rows.some(
        (r) => typeof r.sql === "string" && r.sql.includes("GENERATED ALWAYS AS"),
      );
      const blaProtected = honeyTablesCount > 0 || hasGeneratedTrapColumns;

      return {
        validSqlite: true,
        tableNames,
        honeyTablesCount,
        hasGeneratedTrapColumns,
        blaProtected,
      };
    } finally {
      db.close();
    }
  } catch {
    return {
      validSqlite: false,
      tableNames: [],
      honeyTablesCount: 0,
      hasGeneratedTrapColumns: false,
      blaProtected: false,
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Protects a SQLite 3 database file (`.sqlite`, `.db`, `.sqlite3`) against
 * REA's `inspect-sqlite-database` (`src/sqlite/SqliteDatabaseInspection.ts`):
 *
 * 1. **Honey Tables & Enclave Ledger Rows**: Injects realistic enterprise TEE/SGX
 *    tables (`_bla_enclave_key_hierarchy`, `_bla_tpm2_attestation_ledger`,
 *    `_bla_zero_trust_session_leases`) populated with decoy cryptographic manifests.
 * 2. **Generated Column Expression Trap (`SqliteColumnEvaluationFailure`)**:
 *    Adds `GENERATED ALWAYS AS (bla_enclave_unseal(sealed_payload)) VIRTUAL` columns
 *    to honey tables (and optionally adds a virtual enclave audit column to existing tables).
 *    When REA opens the snapshot on its bare `readOnly: true, allowExtension: false`
 *    connection (`SqliteDatabaseInspection.ts:792`) without the `bla_enclave_unseal`
 *    application scalar function registered, REA's `SELECT` projection hits
 *    `SqliteColumnEvaluationFailure` (`SQLite cannot evaluate selected column(s) ... on REA's read-only connection`)!
 * 3. **Schema Inventory Chaff**: Adds decoy views and triggers referencing hardware
 *    enclave state so `rea inspect-sqlite-database` harvests decoy schema topology.
 */
export function protectSqliteBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly honeyTablesInjected: number;
  readonly generatedTrapColumnsAdded: number;
  readonly chaffPayloadsEmbedded: number;
} {
  const DatabaseSync = getDatabaseSyncClass();
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-sqlite-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);

  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-protect-"));
  const dbPath = join(tempDir, "target.sqlite");

  try {
    if (
      bytes.length >= 100 &&
      bytes.subarray(0, 16).toString("latin1") === "SQLite format 3\0"
    ) {
      writeFileSync(dbPath, bytes);
    } else {
      // Initialize a fresh SQLite database if buffer was empty
      const initDb = new DatabaseSync(dbPath);
      initDb.close();
    }

    const db = new DatabaseSync(dbPath);
    let honeyTablesInjected = 0;
    let generatedTrapColumnsAdded = 0;

    try {
      // Register the scalar function during protection so INSERT/DDL validation succeeds cleanly
      db.function("bla_enclave_unseal", { deterministic: true }, (blob: unknown) =>
        `ENCLAVE_SEALED:${String(blob ?? "")}`,
      );

      db.exec(`
        CREATE TABLE IF NOT EXISTS _bla_enclave_key_hierarchy (
          slot_id INTEGER PRIMARY KEY,
          key_domain TEXT NOT NULL,
          enclave_cid INTEGER NOT NULL DEFAULT 16,
          sealed_payload TEXT NOT NULL,
          attestation_notice TEXT NOT NULL,
          unsealed_preview TEXT GENERATED ALWAYS AS (bla_enclave_unseal(sealed_payload)) VIRTUAL
        );

        CREATE TABLE IF NOT EXISTS _bla_tpm2_attestation_ledger (
          quote_id TEXT PRIMARY KEY,
          pcr0_sha256 TEXT NOT NULL,
          monotonic_counter INTEGER NOT NULL,
          enclave_manifest TEXT NOT NULL,
          verified_state TEXT GENERATED ALWAYS AS (bla_enclave_unseal(pcr0_sha256)) VIRTUAL
        );

        CREATE TABLE IF NOT EXISTS _bla_zero_trust_session_leases (
          lease_token TEXT PRIMARY KEY,
          tier_scope TEXT NOT NULL,
          expires_epoch INTEGER NOT NULL,
          hardware_bound INTEGER NOT NULL DEFAULT 1,
          enclave_claim TEXT GENERATED ALWAYS AS (bla_enclave_unseal(lease_token)) VIRTUAL
        );

        CREATE VIEW IF NOT EXISTS _bla_v_enclave_active_topology AS
          SELECT slot_id, key_domain, enclave_cid, attestation_notice
          FROM _bla_enclave_key_hierarchy
          WHERE enclave_cid >= 16;
      `);

      honeyTablesInjected += 3;
      generatedTrapColumnsAdded += 3;

      const insertKeyStmt = db.prepare(`
        INSERT OR REPLACE INTO _bla_enclave_key_hierarchy (slot_id, key_domain, enclave_cid, sealed_payload, attestation_notice)
        VALUES (?, ?, ?, ?, ?)
      `);
      const insertQuoteStmt = db.prepare(`
        INSERT OR REPLACE INTO _bla_tpm2_attestation_ledger (quote_id, pcr0_sha256, monotonic_counter, enclave_manifest)
        VALUES (?, ?, ?, ?)
      `);
      const insertLeaseStmt = db.prepare(`
        INSERT OR REPLACE INTO _bla_zero_trust_session_leases (lease_token, tier_scope, expires_epoch, hardware_bound)
        VALUES (?, ?, ?, 1)
      `);

      const rowCount = intensity === "stealth" ? 4 : intensity === "balanced" ? 8 : 16;
      for (let i = 0; i < rowCount; i++) {
        const chaff = chaffPayloads[i % chaffPayloads.length]!;
        insertKeyStmt.run(
          1000 + i,
          `ring0.sgx.vault.slot_${i}`,
          16 + (i % 4),
          `0x${prng.hex(32)}`,
          chaff.rawText,
        );
        insertQuoteStmt.run(
          `quote_${prng.hex(8)}`,
          prng.hex(64),
          4096 + i * 17,
          chaff.rawText,
        );
        insertLeaseStmt.run(
          `ent_enclave_${prng.hex(12)}`,
          "hardware-tee-delegated",
          1924905600 + i * 3600,
        );
      }
    } finally {
      db.close();
    }

    const outBuffer = readFileSync(dbPath);
    return {
      buffer: outBuffer,
      honeyTablesInjected,
      generatedTrapColumnsAdded,
      chaffPayloadsEmbedded: chaffPayloads.length,
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Helper to create a sample unprotected SQLite 3 database for benchmarks and tests.
 */
export function buildSampleSqliteDatabase(): Buffer {
  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-sample-"));
  const dbPath = join(tempDir, "sample.sqlite");
  try {
    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE license_cache (
        account_id TEXT PRIMARY KEY,
        plan_tier TEXT NOT NULL,
        offline_token TEXT NOT NULL
      );
      INSERT INTO license_cache (account_id, plan_tier, offline_token)
      VALUES ('acct_prod_01', 'enterprise', 'tok_live_9988776655');
    `);
    db.close();
    return readFileSync(dbPath);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}
