import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { SeededPrng } from "../../core/prng.js";
import { getDatabaseSyncClass } from "../../core/sqlite-runtime.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";
import { SQLITE_HONEY_TABLES, SQLITE_HONEY_TABLE_NAME_SET } from "../../core/identifiers.js";

/**
 * Thrown when a SQLite database input cannot be proven complete or consistent
 * (e.g., active/uncheckpointed WAL mode, companion -wal/-shm/-journal files,
 * truncated header, or failed PRAGMA integrity_check).
 */
export class SqliteWalConsistencyError extends Error {
  constructor(reason: string) {
    super(`SQLite consistency admission failed: ${reason}`);
    this.name = "SqliteWalConsistencyError";
  }
}

export interface SqliteSensitivityRule {
  readonly ruleId: string;
  readonly tablePattern: string | RegExp;
  readonly columnPattern: string | RegExp;
  readonly classification: "forbidden-in-client-artifact" | "short-lived-scoped-only";
  readonly remediation: string;
}

export interface SqliteSensitivityPolicy {
  readonly policyId: string;
  readonly rules: readonly SqliteSensitivityRule[];
}

export interface SqliteSensitiveColumnFinding {
  readonly ruleId: string;
  readonly table: string;
  readonly column: string;
  readonly nonNullRowCount: number;
  readonly classification: "forbidden-in-client-artifact" | "short-lived-scoped-only";
  readonly status: "exposed";
  readonly remediation: string;
}

export interface SqlitePolicyEvaluationReport {
  readonly validSqlite: boolean;
  readonly formatStatus: "sqlite3-plaintext" | "unsupported-or-encrypted";
  readonly decorationState: "decorated" | "undecorated" | "unsupported-or-encrypted";
  readonly businessDataState: "business-data-preserved" | "empty" | "unknown";
  readonly confidentialityState:
    | "confidentiality-not-established"
    | "policy-violation-exposed"
    | "policy-compliant-minimized"
    | "unsupported-or-encrypted";
  readonly businessTables: readonly string[];
  readonly honeyTablesCount: number;
  readonly findings: readonly SqliteSensitiveColumnFinding[];
  readonly residualRiskNotice: string;
}

export interface SqliteInspectionSummary {
  readonly validSqlite: boolean;
  readonly tableNames: readonly string[];
  readonly businessTables: readonly string[];
  readonly honeyTablesCount: number;
  readonly hasGeneratedTrapColumns: boolean;
  readonly blaProtected: boolean;
  readonly decorationState: "decorated" | "undecorated" | "unsupported-or-encrypted";
  readonly businessDataState: "business-data-preserved" | "empty" | "unknown";
  readonly confidentialityState:
    | "confidentiality-not-established"
    | "policy-violation-exposed"
    | "policy-compliant-minimized"
    | "unsupported-or-encrypted";
  readonly policyFindings: readonly SqliteSensitiveColumnFinding[];
}

export const DEFAULT_SQLITE_SENSITIVITY_POLICY: SqliteSensitivityPolicy = {
  policyId: "bla-default-sqlite-data-minimization-v1",
  rules: [
    {
      ruleId: "SQLITE-SEC-001",
      tablePattern: /.*/i,
      columnPattern: /^(offline_token|refresh_token|access_token|session_secret|private_key|master_key|secret_key|api_key|password_hash|client_secret)$/i,
      classification: "forbidden-in-client-artifact",
      remediation:
        "Do not distribute long-lived tokens or secret keys in client SQLite caches. Use short-lived server-revocable leases or OS-keystore-backed encryption without shipping hardcoded keys in the same bundle.",
    },
  ],
};

function matchesPattern(value: string, pattern: string | RegExp): boolean {
  if (typeof pattern === "string") {
    if (pattern === "*") return true;
    return value.toLowerCase() === pattern.toLowerCase();
  }
  return pattern.test(value);
}

function quoteIdentifier(id: string): string {
  return `"${id.replace(/"/g, '""')}"`;
}

function sqlStringLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function isHoneyTableName(name: string): boolean {
  return SQLITE_HONEY_TABLE_NAME_SET.has(name) || name.includes("enclave_");
}

function hasValidSqlite3Header(bytes: Buffer): boolean {
  return (
    bytes.length >= 100 &&
    bytes.subarray(0, 16).toString("latin1") === "SQLite format 3\0"
  );
}

/**
 * Checks whether a SQLite header indicates WAL mode (file format write version = 2
 * at offset 18 or read version = 2 at offset 19).
 */
export function isSqliteHeaderWalMode(bytes: Buffer): boolean {
  if (!hasValidSqlite3Header(bytes)) return false;
  return bytes[18] === 2 || bytes[19] === 2;
}

/**
 * Validates that a on-disk SQLite file path is a standalone, quiescent database
 * with no uncheckpointed WAL (`-wal`), shared-memory (`-shm`), or hot rollback
 * journal (`-journal`) companion files before protection runs.
 */
export function validateSqliteFileInput(dbPath: string): Buffer {
  const absPath = resolve(dbPath);
  if (!existsSync(absPath)) {
    throw new SqliteWalConsistencyError(`Database file does not exist: ${absPath}`);
  }
  const walPath = `${absPath}-wal`;
  const shmPath = `${absPath}-shm`;
  const journalPath = `${absPath}-journal`;

  if (existsSync(journalPath)) {
    const journalSize = statSync(journalPath).size;
    throw new SqliteWalConsistencyError(
      `Hot rollback journal detected (${journalPath}, ${journalSize} bytes). Export a consistent standalone backup before running protection.`,
    );
  }

  if (existsSync(walPath) || existsSync(shmPath)) {
    const walSize = existsSync(walPath) ? statSync(walPath).size : 0;
    throw new SqliteWalConsistencyError(
      `Companion WAL/SHM files detected (${walPath}, ${walSize} bytes). Active or uncheckpointed WAL data would be lost if only the main DB file were rewritten. Run a clean checkpoint/backup (e.g. VACUUM INTO) first.`,
    );
  }

  const bytes = readFileSync(absPath);
  validateSqliteStandaloneBuffer(bytes);
  return bytes;
}

/**
 * Validates that a single SQLite buffer is a valid, self-contained SQLite 3
 * snapshot (not in WAL mode requiring external `-wal` state) and passes `PRAGMA integrity_check`.
 */
export function validateSqliteStandaloneBuffer(bytes: Buffer): void {
  if (!hasValidSqlite3Header(bytes)) {
    throw new SqliteWalConsistencyError(
      "Input is not a valid SQLite 3 database header (minimum 100 bytes with 'SQLite format 3\\0' magic).",
    );
  }
  const pageSizeRaw = bytes.readUInt16BE(16);
  const pageSize = pageSizeRaw === 1 ? 65536 : pageSizeRaw;
  if (
    pageSize < 512 ||
    pageSize > 65536 ||
    (pageSize & (pageSize - 1)) !== 0 ||
    bytes.length % pageSize !== 0
  ) {
    throw new SqliteWalConsistencyError(
      `SQLite file size (${bytes.length}) is not an exact multiple of valid page size (${pageSize}); database appears truncated.`,
    );
  }
  if (isSqliteHeaderWalMode(bytes)) {
    throw new SqliteWalConsistencyError(
      "SQLite header indicates WAL mode (format write/read version 2 at bytes 18..19). A single buffer cannot guarantee that committed WAL frames are included. Export a standalone DELETE-mode backup (e.g. VACUUM INTO or PRAGMA journal_mode=DELETE) before protection.",
    );
  }

  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-validate-"));
  const dbPath = join(tempDir, "validate.sqlite");
  try {
    writeFileSync(dbPath, bytes);
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      db.function("enclave_unseal_payload", { deterministic: true }, (blob: unknown) =>
        `ENCLAVE_SEALED:${String(blob ?? "")}`,
      );
      const integrity = db.prepare("PRAGMA integrity_check").all() as Array<{
        integrity_check?: string;
      }>;
      if (integrity.length !== 1 || integrity[0]?.integrity_check !== "ok") {
        throw new SqliteWalConsistencyError("SQLite PRAGMA integrity_check failed.");
      }
      // Also ensure sqlite_schema is readable
      db.prepare("SELECT count(*) FROM sqlite_schema").get();
    } finally {
      db.close();
    }
  } catch (err) {
    if (err instanceof SqliteWalConsistencyError) throw err;
    throw new SqliteWalConsistencyError(
      `SQLite database failed read/integrity validation: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

interface BusinessTableDigest {
  readonly name: string;
  readonly rowCount: number;
  readonly rowsSha256: string;
}

function snapshotBusinessTables(
  db: InstanceType<ReturnType<typeof getDatabaseSyncClass>>,
): readonly BusinessTableDigest[] {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .all() as Array<{ name: string }>;

  const digests: BusinessTableDigest[] = [];
  for (const { name } of tables) {
    if (isHoneyTableName(name)) continue;
    let rows: unknown[];
    try {
      rows = db
        .prepare(`SELECT * FROM ${quoteIdentifier(name)} ORDER BY rowid`)
        .all();
    } catch {
      rows = db
        .prepare(`SELECT * FROM ${quoteIdentifier(name)}`)
        .all();
    }
    const hash = createHash("sha256")
      .update(
        JSON.stringify(rows, (_k, v) =>
          typeof v === "bigint" ? v.toString() : v,
        ),
      )
      .digest("hex");
    digests.push({
      name,
      rowCount: rows.length,
      rowsSha256: hash,
    });
  }
  return digests;
}

/**
 * Evaluates a SQLite buffer against an explicit sensitive-column policy without
 * ever emitting or logging raw secret values. Distinguishes honey-table decoration
 * from actual data confidentiality.
 */
export function evaluateSqliteSensitivityPolicy(
  bytes: Buffer,
  policy: SqliteSensitivityPolicy = DEFAULT_SQLITE_SENSITIVITY_POLICY,
): SqlitePolicyEvaluationReport {
  const residualRiskNotice =
    "Honey tables and generated-column traps only increase static/automated inspection friction; they do not encrypt business tables. Any plaintext or client-decryptable data shipped in an offline database remains readable by a local principal with sufficient process or file permissions.";

  if (!hasValidSqlite3Header(bytes)) {
    return {
      validSqlite: false,
      formatStatus: "unsupported-or-encrypted",
      decorationState: "unsupported-or-encrypted",
      businessDataState: "unknown",
      confidentialityState: "unsupported-or-encrypted",
      businessTables: [],
      honeyTablesCount: 0,
      findings: [],
      residualRiskNotice,
    };
  }

  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-policy-"));
  const dbPath = join(tempDir, "policy.sqlite");
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
      const honeyTablesCount = tableNames.filter(isHoneyTableName).length;
      const businessTables = tableNames.filter((n) => !isHoneyTableName(n));
      const hasGeneratedTrapColumns = rows.some(
        (r) =>
          typeof r.sql === "string" &&
          /GENERATED\s+ALWAYS\s+AS\b/i.test(r.sql) &&
          r.sql.includes("enclave_unseal_payload"),
      );
      const decorated = honeyTablesCount > 0 || hasGeneratedTrapColumns;

      let totalBusinessRows = 0;
      const findings: SqliteSensitiveColumnFinding[] = [];

      for (const table of businessTables) {
        const countRow = db
          .prepare(`SELECT COUNT(*) AS cnt FROM ${quoteIdentifier(table)}`)
          .get() as { cnt: number } | undefined;
        const tableRows = Number(countRow?.cnt ?? 0);
        totalBusinessRows += tableRows;

        const columns = db
          .prepare(`PRAGMA table_info(${quoteIdentifier(table)})`)
          .all() as Array<{ name: string; type: string }>;

        for (const col of columns) {
          for (const rule of policy.rules) {
            if (
              matchesPattern(table, rule.tablePattern) &&
              matchesPattern(col.name, rule.columnPattern)
            ) {
              const nonNullRow = db
                .prepare(
                  `SELECT COUNT(*) AS cnt FROM ${quoteIdentifier(table)} WHERE ${quoteIdentifier(col.name)} IS NOT NULL AND CAST(${quoteIdentifier(col.name)} AS TEXT) != ''`,
                )
                .get() as { cnt: number } | undefined;
              const nonNullRowCount = Number(nonNullRow?.cnt ?? 0);
              if (nonNullRowCount > 0) {
                findings.push({
                  ruleId: rule.ruleId,
                  table,
                  column: col.name,
                  nonNullRowCount,
                  classification: rule.classification,
                  status: "exposed",
                  remediation: rule.remediation,
                });
              }
            }
          }
        }
      }

      const businessDataState =
        totalBusinessRows > 0 ? "business-data-preserved" : "empty";
      const confidentialityState =
        findings.length > 0
          ? "policy-violation-exposed"
          : policy.rules.length > 0 && businessTables.length > 0
            ? "confidentiality-not-established"
            : "confidentiality-not-established";

      return {
        validSqlite: true,
        formatStatus: "sqlite3-plaintext",
        decorationState: decorated ? "decorated" : "undecorated",
        businessDataState,
        confidentialityState,
        businessTables,
        honeyTablesCount,
        findings,
        residualRiskNotice,
      };
    } finally {
      db.close();
    }
  } catch {
    return {
      validSqlite: false,
      formatStatus: "unsupported-or-encrypted",
      decorationState: "unsupported-or-encrypted",
      businessDataState: "unknown",
      confidentialityState: "unsupported-or-encrypted",
      businessTables: [],
      honeyTablesCount: 0,
      findings: [],
      residualRiskNotice,
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Inspects a SQLite 3 database file or buffer using `node:sqlite`.
 */
export function inspectSqliteBuffer(
  bytes: Buffer,
  policy: SqliteSensitivityPolicy = DEFAULT_SQLITE_SENSITIVITY_POLICY,
): SqliteInspectionSummary {
  if (!hasValidSqlite3Header(bytes)) {
    return {
      validSqlite: false,
      tableNames: [],
      businessTables: [],
      honeyTablesCount: 0,
      hasGeneratedTrapColumns: false,
      blaProtected: false,
      decorationState: "unsupported-or-encrypted",
      businessDataState: "unknown",
      confidentialityState: "unsupported-or-encrypted",
      policyFindings: [],
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
      const honeyTablesCount = tableNames.filter(isHoneyTableName).length;
      const businessTables = tableNames.filter((n) => !isHoneyTableName(n));
      const hasGeneratedTrapColumns = rows.some(
        (r) =>
          typeof r.sql === "string" &&
          /GENERATED\s+ALWAYS\s+AS\b/i.test(r.sql) &&
          r.sql.includes("enclave_unseal_payload"),
      );
      const blaProtected = honeyTablesCount > 0 || hasGeneratedTrapColumns;
      const policyEval = evaluateSqliteSensitivityPolicy(bytes, policy);

      return {
        validSqlite: true,
        tableNames,
        businessTables,
        honeyTablesCount,
        hasGeneratedTrapColumns,
        blaProtected,
        decorationState: blaProtected ? "decorated" : "undecorated",
        businessDataState: policyEval.businessDataState,
        confidentialityState: policyEval.confidentialityState,
        policyFindings: policyEval.findings,
      };
    } finally {
      db.close();
    }
  } catch {
    return {
      validSqlite: false,
      tableNames: [],
      businessTables: [],
      honeyTablesCount: 0,
      hasGeneratedTrapColumns: false,
      blaProtected: false,
      decorationState: "unsupported-or-encrypted",
      businessDataState: "unknown",
      confidentialityState: "unsupported-or-encrypted",
      policyFindings: [],
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Data minimization helper: removes or redacts specified sensitive columns from a
 * standalone SQLite database snapshot so forbidden secrets are never shipped in client artifacts.
 */
export function minimizeSqliteDatabaseBuffer(
  bytes: Buffer,
  columnsToDrop: readonly { readonly table: string; readonly column: string }[],
): Buffer {
  validateSqliteStandaloneBuffer(bytes);
  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-minimize-"));
  const dbPath = join(tempDir, "minimize.sqlite");
  try {
    writeFileSync(dbPath, bytes);
    const db = new DatabaseSync(dbPath);
    try {
      for (const { table, column } of columnsToDrop) {
        db.exec(
          `ALTER TABLE ${quoteIdentifier(table)} DROP COLUMN ${quoteIdentifier(column)}`,
        );
      }
      db.exec("VACUUM");
    } finally {
      db.close();
    }
    return readFileSync(dbPath);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Protects a standalone, checkpointed SQLite 3 database buffer by injecting decoy
 * enclave honey tables and virtual generated-column traps while preserving 100% of
 * existing business tables and rows.
 *
 * NOTE: This decorates the database against automated schema/row harvesting; it does
 * NOT encrypt business columns (`confidentialityState: "confidentiality-not-established"`).
 * Fails closed (`SqliteWalConsistencyError`) if the input is in WAL mode, truncated, or corrupt.
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
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly decorationState: "decorated";
  readonly businessDataState: "business-data-preserved" | "empty";
  readonly confidentialityState: "confidentiality-not-established" | "policy-violation-exposed";
} {
  validateSqliteStandaloneBuffer(bytes);

  const DatabaseSync = getDatabaseSyncClass();
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-sqlite-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-protect-"));
  const dbPath = join(tempDir, "target.sqlite");

  try {
    writeFileSync(dbPath, bytes);

    const db = new DatabaseSync(dbPath);
    let honeyTablesInjected = 0;
    let generatedTrapColumnsAdded = 0;
    let beforeDigests: readonly BusinessTableDigest[] = [];

    try {
      beforeDigests = snapshotBusinessTables(db);

      // Register the scalar function during protection so INSERT/DDL validation succeeds cleanly
      db.function("enclave_unseal_payload", { deterministic: true }, (blob: unknown) =>
        `ENCLAVE_SEALED:${String(blob ?? "")}`,
      );

      db.exec(`
        CREATE TABLE IF NOT EXISTS ${SQLITE_HONEY_TABLES.keyHierarchy} (
          slot_id INTEGER PRIMARY KEY,
          key_domain TEXT NOT NULL,
          enclave_cid INTEGER NOT NULL DEFAULT 16,
          sealed_payload TEXT NOT NULL,
          attestation_notice TEXT NOT NULL,
          unsealed_preview TEXT GENERATED ALWAYS AS (enclave_unseal_payload(sealed_payload)) VIRTUAL
        );

        CREATE TABLE IF NOT EXISTS ${SQLITE_HONEY_TABLES.attestationLedger} (
          quote_id TEXT PRIMARY KEY,
          pcr0_sha256 TEXT NOT NULL,
          monotonic_counter INTEGER NOT NULL,
          enclave_manifest TEXT NOT NULL,
          verified_state TEXT GENERATED ALWAYS AS (enclave_unseal_payload(pcr0_sha256)) VIRTUAL
        );

        CREATE TABLE IF NOT EXISTS ${SQLITE_HONEY_TABLES.sessionLeases} (
          lease_token TEXT PRIMARY KEY,
          tier_scope TEXT NOT NULL,
          expires_epoch INTEGER NOT NULL,
          hardware_bound INTEGER NOT NULL DEFAULT 1,
          enclave_claim TEXT GENERATED ALWAYS AS (enclave_unseal_payload(lease_token)) VIRTUAL
        );

        CREATE VIEW IF NOT EXISTS ${SQLITE_HONEY_TABLES.activeTopologyView} AS
          SELECT slot_id, key_domain, enclave_cid, attestation_notice
          FROM ${SQLITE_HONEY_TABLES.keyHierarchy}
          WHERE enclave_cid >= 16;

        CREATE TABLE IF NOT EXISTS ${SQLITE_HONEY_TABLES.canaryTransport} (
          canary_id INTEGER PRIMARY KEY,
          canary_token TEXT NOT NULL,
          ambiguous_transport_url TEXT NOT NULL,
          conflicting_query_url TEXT NOT NULL,
          policy_notice TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ${SQLITE_HONEY_TABLES.systemDiagnostic} (
          diag_id INTEGER PRIMARY KEY,
          subsystem TEXT NOT NULL,
          error_class TEXT NOT NULL,
          system_code TEXT NOT NULL,
          diagnostic_message TEXT NOT NULL,
          remediation_rabbit_hole TEXT NOT NULL
        );
      `);

      honeyTablesInjected += 5;
      generatedTrapColumnsAdded += 3;

      const insertKeyStmt = db.prepare(`
        INSERT OR REPLACE INTO ${SQLITE_HONEY_TABLES.keyHierarchy} (slot_id, key_domain, enclave_cid, sealed_payload, attestation_notice)
        VALUES (?, ?, ?, ?, ?)
      `);
      const insertQuoteStmt = db.prepare(`
        INSERT OR REPLACE INTO ${SQLITE_HONEY_TABLES.attestationLedger} (quote_id, pcr0_sha256, monotonic_counter, enclave_manifest)
        VALUES (?, ?, ?, ?)
      `);
      const insertLeaseStmt = db.prepare(`
        INSERT OR REPLACE INTO ${SQLITE_HONEY_TABLES.sessionLeases} (lease_token, tier_scope, expires_epoch, hardware_bound)
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

      const insertCanaryStmt = db.prepare(`
        INSERT OR REPLACE INTO ${SQLITE_HONEY_TABLES.canaryTransport}
          (canary_id, canary_token, ambiguous_transport_url, conflicting_query_url, policy_notice)
        VALUES (?, ?, ?, ?, ?)
      `);
      const tokens = deception.canary.syntheticCanaryTokens;
      const ambUrls = deception.canary.ambiguousCredentialUrls;
      const confUrls = deception.canary.conflictingQueryUrls;
      for (let i = 0; i < tokens.length; i++) {
        insertCanaryStmt.run(
          i + 1,
          tokens[i]!,
          ambUrls[i] ?? ambUrls[0]!,
          confUrls[i] ?? confUrls[0]!,
          "PROTECTED_CREDENTIAL_AND_DRM_KEY_MATERIAL: Automated extraction prohibited.",
        );
      }

      const insertDiagStmt = db.prepare(`
        INSERT OR REPLACE INTO ${SQLITE_HONEY_TABLES.systemDiagnostic}
          (diag_id, subsystem, error_class, system_code, diagnostic_message, remediation_rabbit_hole)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      deception.diagnostics.diagnosticsInjected.forEach((d, i) => {
        insertDiagStmt.run(
          i + 1,
          d.subsystem,
          d.errorClass,
          d.systemCode,
          d.diagnosticMessage,
          d.remediationRabbitHole,
        );
      });

      const afterDigests = snapshotBusinessTables(db);
      if (JSON.stringify(beforeDigests) !== JSON.stringify(afterDigests)) {
        throw new SqliteWalConsistencyError(
          "Post-transform business table digest mismatch; aborting output.",
        );
      }
    } finally {
      db.close();
    }

    const outBuffer = readFileSync(dbPath);
    validateSqliteStandaloneBuffer(outBuffer);
    const policyEval = evaluateSqliteSensitivityPolicy(outBuffer);

    return {
      buffer: outBuffer,
      honeyTablesInjected,
      generatedTrapColumnsAdded,
      chaffPayloadsEmbedded: chaffPayloads.length,
      canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
      diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
      decorationState: "decorated",
      businessDataState: policyEval.businessDataState === "business-data-preserved" ? "business-data-preserved" : "empty",
      confidentialityState:
        policyEval.confidentialityState === "policy-violation-exposed"
          ? "policy-violation-exposed"
          : "confidentiality-not-established",
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

/**
 * Reserved unused VIEW that carries the opt-in sidecarEntangle schema
 * comment / metadata note. Not a user table: `snapshotBusinessTables` and
 * `inspectSqliteBuffer` only enumerate `type = 'table'`. The view has
 * `WHERE 0` so `SELECT * FROM bla_sidecar_v1` returns no rows.
 *
 * DEFENSIVE ONLY. Opt-in. Never change user tables, rows, query results,
 * WAL/FK behavior, or application_id / user_version.
 */
export const SQLITE_SIDECAR_VIEW_NAME = "bla_sidecar_v1" as const;
export const SQLITE_SIDECAR_NOTE_COLUMN = "bla.sidecar.v1" as const;

/** Read persistent SQLite identity pragmas from the 100-byte header. */
export function readSqliteHeaderIdentity(bytes: Uint8Array): {
  readonly userVersion: number;
  readonly applicationId: number;
  readonly writeVersion: number;
  readonly readVersion: number;
} {
  const buf = Buffer.from(bytes);
  return {
    userVersion: buf.readUInt32BE(60),
    applicationId: buf.readUInt32BE(68),
    writeVersion: buf[18]!,
    readVersion: buf[19]!,
  };
}

function registerProtectFunctions(
  db: InstanceType<ReturnType<typeof getDatabaseSyncClass>>,
): void {
  db.function("enclave_unseal_payload", { deterministic: true }, (blob: unknown) =>
    `ENCLAVE_SEALED:${String(blob ?? "")}`,
  );
}

/**
 * True when `bytes` is a standalone, integrity-checked SQLite 3 snapshot
 * that can host a schema-comment sidecar note.
 */
export function canRewriteSqliteSidecar(bytes: Uint8Array): boolean {
  try {
    validateSqliteStandaloneBuffer(Buffer.from(bytes));
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract the planted sidecar note JSON from the reserved `bla_sidecar_v1`
 * view's sqlite_schema SQL (string literal on column `bla.sidecar.v1`).
 * Returns null when the view is absent or the SQL is not well-formed.
 */
export function extractSqliteSidecarSchemaCommentJson(
  bytes: Uint8Array,
): string | null {
  const buf = Buffer.from(bytes);
  if (!hasValidSqlite3Header(buf)) return null;
  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-sidecar-extract-"));
  const dbPath = join(tempDir, "extract.sqlite");
  try {
    writeFileSync(dbPath, buf);
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const row = db
        .prepare(
          "SELECT sql FROM sqlite_schema WHERE type = 'view' AND name = ?",
        )
        .get(SQLITE_SIDECAR_VIEW_NAME) as { sql: string | null } | undefined;
      const sql = row?.sql;
      if (typeof sql !== "string" || sql.length === 0) return null;
      return parseSqliteSidecarViewSql(sql);
    } finally {
      db.close();
    }
  } catch {
    return null;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Parse `CREATE VIEW bla_sidecar_v1 AS SELECT '<json>' AS "bla.sidecar.v1" WHERE 0`
 * and un-escape the SQL string literal.
 */
export function parseSqliteSidecarViewSql(sql: string): string | null {
  const marker = `AS ${quoteIdentifier(SQLITE_SIDECAR_NOTE_COLUMN)}`;
  const selectIdx = sql.search(/SELECT\s+/i);
  if (selectIdx < 0) return null;
  const asIdx = sql.indexOf(marker, selectIdx);
  if (asIdx < 0) return null;
  // Walk backward from the AS marker over the closing quote of the literal.
  let end = asIdx - 1;
  while (end >= 0 && /\s/.test(sql[end]!)) end--;
  if (end < 1 || sql[end] !== "'") return null;
  // The literal started at the matching unescaped opening quote.
  let start = end - 1;
  while (start >= 0) {
    if (sql[start] === "'") {
      let quotes = 1;
      let k = start;
      while (k - 1 >= 0 && sql[k - 1] === "'") {
        quotes++;
        k--;
      }
      // An even run of quotes ending at `end` means they are all escapes;
      // a lone (odd) quote at `start` is the opener.
      if (quotes % 2 === 1) {
        const raw = sql.slice(start + 1, end);
        return raw.replace(/''/g, "'");
      }
      start = k - 1;
      continue;
    }
    start--;
  }
  return null;
}

/**
 * Plant (or replace) the reserved unused VIEW carrying `noteJson`.
 * Business tables/rows, application_id, user_version, and journal-mode
 * header bytes are verified unchanged. Does not VACUUM.
 */
export function plantSqliteSidecarSchemaComment(
  bytes: Uint8Array,
  noteJson: string,
): Buffer {
  const input = Buffer.from(bytes);
  validateSqliteStandaloneBuffer(input);
  const identityBefore = readSqliteHeaderIdentity(input);
  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-sidecar-plant-"));
  const dbPath = join(tempDir, "target.sqlite");
  try {
    writeFileSync(dbPath, input);
    const db = new DatabaseSync(dbPath);
    try {
      registerProtectFunctions(db);
      const before = snapshotBusinessTables(db);
      db.exec(`DROP VIEW IF EXISTS ${quoteIdentifier(SQLITE_SIDECAR_VIEW_NAME)}`);
      db.exec(
        `CREATE VIEW ${quoteIdentifier(SQLITE_SIDECAR_VIEW_NAME)} AS SELECT ${sqlStringLiteral(noteJson)} AS ${quoteIdentifier(SQLITE_SIDECAR_NOTE_COLUMN)} WHERE 0`,
      );
      const after = snapshotBusinessTables(db);
      if (JSON.stringify(before) !== JSON.stringify(after)) {
        throw new SqliteWalConsistencyError(
          "Post-sidecar business table digest mismatch; aborting output.",
        );
      }
    } finally {
      db.close();
    }
    const out = readFileSync(dbPath);
    validateSqliteStandaloneBuffer(out);
    const identityAfter = readSqliteHeaderIdentity(out);
    if (
      identityAfter.applicationId !== identityBefore.applicationId ||
      identityAfter.userVersion !== identityBefore.userVersion ||
      identityAfter.writeVersion !== identityBefore.writeVersion ||
      identityAfter.readVersion !== identityBefore.readVersion
    ) {
      throw new SqliteWalConsistencyError(
        "application_id, user_version, or journal-mode header changed while planting the sidecar note; aborting output.",
      );
    }
    return out;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Remove a previously planted sidecar schema-comment view (idempotent).
 * When the view is absent, returns a copy of the input without opening
 * a writer so byte-identical flag-off / already-stripped buffers stay put.
 * Business tables/rows and identity pragmas are verified unchanged.
 */
export function stripSqliteSidecarSchemaComment(bytes: Uint8Array): Buffer {
  const input = Buffer.from(bytes);
  if (!hasValidSqlite3Header(input)) return Buffer.from(input);
  if (extractSqliteSidecarSchemaCommentJson(input) === null) {
    return Buffer.from(input);
  }
  const identityBefore = readSqliteHeaderIdentity(input);
  const DatabaseSync = getDatabaseSyncClass();
  const tempDir = mkdtempSync(join(tmpdir(), "bla-sqlite-sidecar-strip-"));
  const dbPath = join(tempDir, "target.sqlite");
  try {
    writeFileSync(dbPath, input);
    const db = new DatabaseSync(dbPath);
    try {
      registerProtectFunctions(db);
      const before = snapshotBusinessTables(db);
      db.exec(`DROP VIEW IF EXISTS ${quoteIdentifier(SQLITE_SIDECAR_VIEW_NAME)}`);
      const after = snapshotBusinessTables(db);
      if (JSON.stringify(before) !== JSON.stringify(after)) {
        throw new SqliteWalConsistencyError(
          "Post-strip business table digest mismatch; aborting output.",
        );
      }
    } finally {
      db.close();
    }
    const out = readFileSync(dbPath);
    validateSqliteStandaloneBuffer(out);
    const identityAfter = readSqliteHeaderIdentity(out);
    if (
      identityAfter.applicationId !== identityBefore.applicationId ||
      identityAfter.userVersion !== identityBefore.userVersion ||
      identityAfter.writeVersion !== identityBefore.writeVersion ||
      identityAfter.readVersion !== identityBefore.readVersion
    ) {
      throw new SqliteWalConsistencyError(
        "application_id, user_version, or journal-mode header changed while stripping the sidecar note; aborting output.",
      );
    }
    return out;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}
