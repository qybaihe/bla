import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { getDatabaseSyncClass } from "../src/core/sqlite-runtime.js";
import {
  SQLITE_SIDECAR_METADATA_KEY,
  SQLITE_SIDECAR_METADATA_KIND,
  SIDECAR_ENTANGLE_SCHEMA,
  bindSqliteSidecarEntanglement,
  computeSidecarBindingDigest,
  entangleSqliteEntryWithSidecars,
  extractSqliteSidecarSchemaComment,
  generateSidecarSqliteSchemaComment,
  planSidecarEntanglement,
  stripSqliteSidecarSchemaComment,
  verifySqliteSidecarSchemaComment,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  SQLITE_SIDECAR_VIEW_NAME,
  buildSampleSqliteDatabase,
  inspectSqliteBuffer,
  plantSqliteSidecarSchemaComment,
  protectSqliteBuffer,
  readSqliteHeaderIdentity,
  validateSqliteStandaloneBuffer,
} from "../src/shields/formats/sqlite.js";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifySidecarTarget } from "../src/engine/verify-sidecar.js";

function openReadonly(bytes: Buffer) {
  const DatabaseSync = getDatabaseSyncClass();
  const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-snap-"));
  const dbPath = join(dir, "snap.sqlite");
  writeFileSync(dbPath, bytes);
  const db = new DatabaseSync(dbPath, { readOnly: true });
  db.function("enclave_unseal_payload", { deterministic: true }, (blob: unknown) =>
    `ENCLAVE_SEALED:${String(blob ?? "")}`,
  );
  return { db, dir };
}

function userVisibleState(bytes: Buffer): {
  identity: ReturnType<typeof readSqliteHeaderIdentity>;
  tables: Array<{ name: string; columns: string[]; rows: unknown[] }>;
  views: string[];
} {
  const { db, dir } = openReadonly(bytes);
  try {
    const tableRows = db
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all() as Array<{ name: string }>;
    const tables = tableRows.map(({ name }) => {
      const columns = (
        db.prepare(`PRAGMA table_info("${name.replace(/"/g, '""')}")`).all() as Array<{
          name: string;
        }>
      ).map((c) => c.name);
      const rows = db.prepare(`SELECT * FROM "${name.replace(/"/g, '""')}" ORDER BY rowid`).all();
      return { name, columns, rows };
    });
    const views = (
      db
        .prepare(
          "SELECT name FROM sqlite_schema WHERE type = 'view' ORDER BY name",
        )
        .all() as Array<{ name: string }>
    )
      .map((v) => v.name)
      .filter((n) => n !== SQLITE_SIDECAR_VIEW_NAME);
    return {
      identity: readSqliteHeaderIdentity(bytes),
      tables,
      views,
    };
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function sampleSqliteWithIdentity(): Buffer {
  const DatabaseSync = getDatabaseSyncClass();
  const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-sample-id-"));
  const dbPath = join(dir, "sample.sqlite");
  try {
    const db = new DatabaseSync(dbPath);
    db.exec(`
      PRAGMA user_version = 42;
      PRAGMA application_id = 123456;
      CREATE TABLE accounts (
        account_id TEXT PRIMARY KEY,
        plan_tier TEXT NOT NULL
      );
      CREATE TABLE licenses (
        license_id INTEGER PRIMARY KEY,
        account_id TEXT NOT NULL,
        offline_token TEXT NOT NULL,
        FOREIGN KEY (account_id) REFERENCES accounts(account_id)
      );
      INSERT INTO accounts (account_id, plan_tier)
      VALUES ('acct_prod_01', 'enterprise');
      INSERT INTO licenses (license_id, account_id, offline_token)
      VALUES (1, 'acct_prod_01', 'tok_live_9988776655');
    `);
    db.close();
    return readFileSync(dbPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("sidecar SQLite schema-comment note", () => {
  it("planSidecarEntanglement guesses sqlite-schema-comment for .sqlite/.sqlite3/.db", () => {
    expect(
      planSidecarEntanglement({
        entryPath: "cache.sqlite",
        sidecarPaths: ["enclave.bin"],
      }).entryHookKind,
    ).toBe("sqlite-schema-comment");
    expect(
      planSidecarEntanglement({
        entryPath: "cache.sqlite3",
        sidecarPaths: ["enclave.bin"],
      }).entryHookKind,
    ).toBe("sqlite-schema-comment");
    expect(
      planSidecarEntanglement({
        entryPath: "local.db",
        sidecarPaths: ["enclave.bin"],
      }).entryHookKind,
    ).toBe("sqlite-schema-comment");
  });

  it("generateSidecarSqliteSchemaComment emits the binding note body", () => {
    const digest = computeSidecarBindingDigest(
      { pathLabel: "cache.sqlite", bytes: Buffer.from("entry") },
      [{ pathLabel: "sib.bin", bytes: Buffer.from("sib") }],
      "seed-a",
      "sidecars",
    );
    const inject = generateSidecarSqliteSchemaComment({
      entryPath: "cache.sqlite",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-a",
      expectedHex: digest.hex,
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.kind).toBe(SQLITE_SIDECAR_METADATA_KIND);
    expect(inject.key).toBe(SQLITE_SIDECAR_METADATA_KEY);
    expect(inject.note.digest).toBe(digest.hex);
    expect(inject.noteJson).toContain(digest.hex);
  });

  it("bind + verify round-trips; strip/mutate fail closed; user schema and identity stay stable", () => {
    const entry = sampleSqliteWithIdentity();
    const before = userVisibleState(entry);
    expect(before.identity.userVersion).toBe(42);
    expect(before.identity.applicationId).toBe(123456);

    const sib = Buffer.from("sidecar-payload-v1");
    const bound = bindSqliteSidecarEntanglement({
      entryPath: "cache.sqlite",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-sqlite",
      entryBytes: entry,
      sidecarBytes: [sib],
    });
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("sqlite-schema-comment");
    validateSqliteStandaloneBuffer(bound.bytes);
    expect(userVisibleState(bound.bytes)).toEqual(before);

    const note = extractSqliteSidecarSchemaComment(bound.bytes);
    expect(note).not.toBeNull();
    expect(note!.digest).toBe(bound.digest.hex);
    expect(note!.sidecarPaths).toEqual(["sib.bin"]);
    expect(note!.kind).toBe("sqlite-schema-comment");

    const ok = verifySqliteSidecarSchemaComment({
      entryBytes: bound.bytes,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(ok.ok).toBe(true);
    expect(ok.measuredHex).toBe(bound.digest.hex);

    const bad = verifySqliteSidecarSchemaComment({
      entryBytes: bound.bytes,
      sidecarBytes: { "sib.bin": Buffer.from("tampered") },
    });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/mismatch/);

    const mutatedJson = bound.inject.noteJson.replace(
      bound.digest.hex,
      "aa".repeat(32),
    );
    const mutated = plantSqliteSidecarSchemaComment(entry, mutatedJson);
    const mutatedVerify = verifySqliteSidecarSchemaComment({
      entryBytes: mutated,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(mutatedVerify.ok).toBe(false);
    expect(mutatedVerify.reason).toMatch(/mismatch/);

    const stripped = stripSqliteSidecarSchemaComment(bound.bytes);
    expect(extractSqliteSidecarSchemaComment(stripped)).toBeNull();
    expect(userVisibleState(stripped)).toEqual(before);
    const missing = verifySqliteSidecarSchemaComment({
      entryBytes: stripped,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(missing.ok).toBe(false);

    const rebound = bindSqliteSidecarEntanglement({
      entryPath: "cache.sqlite",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-sqlite",
      entryBytes: bound.bytes,
      sidecarBytes: [sib],
    });
    const { db, dir } = openReadonly(rebound.bytes);
    try {
      const views = db
        .prepare(
          "SELECT count(*) AS cnt FROM sqlite_schema WHERE type = 'view' AND name = ?",
        )
        .get(SQLITE_SIDECAR_VIEW_NAME) as { cnt: number };
      expect(Number(views.cnt)).toBe(1);
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
    expect(userVisibleState(rebound.bytes)).toEqual(before);
    expect(
      verifySqliteSidecarSchemaComment({
        entryBytes: rebound.bytes,
        sidecarBytes: { "sib.bin": sib },
      }).ok,
    ).toBe(true);

    // Quoted path in the note JSON must survive SQL string escaping.
    const quoted = bindSqliteSidecarEntanglement({
      entryPath: "cache.sqlite",
      sidecarPaths: ["it's-sib.bin"],
      seedTag: "seed-sqlite",
      entryBytes: entry,
      sidecarBytes: [sib],
    });
    const quotedNote = extractSqliteSidecarSchemaComment(quoted.bytes);
    expect(quotedNote?.sidecarPaths).toEqual(["it's-sib.bin"]);
    expect(
      verifySqliteSidecarSchemaComment({
        entryBytes: quoted.bytes,
        sidecarBytes: { "it's-sib.bin": sib },
      }).ok,
    ).toBe(true);
  });

  it("entangleSqliteEntryWithSidecars returns null when no sidecars or on a stub", () => {
    expect(
      entangleSqliteEntryWithSidecars({
        entryPath: "cache.sqlite",
        entryBytes: sampleSqliteWithIdentity(),
        sidecars: [],
      }),
    ).toBeNull();
    const stub = Buffer.alloc(112, 0);
    stub.write("SQLite format 3\0", 0, "latin1");
    expect(
      entangleSqliteEntryWithSidecars({
        entryPath: "cache.sqlite",
        entryBytes: stub,
        sidecars: [{ pathLabel: "sib.bin", bytes: Buffer.from("x") }],
      }),
    ).toBeNull();
  });

  it("protectTarget with sidecarEntangle plants the note (host-verify only)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-prot-"));
    try {
      const inPath = join(dir, "cache.sqlite");
      const sibPath = join(dir, "sib.bin");
      const outPath = join(dir, "out.sqlite");
      const input = sampleSqliteWithIdentity();
      writeFileSync(inPath, input);
      writeFileSync(sibPath, Buffer.from("sibling-bytes"));
      const report = protectTarget({
        inputPath: inPath,
        outputPath: outPath,
        intensity: "stealth",
        seed: "sqlite-sidecar-protect",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
      });
      expect(report.sidecarEntangle).toBe(true);
      expect(existsSync(outPath)).toBe(true);
      const out = readFileSync(outPath);
      validateSqliteStandaloneBuffer(out);
      const note = extractSqliteSidecarSchemaComment(out);
      expect(note).not.toBeNull();
      expect(note!.key).toBe(SQLITE_SIDECAR_METADATA_KEY);
      const verified = verifySqliteSidecarSchemaComment({
        entryBytes: out,
        sidecarBytes: { "sib.bin": readFileSync(sibPath) },
      });
      expect(verified.ok).toBe(true);
      expect(report.counteredReaVectors).not.toContain("sqlite-sidecar-entangle");
      expect(report.counteredReaVectors).toContain("sqlite-database-inspection");
      const cli = verifySidecarTarget(outPath);
      expect(cli.ok, cli.reason).toBe(true);
      expect(cli.verifier).toBe("sqlite-schema-comment");

      const identity = readSqliteHeaderIdentity(out);
      expect(identity.userVersion).toBe(42);
      expect(identity.applicationId).toBe(123456);
      const inspection = inspectSqliteBuffer(out);
      expect(inspection.businessTables).toEqual(
        expect.arrayContaining(["accounts", "licenses"]),
      );
      expect(inspection.businessTables).not.toContain(SQLITE_SIDECAR_VIEW_NAME);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("default OFF: protectTarget without the flag leaves user-visible schema/data unchanged", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-off-"));
    try {
      const input = sampleSqliteWithIdentity();
      const inPath = join(dir, "cache.sqlite");
      const offOut = join(dir, "off.sqlite");
      const onOut = join(dir, "on.sqlite");
      const sibPath = join(dir, "sib.bin");
      writeFileSync(inPath, input);
      writeFileSync(sibPath, Buffer.from("sibling-bytes"));
      const offReport = protectTarget({
        inputPath: inPath,
        outputPath: offOut,
        intensity: "stealth",
        seed: "sqlite-sidecar-off",
      });
      expect(offReport.sidecarEntangle).not.toBe(true);
      const offBytes = readFileSync(offOut);
      expect(extractSqliteSidecarSchemaComment(offBytes)).toBeNull();

      // Same seed, flag on: reserved view appears, but user-visible schema/data
      // and identity pragmas match the flag-off protect output (honey tables included).
      const onReport = protectTarget({
        inputPath: inPath,
        outputPath: onOut,
        intensity: "stealth",
        seed: "sqlite-sidecar-off",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
      });
      expect(onReport.sidecarEntangle).toBe(true);
      const onBytes = readFileSync(onOut);
      expect(extractSqliteSidecarSchemaComment(onBytes)).not.toBeNull();
      expect(userVisibleState(onBytes)).toEqual(userVisibleState(offBytes));

      // Flag-off protect is the same as calling protectSqliteBuffer alone.
      const direct = protectSqliteBuffer(input, {
        intensity: "stealth",
        seed: "sqlite-sidecar-off",
      });
      expect(userVisibleState(offBytes)).toEqual(userVisibleState(direct.buffer));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("hardenProject SQLite-only post-pass plants the note against sibling artifacts", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-harden-"));
    try {
      // Two SQLite files so the harden post-pass has a sibling to bind.
      // Identity pragmas live on a-cache.sqlite; z-aux.sqlite is the measured sibling.
      writeFileSync(join(dir, "a-cache.sqlite"), sampleSqliteWithIdentity());
      writeFileSync(join(dir, "z-aux.sqlite"), buildSampleSqliteDatabase());
      const report = hardenProject({
        directory: dir,
        intensity: "stealth",
        seed: "sqlite-harden-seed",
        sidecarEntangle: true,
        dryRun: false,
      });
      expect(report.overallSuccess).toBe(true);
      const cache = report.artifacts.find(
        (a) => a.relativePath.replaceAll("\\", "/").endsWith("a-cache.sqlite") && a.success,
      );
      expect(cache).toBeTruthy();
      const out = readFileSync(cache!.outputPath);
      const note = extractSqliteSidecarSchemaComment(out);
      expect(note).not.toBeNull();
      const verified = verifySidecarTarget(cache!.outputPath);
      expect(verified.ok, verified.reason).toBe(true);
      expect(verified.verifier).toBe("sqlite-schema-comment");
      expect(userVisibleState(out).identity.userVersion).toBe(42);
      expect(userVisibleState(out).identity.applicationId).toBe(123456);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
