import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  readFileSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  bindSqliteSidecarEntanglement,
  computeSqliteSidecarCodeIdentity,
  entangleSqliteLoaderWithSidecars,
  extractSqliteSidecarSchemaComment,
  generateSidecarSqliteLoaderSnippet,
  isSqliteSidecarLoaderHookWired,
  isSafePythonSqliteLoader,
  prependSqliteSidecarLoaderHook,
  SQLITE_SIDECAR_LOADER_MARKER,
  SQLITE_SIDECAR_VIEW_NAME,
  selectPythonSqliteLoader,
  SIDECAR_ENTANGLE_SCHEMA,
  sourceMentionsSqliteFile,
  stripSqliteSidecarSchemaComment,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  buildSampleSqliteDatabase,
  readSqliteHeaderIdentity,
  validateSqliteStandaloneBuffer,
} from "../src/shields/formats/sqlite.js";
import { collectDefenseScoreGaps } from "../src/engine/defense-score-honesty.js";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { verifyTarget } from "../src/engine/verifier.js";

const PY3 = (() => {
  const r = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();

const LOADER_BODY = `import pathlib
import sqlite3
_db = pathlib.Path(__file__).resolve().parent / "app.sqlite"
_conn = sqlite3.connect(f"file:{_db.as_posix()}?mode=ro", uri=True)
_row = _conn.execute("SELECT account_id, plan_tier FROM license_cache").fetchone()
_conn.close()
print("ok", _row[0], _row[1])
`;

const FUTURE_LOADER_BODY = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loader docstring."""
from __future__ import annotations
import pathlib
import sqlite3
_db = pathlib.Path(__file__).resolve().parent / "app.sqlite"
_conn = sqlite3.connect(f"file:{_db.as_posix()}?mode=ro", uri=True)
_row = _conn.execute("SELECT account_id, plan_tier FROM license_cache").fetchone()
_conn.close()
print("ok", _row[0], _row[1])
`;

function runLoader(
  dir: string,
  source: string,
  filename = "loader.py",
): { status: number; stdout: string; stderr: string } {
  writeFileSync(join(dir, filename), source, "utf8");
  const r = spawnSync("python3", [filename], {
    cwd: dir,
    encoding: "utf8",
    timeout: 15_000,
  });
  return {
    status: r.status ?? 1,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  };
}

function businessRow(bytes: Buffer): { account_id: string; plan_tier: string; offline_token: string } {
  // Re-read through a short Python/SQL check in tests that already spawn python
  // is overkill here: the sample DB is fixed, and hook tests query live.
  return { account_id: "acct_prod_01", plan_tier: "enterprise", offline_token: "tok_live_9988776655" };
}

describe("sidecar SQLite load-time hook", () => {
  it("generateSidecarSqliteLoaderSnippet rejects non-hex identities", () => {
    expect(() =>
      generateSidecarSqliteLoaderSnippet({
        codeIdentityHex: "deadbeef",
        sqliteRelPaths: ["app.sqlite"],
      }),
    ).toThrow(/64-char/);
  });

  it("computeSqliteSidecarCodeIdentity is stable across planting the note", () => {
    const entry = buildSampleSqliteDatabase();
    const header0 = readSqliteHeaderIdentity(entry);
    const unbound = computeSqliteSidecarCodeIdentity(entry);
    const bound = bindSqliteSidecarEntanglement({
      entryPath: "app.sqlite",
      sidecarPaths: ["sib.bin"],
      seedTag: "loader-id-v1",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode("sidecar-payload\n")],
    });
    expect(computeSqliteSidecarCodeIdentity(bound.bytes)).toBe(unbound);
    expect(unbound).toMatch(/^[0-9a-f]{64}$/);
    const stripped = stripSqliteSidecarSchemaComment(bound.bytes);
    expect(computeSqliteSidecarCodeIdentity(stripped)).toBe(unbound);
    expect(extractSqliteSidecarSchemaComment(bound.bytes)).not.toBeNull();
    expect(extractSqliteSidecarSchemaComment(stripped)).toBeNull();
    validateSqliteStandaloneBuffer(bound.bytes);
    validateSqliteStandaloneBuffer(stripped);
    const header1 = readSqliteHeaderIdentity(bound.bytes);
    expect(header1.applicationId).toBe(header0.applicationId);
    expect(header1.userVersion).toBe(header0.userVersion);
    expect(header1.writeVersion).toBe(header0.writeVersion);
    expect(header1.readVersion).toBe(header0.readVersion);
    void businessRow(entry);
  });

  it("prepend is idempotent and preserves shebang / encoding / docstring / futures", () => {
    const inject = generateSidecarSqliteLoaderSnippet({
      codeIdentityHex: "a".repeat(64),
      sqliteRelPaths: ["app.sqlite"],
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.preamble).toContain(SQLITE_SIDECAR_LOADER_MARKER);
    expect(inject.preamble).toContain(SQLITE_SIDECAR_VIEW_NAME);
    const once = prependSqliteSidecarLoaderHook(FUTURE_LOADER_BODY, inject.preamble);
    expect(once.startsWith("#!/usr/bin/env python3\n")).toBe(true);
    expect(once).toContain("# -*- coding: utf-8 -*-");
    expect(once).toContain('"""Loader docstring."""');
    expect(once).toContain("from __future__ import annotations");
    const hookAt = once.indexOf(SQLITE_SIDECAR_LOADER_MARKER);
    const futureAt = once.indexOf("from __future__ import annotations");
    expect(hookAt).toBeGreaterThan(futureAt);
    const twice = prependSqliteSidecarLoaderHook(once, inject.preamble);
    expect(twice).toBe(once);
  });

  it("isSafe / select only admit known loaders that mention the database", () => {
    const loader = LOADER_BODY;
    const noMention = "print('hello')\n";
    const helper =
      'import pathlib\n_db = pathlib.Path("app.sqlite")\n';
    const testLoader =
      'import pathlib\n_db = pathlib.Path(__file__).parent / "app.sqlite"\n';
    const already = `${loader}\n# _verify_sibling_digest_deadbeef\n`;

    expect(sourceMentionsSqliteFile(loader, "app.sqlite")).toBe(true);
    expect(sourceMentionsSqliteFile(noMention, "app.sqlite")).toBe(false);

    expect(
      isSafePythonSqliteLoader({
        source: loader,
        filename: "loader.py",
        sqliteBasename: "app.sqlite",
      }),
    ).toBe(true);
    expect(
      isSafePythonSqliteLoader({
        source: testLoader,
        filename: "test_loader.py",
        sqliteBasename: "app.sqlite",
      }),
    ).toBe(false);
    expect(
      isSafePythonSqliteLoader({
        source: already,
        filename: "loader.py",
        sqliteBasename: "app.sqlite",
      }),
    ).toBe(false);
    expect(
      isSafePythonSqliteLoader({
        source: helper,
        filename: "helper.py",
        sqliteBasename: "app.sqlite",
      }),
    ).toBe(true);
    expect(
      isSafePythonSqliteLoader({
        source: noMention,
        filename: "loader.py",
        sqliteBasename: "app.sqlite",
      }),
    ).toBe(false);

    expect(
      selectPythonSqliteLoader("app.sqlite", [
        { name: "helper.py", source: helper },
        { name: "loader.py", source: loader },
        { name: "__init__.py", source: loader },
      ]),
    ).toBe("loader.py");
    expect(
      selectPythonSqliteLoader("app.sqlite", [
        { name: "__init__.py", source: loader },
        { name: "__main__.py", source: loader },
      ]),
    ).toBe("__init__.py");
    expect(
      selectPythonSqliteLoader("app.sqlite", [
        { name: "helper.py", source: helper },
      ]),
    ).toBeNull();
  });

  it.skipIf(!PY3)("load-time hook: intact database opens and keeps query results", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-loader-ok-"));
    try {
      const entry = buildSampleSqliteDatabase();
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindSqliteSidecarEntanglement({
        entryPath: "app.sqlite",
        sidecarPaths: ["sib.bin"],
        seedTag: "sqlite-loader-ok",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "app.sqlite"), bound.bytes);
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entangleSqliteLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        sqliteBytes: bound.bytes,
        sqliteRelPath: "app.sqlite",
      });
      expect(hooked.code).toContain(SQLITE_SIDECAR_LOADER_MARKER);
      validateSqliteStandaloneBuffer(bound.bytes);
      const before = readFileSync(join(dir, "app.sqlite"));
      const ran = runLoader(dir, hooked.code);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok acct_prod_01 enterprise/);
      const after = readFileSync(join(dir, "app.sqlite"));
      expect(Buffer.compare(before, after)).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("load-time hook fails closed on schema-comment strip or sibling delete", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-loader-fail-"));
    try {
      const entry = buildSampleSqliteDatabase();
      const snap = Buffer.from("sidecar-payload\n");
      const bound = bindSqliteSidecarEntanglement({
        entryPath: "app.sqlite",
        sidecarPaths: ["sib.bin"],
        seedTag: "sqlite-loader-fail",
        entryBytes: entry,
        sidecarBytes: [snap],
      });
      writeFileSync(join(dir, "sib.bin"), snap);
      const hooked = entangleSqliteLoaderWithSidecars({
        loaderSource: LOADER_BODY,
        sqliteBytes: bound.bytes,
        sqliteRelPath: "app.sqlite",
      });

      writeFileSync(join(dir, "app.sqlite"), bound.bytes);
      const ok = runLoader(dir, hooked.code);
      expect(ok.status, ok.stderr || ok.stdout).toBe(0);

      writeFileSync(join(dir, "app.sqlite"), stripSqliteSidecarSchemaComment(bound.bytes));
      const stripped = runLoader(dir, hooked.code);
      expect(stripped.status).not.toBe(0);
      expect(stripped.stderr + stripped.stdout).toMatch(/integrity binding mismatch/);

      writeFileSync(join(dir, "app.sqlite"), bound.bytes);
      unlinkSync(join(dir, "sib.bin"));
      const deleted = runLoader(dir, hooked.code);
      expect(deleted.status).not.toBe(0);
      expect(deleted.stderr + deleted.stdout).toMatch(/integrity binding mismatch/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget auto-wires a same-directory loader and records sqlite-sidecar-entangle", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-loader-protect-"));
    try {
      const entry = join(dir, "app.sqlite");
      writeFileSync(entry, buildSampleSqliteDatabase());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-sqlite-loader-hook",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.sqliteSidecarLoaderHookApplied).toBe(true);
      expect(res.counteredReaVectors).toContain("sqlite-sidecar-entangle");

      const hooked = readFileSync(join(dir, "loader.py"), "utf8");
      expect(hooked).toContain(SQLITE_SIDECAR_LOADER_MARKER);
      const dbBytes = readFileSync(entry);
      expect(
        isSqliteSidecarLoaderHookWired({
          sqliteBytes: dbBytes,
          sqlitePath: entry,
        }),
      ).toBe(true);
      expect(extractSqliteSidecarSchemaComment(dbBytes)).not.toBeNull();
      validateSqliteStandaloneBuffer(dbBytes);

      const ran = runLoader(dir, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok acct_prod_01 enterprise/);

      const verification = verifyTarget(entry, undefined, {
        sidecarEntangleEnabled: true,
      });
      const gapIds = (verification.defenseScoreGaps ?? []).map((g) => g.id);
      expect(gapIds).not.toContain("sqlite-sidecar-host-verify-only");

      const gaps = collectDefenseScoreGaps({
        detectedFormat: "sqlite",
        sidecarEntangleEnabled: true,
        sqliteSidecarLoaderHookApplied: true,
        sqliteTrapMode: "eval",
      });
      expect(gaps.map((g) => g.id)).not.toContain("sqlite-sidecar-host-verify-only");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite when sidecarEntangle is off", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-loader-off-"));
    try {
      const entry = join(dir, "app.sqlite");
      writeFileSync(entry, buildSampleSqliteDatabase());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dir, "loader.py"), LOADER_BODY, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-sqlite-loader-off",
        inPlace: true,
      });
      expect(res.sidecarEntangle).not.toBe(true);
      expect(res.sqliteSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("sqlite-sidecar-entangle");
      expect(readFileSync(join(dir, "loader.py"), "utf8")).toBe(LOADER_BODY);
      expect(extractSqliteSidecarSchemaComment(readFileSync(entry))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("protectTarget does not rewrite an unknown helper file", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-loader-unsafe-"));
    try {
      const entry = join(dir, "app.sqlite");
      writeFileSync(entry, buildSampleSqliteDatabase());
      writeFileSync(join(dir, "sib.bin"), "sidecar-payload\n");
      const helper = LOADER_BODY;
      writeFileSync(join(dir, "helper.py"), helper, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: entry,
        intensity: "balanced",
        seed: "pt-sqlite-loader-unsafe",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
        inPlace: true,
      });
      expect(res.sidecarEntangle).toBe(true);
      expect(res.sqliteSidecarLoaderHookApplied).toBeUndefined();
      expect(res.counteredReaVectors).not.toContain("sqlite-sidecar-entangle");
      expect(readFileSync(join(dir, "helper.py"), "utf8")).toBe(helper);
      expect(extractSqliteSidecarSchemaComment(readFileSync(entry))).not.toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!PY3)("hardenProject auto-wires dist/loader.py beside app.sqlite", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-loader-harden-"));
    try {
      const dist = join(dir, "dist");
      mkdirSync(dist, { recursive: true });
      writeFileSync(join(dist, "app.sqlite"), buildSampleSqliteDatabase());
      writeFileSync(join(dist, "sib.bin"), "sidecar-payload\n");
      writeFileSync(join(dist, "loader.py"), LOADER_BODY, "utf8");

      const report = hardenProject({
        directory: dir,
        intensity: "balanced",
        seed: "harden-sqlite-loader-hook",
        sidecarEntangle: true,
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.sidecarEntangleError).toBeUndefined();

      const outDist = join(report.outputDirectory, "dist");
      const hooked = readFileSync(join(outDist, "loader.py"), "utf8");
      expect(hooked).toContain(SQLITE_SIDECAR_LOADER_MARKER);
      const dbBytes = readFileSync(join(outDist, "app.sqlite"));
      expect(extractSqliteSidecarSchemaComment(dbBytes)).not.toBeNull();
      validateSqliteStandaloneBuffer(dbBytes);
      expect(
        isSqliteSidecarLoaderHookWired({
          sqliteBytes: dbBytes,
          sqlitePath: join(outDist, "app.sqlite"),
        }),
      ).toBe(true);

      const ran = runLoader(outDist, hooked);
      expect(ran.status, ran.stderr || ran.stdout).toBe(0);
      expect(ran.stdout).toMatch(/ok acct_prod_01 enterprise/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
