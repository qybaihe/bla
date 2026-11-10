import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { getDatabaseSyncClass, isNodeSqliteAvailable } from "../src/core/sqlite-runtime.js";
import {
  buildSampleSqliteDatabase,
  DEFAULT_SQLITE_SENSITIVITY_POLICY,
  evaluateSqliteSensitivityPolicy,
  inspectSqliteBuffer,
  minimizeSqliteDatabaseBuffer,
  protectSqliteBuffer,
  SqliteWalConsistencyError,
  validateSqliteFileInput,
  type SqliteSensitivityPolicy,
} from "../src/shields/formats/sqlite.js";
import {
  inspectProductionDebugPosture,
} from "../src/core/debug-posture.js";
import {
  buildDefenseCoverageContract,
  ReferenceTenantAuthorizationService,
} from "../src/core/coverage-contract.js";
import { generateRuntimeDeceptionSnippet } from "../src/shields/runtime/runtime-shield.js";
import { SeededPrng } from "../src/core/prng.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

describe("Issues #18, #19, #20, #21 — SQLite Consistency/Policy, Debug Posture & Server Coverage", () => {
  const tempDirs: string[] = [];
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // ==========================================================================
  // Issue #18: SQLite DB/WAL Consistency Admission
  // ==========================================================================
  describe.skipIf(!isNodeSqliteAvailable())("Issue #18: SQLite DB/WAL consistency validation before protection", () => {
    it("rejects uncheckpointed WAL database (both by path and by main-file buffer) instead of dropping committed rows", () => {
      const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-wal-repro-"));
      tempDirs.push(dir);
      const dbPath = join(dir, "live.sqlite");
      const DatabaseSync = getDatabaseSyncClass();

      const conn = new DatabaseSync(dbPath);
      try {
        conn.exec("PRAGMA journal_mode = WAL;");
        conn.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT NOT NULL);");
        conn.exec("PRAGMA wal_checkpoint(TRUNCATE);");
        conn.exec("PRAGMA wal_autocheckpoint = 0;");
        conn.exec("INSERT INTO orders (id, item) VALUES (1, 'committed-in-wal-only');");

        const committedRows = conn.prepare("SELECT COUNT(*) AS cnt FROM orders").get() as {
          cnt: number;
        };
        expect(committedRows.cnt).toBe(1);

        const mainDbBytesBefore = readFileSync(dbPath);
        const walBytesBefore = readFileSync(`${dbPath}-wal`);
        expect(walBytesBefore.length).toBeGreaterThan(0);

        // 1. File-set validator rejects because companion -wal/-shm exists
        expect(() => validateSqliteFileInput(dbPath)).toThrow(SqliteWalConsistencyError);

        // 2. Single-buffer API also rejects because header bytes 18..19 indicate WAL mode (version 2)
        expect(() => protectSqliteBuffer(mainDbBytesBefore)).toThrow(SqliteWalConsistencyError);

        // Source DB and WAL files remain completely untouched
        expect(readFileSync(dbPath)).toEqual(mainDbBytesBefore);
        expect(readFileSync(`${dbPath}-wal`)).toEqual(walBytesBefore);
      } finally {
        conn.close();
      }
    });

    it("rejects hot rollback journal (-journal) and truncated/corrupt SQLite buffers", () => {
      const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-journal-"));
      tempDirs.push(dir);
      const dbPath = join(dir, "app.sqlite");
      const validBytes = buildSampleSqliteDatabase();
      writeFileSync(dbPath, validBytes);
      writeFileSync(`${dbPath}-journal`, Buffer.from("hot-rollback-journal-bytes"));

      expect(() => validateSqliteFileInput(dbPath)).toThrow(SqliteWalConsistencyError);

      // Truncated buffer (not a multiple of page size)
      const truncated = validBytes.subarray(0, validBytes.length - 17);
      expect(() => protectSqliteBuffer(truncated)).toThrow(SqliteWalConsistencyError);

      // Non-SQLite buffer
      expect(() => protectSqliteBuffer(Buffer.from("not-a-sqlite-db"))).toThrow(
        SqliteWalConsistencyError,
      );
    });

    it("accepts a consistent standalone backup (VACUUM INTO) from a WAL database and preserves 100% of business rows", () => {
      const dir = mkdtempSync(join(tmpdir(), "bla-sqlite-backup-"));
      tempDirs.push(dir);
      const livePath = join(dir, "live.sqlite");
      const backupPath = join(dir, "standalone-backup.sqlite");
      const DatabaseSync = getDatabaseSyncClass();

      const conn = new DatabaseSync(livePath);
      try {
        conn.exec("PRAGMA journal_mode = WAL;");
        conn.exec("CREATE TABLE invoices (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL);");
        conn.exec("PRAGMA wal_autocheckpoint = 0;");
        conn.exec("INSERT INTO invoices (id, amount) VALUES (101, 4500), (102, 9200);");
        // Application creates a consistent standalone backup via VACUUM INTO
        conn.exec(`VACUUM INTO '${backupPath.replace(/'/g, "''")}';`);
      } finally {
        conn.close();
      }

      const backupBytes = validateSqliteFileInput(backupPath);
      const protectedRes = protectSqliteBuffer(backupBytes, { intensity: "balanced" });

      const verifyPath = join(dir, "protected.sqlite");
      writeFileSync(verifyPath, protectedRes.buffer);
      const verifyDb = new DatabaseSync(verifyPath, { readOnly: true });
      try {
        const rows = verifyDb
          .prepare("SELECT id, amount FROM invoices ORDER BY id")
          .all() as Array<{ id: number; amount: number }>;
        expect(rows).toEqual([
          { id: 101, amount: 4500 },
          { id: 102, amount: 9200 },
        ]);
      } finally {
        verifyDb.close();
      }
    });
  });

  // ==========================================================================
  // Issue #21: SQLite Sensitive Data Policy & Confidentiality Separation
  // ==========================================================================
  describe("Issue #21: SQLite sensitive data exposure policy and decoration vs confidentiality", () => {
    it.skipIf(!isNodeSqliteAvailable())("reports exposed sensitive columns even when honey tables are present, without leaking secret values in output", () => {
      const rawSqlite = buildSampleSqliteDatabase();
      const protectedSqlite = protectSqliteBuffer(rawSqlite, { intensity: "maximum" });

      const customPolicy: SqliteSensitivityPolicy = {
        policyId: "synthetic-client-cache-policy",
        rules: [
          {
            ruleId: "SYNTH-NO-OFFLINE-TOKEN",
            tablePattern: "license_cache",
            columnPattern: "offline_token",
            classification: "forbidden-in-client-artifact",
            remediation: "Remove offline_token before distributing SQLite cache.",
          },
        ],
      };

      const inspection = inspectSqliteBuffer(protectedSqlite.buffer, customPolicy);
      expect(inspection.validSqlite).toBe(true);
      expect(inspection.blaProtected).toBe(true);
      expect(inspection.decorationState).toBe("decorated");
      expect(inspection.businessDataState).toBe("business-data-preserved");
      // Honey tables DO NOT establish confidentiality!
      expect(inspection.confidentialityState).toBe("policy-violation-exposed");
      expect(inspection.policyFindings).toHaveLength(1);
      expect(inspection.policyFindings[0]).toMatchObject({
        ruleId: "SYNTH-NO-OFFLINE-TOKEN",
        table: "license_cache",
        column: "offline_token",
        nonNullRowCount: 1,
        status: "exposed",
      });

      // Verify raw secret value ("tok_live_9988776655") is NEVER present in serialized inspection or policy report
      const serialized = JSON.stringify(inspection);
      expect(serialized).not.toContain("tok_live_9988776655");
    });

    it.skipIf(!isNodeSqliteAvailable())("clears policy violations after data minimization while keeping confidentialityState as confidentiality-not-established", () => {
      const rawSqlite = buildSampleSqliteDatabase();
      const minimized = minimizeSqliteDatabaseBuffer(rawSqlite, [
        { table: "license_cache", column: "offline_token" },
      ]);
      const protectedMinimized = protectSqliteBuffer(minimized);

      const report = evaluateSqliteSensitivityPolicy(
        protectedMinimized.buffer,
        DEFAULT_SQLITE_SENSITIVITY_POLICY,
      );
      expect(report.validSqlite).toBe(true);
      expect(report.decorationState).toBe("decorated");
      expect(report.businessDataState).toBe("business-data-preserved");
      expect(report.findings).toEqual([]);
      // Plaintext business columns (account_id, plan_tier) are not misreported as encrypted
      expect(report.confidentialityState).toBe("confidentiality-not-established");
      expect(report.residualRiskNotice).toContain("local principal");
    });

    it("reports unsupported-or-encrypted on encrypted or unknown database bytes rather than claiming no secrets", () => {
      const encryptedLikeBytes = Buffer.alloc(4096, 0xa5);
      const report = evaluateSqliteSensitivityPolicy(encryptedLikeBytes);
      expect(report.validSqlite).toBe(false);
      expect(report.formatStatus).toBe("unsupported-or-encrypted");
      expect(report.decorationState).toBe("unsupported-or-encrypted");
      expect(report.confidentialityState).toBe("unsupported-or-encrypted");
    });
  });

  // ==========================================================================
  // Issue #19: Production Debug Posture & Runtime Boundary
  // ==========================================================================
  describe("Issue #19: Production debug exposure posture and decorative runtime boundary", () => {
    it("distinguishes exposed debuggable build configs, hardened production configs, and unknown configs", () => {
      const debugDir = mkdtempSync(join(tmpdir(), "bla-debug-posture-exposed-"));
      const prodDir = mkdtempSync(join(tmpdir(), "bla-debug-posture-hardened-"));
      const emptyDir = mkdtempSync(join(tmpdir(), "bla-debug-posture-unknown-"));
      tempDirs.push(debugDir, prodDir, emptyDir);

      // 1. Debuggable fixture
      writeFileSync(
        join(debugDir, "package.json"),
        JSON.stringify({
          name: "debug-app",
          scripts: {
            start: "electron . --inspect=9229 --remote-debugging-port=9222",
          },
        }),
      );
      writeFileSync(
        join(debugDir, "entitlements.plist"),
        `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>`,
      );
      writeFileSync(
        join(debugDir, "AndroidManifest.xml"),
        `<manifest><application android:debuggable="true"></application></manifest>`,
      );

      const debugReport = inspectProductionDebugPosture({ targetDir: debugDir });
      expect(debugReport.overallPosture).toBe("exposed");
      expect(debugReport.checks.every((c) => c.status === "exposed")).toBe(true);
      expect(debugReport.runtimeBoundaryContract.shadowObjectsClassification).toBe(
        "decorative-deception-signal",
      );
      expect(debugReport.runtimeBoundaryContract.absenceOfRuntimeMarkersImpliesNoDebugger).toBe(
        false,
      );
      expect(debugReport.runtimeBoundaryContract.blocksFridaOrGdbWithLocalPrivileges).toBe(false);

      // 2. Hardened production fixture
      writeFileSync(
        join(prodDir, "package.json"),
        JSON.stringify({
          name: "prod-app",
          scripts: {
            start: "electron .",
          },
        }),
      );
      writeFileSync(
        join(prodDir, "entitlements.plist"),
        `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><false/></dict></plist>`,
      );
      writeFileSync(
        join(prodDir, "AndroidManifest.xml"),
        `<manifest><application android:debuggable="false"></application></manifest>`,
      );

      const prodReport = inspectProductionDebugPosture({ targetDir: prodDir });
      expect(prodReport.overallPosture).toBe("not-observed");
      expect(prodReport.checks.every((c) => c.status === "not-observed")).toBe(true);

      // 3. Unknown empty directory fixture
      const unknownReport = inspectProductionDebugPosture({ targetDir: emptyDir });
      expect(unknownReport.overallPosture).toBe("unknown");
      expect(unknownReport.checks.every((c) => c.status === "unknown")).toBe(true);
    });

    it("marks runtime shadow objects as decorative-deception-signal with no security boundary", () => {
      const prng = new SeededPrng("runtime-boundary-seed");
      const chaff = generateChaffPayloads(prng, "balanced");
      const snippet = generateRuntimeDeceptionSnippet(prng, "balanced", chaff);
      expect(snippet.classification).toBe("decorative-deception-signal");
      expect(snippet.revokesDebuggerAttach).toBe(false);
      expect(snippet.protectsClientPlaintextSecrets).toBe(false);
      // Emitted bundle code must NOT self-report as a decorative decoy to an inspecting LLM/reverser
      expect(snippet.code).not.toContain('classification: "decorative-deception-signal"');
      expect(snippet.code).not.toContain('securityBoundary: "none-client-side-only"');
      expect(snippet.code).not.toContain("decorative shadow runtime signal");
      expect(snippet.code).toContain('status: "HARDWARE_ENCLAVE_DELEGATED"');
    });
  });

  // ==========================================================================
  // Issue #20: Server Authorization Coverage Contract & Multi-Tenant Reference
  // ==========================================================================
  describe("Issue #20: Server authorization coverage contract and synthetic multi-tenant reference fixture", () => {
    it("separates client-artifact coverage from server-authorization external responsibility", () => {
      const defaultContract = buildDefenseCoverageContract();
      expect(defaultContract.clientArtifact.enforcesAccessControl).toBe(false);
      expect(defaultContract.clientArtifact.guaranteesConfidentialityOfShippedData).toBe(false);
      expect(defaultContract.serverAuthorization.status).toBe(
        "not-assessed/external-control-required",
      );
    });

    it("enforces tenant isolation, role checks, CSRF/replay protection, session expiry/revocation, and response data minimization across two synthetic tenants", () => {
      let currentNow = 1_700_000_000_000;
      const service = new ReferenceTenantAuthorizationService({
        allowedOrigin: "https://app.local.fixture",
        nowFn: () => currentNow,
      });

      service.seedDocument({
        docId: "doc_alpha_1",
        tenantId: "tenant_alpha",
        title: "Alpha Roadmap",
        quotaLimit: 100,
        internalSigningKeyMaterial: "SECRET_INTERNAL_SIGNING_KEY_ALPHA_DO_NOT_LEAK",
        internalBillingWebhookSecret: "whsec_INTERNAL_ALPHA_999",
      });
      service.seedDocument({
        docId: "doc_beta_1",
        tenantId: "tenant_beta",
        title: "Beta Financials",
        quotaLimit: 500,
        internalSigningKeyMaterial: "SECRET_INTERNAL_SIGNING_KEY_BETA_DO_NOT_LEAK",
        internalBillingWebhookSecret: "whsec_INTERNAL_BETA_999",
      });

      const alphaViewer = service.issueSession({
        userId: "user_a_viewer",
        tenantId: "tenant_alpha",
        role: "viewer",
        ttlMs: 30_000,
      });
      const alphaAdmin = service.issueSession({
        userId: "user_a_admin",
        tenantId: "tenant_alpha",
        role: "admin",
        ttlMs: 30_000,
      });

      // 1. Authorized GET succeeds and strips backend-only secret fields (data minimization)
      const getAlpha = service.handleRequest({
        method: "GET",
        path: "/api/tenants/tenant_alpha/documents/doc_alpha_1",
        origin: "https://app.local.fixture",
        sessionId: alphaViewer.sessionId,
      });
      expect(getAlpha.status).toBe(200);
      expect(getAlpha.data).toEqual({
        docId: "doc_alpha_1",
        tenantId: "tenant_alpha",
        title: "Alpha Roadmap",
        quotaLimit: 100,
      });
      expect(JSON.stringify(getAlpha)).not.toContain("SECRET_INTERNAL_SIGNING_KEY");
      expect(JSON.stringify(getAlpha)).not.toContain("whsec_INTERNAL");

      // 2. Same-origin cross-tenant fetch (tenant_alpha session requesting tenant_beta resource) is rejected
      const crossTenantGet = service.handleRequest({
        method: "GET",
        path: "/api/tenants/tenant_beta/documents/doc_beta_1",
        origin: "https://app.local.fixture",
        sessionId: alphaAdmin.sessionId,
      });
      expect(crossTenantGet.status).toBe(403);
      expect(crossTenantGet.errorCode).toBe("FORBIDDEN_TENANT_OR_ROLE");

      // 3. Viewer attempting state mutation via direct same-origin POST (bypassing hidden UI button) is rejected with no state change
      const viewerMutate = service.handleRequest({
        method: "POST",
        path: "/api/tenants/tenant_alpha/documents/doc_alpha_1",
        origin: "https://app.local.fixture",
        sessionId: alphaViewer.sessionId,
        csrfToken: alphaViewer.csrfToken,
        requestNonce: "nonce_viewer_attempt_01",
        body: { title: "Tampered by Viewer", quotaLimit: 99999 },
      });
      expect(viewerMutate.status).toBe(403);
      expect(service.snapshotDocumentState("doc_alpha_1")).toEqual({
        title: "Alpha Roadmap",
        quotaLimit: 100,
      });

      // 4. Admin mutation with valid CSRF and fresh nonce succeeds; replaying the same nonce is rejected
      const adminMutate = service.handleRequest({
        method: "POST",
        path: "/api/tenants/tenant_alpha/documents/doc_alpha_1",
        origin: "https://app.local.fixture",
        sessionId: alphaAdmin.sessionId,
        csrfToken: alphaAdmin.csrfToken,
        requestNonce: "nonce_admin_valid_001",
        body: { title: "Alpha Roadmap v2", quotaLimit: 250 },
      });
      expect(adminMutate.status).toBe(200);
      expect(service.snapshotDocumentState("doc_alpha_1")).toEqual({
        title: "Alpha Roadmap v2",
        quotaLimit: 250,
      });

      const replayAttempt = service.handleRequest({
        method: "POST",
        path: "/api/tenants/tenant_alpha/documents/doc_alpha_1",
        origin: "https://app.local.fixture",
        sessionId: alphaAdmin.sessionId,
        csrfToken: alphaAdmin.csrfToken,
        requestNonce: "nonce_admin_valid_001",
        body: { title: "Replayed Mutation", quotaLimit: 999 },
      });
      expect(replayAttempt.status).toBe(403);
      expect(replayAttempt.errorCode).toBe("CSRF_OR_REPLAY_REJECTED");
      expect(service.snapshotDocumentState("doc_alpha_1")).toEqual({
        title: "Alpha Roadmap v2",
        quotaLimit: 250,
      });

      // 5. Session revocation and expiration
      service.revokeSession(alphaViewer.sessionId);
      const revokedRes = service.handleRequest({
        method: "GET",
        path: "/api/tenants/tenant_alpha/documents/doc_alpha_1",
        origin: "https://app.local.fixture",
        sessionId: alphaViewer.sessionId,
      });
      expect(revokedRes.status).toBe(401);

      currentNow += 60_000;
      const expiredRes = service.handleRequest({
        method: "GET",
        path: "/api/tenants/tenant_alpha/documents/doc_alpha_1",
        origin: "https://app.local.fixture",
        sessionId: alphaAdmin.sessionId,
      });
      expect(expiredRes.status).toBe(401);

      // 6. Client workflow produces identical results before and after BLA AST protection
      const freshSession = service.issueSession({
        userId: "user_a_client",
        tenantId: "tenant_alpha",
        role: "viewer",
      });
      const clientCode = `
        function fetchTenantDoc(api, sessionId, tenantId, docId) {
          return api.handleRequest({
            method: "GET",
            path: "/api/tenants/" + tenantId + "/documents/" + docId,
            origin: "https://app.local.fixture",
            sessionId: sessionId
          });
        }
        module.exports = { fetchTenantDoc };
      `;
      const protectedClientCode = transformJavaScriptWithBlaShield(clientCode, {
        intensity: "balanced",
        seed: "client-workflow-seed",
      }).code;

      const runClient = (code: string) => {
        const mod = { exports: {} as Record<string, unknown> };
        vm.runInNewContext(code, { module: mod, exports: mod.exports, Object, Array, String, Number, Math });
        return (
          mod.exports.fetchTenantDoc as (
            s: ReferenceTenantAuthorizationService,
            sid: string,
            tid: string,
            did: string,
          ) => unknown
        )(service, freshSession.sessionId, "tenant_alpha", "doc_alpha_1");
      };

      expect(runClient(protectedClientCode)).toEqual(runClient(clientCode));
    });
  });
});
