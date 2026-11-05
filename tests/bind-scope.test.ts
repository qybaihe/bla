import {
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  BIND_SCOPE_RUNTIME_MARKER,
  BIND_SCOPE_SCHEMA,
  applyBindScope,
  buildBindScopeContract,
  discoverAndLintBindScope,
  evaluateBindHost,
  evaluateBindTime,
  hostMatchesBindDomain,
  lintBindScopeFile,
  validateBindScopeContract,
} from "../src/engine/bind-scope.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import { scanPackagingGates } from "../src/engine/packaging-gates.js";

const ENTRY = `"use strict";
module.exports.unlock = function unlock(key) {
  return key === "ok" ? "FLAG{in_scope}" : null;
};
`;

describe("bind-scope (Direction-4 honest code lock)", () => {
  it("requires public:true and rejects hidden fields / empty constraints", () => {
    expect(
      validateBindScopeContract({
        schema: BIND_SCOPE_SCHEMA,
        public: false,
        domains: ["app.example.com"],
      }).reasons,
    ).toContain("not-public");
    expect(
      validateBindScopeContract({
        schema: BIND_SCOPE_SCHEMA,
        public: true,
        domains: ["app.example.com"],
        covertAllow: ["evil.com"],
      }).reasons,
    ).toContain("hidden-field");
    expect(
      validateBindScopeContract({
        schema: BIND_SCOPE_SCHEMA,
        public: true,
      }).reasons,
    ).toContain("empty-constraints");
  });

  it("matches exact and *.suffix hosts; evaluates validity window", () => {
    expect(hostMatchesBindDomain("app.example.com", "app.example.com")).toBe(true);
    expect(hostMatchesBindDomain("x.example.com", "*.example.com")).toBe(true);
    expect(hostMatchesBindDomain("example.com", "*.example.com")).toBe(false);
    expect(evaluateBindHost("api.foo.test", ["*.foo.test"])).toBe(true);
    const from = "2026-01-01T00:00:00.000Z";
    const until = "2026-12-31T23:59:59.999Z";
    expect(evaluateBindTime(Date.parse("2026-06-01T00:00:00.000Z"), from, until)).toBe(true);
    expect(evaluateBindTime(Date.parse("2025-06-01T00:00:00.000Z"), from, until)).toBe(false);
    expect(evaluateBindTime(Date.parse("2027-06-01T00:00:00.000Z"), from, until)).toBe(false);
  });

  it("writes public contract + injects runtime check; in-scope loads, out-of-scope throws", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-bind-"));
    writeFileSync(join(dir, "license.cjs"), ENTRY);
    const report = applyBindScope({
      directory: dir,
      domains: ["allowed.example"],
      validFrom: "2020-01-01T00:00:00.000Z",
      validUntil: "2099-01-01T00:00:00.000Z",
    });
    expect(report.status).toBe("ok");
    expect(report.written).toBe(true);
    expect(report.runtimeInjected).toBe(true);
    expect(report.lint.ok).toBe(true);
    expect(existsSync(join(dir, "bind-scope.json"))).toBe(true);
    const contract = JSON.parse(readFileSync(join(dir, "bind-scope.json"), "utf8"));
    expect(contract.schema).toBe(BIND_SCOPE_SCHEMA);
    expect(contract.public).toBe(true);
    expect(contract.domains).toEqual(["allowed.example"]);

    const src = readFileSync(join(dir, "license.cjs"), "utf8");
    expect(src).toContain(BIND_SCOPE_RUNTIME_MARKER);

    const prev = process.env.BLA_BIND_HOST;
    try {
      process.env.BLA_BIND_HOST = "allowed.example";
      const mod = require(join(dir, "license.cjs"));
      expect(mod.unlock("ok")).toBe("FLAG{in_scope}");
    } finally {
      if (prev === undefined) delete process.env.BLA_BIND_HOST;
      else process.env.BLA_BIND_HOST = prev;
    }

    // Fresh copy for out-of-scope (module cache)
    const dir2 = mkdtempSync(join(tmpdir(), "bla-bind-oos-"));
    writeFileSync(join(dir2, "license.cjs"), ENTRY);
    applyBindScope({
      directory: dir2,
      domains: ["allowed.example"],
    });
    process.env.BLA_BIND_HOST = "evil.example";
    expect(() => require(join(dir2, "license.cjs"))).toThrow(/bind-scope: host not in public domains/);
    delete process.env.BLA_BIND_HOST;
  });

  it("lint refuses contract without runtime marker; packaging gates pick it up", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-bind-lint-"));
    writeFileSync(join(dir, "license.cjs"), ENTRY);
    writeFileSync(
      join(dir, "bind-scope.json"),
      JSON.stringify(buildBindScopeContract({ domains: ["a.example"] }), null, 2),
    );
    const reports = discoverAndLintBindScope(dir);
    expect(reports.length).toBe(1);
    expect(reports[0]!.shouldRefuseBankrupt).toBe(true);
    expect(reports[0]!.reasons).toContain("missing-runtime-check");

    const gates = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    expect(gates.gateCounts["bind-scope"]).toBeGreaterThanOrEqual(1);
    expect(gates.shouldRefuseBankrupt).toBe(true);
  });

  it("MCP bla_bind_scope dry_run writes nothing; apply then lint passes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-bind-mcp-"));
    writeFileSync(join(dir, "license.cjs"), ENTRY);
    const dry = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "bla_bind_scope",
        arguments: {
          directory: dir,
          domains: ["mcp.example"],
          dry_run: true,
        },
      },
    });
    expect(dry?.error).toBeUndefined();
    expect(existsSync(join(dir, "bind-scope.json"))).toBe(false);

    const live = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "bla_bind_scope",
        arguments: {
          directory: dir,
          domains: ["mcp.example"],
          valid_until: "2099-12-31T00:00:00.000Z",
        },
      },
    });
    expect(live?.error).toBeUndefined();
    expect((live!.result as { isError?: boolean }).isError).toBe(false);
    expect(existsSync(join(dir, "bind-scope.json"))).toBe(true);

    const lint = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "bla_lint_bind_scope",
        arguments: { path: dir },
      },
    });
    const content = (lint!.result as { structuredContent: { shouldRefuseBankrupt: boolean } })
      .structuredContent;
    expect(content.shouldRefuseBankrupt).toBe(false);
  });
});
