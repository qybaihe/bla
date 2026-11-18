import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";
import {
  classifyFunctionRole,
  isCrownJewelIdentifier,
  verifyWeaveTarget,
} from "../src/shields/weave/weave-decoy.js";

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const LICENSE_JS = `
const crypto = require("node:crypto");
function verifyLicenseKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex") === "abc";
}
module.exports = { verifyLicenseKey };
`;
const FORMAT_JS = `
function formatCurrency(amount) { return "$" + amount.toFixed(2); }
function navigateTo(route) { return "/" + route; }
module.exports = { formatCurrency, navigateTo };
`;
const LEDGER_JS = `
class Ledger {
  constructor() { this.total = 0; }
  get balance() { return this.total; }
  add(n) { this.total += n; return this; }
}
module.exports = { Ledger };
`;

describe("weave role vocabulary", () => {
  it("names gates by word, not by substring", () => {
    // Substring matching used to call every one of these a licence gate
    // (`navi-GATE-To`, `aggre-GATE`, `de-SIGN`, `AUTH-or`, `TOKEN-ize`, `CHECK-out`).
    for (const name of [
      "navigateTo",
      "aggregateTotals",
      "designTheme",
      "getAuthorName",
      "tokenize",
      "handleCheckout",
      "healthCheck",
      "checkUpdate",
      "validateEmail",
      "validateFormFields",
      "LicenseError",
      "TokenExpiredException",
    ]) {
      expect(classifyFunctionRole(name, false), name).not.toBe("gate-or-auth");
      expect(isCrownJewelIdentifier(name), name).toBe(false);
    }
    for (const name of [
      "verifyLicenseKey",
      "isLicensed",
      "checklicense",
      "verify2fa",
      "jwtVerify",
      "unlockPremium",
      "validateLicense",
      "validateToken",
      "signIn",
    ]) {
      expect(classifyFunctionRole(name, false), name).toBe("gate-or-auth");
      expect(isCrownJewelIdentifier(name), name).toBe(true);
    }
    expect(classifyFunctionRole("handleCheckout", false)).toBe("route-handler");
    expect(classifyFunctionRole("formatCurrency", true)).toBe("exported-api");
    expect(classifyFunctionRole("formatCurrency", false)).toBe("internal-helper");
  });
});

describe("weave verification scope", () => {
  it("a directory verdict rests on the files that hold gate logic", () => {
    const dir = tempDir("bla-weave-scope-");
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "license.js"), LICENSE_JS, "utf8");
    writeFileSync(join(dir, "src", "format.js"), FORMAT_JS, "utf8");
    writeFileSync(join(dir, "src", "ledger.js"), LEDGER_JS, "utf8");

    const report = verifyWeaveTarget(dir);
    expect(report.scope).toBe("crown-jewels");
    expect(report.requiredFiles).toEqual(["src/license.js"]);
    expect([...report.advisoryFiles].sort()).toEqual(["src/format.js", "src/ledger.js"]);
    expect(report.overallPassed).toBe(false);

    // Every action is about the gate file — none asks to "weave" a formatter.
    expect(report.agentActions.length).toBeGreaterThan(0);
    expect(new Set(report.agentActions.map((a) => a.file))).toEqual(new Set(["src/license.js"]));
    const license = report.files.find((f) => f.relativePath === "src/license.js")!;
    expect(license.scope).toBe("required");
    expect(license.crownJewelSignals?.join(" ")).toMatch(/verifyLicenseKey/);
    expect(report.files.find((f) => f.relativePath === "src/format.js")!.scope).toBe("advisory");
    expect(report.summary).toMatch(/1\/1 crown-jewel file\(s\)/);
    expect(report.summary).toMatch(/advisory only/);
  });

  it("scope: all restores the every-file verdict, and a single file is always required", () => {
    const dir = tempDir("bla-weave-scope-");
    writeFileSync(join(dir, "license.js"), LICENSE_JS, "utf8");
    writeFileSync(join(dir, "format.js"), FORMAT_JS, "utf8");

    const all = verifyWeaveTarget(dir, { scope: "all" });
    expect(all.scope).toBe("all");
    expect([...all.requiredFiles].sort()).toEqual(["format.js", "license.js"]);
    expect(all.advisoryFiles).toEqual([]);

    const single = verifyWeaveTarget(join(dir, "format.js"));
    expect(single.requiredFiles).toHaveLength(1);
    expect(single.advisoryFiles).toEqual([]);
  });

  it("a project without gate logic is not blamed file by file", () => {
    const dir = tempDir("bla-weave-scope-");
    writeFileSync(join(dir, "format.js"), FORMAT_JS, "utf8");
    writeFileSync(join(dir, "ledger.js"), LEDGER_JS, "utf8");

    const report = verifyWeaveTarget(dir);
    expect(report.scope).toBe("agent-selected");
    expect(report.requiredFiles).toHaveLength(1);
    expect(report.advisoryFiles).toHaveLength(1);
    // Class methods and accessors are not "disconnected no-op helpers".
    const ledger = report.files.find((f) => f.relativePath === "ledger.js")!;
    const failed = ledger.checks.filter((c) => !c.passed).map((c) => c.id);
    expect(failed).not.toContain("filter-resistance");
    expect(failed).not.toContain("customer-entry-edges");
  });

  it("skips declarations and toolchain files", () => {
    const dir = tempDir("bla-weave-scope-");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }), "utf8");
    writeFileSync(join(dir, "license.js"), LICENSE_JS, "utf8");
    writeFileSync(join(dir, "license.d.ts"), "export declare function verifyLicenseKey(key: string): boolean;\n", "utf8");
    writeFileSync(join(dir, "vite.config.js"), "module.exports = { build: {} };\n", "utf8");
    writeFileSync(join(dir, "license.test.js"), "test('x', () => {});\n", "utf8");

    const report = verifyWeaveTarget(dir, { scope: "all" });
    expect(report.files.map((f) => f.relativePath)).toEqual(["license.js"]);
  });

  it("MCP bla_verify_weave returns required files only unless verbose", async () => {
    const dir = tempDir("bla-weave-scope-");
    writeFileSync(join(dir, "license.js"), LICENSE_JS, "utf8");
    writeFileSync(join(dir, "format.js"), FORMAT_JS, "utf8");
    const call = async (args: Record<string, unknown>) => {
      const res = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "bla_verify_weave", arguments: args },
      });
      expect(res?.error).toBeUndefined();
      return res!.result as { isError?: boolean; structuredContent: Record<string, any> };
    };

    const compact = await call({ path: dir });
    expect(compact.isError).toBe(true); // license.js is not woven yet
    expect(compact.structuredContent.files.map((f: { relativePath: string }) => f.relativePath)).toEqual([
      "license.js",
    ]);
    expect(compact.structuredContent.advisoryFiles).toEqual(["format.js"]);

    const verbose = await call({ path: dir, verbose: true });
    expect(verbose.structuredContent.files).toHaveLength(2);

    const everything = await call({ path: dir, scope: "all" });
    expect([...everything.structuredContent.requiredFiles].sort()).toEqual(["format.js", "license.js"]);
  });
});
