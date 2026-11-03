import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest, BLA_MCP_TOOLS } from "../src/mcp/server.js";
import { SEAL_COMMITMENT_SCHEMA } from "../src/engine/seal-commitment-lint.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function call(name: string, args: Record<string, unknown>) {
  return handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
}

const ROUND2 = {
  schema: "bla-redblue-r2-seal/v1",
  rounds: 28,
  scheduleSalt: 1374179543,
  revision: "7f325fec37206b637a224e9630b67c4a",
  certificateCipherHex: "aabb",
};

const ONE_WAY = {
  schema: "bla-entitlement-seal/v1",
  algorithm: "sha256",
  revision: "b38091d4a394ded9012846e8d4b647083b260beb6ee5ad1e42265fe6f107c660",
};

describe("MCP bla_lint_seal", () => {
  it("is registered once", () => {
    expect(BLA_MCP_TOOLS.filter((t) => t.name === "bla_lint_seal")).toHaveLength(1);
  });

  it("flags reversible seal and sets isError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-seal-bad-"));
    tempDirs.push(dir);
    const file = join(dir, "seal.json");
    writeFileSync(file, JSON.stringify(ROUND2), "utf8");
    const res = await call("bla_lint_seal", { path: file });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError?: boolean;
      structuredContent: {
        schema: string;
        shouldRefuseBankrupt: boolean;
        findings: ReadonlyArray<{ id: string; severity: string }>;
      };
    };
    expect(result.structuredContent.schema).toBe(SEAL_COMMITMENT_SCHEMA);
    expect(result.structuredContent.shouldRefuseBankrupt).toBe(true);
    expect(result.isError).toBe(true);
    expect(
      result.structuredContent.findings.some((f) => f.id === "reversible-public-commitment"),
    ).toBe(true);
  });

  it("passes one-way digest without refuse", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-seal-ok-"));
    tempDirs.push(dir);
    const file = join(dir, "seal.json");
    writeFileSync(file, JSON.stringify(ONE_WAY), "utf8");
    const res = await call("bla_lint_seal", { path: file });
    const result = res!.result as {
      isError?: boolean;
      structuredContent: { shouldRefuseBankrupt: boolean };
    };
    expect(result.structuredContent.shouldRefuseBankrupt).toBe(false);
    expect(result.isError).toBeFalsy();
  });
});
