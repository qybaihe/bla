import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const SECRET_ENTRY = `module.exports.unlock = function unlock(key) {
  const flag = "FLAG{mcp_gate_demo_fixture}";
  const token = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c";
  return key === "ok" ? flag : token;
};
`;

const PLAIN_ENTRY = `"use strict";
module.exports.unlock = function unlock(key) {
  return key === "ok" ? "FLAG{in_scope}" : null;
};
`;

async function call(name: string, args: Record<string, unknown>) {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
  expect(res?.error).toBeUndefined();
  return res!.result as {
    isError: boolean;
    structuredContent: {
      readonly [key: string]: unknown;
      status?: string;
      wouldOverwrite?: readonly string[];
      writeReceipt?: Record<string, unknown>;
      totalEncrypted?: number;
    };
  };
}

describe("MCP in-place writes require confirm_overwrite", () => {
  it("bla_encrypt_strings refuses an unconfirmed in-place rewrite", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-enc-"));
    tempDirs.push(dir);
    const file = join(dir, "license.cjs");
    writeFileSync(file, SECRET_ENTRY, "utf8");

    const refused = await call("bla_encrypt_strings", {
      path: dir,
      seed: "mcp-gate-1",
    });

    expect(refused.isError).toBe(true);
    expect(refused.structuredContent.status).toBe("confirmation_required");
    expect(refused.structuredContent.wouldOverwrite).toEqual([file]);
    expect(readFileSync(file, "utf8")).toBe(SECRET_ENTRY);
  });

  it("bla_encrypt_strings rewrites in place once confirmed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-enc-ok-"));
    tempDirs.push(dir);
    const file = join(dir, "license.cjs");
    writeFileSync(file, SECRET_ENTRY, "utf8");

    const ok = await call("bla_encrypt_strings", {
      path: dir,
      seed: "mcp-gate-1",
      confirm_overwrite: true,
    });

    expect(ok.isError).toBe(false);
    expect(ok.structuredContent.status).toBe("ok");
    const after = readFileSync(file, "utf8");
    expect(after).not.toContain("FLAG{mcp_gate_demo_fixture}");
    expect(after).not.toContain("7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c");
    expect(ok.structuredContent.writeReceipt).toEqual({
      status: "written",
      wrote: [file],
      overwrote: [file],
      confirmed: true,
    });
  });

  it("bla_encrypt_strings dry_run never needs confirmation and writes nothing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-enc-dry-"));
    tempDirs.push(dir);
    const file = join(dir, "license.cjs");
    writeFileSync(file, SECRET_ENTRY, "utf8");

    const dry = await call("bla_encrypt_strings", {
      path: dir,
      seed: "mcp-gate-1",
      dry_run: true,
    });

    expect(dry.isError).toBe(false);
    expect(dry.structuredContent.status).toBe("ok");
    expect(dry.structuredContent.writeReceipt).toBeUndefined();
    expect(readFileSync(file, "utf8")).toBe(SECRET_ENTRY);
  });

  it("bla_encrypt_strings keeps out_dir runs confirmation-free when nothing is clobbered", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-enc-out-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, "license.cjs"), SECRET_ENTRY, "utf8");

    const ok = await call("bla_encrypt_strings", {
      path: dir,
      seed: "mcp-gate-1",
      out_dir: join(dir, "out"),
    });

    expect(ok.isError).toBe(false);
    expect(ok.structuredContent.status).toBe("ok");
    expect(ok.structuredContent.writeReceipt).toEqual({
      status: "written",
      wrote: [join(dir, "out", "license.cjs")],
      overwrote: [],
      confirmed: false,
    });
  });

  it("bla_bind_scope refuses to rewrite an existing entry without confirmation", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-bind-"));
    tempDirs.push(dir);
    const entry = join(dir, "license.cjs");
    writeFileSync(entry, PLAIN_ENTRY, "utf8");

    const refused = await call("bla_bind_scope", {
      directory: dir,
      domains: ["app.example.com"],
      valid_from: "2020-01-01T00:00:00.000Z",
      valid_until: "2099-01-01T00:00:00.000Z",
    });

    expect(refused.isError).toBe(true);
    expect(refused.structuredContent.status).toBe("confirmation_required");
    expect(refused.structuredContent.wouldOverwrite).toEqual([entry]);
    expect(readFileSync(entry, "utf8")).toBe(PLAIN_ENTRY);
  });

  it("bla_bind_scope writes once confirmed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-bind-ok-"));
    tempDirs.push(dir);
    const entry = join(dir, "license.cjs");
    writeFileSync(entry, PLAIN_ENTRY, "utf8");

    const ok = await call("bla_bind_scope", {
      directory: dir,
      domains: ["app.example.com"],
      valid_from: "2020-01-01T00:00:00.000Z",
      valid_until: "2099-01-01T00:00:00.000Z",
      confirm_overwrite: true,
    });

    expect(ok.isError).toBe(false);
    expect(ok.structuredContent.status).toBe("ok");
    expect(readFileSync(entry, "utf8")).toContain("BLA_BIND_SCOPE_CHECK");
    expect(ok.structuredContent.writeReceipt).toEqual({
      status: "written",
      wrote: [join(dir, "bind-scope.json"), entry],
      overwrote: [entry],
      confirmed: true,
    });
  });
});