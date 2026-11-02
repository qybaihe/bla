import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest, BLA_MCP_TOOLS } from "../src/mcp/server.js";
import {
  buildTestJsAesUnwrapFootgun,
  JS_AES_UNWRAP_SCHEMA,
} from "../src/engine/js-aes-unwrap-lint.js";

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

describe("MCP bla_lint_js_aes_unwrap", () => {
  it("registers once", () => {
    expect(BLA_MCP_TOOLS.filter((t) => t.name === "bla_lint_js_aes_unwrap")).toHaveLength(1);
  });

  it("flags R4 footgun with isError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-aes-"));
    tempDirs.push(dir);
    const file = join(dir, "license.cjs");
    writeFileSync(file, buildTestJsAesUnwrapFootgun({}), "utf8");
    const res = await call("bla_lint_js_aes_unwrap", { path: file });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError?: boolean;
      structuredContent: { schema: string; shouldRefuseBankrupt: boolean };
    };
    expect(result.structuredContent.schema).toBe(JS_AES_UNWRAP_SCHEMA);
    expect(result.structuredContent.shouldRefuseBankrupt).toBe(true);
    expect(result.isError).toBe(true);
  });
});
