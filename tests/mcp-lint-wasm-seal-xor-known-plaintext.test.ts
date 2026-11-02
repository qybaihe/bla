import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest, BLA_MCP_TOOLS } from "../src/mcp/server.js";
import {
  buildTestWasmWithSealXorKnownPlaintext,
  WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA,
} from "../src/engine/wasm-seal-xor-known-plaintext-lint.js";

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

describe("MCP bla_lint_wasm_seal_xor_known_plaintext", () => {
  it("registers once", () => {
    expect(BLA_MCP_TOOLS.filter((t) => t.name === "bla_lint_wasm_seal_xor_known_plaintext")).toHaveLength(1);
  });

  it("flags R7 footgun with isError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-sealxor-"));
    tempDirs.push(dir);
    const { wasm, seal } = buildTestWasmWithSealXorKnownPlaintext({});
    const file = join(dir, "core.wasm");
    writeFileSync(file, wasm);
    writeFileSync(join(dir, "seal.json"), JSON.stringify(seal));
    const res = await call("bla_lint_wasm_seal_xor_known_plaintext", { path: file });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError?: boolean;
      structuredContent: { schema: string; shouldRefuseBankrupt: boolean };
    };
    expect(result.structuredContent.schema).toBe(WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA);
    expect(result.structuredContent.shouldRefuseBankrupt).toBe(true);
    expect(result.isError).toBe(true);
  });
});
