import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest, BLA_MCP_TOOLS } from "../src/mcp/server.js";
import { buildTestWasmWithParamCarrier } from "../src/engine/wasm-param-carrier-lint.js";
import { WASM_PARAM_CARRIER_SCHEMA } from "../src/engine/wasm-param-carrier-lint.js";
import { PANEL_DERIVE_ABI_SCHEMA } from "../src/engine/panel-derive-abi-lint.js";

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

describe("MCP bla_lint_wasm_params / bla_lint_panel_derive", () => {
  it("registers both tools once", () => {
    expect(BLA_MCP_TOOLS.filter((t) => t.name === "bla_lint_wasm_params")).toHaveLength(1);
    expect(BLA_MCP_TOOLS.filter((t) => t.name === "bla_lint_panel_derive")).toHaveLength(1);
  });

  it("flags clear WASM carriers with isError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-wasm-"));
    tempDirs.push(dir);
    const file = join(dir, "core.wasm");
    writeFileSync(file, buildTestWasmWithParamCarrier({}));
    const res = await call("bla_lint_wasm_params", { path: file });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError?: boolean;
      structuredContent: { schema: string; shouldRefuseBankrupt: boolean };
    };
    expect(result.structuredContent.schema).toBe(WASM_PARAM_CARRIER_SCHEMA);
    expect(result.structuredContent.shouldRefuseBankrupt).toBe(true);
    expect(result.isError).toBe(true);
  });

  it("flags stable panel derive with isError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-mcp-panel-"));
    tempDirs.push(dir);
    const file = join(dir, "panel.js");
    writeFileSync(file, "globalThis.__vaultPanelDerive_r3 = (x) => x;\n", "utf8");
    const res = await call("bla_lint_panel_derive", { path: file });
    const result = res!.result as {
      isError?: boolean;
      structuredContent: { schema: string; shouldRewriteOrRefuse: boolean };
    };
    expect(result.structuredContent.schema).toBe(PANEL_DERIVE_ABI_SCHEMA);
    expect(result.structuredContent.shouldRewriteOrRefuse).toBe(true);
    expect(result.isError).toBe(true);
  });
});
