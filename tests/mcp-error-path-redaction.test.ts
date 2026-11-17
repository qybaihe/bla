import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function call(name: string, args: Record<string, unknown>) {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
  expect(res?.error).toBeUndefined();
  const result = res!.result as {
    isError: boolean;
    content: ReadonlyArray<{ type: string; text: string }>;
  };
  return result;
}

describe("MCP error text path redaction", () => {
  it("does not leak the operator's absolute paths in engine error text", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-redact-probe-"));
    dirs.push(dir);
    const missing = join(dir, "does-not-exist.js");
    const result = await call("bla_protect", { input_path: missing });
    expect(result.isError).toBe(true);
    const text = result.content.map((c) => c.text).join("\n");
    expect(text).not.toContain(missing);
    expect(text).not.toContain(dir);
    expect(text).toContain("<path>");
  });
});
