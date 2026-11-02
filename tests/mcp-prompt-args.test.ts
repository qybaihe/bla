import { describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";

async function getPrompt(params: Record<string, unknown>) {
  return handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "prompts/get", params });
}
function text(res: unknown): string {
  return (res as any)?.result?.messages?.[0]?.content?.text ?? "";
}

describe("MCP prompt arguments and interpolation", () => {
  it("allows omitting arguments for an optional-only prompt", async () => {
    const res = await getPrompt({ name: "bla-harden-project" });
    expect((res as any).error).toBeUndefined();
    expect(text(res)).toContain('"directory": "."');
    expect(text(res)).toContain("dry_run");
  });

  it("still rejects missing required and malformed arguments", async () => {
    expect(((await getPrompt({ name: "shield-against-rea", arguments: {} })) as any).error?.code).toBe(-32602);
    expect(((await getPrompt({ name: "bla-harden-project", arguments: "x" })) as any).error?.code).toBe(-32602);
  });

  it("JSON-escapes paths containing quotes", async () => {
    const t = text(await getPrompt({ name: "bla-harden-project", arguments: { directory: './we"ird' } }));
    expect(t).toContain('"./we\\"ird"');
  });

  it("gives each generic prompt scenario-specific copy", async () => {
    const names = ["shield-against-rea", "bla-hardening-workflow", "bla-counter-rea"];
    const texts = await Promise.all(
      names.map(async (name) => text(await getPrompt({ name, arguments: { target_path: "dist/app.js" } }))),
    );
    expect(new Set(texts).size).toBe(3);
    for (const t of texts) {
      expect(t).toContain('"dist/app.js"');
      expect(t).toContain("confirm_overwrite");
    }
  });
});
