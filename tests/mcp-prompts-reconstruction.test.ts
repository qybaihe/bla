import { describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";

async function getPrompt(name: string, params?: Record<string, unknown>) {
  return handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "prompts/get",
    params: params ? { name, ...params } : { name },
  });
}

function promptText(res: unknown): string {
  const result = (res as { result?: { messages?: Array<{ content?: { text?: string } }> } }).result;
  return result?.messages?.[0]?.content?.text ?? "";
}

describe("MCP prompts reconstruction (PR1)", () => {
  it("allows omitting arguments entirely for an optional-only prompt", async () => {
    const res = await getPrompt("bla-harden-project");
    expect((res as { error?: unknown }).error).toBeUndefined();
    expect(promptText(res)).toContain("bla_harden");
  });

  it("still rejects missing required arguments", async () => {
    const res = await getPrompt("shield-against-rea", { arguments: {} });
    expect((res as { error?: { code?: number } }).error?.code).toBe(-32602);
  });

  it("still rejects a present-but-malformed arguments value", async () => {
    const res = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "prompts/get",
      params: { name: "bla-harden-project", arguments: "not-an-object" },
    });
    expect((res as { error?: { code?: number } }).error?.code).toBe(-32602);
  });

  it("gives each generic prompt its own decision table and acceptance criteria", async () => {
    const shield = promptText(
      await getPrompt("shield-against-rea", { arguments: { target_path: "./dist/app.js" } }),
    );
    const workflow = promptText(
      await getPrompt("bla-hardening-workflow", { arguments: { target_path: "./dist/app.js" } }),
    );
    const counter = promptText(
      await getPrompt("bla-counter-rea", { arguments: { target_path: "./dist/app.js" } }),
    );
    expect(new Set([shield, workflow, counter]).size).toBe(3);
    expect(shield).toContain("bla_protect");
    expect(shield).toContain("Acceptance");
    expect(workflow).toContain("bla_inspect_release");
    expect(workflow).toContain("lint-lanes");
    expect(counter).toContain("do not invent new MCP tools");
    expect(counter).toContain("Acceptance");
    for (const text of [shield, workflow, counter]) {
      expect(text).toContain("./dist/app.js");
    }
  });

  it("escapes a directory containing quotes in the harden prompt", async () => {
    const res = await getPrompt("bla-harden-project", {
      arguments: { directory: './we"ird\\path' },
    });
    const text = promptText(res);
    expect(text).toContain('\\"');
    expect(text).not.toContain('{ "directory": "./we"ird');
  });
});
