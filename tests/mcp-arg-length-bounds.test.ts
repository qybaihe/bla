import { afterEach, describe, expect, it, vi } from "vitest";
import {
  handleMcpRequest,
  type McpEngineHandlers,
} from "../src/mcp/server.js";

function spyHandlers(): McpEngineHandlers {
  return {
    hardenProject: vi.fn(),
    defendTarget: vi.fn(),
    auditTarget: vi.fn(),
    protectTarget: vi.fn(),
    verifyTarget: vi.fn(),
    runShowcaseBenchmark: vi.fn(),
    emitCompileTimeNativeHeader: vi.fn(),
    runDoctor: vi.fn(),
    inspectReleaseExposure: vi.fn(),
    initBlaConfig: vi.fn(),
  };
}

async function call(name: string, args: Record<string, unknown>) {
  const handlers = spyHandlers();
  const res = await handleMcpRequest(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    },
    handlers,
  );
  return { res, handlers };
}

describe("MCP string-length and numeric magnitude bounds", () => {
  it("rejects a string argument beyond the default length cap", async () => {
    const { res, handlers } = await call("bla_harden", {
      seed: "s".repeat(65_537),
    });
    expect(res?.error?.code).toBe(-32602);
    expect(res?.error?.message).toContain("character limit");
    for (const fn of Object.values(handlers)) expect(fn).not.toHaveBeenCalled();
  });

  it("accepts string arguments within the cap", async () => {
    const { res } = await call("bla_harden", { seed: "deterministic-seed" });
    expect(res?.error).toBeUndefined();
  });

  it("rejects an astronomically large numeric argument", async () => {
    const { res, handlers } = await call("bla_discover", { offset: 2_000_000_000 });
    expect(res?.error?.code).toBe(-32602);
    expect(res?.error?.message).toContain("magnitude");
    for (const fn of Object.values(handlers)) expect(fn).not.toHaveBeenCalled();
  });

  it("accepts realistic numeric arguments", async () => {
    const { res } = await call("bla_discover", { offset: 0 });
    expect(res?.error).toBeUndefined();
  });
});
