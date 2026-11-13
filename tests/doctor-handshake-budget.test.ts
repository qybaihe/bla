import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_HANDSHAKE_TIMEOUT_MS,
  probeLocalMcpHandshake,
  resolveHandshakeTimeoutMs,
} from "../src/setup/doctor.js";

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "bla-doctor-budget-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A local MCP server that answers `initialize`, but only after `delayMs`. */
function slowMcpServer(delayMs: number): string {
  const script = join(dir(), "slow-mcp.mjs");
  writeFileSync(
    script,
    `
let buf = "";
process.stdin.on("data", (chunk) => { buf += chunk; });
process.stdin.on("end", () => {
  setTimeout(() => {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "bla", version: "3.2.5" },
        },
      }) + "\\n",
    );
  }, ${delayMs});
});
`,
    "utf8",
  );
  return script;
}

describe("doctor handshake budget", () => {
  it("gives a working-but-slow server enough time by default", () => {
    // The previous 8s budget was missed under load, producing a false unhealthy.
    expect(DEFAULT_HANDSHAKE_TIMEOUT_MS).toBeGreaterThanOrEqual(15_000);
  });

  it("honours an explicit budget instead of the default", () => {
    expect(resolveHandshakeTimeoutMs(9_000)).toBe(9_000);
    expect(resolveHandshakeTimeoutMs()).toBe(DEFAULT_HANDSHAKE_TIMEOUT_MS);
  });

  it("honours BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS", () => {
    const previous = process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS;
    process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS = "1234";
    try {
      expect(resolveHandshakeTimeoutMs()).toBe(1234);
      expect(resolveHandshakeTimeoutMs(50_000)).toBe(50_000); // explicit wins
    } finally {
      if (previous === undefined) delete process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS;
      else process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS = previous;
    }
  });

  it("still fails a probe whose budget is genuinely too small", () => {
    const script = slowMcpServer(1_500);
    expect(probeLocalMcpHandshake(process.execPath, [script], 300)).toBe(false);
  });

  it("verifies a slow-but-working server once the budget allows it", () => {
    const script = slowMcpServer(700);
    expect(probeLocalMcpHandshake(process.execPath, [script], 8_000)).toBe(true);
  });
});