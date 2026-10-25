import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { runSetup, runUninstall } from "../src/setup/setup.js";
import { runDoctor } from "../src/setup/doctor.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import { runShowcaseBenchmark } from "../src/engine/benchmark.js";

describe("CLI Setup, Doctor, Benchmark & MCP Server", () => {
  it("registers and uninstalls BLA MCP server + skill across all 6 AI coding agents in an isolated homeDir", () => {
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "bla-home-test-"));
    try {
      const setupReport = runSetup({
        homeDir: fakeHome,
        clientIds: [
          "claude_code",
          "cursor",
          "windsurf",
          "codex",
          "gemini_cli",
          "antigravity",
        ],
        yes: true,
      });
      expect(setupReport.status).toBe("applied");
      expect(setupReport.actions.length).toBe(6);

      // Verify Claude Code config and skill file exist
      const claudeConfig = JSON.parse(
        fs.readFileSync(path.join(fakeHome, ".claude.json"), "utf8"),
      ) as { mcpServers?: Record<string, unknown> };
      expect(claudeConfig.mcpServers?.bla).toBeDefined();

      const skillPath = path.join(fakeHome, ".claude", "skills", "blind-llm-agents", "SKILL.md");
      expect(fs.existsSync(skillPath)).toBe(true);

      // Run doctor and verify the 6 configured clients report healthy MCP + Skill
      const doctorReport = runDoctor(fakeHome);
      expect(doctorReport.healthy).toBe(true);
      const configuredClients = doctorReport.agentClients.filter((c) => c.mcpRegistered);
      expect(configuredClients.length).toBe(6);
      expect(configuredClients.every((c) => c.skillInstalled)).toBe(true);

      // Run uninstall and verify clean removal
      const removed = runUninstall({ homeDir: fakeHome });
      expect(removed.removedClients.length).toBe(6);
      expect(fs.existsSync(skillPath)).toBe(false);
    } finally {
      fs.rmSync(fakeHome, { recursive: true, force: true });
    }
  });

  it("handles MCP JSON-RPC 2.0 requests (initialize, tools/list, tools/call)", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-mcp-test-"));

    try {
      const initRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
      });
      expect(initRes?.result).toMatchObject({
        serverInfo: { name: "bla" },
      });

      const listRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      });
      const tools = (listRes?.result as { tools: Array<{ name: string }> }).tools;
      expect(tools.map((t) => t.name)).toEqual([
        "bla_audit",
        "bla_protect",
        "bla_verify",
        "bla_benchmark",
        "bla_emit_headers",
        "bla_doctor",
      ]);

      // Test bla_audit + bla_protect + bla_verify via MCP tool calls
      const sampleFile = path.join(tmpDir, "sample.js");
      const protectedFile = path.join(tmpDir, "sample.bla.js");
      fs.writeFileSync(
        sampleFile,
        `function validateKey(k) { return k === "live-secret-token-2026"; }\nmodule.exports = { validateKey };\n`,
        "utf8",
      );

      const auditCall = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "bla_audit",
          arguments: { path: sampleFile },
        },
      });
      expect((auditCall?.result as { isError?: boolean }).isError).toBe(false);

      const protectCall = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "bla_protect",
          arguments: {
            input_path: sampleFile,
            output_path: protectedFile,
            intensity: "balanced",
          },
        },
      });
      expect((protectCall?.result as { isError?: boolean }).isError).toBe(false);
      expect(fs.existsSync(protectedFile)).toBe(true);

      const verifyCall = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "bla_verify",
          arguments: {
            target_path: protectedFile,
            original_path: sampleFile,
          },
        },
      });
      const verifyPayload = (verifyCall?.result as { structuredContent: { overallPassed: boolean } })
        .structuredContent;
      expect(verifyPayload.overallPassed).toBe(false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("reports eight synthetic fixtures with bounded runtime samples and projected costs", async () => {
    const report = await runShowcaseBenchmark();
    expect(report.cases.length).toBe(8);
    expect(report.cases.filter((c) => c.functionalCheckPassed).map((c) => c.id)).toEqual(["dx-ball", "license-guard", "wasm-core"]);
    expect(report.cases.filter((c) => c.functionalCheckStatus === "not-run")).toHaveLength(5);
    expect(report.reaExecuted).toBe(false);
    expect(report.agentExecuted).toBe(false);
    expect(report.aggregateTokenMultiplier).toBeGreaterThanOrEqual(30);
    expect(report.aggregateCostMultiplier).toBeGreaterThanOrEqual(30);
  });
});
