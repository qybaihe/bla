import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  BLA_MCP_PROMPTS,
  BLA_MCP_RESOURCES,
  BLA_MCP_TOOLS,
  handleMcpRequest,
} from "../src/mcp/server.js";
import {
  buildWeavePlan,
  getWeaveDirectivesMarkdown,
  WEAVE_ACCEPTANCE_TESTS,
  WEAVE_DECOY_SCHEMA,
  WEAVE_DIRECTIVES_URI,
  WEAVE_EXECUTOR_CHECKLIST,
  WEAVE_FORBIDDEN,
  WEAVE_PRINCIPLES,
} from "../src/shields/weave/weave-decoy.js";

const temps: string[] = [];
afterEach(() => {
  for (const d of temps.splice(0)) {
    rmSync(d, { recursive: true, force: true });
  }
});

describe("weave-decoy theory pack", () => {
  it("exposes principles, forbidden patterns, checklist, and acceptance tests", () => {
    expect(WEAVE_PRINCIPLES.length).toBeGreaterThanOrEqual(5);
    expect(WEAVE_FORBIDDEN.some((f) => f.id === "pure-noise-layer")).toBe(true);
    expect(WEAVE_FORBIDDEN.some((f) => f.id === "offensive-content")).toBe(true);
    expect(WEAVE_EXECUTOR_CHECKLIST.some((s) => s.id === "run-weave-plan")).toBe(
      true,
    );
    expect(WEAVE_ACCEPTANCE_TESTS.some((a) => a.id === "customer-entry-edges")).toBe(
      true,
    );
    const md = getWeaveDirectivesMarkdown();
    expect(md).toContain("WorkBuddy");
    expect(md).toContain(WEAVE_DIRECTIVES_URI);
    expect(md.toLowerCase()).not.toMatch(/exploit poc|crackme bypass playbook/);
  });

  it("buildWeavePlan classifies JS and Python source as woven", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-weave-plan-"));
    temps.push(dir);
    writeFileSync(join(dir, "app.js"), "function main(){ return 1; }\n");
    writeFileSync(join(dir, "svc.py"), "def main():\n    return 1\n");
    const plan = buildWeavePlan(dir);
    expect(plan.schema).toBe(WEAVE_DECOY_SCHEMA);
    expect(plan.overallStatus).toBe("ready");
    const js = plan.targets.find((t) => t.relativePath.endsWith("app.js"));
    const py = plan.targets.find((t) => t.relativePath.endsWith("svc.py"));
    expect(js?.maturity).toBe("woven");
    expect(js?.status).toBe("ready");
    expect(py?.maturity).toBe("woven");
    expect(py?.status).toBe("ready");
    expect(plan.pipelineHook.mcpFlag).toBe("weave_decoys");
    expect(plan.pipelineHook.todayBehaviorZh).toMatch(/结构织入|customer|FunctionDef|weave_decoys/);
    expect(plan.pipelineHook.todayBehaviorZh).not.toMatch(/尚未改客户 def|future hooks only/);
  });
});

describe("weave-decoy MCP descriptors", () => {
  it("lists bla_weave_plan and weave_decoys on harden/defend/protect", () => {
    expect(BLA_MCP_TOOLS.map((t) => t.name)).toContain("bla_weave_plan");
    for (const name of ["bla_harden", "bla_defend", "bla_protect"] as const) {
      const tool = BLA_MCP_TOOLS.find((t) => t.name === name)!;
      expect(tool.inputSchema.properties.weave_decoys?.type).toBe("boolean");
    }
    expect(BLA_MCP_RESOURCES.some((r) => r.uri === WEAVE_DIRECTIVES_URI)).toBe(
      true,
    );
    expect(BLA_MCP_PROMPTS.some((p) => p.name === "bla-weave-decoy")).toBe(true);
  });

  it("initialize advertises resources; resources/read returns directives", async () => {
    const init = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    });
    expect(
      (init?.result as { capabilities: { resources: object } }).capabilities
        .resources,
    ).toEqual({});

    const listed = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "resources/list",
    });
    const resources = (
      listed?.result as { resources: Array<{ uri: string }> }
    ).resources;
    expect(resources.map((r) => r.uri)).toContain(WEAVE_DIRECTIVES_URI);

    const read = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "resources/read",
      params: { uri: WEAVE_DIRECTIVES_URI },
    });
    const contents = (
      read?.result as { contents: Array<{ text: string; uri: string }> }
    ).contents;
    expect(contents[0]!.uri).toBe(WEAVE_DIRECTIVES_URI);
    expect(contents[0]!.text).toContain("bla_weave_plan");
  });

  it("tools/call bla_weave_plan returns structured plan", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-weave-mcp-"));
    temps.push(dir);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "x.js"), "exports.x = 1;\n");

    const res = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "bla_weave_plan",
        arguments: { path: dir },
      },
    });
    expect((res?.result as { isError?: boolean }).isError).toBe(false);
    const plan = (res?.result as { structuredContent: { schema: string; targets: unknown[] } })
      .structuredContent;
    expect(plan.schema).toBe(WEAVE_DECOY_SCHEMA);
    expect(plan.targets.length).toBeGreaterThanOrEqual(1);
  });

  it("prompts/get bla-weave-decoy mentions weave_decoys", async () => {
    const res = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 5,
      method: "prompts/get",
      params: {
        name: "bla-weave-decoy",
        arguments: { target_path: "." },
      },
    });
    const text = (
      res?.result as { messages: Array<{ content: { text: string } }> }
    ).messages[0]!.content.text;
    expect(text).toContain("weave_decoys");
    expect(text).toContain("bla_weave_plan");
  });
});
