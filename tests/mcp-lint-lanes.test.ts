import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest, BLA_MCP_TOOLS } from "../src/mcp/server.js";
import { LANE_INDEPENDENCE_SCHEMA } from "../src/engine/lane-independence-lint.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function call(name: string, args: Record<string, unknown>) {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
  return res;
}

describe("MCP bla_lint_lanes", () => {
  it("is registered once next to the CLI-homologous engine", () => {
    expect(BLA_MCP_TOOLS.filter((t) => t.name === "bla_lint_lanes")).toHaveLength(1);
    const tool = BLA_MCP_TOOLS.find((t) => t.name === "bla_lint_lanes")!;
    expect(tool.inputSchema.required).toEqual(["path"]);
    expect(tool.inputSchema.properties.path?.type).toBe("string");
  });

  it("returns a clean report for whole-key mixing source", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-lint-clean-"));
    tempDirs.push(dir);
    const file = join(dir, "gate.js");
    writeFileSync(
      file,
      `
      function activate(key) {
        let a = pack(key.slice(0,5)), b = pack(key.slice(5,10));
        let c = pack(key.slice(10,15)), d = pack(key.slice(15,20));
        for (let r = 0; r < 24; r++) {
          a = (a + b) | 0; b = rotl(b ^ a, 7);
          c = (c + d) | 0; d = rotl(d ^ c, 9);
          a ^= c; b ^= d;
        }
        return hex(a,b,c,d) === catalog.revision;
      }
      `,
      "utf8",
    );
    const res = await call("bla_lint_lanes", { path: file });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError?: boolean;
      structuredContent: {
        schema: string;
        looksLaneIndependent: boolean;
        findings: readonly unknown[];
        oneLineAdvice: string;
      };
    };
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent.schema).toBe(LANE_INDEPENDENCE_SCHEMA);
    expect(result.structuredContent.looksLaneIndependent).toBe(false);
    expect(result.structuredContent.findings).toHaveLength(0);
  });

  it("returns error findings for independent per-lane gate shapes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-lint-warn-"));
    tempDirs.push(dir);
    const file = join(dir, "oracle.js");
    writeFileSync(
      file,
      `
      const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];
      function check(key) {
        return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]);
      }
      `,
      "utf8",
    );
    const res = await call("bla_lint_lanes", { path: file });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      structuredContent: {
        looksLaneIndependent: boolean;
        findings: ReadonlyArray<{ id: string; severity: string }>;
        oneLineAdvice: string;
      };
    };
    expect(result.structuredContent.looksLaneIndependent).toBe(true);
    expect(result.structuredContent.findings.some((f) => f.id === "per-lane-byte-compare-array")).toBe(
      true,
    );
    expect(result.structuredContent.findings.every((f) => f.severity === "error")).toBe(true);
    expect(result.structuredContent.oneLineAdvice).toMatch(/whole-key chained mixing/i);
  });

  it("errors when the source file is missing", async () => {
    const res = await call("bla_lint_lanes", {
      path: join(tmpdir(), "bla-missing-lane-gate-does-not-exist.js"),
    });
    expect(res?.error).toBeUndefined();
    const result = res!.result as { isError: boolean; content: ReadonlyArray<{ text: string }> };
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toMatch(/not found/i);
  });
});
