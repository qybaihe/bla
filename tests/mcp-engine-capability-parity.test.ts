import { describe, expect, it } from "vitest";
import { BLA_MCP_TOOLS } from "../src/mcp/server.js";

/**
 * Maintainable expectation list: engine capabilities agents rely on that MCP
 * must expose. Add a row when a new engine knob is intentionally hung on MCP;
 * do not assert raw schema prose — only tool name + param keys.
 *
 * This is NOT "full CLI mirror"; only the agreed agent-facing surface.
 */
const EXPECTED_MCP_ENGINE_CAPABILITIES: ReadonlyArray<{
  readonly tool: string;
  readonly params: readonly string[];
}> = Object.freeze([
  {
    tool: "bla_harden",
    params: [
      "directory",
      "intensity",
      "emit_manifest",
      "llm_directives",
      "weave_decoys",
      "self_seal",
      "wasm_preserve_exports",
      "seed",
      "dry_run",
      "max_artifacts",
      "confirm_overwrite",
      "output_directory",
    ],
  },
  {
    tool: "bla_discover",
    params: ["directory", "max_artifacts"],
  },
  {
    tool: "bla_defend",
    params: [
      "input_path",
      "output_path",
      "intensity",
      "emit_manifest",
      "llm_directives",
      "weave_decoys",
      "self_seal",
      "wasm_preserve_exports",
      "seed",
      "in_place",
      "confirm_overwrite",
    ],
  },
  {
    tool: "bla_protect",
    params: [
      "input_path",
      "output_path",
      "intensity",
      "weave_decoys",
      "self_seal",
      "wasm_preserve_exports",
      "seed",
      "llm_directives",
      "in_place",
      "honey_source_maps",
      "confirm_overwrite",
    ],
  },
  {
    tool: "bla_verify",
    params: [
      "target_path",
      "original_path",
      "self_seal_enabled",
      "wasm_export_rename_applied",
      "numeric_template_leak_known",
    ],
  },
  {
    tool: "bla_lint_lanes",
    params: ["path"],
  },
]);

describe("MCP ↔ engine capability parity (agent-facing)", () => {
  it("exposes every agreed engine capability on the named MCP tools", () => {
    for (const expected of EXPECTED_MCP_ENGINE_CAPABILITIES) {
      const tool = BLA_MCP_TOOLS.find((t) => t.name === expected.tool);
      expect(tool, `missing MCP tool ${expected.tool}`).toBeDefined();
      const props = Object.keys(tool!.inputSchema.properties);
      for (const param of expected.params) {
        expect(props, `${expected.tool} missing param ${param}`).toContain(param);
      }
    }
  });

  it("does not register duplicate tool names", () => {
    const names = BLA_MCP_TOOLS.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
  });
});
