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
      "allow_lane_independent",
      "allow_plaintext_seal",
      "allow_wasm_clear_params",
      "allow_stable_panel_derive",
      "allow_js_aes_unwrap",
      "allow_panel_offline_oracle",
      "allow_js_wasm_hydrate_dump",
      "allow_wasm_xor_mask_sidecar",
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
      "allow_lane_independent",
      "allow_plaintext_seal",
      "allow_wasm_clear_params",
      "allow_stable_panel_derive",
      "allow_js_aes_unwrap",
      "allow_panel_offline_oracle",
      "allow_js_wasm_hydrate_dump",
      "allow_wasm_xor_mask_sidecar",
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
      "allow_lane_independent",
      "allow_plaintext_seal",
      "allow_wasm_clear_params",
      "allow_stable_panel_derive",
      "allow_js_aes_unwrap",
      "allow_panel_offline_oracle",
      "allow_js_wasm_hydrate_dump",
      "allow_wasm_xor_mask_sidecar",
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
      "summary_path",
      "run_id",
    ],
  },
  {
    tool: "bla_lint_lanes",
    params: ["path"],
  },
  {
    tool: "bla_lint_seal",
    params: ["path"],
  },
  {
    tool: "bla_lint_wasm_params",
    params: ["path"],
  },
  {
    tool: "bla_lint_panel_derive",
    params: ["path"],
  },
  {
    tool: "bla_lint_js_aes_unwrap",
    params: ["path"],
  },
  {
    tool: "bla_lint_js_wasm_hydrate_dump",
    params: ["path"],
  },
  {
    tool: "bla_lint_wasm_xor_mask_sidecar",
    params: ["path"],
  },
  {
    tool: "bla_run_lookup",
    params: ["summary_path", "run_id"],
  },
  {
    tool: "bla_rea_drift",
    params: ["rea_root"],
  },
  {
    tool: "bla_redteam_report",
    params: ["execute", "rea_root", "report_path"],
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
