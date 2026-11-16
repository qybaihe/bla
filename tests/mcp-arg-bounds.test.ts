import { describe, expect, it } from "vitest";
import {
  MAX_STRING_ARRAY_ITEMS,
  validateMcpToolCall,
} from "../src/mcp/server.js";

function validate(name: string, args: Record<string, unknown>) {
  return validateMcpToolCall({ name, arguments: args });
}

describe("MCP argument bounds", () => {
  it("rejects a string array larger than the declared cap", () => {
    const oversized = Array.from(
      { length: MAX_STRING_ARRAY_ITEMS + 1 },
      (_, i) => `export_${i}`,
    );
    const res = validate("bla_harden", {
      directory: ".",
      wasm_preserve_exports: oversized,
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe(-32602);
    expect(res.message).toContain(`at most ${MAX_STRING_ARRAY_ITEMS}`);
  });

  it("accepts a string array exactly at the cap", () => {
    const atCap = Array.from(
      { length: MAX_STRING_ARRAY_ITEMS },
      (_, i) => `export_${i}`,
    );
    expect(
      validate("bla_harden", { directory: ".", wasm_preserve_exports: atCap }).ok,
    ).toBe(true);
  });

  it("bounds the domains list on bla_bind_scope too", () => {
    const domains = Array.from(
      { length: MAX_STRING_ARRAY_ITEMS + 1 },
      (_, i) => `host${i}.example.com`,
    );
    const res = validate("bla_bind_scope", { directory: ".", domains });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.message).toContain(`at most ${MAX_STRING_ARRAY_ITEMS}`);
  });

  it("rejects fractional count arguments", () => {
    const res = validate("bla_harden", { directory: ".", max_artifacts: 1.5 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe(-32602);
    expect(res.message).toContain("integer");
  });

  it("still accepts integer counts and a zero offset", () => {
    expect(
      validate("bla_harden", { directory: ".", max_artifacts: 8 }).ok,
    ).toBe(true);
    expect(
      validate("bla_discover", { directory: ".", max_artifacts: 8, offset: 0 }).ok,
    ).toBe(true);
  });

  it("keeps fractional drift thresholds accepted", () => {
    const res = validate("bla_polymorph_report", {
      dir_a: "a",
      dir_b: "b",
      different_threshold: 0.25,
      same_threshold: 0.01,
    });
    expect(res.ok).toBe(true);
  });
});