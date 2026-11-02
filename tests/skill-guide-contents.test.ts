import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const skillPath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../.agents/skills/blind-llm-agents/SKILL.md",
);

describe("blind-llm-agents skill guide contents", () => {
  it("ships v1.3+ one-click harden guide with weave + forbidden surfaces", () => {
    const text = fs.readFileSync(skillPath, "utf8");
    expect(text).toMatch(/metadata:\s*\n\s*version:\s*"1\.3\.\d+"/);
    expect(text).toContain("bla_harden");
    expect(text).toContain("npx bla-agents@latest harden .");
    expect(text).toContain("weave_decoys");
    expect(text).toContain("bla_weave_plan");
    expect(text).toContain("bla://directives/weave-decoy");
    expect(text).toContain("bla-weave-decoy");
    expect(text).toMatch(/FORBIDDEN/i);
    expect(text).toMatch(/bla_defend/);
    expect(text).toContain("counter-rea-matrix.md");
    expect(text).toContain("weave-decoy-mcp.md");
    // Prefer skill guide + existing MCP tools; refuse offensive RE/crack framing.
    expect(text.toLowerCase()).toMatch(/refuse|defensive only/);
    expect(text).toMatch(/Do not ask which files to protect/i);
    // Write-safety principles: preview/discover first, never overwrite unconfirmed.
    expect(text).toContain("bla_discover");
    expect(text).toContain("dry_run");
    expect(text).toContain("confirm_overwrite");
  });

  it("parseCliArgs accepts --weave-decoys for harden/defend/protect parity with MCP", async () => {
    const { parseCliArgs } = await import("../src/cli.js");
    const parsed = parseCliArgs(["harden", ".", "--weave-decoys", "--json"]);
    expect(parsed.command).toBe("harden");
    expect(parsed.weaveDecoys).toBe(true);
    expect(parseCliArgs(["defend", "x.js"]).weaveDecoys).toBe(false);
  });
});
