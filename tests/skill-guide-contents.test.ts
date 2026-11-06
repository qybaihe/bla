import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveBundledSkillBundle } from "../src/setup/setup.js";

const skillDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../.agents/skills/blind-llm-agents",
);
const skillPath = path.join(skillDir, "SKILL.md");

describe("blind-llm-agents skill guide contents", () => {
  it("ships v1.5+/2.0/3.0 short decision guide with write-safety, lint-lanes, verify-weave, and run evidence", () => {
    const text = fs.readFileSync(skillPath, "utf8");
    expect(text).toMatch(/metadata:\s*\n\s*version:\s*"(?:1\.5\.\d+|2\.\d+\.\d+|3\.\d+\.\d+)"/);
    expect(text).toContain("bla_harden");
    expect(text).toContain("npx bla-agents@latest harden .");
    expect(text).toContain("weave_decoys");
    expect(text).toContain("bla_weave_plan");
    expect(text).toContain("bla_verify_weave");
    expect(text).toContain("surgicalWorkorder");
    expect(text).toContain("remediationPlan");
    expect(text).toContain("bla://directives/weave-decoy");
    expect(text).toContain("bla_lint_lanes");
    expect(text).toMatch(/FORBIDDEN/i);
    expect(text).toMatch(/bla_defend/);
    expect(text).toContain("counter-rea-matrix.md");
    expect(text.toLowerCase()).toMatch(/refuse|defensive only/);
    expect(text).toMatch(/Do not ask which files to protect/i);
    expect(text).toContain("bla_discover");
    expect(text).toContain("dry_run");
    expect(text).toContain("confirm_overwrite");
    expect(text).toContain("in_place");
    expect(text).toContain("bla_run_lookup");
    expect(text).toContain("bla_rea_drift");
    expect(text).toContain("bla_polymorph_report");
    expect(text).toContain("bla_encrypt_strings");
    expect(text).toContain("bla_lint_plaintext_secrets");
    expect(text).toContain("bla_redteam_report");
    expect(text).toMatch(/unverified/i);
    expect(text).toContain("available");
    expect(text).toContain("overallSuccess");
    // No brittle repo-relative ../../../docs links that break after setup install.
    expect(text).not.toMatch(/\.\.\/\.\.\/\.\.\/docs\//);
  });

  it("bundles format appendices next to SKILL.md for setup/doctor", () => {
    const required = [
      "references/counter-rea-matrix.md",
      "references/format-javascript.md",
      "references/format-wasm.md",
      "references/format-python.md",
      "references/format-android.md",
    ];
    for (const rel of required) {
      expect(fs.existsSync(path.join(skillDir, rel)), rel).toBe(true);
    }
    const bundled = resolveBundledSkillBundle().map((f) => f.relativePath);
    expect(bundled[0]).toBe("SKILL.md");
    for (const rel of required) {
      expect(bundled).toContain(rel);
    }
    const skill = fs.readFileSync(skillPath, "utf8");
    expect(skill).toContain("format-javascript.md");
    expect(skill).toContain("format-wasm.md");
    expect(skill).toContain("format-python.md");
    expect(skill).toContain("format-android.md");
  });

  it("parseCliArgs accepts --weave-decoys for harden/defend/protect parity with MCP", async () => {
    const { parseCliArgs } = await import("../src/cli.js");
    const parsed = parseCliArgs(["harden", ".", "--weave-decoys", "--json"]);
    expect(parsed.command).toBe("harden");
    expect(parsed.weaveDecoys).toBe(true);
    expect(parseCliArgs(["defend", "x.js"]).weaveDecoys).toBe(false);
  });
});
