import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BLA_IDENTITY } from "../src/identity.js";
import { BLA_MCP_TOOLS } from "../src/mcp/server.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const escape = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const packageJson = JSON.parse(read("package.json")) as {
  version: string;
  engines: { node: string };
};

function implementedBenchmarkTargets(): number {
  return [...read("src/engine/benchmark.ts").matchAll(/cases\.push\(buildCaseResult\(/g)].length;
}

describe("version and public-claim drift", () => {
  it("keeps every release surface on the package version", () => {
    const version = packageJson.version;
    expect(BLA_IDENTITY.version).toBe(version);

    expect(read("STATE.md")).toMatch(
      new RegExp(`\\*\\*Version:\\*\\*\\s*${escape(version)}`),
    );
    expect(read(".agents/skills/blind-llm-agents/SKILL.md")).toMatch(
      new RegExp(`\\n\\s{2}version:\\s*"${escape(version)}"`),
    );

    const lock = JSON.parse(read("package-lock.json")) as {
      version: string;
      packages: Record<string, { version?: string } | undefined>;
    };
    expect(lock.version).toBe(version);
    expect(lock.packages[""]?.version).toBe(version);

    expect(read("CHANGELOG.md")).toContain(`## [${version}]`);

    for (const entry of readdirSync(join(ROOT, "challenge"), { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^v\d+$/.test(entry.name)) continue;
      const sealRel = `challenge/${entry.name}/SEAL.json`;
      const seal = JSON.parse(read(sealRel)) as { blaVersion?: string };
      expect(seal.blaVersion, sealRel).toBe(version);
    }

    for (const rel of [".claude-plugin/plugin.json", ".codex-plugin/plugin.json"]) {
      expect((JSON.parse(read(rel)) as { version?: string }).version, rel).toBe(version);
    }
    const marketplace = JSON.parse(read(".claude-plugin/marketplace.json")) as {
      plugins: Array<{ name: string; version?: string }>;
    };
    for (const plugin of marketplace.plugins) {
      expect(plugin.version, `.claude-plugin/marketplace.json ${plugin.name}`).toBe(version);
    }

    // The website's structured data: 3.4.1 stayed in SoftwareSourceCode for four releases.
    const site = read("website/index.html");
    const jsonLd = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(site);
    expect(jsonLd, "website/index.html has no JSON-LD block").not.toBeNull();
    const graph = (JSON.parse(jsonLd![1]) as { "@graph": Array<Record<string, unknown>> })["@graph"];
    const node = (type: string): Record<string, unknown> | undefined =>
      graph.find((entry) => entry["@type"] === type);
    expect(node("SoftwareApplication")?.softwareVersion, "SoftwareApplication.softwareVersion").toBe(version);
    expect(node("SoftwareApplication")?.releaseNotes, "SoftwareApplication.releaseNotes").toBe(
      `https://github.com/qybaihe/bla/releases/tag/bla-agents-${version}`,
    );
    expect(node("SoftwareSourceCode")?.version, "SoftwareSourceCode.version").toBe(version);

    expect(read("examples/github-actions-defend.yml")).toMatch(
      new RegExp(`\\bBLA_VERSION:\\s*"${escape(version)}"`),
    );
  });

  it("documents the benchmark target count that the code actually implements", () => {
    const targets = implementedBenchmarkTargets();
    expect(targets).toBeGreaterThan(0);

    const claims: ReadonlyArray<readonly [string, RegExp]> = [
      ["README.md", /(\d+) showcase benchmark targets/],
      ["AGENTS.md", /\((\d+)-target showcase benchmark\)/],
      ["docs/cli-and-mcp.md", /Runs the (\d+)-target Counter-REA Showcase Benchmark suite/],
      ["docs/cli-and-mcp.md", /Runs the (\d+)-target showcase benchmark suite/],
      ["src/cli.ts", /Run the (\d+)-target Counter-REA Showcase Benchmark suite/],
      ["website/assets/i18n.js", /"(\d+)-Target Benchmark Suite"/],
      ["website/assets/i18n.js", /Run all (\d+) benchmark targets/],
      ["website/assets/i18n.js", /"(\d+) 项基准测试套件"/],
      ["website/assets/i18n.js", /全部 (\d+) 个测试目标/],
    ];

    for (const [rel, pattern] of claims) {
      const match = pattern.exec(read(rel));
      expect(match, `${rel} does not state the benchmark target count (${pattern})`).not.toBeNull();
      expect(match![1], `${rel} (${pattern})`).toBe(String(targets));
    }

    // Localized READMEs repeat the same English claim. A translation that does
    // not carry the sentence is skipped; one that does must match the code.
    for (const entry of readdirSync(join(ROOT, "docs/readme"), { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".md")) continue;
      const rel = `docs/readme/${entry.name}`;
      const match = /Run (\d+)-target Counter-REA benchmark/.exec(read(rel));
      if (!match) continue;
      expect(match[1], `${rel} benchmark claim`).toBe(String(targets));
    }

    const websiteReadme = read("website/README.md");
    const siteClaim = /(\d+)-target Counter-REA benchmark suite/.exec(websiteReadme);
    expect(siteClaim, "website/README.md does not state the benchmark target count").not.toBeNull();
    expect(siteClaim![1], "website/README.md benchmark claim").toBe(String(targets));
  });

  it("keeps the website Node floor equal to the declared engines range", () => {
    expect(packageJson.engines.node).toBe("^22.23.4 || >=24.0.0");
    const index = read("website/index.html");
    expect(index).toContain("22.23.4");
    expect(index).not.toContain("22.13");
  });

  it("keeps every documented artifact-format count equal to the real format registry", () => {
    // Derive the count from the ArtifactFormat union minus the two sentinels.
    const union = /export type ArtifactFormat =([^;]+);/.exec(read("src/core/types.ts"));
    expect(union, "ArtifactFormat union not found").not.toBeNull();
    const members = union![1]!.match(/"[a-z0-9-]+"/g) ?? [];
    const count = members.length - 2; // directory + unknown sentinels
    expect(count).toBeGreaterThan(0);

    expect(read("src/core/detector.ts")).toContain(
      `across all ${count} artifact formats`,
    );
    expect(read("README.md")).toContain(`All ${count} format shields`);
    // Translated READMEs phrase the FAQ answer in their own language — assert
    // that each still states the CURRENT derived count somewhere.
    for (const entry of readdirSync(join(ROOT, "docs", "readme"))) {
      expect(read(`docs/readme/${entry}`), entry).toContain(String(count));
    }
    expect(read("website/index.html")).toContain(
      `${count} supported software`,
    );
  });

  it("keeps the documented MCP tool count and catalogue in step with the registry", () => {
    const tools = BLA_MCP_TOOLS.length;
    expect(tools).toBeGreaterThan(0);

    const readme = read("README.md");
    expect(readme).toContain(`MCP-${tools}_Defense_Tools`);
    expect(readme).toContain(`${tools}-Tool MCP Catalog`);

    const docs = read("docs/cli-and-mcp.md");
    const missing = BLA_MCP_TOOLS.map((tool) => tool.name).filter(
      (name) => !docs.includes(`\`${name}\``),
    );
    expect(missing, `undocumented MCP tools: ${missing.join(", ")}`).toEqual([]);
  });
});
