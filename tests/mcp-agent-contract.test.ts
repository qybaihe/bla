import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BLA_IDENTITY } from "../src/identity.js";
import {
  BLA_MCP_INSTRUCTIONS,
  BLA_MCP_TOOLS,
  SUPPORTED_MCP_PROTOCOL_VERSIONS,
  handleMcpRequest,
} from "../src/mcp/server.js";
import { pinnedBlaVersionOf, runDoctor } from "../src/setup/doctor.js";
import { runSetup } from "../src/setup/setup.js";

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function rpc(method: string, params?: Record<string, unknown>) {
  return handleMcpRequest({ jsonrpc: "2.0", id: 1, method, ...(params ? { params } : {}) });
}
async function callTool(name: string, args: Record<string, unknown>) {
  const res = await rpc("tools/call", { name, arguments: args });
  expect(res?.error).toBeUndefined();
  return res!.result as {
    isError?: boolean;
    content: { type: string; text: string }[];
    structuredContent: Record<string, any>;
  };
}

/** Minimal WASM: (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add). */
const ADD_WASM = Buffer.from(
  "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b",
  "hex",
);

describe("MCP contract an agent relies on", () => {
  it("negotiates the protocol revision per the lifecycle rules", async () => {
    expect(SUPPORTED_MCP_PROTOCOL_VERSIONS).toContain("2025-06-18");
    const version = async (requested?: string) =>
      (
        (await rpc("initialize", {
          ...(requested !== undefined ? { protocolVersion: requested } : {}),
          capabilities: {},
          clientInfo: { name: "t", version: "0" },
        }))!.result as { protocolVersion: string }
      ).protocolVersion;

    // A supported revision is echoed.
    for (const supported of SUPPORTED_MCP_PROTOCOL_VERSIONS) {
      expect(await version(supported)).toBe(supported);
    }
    // An unknown one gets the latest this server speaks, not the oldest.
    expect(await version("2099-01-01")).toBe("2025-06-18");
    // A client that sends none is answered conservatively.
    expect(await version()).toBe("2024-11-05");
  });

  it("ships the playbook as server instructions, so the skill is not required", async () => {
    const init = (await rpc("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "t", version: "0" },
    }))!.result as { instructions: string };
    expect(init.instructions).toBe(BLA_MCP_INSTRUCTIONS);
    for (const phrase of [
      "bla_harden",
      "nextSteps",
      "apply",
      "confirm_overwrite",
      "restore",
      "isError",
      "skippedHardenedOutputs",
      "exclude",
      "Defensive use only",
    ]) {
      expect(init.instructions).toContain(phrase);
    }
    // Small enough to sit in every session's context.
    expect(init.instructions.length).toBeLessThan(2500);

    const prompt = (await rpc("prompts/get", { name: "bla-harden-project" }))!.result as {
      messages: { content: { text: string } }[];
    };
    expect(prompt.messages[0]!.content.text).toMatch(/nextSteps/);
    expect(prompt.messages[0]!.content.text).toMatch(/apply: true/);
  });

  it("keeps a bla_defend result small even when the audit lists thousands of decoys", async () => {
    const dir = tempDir("bla-mcp-compact-");
    writeFileSync(join(dir, "math.wasm"), ADD_WASM);
    const result = await callTool("bla_defend", {
      input_path: join(dir, "math.wasm"),
      output_path: join(dir, "out", "math.wasm"),
      seed: "compact-seed",
    });
    expect(result.isError).toBeFalsy();
    const report = result.structuredContent;
    expect(report.overallSuccess).toBe(true);

    // Was megabytes: every injected decoy export, each with a multi-KB name.
    expect(result.content[0]!.text.length).toBeLessThan(40_000);
    const after = report.protection.afterAudit;
    expect(after.exposedItems.length).toBeLessThanOrEqual(8);
    expect(after.exposedItemsTruncated).toBe(true);
    expect(after.exposedItemsTotal).toBeGreaterThan(after.exposedItems.length);
    for (const item of after.exposedItems) {
      for (const value of Object.values(item)) {
        if (typeof value === "string") expect(value.length).toBeLessThan(200);
      }
    }
    // The audit that is already at the top level is not repeated inside protection,
    // and the coverage contract is stated once.
    expect(report.protection.beforeAudit).toBeUndefined();
    expect(report.beforeAudit).toBeDefined();
    expect(report.coverageContract.clientArtifact.enforcesAccessControl).toBe(false);
    expect(report.beforeAudit.coverageContract).toBeUndefined();
    expect(after.coverageContract).toBeUndefined();
    expect(report.verification.coverageContract).toBeUndefined();
    // A shielded artifact is not told to "protect" itself again.
    expect(after.protectionStatus).toBe("BLA_PROTECTED");
    expect(after.recommendedCommand).toBeUndefined();
    expect(report.beforeAudit.recommendedCommand).toMatch(/protect/);
    // The headline facts survive compaction.
    expect(report.protection.wasmExportRenames).toBeDefined();
    expect(report.writeReceipt).toBeDefined();
  }, 60000);

  it("reports harden failures as isError with the reason an agent can act on", async () => {
    const dir = tempDir("bla-mcp-fail-");
    mkdirSync(join(dir, "dist"), { recursive: true });
    writeFileSync(join(dir, "dist", "broken.js"), "function ( {\n", "utf8");
    const result = await callTool("bla_harden", { directory: dir, seed: "fail-seed" });
    expect(result.isError).toBe(true);
    expect(result.structuredContent.overallSuccess).toBe(false);
    expect(result.structuredContent.artifacts[0].error).toMatch(/parse/i);
    expect(result.structuredContent.nextSteps[0]).toMatch(/were not hardened/);
  }, 60000);

  it("bla_lint says which findings bla_harden actually enforces", async () => {
    const dir = tempDir("bla-mcp-lint-");
    writeFileSync(
      join(dir, "license.cjs"),
      `const EXPECTED = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";\nmodule.exports = { check: (k) => k === EXPECTED };\n`,
      "utf8",
    );
    const lint = await callTool("bla_lint", { directory: dir });
    expect(lint.isError).toBe(true);
    const finding = lint.structuredContent.findings.find(
      (f: { gate: string }) => f.gate === "plaintext-secret",
    );
    expect(finding.enforcedByHarden).toBe(false);
    expect(lint.structuredContent.oneLineAdvice).toMatch(/bla_harden does not refuse on them/);
    expect(finding.remediationRecipe).toMatch(/plaintextSurvivors/);

    writeFileSync(
      join(dir, "gate.js"),
      `const lanes = [0x41, 0x42, 0x43, 0x44];\nfunction check(key) { return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]); }\n`,
      "utf8",
    );
    const both = (await callTool("bla_lint", { directory: dir })).structuredContent;
    const lane = both.findings.find((f: { gate: string }) => f.gate === "lane-independence");
    expect(lane.enforcedByHarden).toBe(true);
    expect(both.oneLineAdvice).toMatch(/1 packaging gate\(s\) would refuse bankrupt harden, and 1 more fail this lint only/);

    // A warning blocks nothing, so it must not claim harden refuses on it.
    writeFileSync(
      join(dir, "hash.cjs"),
      `function fnv1a(text) {\n  let h = 0x811c9dc5;\n  for (let i = 0; i < text.length; i++) {\n    h ^= text.charCodeAt(i);\n    h = Math.imul(h, 0x01000193);\n  }\n  return h >>> 0;\n}\nmodule.exports = { fnv1a };\n`,
      "utf8",
    );
    const withWarning = (await callTool("bla_lint", { directory: dir })).structuredContent;
    const warning = withWarning.findings.find(
      (f: { gate: string; relativePath: string }) => f.relativePath === "hash.cjs",
    );
    expect(warning).toBeDefined();
    expect(warning.shouldRefuseBankrupt).toBe(false);
    expect(warning.enforcedByHarden).toBe(false);
    expect(withWarning.oneLineAdvice).toMatch(/1 packaging gate\(s\) would refuse bankrupt harden, and 1 more fail this lint only/);
  });

  it("bla_doctor is compact and flags a client pinned to another release", async () => {
    const home = tempDir("bla-mcp-home-");
    mkdirSync(join(home, ".cursor"), { recursive: true });
    const setup = runSetup({ homeDir: home, clientIds: ["cursor"], yes: true });
    expect(setup.status).toBe("applied");
    const configPath = join(home, ".cursor", "mcp.json");
    const pinned = `${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version}`;
    expect(readFileSync(configPath, "utf8")).toContain(pinned);

    const healthy = (await callTool("bla_doctor", { home_dir: home, directory: home })).structuredContent;
    expect(healthy.status).toBe("pass");
    expect(healthy.clients).toBeUndefined();
    expect(healthy.reaLimitsTargeted).toBeUndefined();
    expect(healthy.reaLimitsTargetedCount).toBeGreaterThan(0);
    expect(healthy.agentClients.map((c: { id: string }) => c.id)).toEqual(["cursor"]);
    expect(healthy.agentClients[0].pinnedVersion).toBe(BLA_IDENTITY.version);
    expect(healthy.agentClients[0].versionSkew).toBe(false);
    expect(healthy.clientsNotDetected).toContain("windsurf");
    expect(JSON.stringify(healthy).length).toBeLessThan(6000);

    writeFileSync(
      configPath,
      readFileSync(configPath, "utf8").replace(pinned, `${BLA_IDENTITY.packageName}@0.0.1`),
      "utf8",
    );
    const skewed = (
      await callTool("bla_doctor", { home_dir: home, directory: home, verify_handshake: true })
    ).structuredContent;
    expect(skewed.status).toBe("warn");
    expect(skewed.healthy).toBe(true);
    const cursor = skewed.agentClients[0];
    expect(cursor.pinnedVersion).toBe("0.0.1");
    expect(cursor.versionSkew).toBe(true);
    // The probe would start this checkout, not 0.0.1 — so it is not claimed.
    expect(cursor.handshakeStatus).toBe("not_checked");
    expect(skewed.issues.join("\n")).toMatch(/launches bla-agents@0\.0\.1, but this is bla-agents/);
    expect(skewed.nextSteps.join("\n")).toMatch(/setup --yes/);
  }, 60000);

  it("doctor explains what to do when nothing is registered", () => {
    const home = tempDir("bla-mcp-home-");
    const report = runDoctor({ homeDir: home });
    expect(report.agentClients.every((c) => !c.configured)).toBe(true);
    expect(report.nextSteps?.[0]).toMatch(/setup --yes|register BLA by hand/);
  });

  it("doctor reads a BLA entry checked into the project's own MCP config", () => {
    const home = tempDir("bla-mcp-home-");
    const project = tempDir("bla-mcp-project-");
    const entry = (command: string, version: string) => ({
      command,
      args: ["-y", `${BLA_IDENTITY.packageName}@${version}`, "mcp"],
    });
    const writeMcp = (command: string, version: string) =>
      writeFileSync(
        join(project, ".mcp.json"),
        JSON.stringify({ mcpServers: { bla: entry(command, version) } }),
        "utf8",
      );

    // No project directory given, or a project without an entry: nothing is claimed.
    expect(runDoctor({ homeDir: home }).projectRegistrations).toBeUndefined();
    expect(runDoctor({ homeDir: home, projectDirectory: project }).projectRegistrations).toBeUndefined();

    writeMcp(process.execPath, BLA_IDENTITY.version);
    const ok = runDoctor({ homeDir: home, projectDirectory: project });
    expect(ok.projectRegistrations?.map((r) => [r.relativePath, r.client, r.status])).toEqual([
      [".mcp.json", "Claude Code", "pass"],
    ]);
    expect(ok.healthy).toBe(true);
    // Registered where the team put it: do not send the agent off to register a second copy.
    expect(ok.nextSteps?.[0]).toMatch(/registered for this project only \(\.mcp\.json → Claude Code\)/);
    expect(ok.nextSteps?.join("\n")).not.toMatch(/No coding agent has the BLA MCP server registered/);
    expect(ok.nextSteps?.join("\n")).toMatch(/verify_handshake/);

    // Pinned to another release: a warning that setup cannot repair.
    writeMcp(process.execPath, "0.0.1");
    const skewed = runDoctor({ homeDir: home, projectDirectory: project, verifyHandshake: true });
    expect(skewed.status).toBe("warn");
    expect(skewed.healthy).toBe(true);
    expect(skewed.projectRegistrations?.[0]?.handshakeStatus).toBe("not_checked");
    expect(skewed.issues.join("\n")).toMatch(
      /\[project:\.mcp\.json\] \.mcp\.json launches bla-agents@0\.0\.1, but this is bla-agents/,
    );
    expect(skewed.nextSteps?.join("\n")).toMatch(/by hand — setup only writes per-user configs/);

    // A command that does not exist is a broken registration, not a healthy setup.
    writeMcp("/no/such/bla-launcher", BLA_IDENTITY.version);
    const broken = runDoctor({ homeDir: home, projectDirectory: project });
    expect(broken.projectRegistrations?.[0]?.status).toBe("fail");
    expect(broken.healthy).toBe(false);
    expect(broken.issues.join("\n")).toMatch(/not resolvable on disk or PATH/);

    // VS Code keeps its servers under another key; unrelated files are not reported.
    writeMcp(process.execPath, BLA_IDENTITY.version);
    mkdirSync(join(project, ".vscode"), { recursive: true });
    writeFileSync(
      join(project, ".vscode", "mcp.json"),
      JSON.stringify({ servers: { bla: { type: "stdio", ...entry(process.execPath, BLA_IDENTITY.version) } } }),
      "utf8",
    );
    mkdirSync(join(project, ".cursor"), { recursive: true });
    writeFileSync(
      join(project, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { other: { command: "node", args: ["x.js"] } } }),
      "utf8",
    );
    const both = runDoctor({ homeDir: home, projectDirectory: project });
    expect(both.projectRegistrations?.map((r) => `${r.relativePath}:${r.client}:${r.status}`)).toEqual([
      ".mcp.json:Claude Code:pass",
      ".vscode/mcp.json:VS Code:pass",
    ]);

    // A per-user config that sits under the "project" (doctor run from home) is not listed twice.
    const cursorHome = tempDir("bla-mcp-home-");
    mkdirSync(join(cursorHome, ".cursor"), { recursive: true });
    writeFileSync(
      join(cursorHome, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { bla: entry(process.execPath, BLA_IDENTITY.version) } }),
      "utf8",
    );
    const fromHome = runDoctor({ homeDir: cursorHome, projectDirectory: cursorHome });
    expect(fromHome.agentClients.find((c) => c.id === "cursor")?.configured).toBe(true);
    expect(fromHome.projectRegistrations).toBeUndefined();
  });

  it("bla_doctor reports project registrations for the directory it is given", async () => {
    const home = tempDir("bla-mcp-home-");
    const project = tempDir("bla-mcp-project-");
    writeFileSync(
      join(project, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          bla: { command: process.execPath, args: ["-y", `${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version}`, "mcp"] },
        },
      }),
      "utf8",
    );
    const report = (await callTool("bla_doctor", { home_dir: home, directory: project })).structuredContent;
    expect(report.projectRegistrations.map((r: { relativePath: string }) => r.relativePath)).toEqual([".mcp.json"]);
    expect(report.status).toBe("pass");
  });

  it("reads the pinned release out of an MCP entry's arguments", () => {
    expect(pinnedBlaVersionOf(["-y", "bla-agents@3.4.3", "mcp"])).toBe("3.4.3");
    expect(pinnedBlaVersionOf(["--package=bla-agents@3.5.0-rc.1", "bla", "mcp"])).toBe("3.5.0-rc.1");
    expect(pinnedBlaVersionOf(["-y", "bla-agents@latest", "mcp"])).toBeNull();
    expect(pinnedBlaVersionOf(["-y", "bla-agents", "mcp"])).toBeNull();
    expect(pinnedBlaVersionOf(["/usr/local/bin/bla", "mcp"])).toBeNull();
  });

  it("documents the new tool parameters in the schemas", () => {
    const schemaOf = (name: string) => BLA_MCP_TOOLS.find((t) => t.name === name)!.inputSchema;
    expect(Object.keys(schemaOf("bla_harden").properties)).toEqual(
      expect.arrayContaining(["apply", "restore", "confirm_overwrite", "dry_run", "exclude"]),
    );
    expect(Object.keys(schemaOf("bla_discover").properties)).toContain("exclude");
    expect(Object.keys(schemaOf("bla_doctor").properties)).toEqual(
      expect.arrayContaining(["verify_handshake", "directory"]),
    );
    expect(Object.keys(schemaOf("bla_verify_weave").properties)).toEqual(
      expect.arrayContaining(["scope", "verbose"]),
    );
  });
});
