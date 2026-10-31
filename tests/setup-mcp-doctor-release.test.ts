import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BLA_IDENTITY } from "../src/identity.js";
import {
  packDualReleaseTarballs,
  planNpmPublishRetry,
  ReleaseConsistencyError,
  verifyReleaseConsistency,
} from "../src/core/release-plan.js";
import {
  BLA_MCP_PROMPTS,
  BLA_MCP_TOOLS,
  handleMcpRequest,
  type JsonRpcResponse,
  type McpEngineHandlers,
} from "../src/mcp/server.js";
import {
  CLIENT_COMPATIBILITY_MATRIX,
  detectInstalledClients,
  readCodexTomlMcp,
  resolveSupportedAgentClients,
} from "../src/setup/clients.js";
import { runDoctor } from "../src/setup/doctor.js";
import { isNodeSqliteAvailable } from "../src/core/sqlite-runtime.js";
import {
  getInstallManifestPath,
  readInstallManifest,
  runSetup,
  runUninstall,
} from "../src/setup/setup.js";

const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";

const tempDirs: string[] = [];

function makeTempDir(prefix: string = "bla-issue-8-12-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("Issue #8: Native Client Config Formats, Accurate Detection & Cross-Platform Fixtures", () => {
  it("does not detect any installed clients in an empty fakeHome and separates explicit vs discovered selection", () => {
    const emptyHome = makeTempDir("bla-empty-home-");

    // 1. Empty home must never falsely detect Claude Code or any other client
    expect(detectInstalledClients(emptyHome)).toEqual([]);
    const defs = resolveSupportedAgentClients(emptyHome);
    expect(defs.every((d) => d.detected === false)).toBe(true);

    // 2. Running setup without explicit clients on an empty home discovers 0 clients and writes nothing
    const autoSetup = runSetup({ homeDir: emptyHome, yes: true });
    expect(autoSetup.discoveredClients).toEqual([]);
    expect(autoSetup.explicitClients).toEqual([]);
    expect(autoSetup.selectionMode).toBe("discovered");
    expect(autoSetup.actions).toEqual([]);

    // 3. Running setup with explicit clients reports discoveredClients: [] separately from explicitClients
    const explicitSetup = runSetup({
      homeDir: emptyHome,
      clientIds: ["claude_code", "codex"],
      yes: true,
    });
    expect(explicitSetup.status).toBe("applied");
    expect(explicitSetup.selectionMode).toBe("explicit");
    expect(explicitSetup.discoveredClients).toEqual([]);
    expect(explicitSetup.explicitClients).toEqual(["claude_code", "codex"]);
    expect(explicitSetup.actions.every((a) => a.selectionSource === "explicit")).toBe(true);
    expect(explicitSetup.actions.every((a) => a.clientDetected === false)).toBe(true);
  });

  it("writes native Codex TOML (~/.codex/config.toml), VS Code servers JSON, and OpenCode mcp local array JSON while preserving comments and unrelated keys", () => {
    const fakeHome = makeTempDir("bla-native-formats-");

    // Seed Codex config.toml with comments, top-level keys, and another MCP server
    const codexDir = join(fakeHome, ".codex");
    mkdirSync(codexDir, { recursive: true });
    const codexConfigPath = join(codexDir, "config.toml");
    const initialCodexToml = [
      "# Codex user configuration comment",
      'model = "o3"',
      'approval_policy = "on-request"',
      "",
      "[mcp_servers.git]",
      'command = "uvx"',
      'args = ["mcp-server-git", "--repository", "."]',
      "",
    ].join("\n");
    writeFileSync(codexConfigPath, initialCodexToml, "utf8");

    // Seed VS Code user-profile mcp.json with `inputs` and an existing `servers` entry
    const vscodeClient = resolveSupportedAgentClients(fakeHome).find((c) => c.id === "vscode")!;
    mkdirSync(join(vscodeClient.configPath, ".."), { recursive: true });
    writeFileSync(
      vscodeClient.configPath,
      JSON.stringify(
        {
          inputs: [{ id: "token", type: "promptString", description: "API Token" }],
          servers: {
            existing_stdio: {
              type: "stdio",
              command: "node",
              args: ["./existing-server.js"],
            },
          },
        },
        null,
        2,
      ) + "\n",
      "utf8",
    );

    // Seed OpenCode opencode.json with $schema, theme, and an existing `mcp` entry
    const opencodeClient = resolveSupportedAgentClients(fakeHome).find((c) => c.id === "opencode")!;
    mkdirSync(join(opencodeClient.configPath, ".."), { recursive: true });
    writeFileSync(
      opencodeClient.configPath,
      JSON.stringify(
        {
          $schema: "https://opencode.ai/config.json",
          theme: "tokyonight",
          mcp: {
            memory: {
              type: "local",
              command: ["npx", "-y", "@modelcontextprotocol/server-memory"],
              enabled: true,
            },
          },
        },
        null,
        2,
      ) + "\n",
      "utf8",
    );

    // Auto-discovery should now detect exactly codex, vscode, and opencode
    expect(detectInstalledClients(fakeHome).sort()).toEqual(["codex", "opencode", "vscode"]);

    const res = runSetup({
      homeDir: fakeHome,
      onlyDetected: true,
      yes: true,
    });
    expect(res.status).toBe("applied");
    expect(res.selectionMode).toBe("discovered");
    expect([...res.discoveredClients].sort()).toEqual(["codex", "opencode", "vscode"]);

    // Verify Codex native ~/.codex/config.toml independently of BLA's adapter
    expect(existsSync(join(codexDir, "mcp.json"))).toBe(false);
    const writtenToml = readFileSync(codexConfigPath, "utf8");
    expect(readCodexTomlMcp(writtenToml).status).toBe("valid");
    expect(writtenToml).toContain("# Codex user configuration comment");
    expect(writtenToml).toContain('model = "o3"');
    expect(writtenToml).toContain("[mcp_servers.git]");
    expect(writtenToml).toContain("[mcp_servers.bla]");
    expect(writtenToml).toContain('command = "npx"');
    expect(writtenToml).toContain('args = ["-y", "bla-agents@latest", "mcp"]');

    // Verify VS Code native mcp.json uses root key `servers` (NOT `mcpServers`)
    const writtenVscode = JSON.parse(readFileSync(vscodeClient.configPath, "utf8")) as Record<
      string,
      unknown
    >;
    expect(writtenVscode.mcpServers).toBeUndefined();
    expect(writtenVscode.inputs).toEqual([
      { id: "token", type: "promptString", description: "API Token" },
    ]);
    const vscodeServers = writtenVscode.servers as Record<string, unknown>;
    expect(vscodeServers.existing_stdio).toBeDefined();
    expect(vscodeServers.bla).toEqual({
      type: "stdio",
      command: "npx",
      args: ["-y", "bla-agents@latest", "mcp"],
    });

    // Verify OpenCode native opencode.json uses root key `mcp` with `type: "local"` and `command` array
    const writtenOpencode = JSON.parse(readFileSync(opencodeClient.configPath, "utf8")) as Record<
      string,
      unknown
    >;
    expect(writtenOpencode.mcpServers).toBeUndefined();
    expect(writtenOpencode.$schema).toBe("https://opencode.ai/config.json");
    expect(writtenOpencode.theme).toBe("tokyonight");
    const opencodeMcp = writtenOpencode.mcp as Record<string, unknown>;
    expect(opencodeMcp.memory).toBeDefined();
    expect(opencodeMcp.bla).toEqual({
      type: "local",
      command: ["npx", "-y", "bla-agents@latest", "mcp"],
      enabled: true,
    });
  });

  it("resolves Linux, macOS, and Windows client paths with spaces in homeDir and exposes the compatibility matrix", () => {
    const baseTmp = makeTempDir("bla-platform-paths-");
    const spacedHome = join(baseTmp, "User Home With Spaces");
    mkdirSync(spacedHome, { recursive: true });

    const darwinClients = resolveSupportedAgentClients(spacedHome, "darwin");
    const linuxClients = resolveSupportedAgentClients(spacedHome, "linux", {
      XDG_CONFIG_HOME: join(spacedHome, ".xdg config"),
    });
    const winClients = resolveSupportedAgentClients(spacedHome, "win32", {
      APPDATA: join(spacedHome, "AppData", "Roaming"),
    });

    expect(darwinClients.find((c) => c.id === "vscode")?.configPath).toBe(
      join(spacedHome, "Library", "Application Support", "Code", "User", "mcp.json"),
    );
    expect(linuxClients.find((c) => c.id === "vscode")?.configPath).toBe(
      join(spacedHome, ".xdg config", "Code", "User", "mcp.json"),
    );
    expect(linuxClients.find((c) => c.id === "opencode")?.configPath).toBe(
      join(spacedHome, ".xdg config", "opencode", "opencode.json"),
    );
    expect(winClients.find((c) => c.id === "vscode")?.configPath).toBe(
      join(spacedHome, "AppData", "Roaming", "Code", "User", "mcp.json"),
    );

    expect(CLIENT_COMPATIBILITY_MATRIX.length).toBe(10);
    expect(CLIENT_COMPATIBILITY_MATRIX.find((m) => m.clientId === "codex")?.format).toBe(
      "toml-codex",
    );
    expect(CLIENT_COMPATIBILITY_MATRIX.find((m) => m.clientId === "vscode")?.rootKey).toBe(
      "servers",
    );
    expect(CLIENT_COMPATIBILITY_MATRIX.find((m) => m.clientId === "opencode")?.rootKey).toBe(
      "mcp",
    );
  });
});

describe("Issue #9: Fail-Closed Config Parsing, Non-Clobbering Backups & Ownership-Checked Uninstall", () => {
  it("refuses to overwrite malformed JSON/TOML or invalid schema configs and preserves original bytes and hashes", () => {
    const fakeHome = makeTempDir("bla-malformed-");

    // 1. Malformed JSON in .claude.json
    const claudePath = join(fakeHome, ".claude.json");
    writeFileSync(claudePath, '{ "mcpServers": { "broken": true, ', "utf8");
    const claudeOriginalSha = sha256File(claudePath);

    // 2. Malformed TOML in .codex/config.toml
    const codexDir = join(fakeHome, ".codex");
    mkdirSync(codexDir, { recursive: true });
    const codexPath = join(codexDir, "config.toml");
    writeFileSync(codexPath, '[mcp_servers.unclosed\ncommand = "npx"\n', "utf8");
    const codexOriginalSha = sha256File(codexPath);

    // 3. Schema type error in Cursor mcp.json (`mcpServers` is an array instead of object)
    const cursorDir = join(fakeHome, ".cursor");
    mkdirSync(cursorDir, { recursive: true });
    const cursorPath = join(cursorDir, "mcp.json");
    writeFileSync(cursorPath, '{"mcpServers": ["not-an-object"]}\n', "utf8");
    const cursorOriginalSha = sha256File(cursorPath);

    const res = runSetup({
      homeDir: fakeHome,
      clientIds: ["claude_code", "codex", "cursor"],
      yes: true,
    });

    expect(res.status).toBe("error");
    expect(res.actions.every((a) => a.status === "error" && a.applied === false)).toBe(true);

    // Byte-for-byte SHA-256 must remain identical
    expect(sha256File(claudePath)).toBe(claudeOriginalSha);
    expect(sha256File(codexPath)).toBe(codexOriginalSha);
    expect(sha256File(cursorPath)).toBe(cursorOriginalSha);

    // Skills must NOT have been written for any failed client
    for (const action of res.actions) {
      expect(existsSync(action.skillPath)).toBe(false);
    }
  });

  it("never clobbers the original .bla-backup recovery point across repeated setup runs", () => {
    const fakeHome = makeTempDir("bla-backup-preserve-");
    const claudePath = join(fakeHome, ".claude.json");
    const backupPath = `${claudePath}.bla-backup`;

    const originalContent = JSON.stringify(
      {
        customSetting: "preserve-me-forever",
        mcpServers: {
          customServer: { command: "node", args: ["custom.js"] },
        },
      },
      null,
      2,
    );
    writeFileSync(claudePath, originalContent, "utf8");
    const originalSha = sha256File(claudePath);

    // First setup creates `.bla-backup`
    const first = runSetup({
      homeDir: fakeHome,
      clientIds: ["claude_code"],
      yes: true,
    });
    expect(first.status).toBe("applied");
    expect(existsSync(backupPath)).toBe(true);
    expect(sha256File(backupPath)).toBe(originalSha);

    // Second setup modifies `.claude.json` again, but MUST NOT overwrite `.bla-backup`
    const second = runSetup({
      homeDir: fakeHome,
      clientIds: ["claude_code"],
      mcpCommand: "node",
      mcpArgs: ["dist/cli.js", "mcp"],
      yes: true,
    });
    expect(second.status).toBe("applied");
    expect(sha256File(backupPath)).toBe(originalSha);

    // Even if `.claude.json` becomes malformed later and setup is run a third time, `.bla-backup` is untouched
    writeFileSync(claudePath, "{ malformed json", "utf8");
    const third = runSetup({
      homeDir: fakeHome,
      clientIds: ["claude_code"],
      yes: true,
    });
    expect(third.status).toBe("error");
    expect(sha256File(backupPath)).toBe(originalSha);

    // Verify install manifest was recorded atomically
    expect(existsSync(getInstallManifestPath(fakeHome))).toBe(true);
    const manifest = readInstallManifest(fakeHome);
    expect(manifest.clients.claude_code?.backupSha256).toBe(originalSha);
  });

  it("preserves user-note.txt, custom SKILL.md, modified SKILL.md, shared skillDirectory, and custom 'bla' MCP servers on uninstall", () => {
    const fakeHome = makeTempDir("bla-uninstall-ownership-");

    // Case A: User manually created `.agents/skills/blind-llm-agents/user-note.txt` WITHOUT installing BLA
    const sharedSkillDir = join(fakeHome, ".agents", "skills", "blind-llm-agents");
    mkdirSync(sharedSkillDir, { recursive: true });
    const userNotePath = join(sharedSkillDir, "user-note.txt");
    writeFileSync(userNotePath, "Important user research notes - DO NOT DELETE\n", "utf8");

    const uninstallBeforeInstall = runUninstall({ homeDir: fakeHome });
    expect(uninstallBeforeInstall.removedClients).toEqual([]);
    expect(existsSync(userNotePath)).toBe(true);

    // Case B: Multiple clients sharing `.agents/skills/blind-llm-agents` (`windsurf` and `vscode`)
    const setupShared = runSetup({
      homeDir: fakeHome,
      clientIds: ["windsurf", "vscode"],
      yes: true,
    });
    expect(setupShared.status).toBe("applied");
    const sharedSkillMd = join(sharedSkillDir, "SKILL.md");
    expect(existsSync(sharedSkillMd)).toBe(true);

    // Uninstalling ONLY `windsurf` must keep `SKILL.md` because `vscode` still owns it
    const partialUninstall = runUninstall({
      homeDir: fakeHome,
      clientIds: ["windsurf"],
    });
    expect(partialUninstall.removedClients).toEqual(["windsurf"]);
    expect(existsSync(sharedSkillMd)).toBe(true);
    expect(existsSync(userNotePath)).toBe(true);

    // Uninstalling `vscode` removes `SKILL.md`, but preserves `user-note.txt` and `sharedSkillDir`!
    const secondUninstall = runUninstall({
      homeDir: fakeHome,
      clientIds: ["vscode"],
    });
    expect(secondUninstall.removedClients).toEqual(["vscode"]);
    expect(existsSync(sharedSkillMd)).toBe(false);
    expect(existsSync(userNotePath)).toBe(true);

    // Case C: User modifies `SKILL.md` after installing `cursor`
    runSetup({ homeDir: fakeHome, clientIds: ["cursor"], yes: true });
    const cursorSkillPath = join(fakeHome, ".cursor", "skills", "blind-llm-agents", "SKILL.md");
    writeFileSync(cursorSkillPath, "# Custom user edits to SKILL.md\n", "utf8");
    const modifiedUninstall = runUninstall({ homeDir: fakeHome, clientIds: ["cursor"] });
    expect(modifiedUninstall.conflicts.length).toBe(1);
    expect(existsSync(cursorSkillPath)).toBe(true);

    // Case D: User has a custom non-BLA MCP server named `bla` in `.claude.json`
    const claudePath = join(fakeHome, ".claude.json");
    writeFileSync(
      claudePath,
      JSON.stringify({
        mcpServers: {
          bla: { command: "/opt/my-unrelated-bla-binary", args: ["--serve"] },
        },
      }),
      "utf8",
    );
    const customUninstall = runUninstall({ homeDir: fakeHome, clientIds: ["claude_code"] });
    expect(customUninstall.conflicts.some((c) => c.clientId === "claude_code")).toBe(true);
    const preservedClaude = JSON.parse(readFileSync(claudePath, "utf8")) as {
      mcpServers: { bla: { command: string } };
    };
    expect(preservedClaude.mcpServers.bla.command).toBe("/opt/my-unrelated-bla-binary");
  });

  it("performs zero filesystem writes when dryRun is true", () => {
    const fakeHome = makeTempDir("bla-dryrun-");
    const res = runSetup({
      homeDir: fakeHome,
      clientIds: ["claude_code", "codex", "vscode", "opencode"],
      dryRun: true,
      yes: true,
    });
    expect(res.status).toBe("planned");
    for (const action of res.actions) {
      expect(existsSync(action.configPath)).toBe(false);
      expect(existsSync(action.skillPath)).toBe(false);
    }
    expect(existsSync(getInstallManifestPath(fakeHome))).toBe(false);
  });
});

describe("Issue #10: MCP Runtime Argument Validation, Prompts Contract & Subprocess Stdio Verification", () => {
  it("rejects missing, empty, non-string, and invalid-enum arguments across all MCP tools with -32602 and zero engine/FS side effects", async () => {
    const spyHandlers: McpEngineHandlers = {
      hardenProject: vi.fn(),
      defendTarget: vi.fn(),
      auditTarget: vi.fn(),
      protectTarget: vi.fn(),
      verifyTarget: vi.fn(),
      runShowcaseBenchmark: vi.fn(),
      emitCompileTimeNativeHeader: vi.fn(),
      runDoctor: vi.fn(),
      inspectReleaseExposure: vi.fn(),
      initBlaConfig: vi.fn(),
    };

    const invalidCalls: Array<{ name: string; arguments: unknown }> = [
      { name: "bla_audit", arguments: {} },
      { name: "bla_audit", arguments: { path: "" } },
      { name: "bla_audit", arguments: { path: "   " } },
      { name: "bla_audit", arguments: { path: null } },
      { name: "bla_audit", arguments: { path: 123 } },
      { name: "bla_audit", arguments: { path: {} } },
      { name: "bla_protect", arguments: {} },
      { name: "bla_protect", arguments: { input_path: "" } },
      { name: "bla_protect", arguments: { input_path: "./a.js", intensity: "invalid-preset" } },
      { name: "bla_defend", arguments: {} },
      { name: "bla_defend", arguments: { input_path: null } },
      { name: "bla_defend", arguments: { input_path: "./a.js", emit_manifest: "yes" } },
      { name: "bla_verify", arguments: {} },
      { name: "bla_verify", arguments: { target_path: "" } },
      { name: "bla_emit_headers", arguments: {} },
      { name: "bla_emit_headers", arguments: { language: "python" } },
      { name: "bla_inspect_release", arguments: {} },
      { name: "bla_inspect_release", arguments: { path: "./dist", max_files: -5 } },
      { name: "bla_init", arguments: {} },
      { name: "bla_init", arguments: { directory: "" } },
      { name: "bla_doctor", arguments: { home_dir: "" } },
      { name: "bla_benchmark", arguments: { unexpected: true } },
    ];

    for (const [idx, call] of invalidCalls.entries()) {
      const res = await handleMcpRequest(
        {
          jsonrpc: "2.0",
          id: idx + 1,
          method: "tools/call",
          params: call,
        },
        spyHandlers,
      );
      expect(res?.error?.code).toBe(-32602);
    }

    // Prove ZERO engine handlers were invoked for any invalid call
    for (const fn of Object.values(spyHandlers)) {
      expect(fn).not.toHaveBeenCalled();
    }

    // Prove explicit `path: "."` is distinguished from missing `path`
    await handleMcpRequest(
      {
        jsonrpc: "2.0",
        id: 999,
        method: "tools/call",
        params: {
          name: "bla_audit",
          arguments: { path: "." },
        },
      },
      spyHandlers,
    );
    expect(spyHandlers.auditTarget).toHaveBeenCalledWith(".");
  });

  it("implements prompts/get for all advertised prompts in prompts/list and validates required arguments", async () => {
    const listRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "prompts/list",
    });
    const prompts = (listRes?.result as { prompts: typeof BLA_MCP_PROMPTS }).prompts;
    expect(prompts.length).toBeGreaterThanOrEqual(1);

    for (const p of prompts) {
      const isHarden = p.name === "bla-harden-project";
      const args = isHarden
        ? { directory: "./dist" }
        : { target_path: "./dist/app.js" };
      const getRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 2,
        method: "prompts/get",
        params: {
          name: p.name,
          arguments: args,
        },
      });
      expect(getRes?.error).toBeUndefined();
      const result = getRes?.result as {
        description: string;
        messages: Array<{ role: string; content: { type: string; text: string } }>;
      };
      expect(result.messages.length).toBeGreaterThan(0);
      if (isHarden) {
        expect(result.messages[0]?.content.text).toContain("bla_harden");
        expect(result.messages[0]?.content.text).toContain("./dist");
      } else {
        expect(result.messages[0]?.content.text).toContain("./dist/app.js");
      }

      // Missing required args must return -32602; optional-only prompts succeed.
      const badRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 3,
        method: "prompts/get",
        params: {
          name: p.name,
          arguments: {},
        },
      });
      if (p.arguments.some((a) => a.required)) {
        expect(badRes?.error?.code).toBe(-32602);
      } else {
        expect(badRes?.error).toBeUndefined();
      }
    }
  });

  it("completes end-to-end stdio protocol exchange with a real `node dist/cli.js mcp` child process", async () => {
    const fixtureDir = makeTempDir("bla-stdio-fixture-");
    const sampleJs = join(fixtureDir, "sample.js");
    writeFileSync(sampleJs, "export function add(a, b) { return a + b; }\n", "utf8");

    const cliPath = resolve(process.cwd(), "dist/cli.js");
    if (!existsSync(cliPath)) {
      const buildRes = spawnSync(npmCmd, ["run", "build"], {
        cwd: process.cwd(),
        stdio: "pipe",
      });
      expect(buildRes.status).toBe(0);
    }

    const child = spawn(process.execPath, [cliPath, "mcp"], {
      cwd: fixtureDir,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdoutLines: string[] = [];
    let buffer = "";

    const collectResponses = new Promise<void>((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        child.kill();
        rejectPromise(new Error(`Timed out waiting for MCP stdio responses. Got: ${stdoutLines.length}`));
      }, 10000);

      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        buffer += chunk;
        let idx: number;
        while ((idx = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, idx).trim();
          buffer = buffer.slice(idx + 1);
          if (line.length > 0) {
            stdoutLines.push(line);
            if (stdoutLines.length >= 5) {
              clearTimeout(timer);
              resolvePromise();
            }
          }
        }
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        rejectPromise(err);
      });
    });

    const requests = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "bla-stdio-test-client", version: "1.0.0" },
        },
      },
      // Notification without `id` must NOT emit a response line
      {
        jsonrpc: "2.0",
        method: "notifications/initialized",
      },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "prompts/get",
        params: {
          name: "shield-against-rea",
          arguments: { target_path: sampleJs },
        },
      },
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "bla_audit",
          arguments: { path: sampleJs },
        },
      },
      {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "bla_audit",
          arguments: {},
        },
      },
    ];

    for (const req of requests) {
      child.stdin.write(JSON.stringify(req) + "\n");
    }

    await collectResponses;
    child.kill();

    // Every line on stdout must be valid JSON-RPC 2.0
    expect(stdoutLines.length).toBe(5);
    const parsedResponses = stdoutLines.map((l) => JSON.parse(l) as JsonRpcResponse);
    expect(parsedResponses.map((r) => r.id)).toEqual([1, 2, 3, 4, 5]);

    expect(parsedResponses[0]?.result).toMatchObject({
      protocolVersion: "2024-11-05",
      serverInfo: { name: "bla", version: BLA_IDENTITY.version },
    });
    expect(
      (parsedResponses[1]?.result as { tools: unknown[] }).tools.length,
    ).toBe(BLA_MCP_TOOLS.length);
    expect(parsedResponses[2]?.error).toBeUndefined();
    expect((parsedResponses[3]?.result as { isError: boolean }).isError).toBe(false);
    expect(parsedResponses[4]?.error?.code).toBe(-32602);
  });
});

describe("Issue #11: Doctor Real Readiness Checks & Command/Config/Skill/Handshake Diagnostics", () => {
  it("reports healthy: false and mcpRegistered: false when bla.command is '/no/such/command' and skill is missing", () => {
    const fakeHome = makeTempDir("bla-doctor-broken-cmd-");
    writeFileSync(
      join(fakeHome, ".claude.json"),
      JSON.stringify({
        mcpServers: {
          bla: {
            command: "/no/such/command",
            args: ["mcp"],
          },
        },
      }),
      "utf8",
    );

    const report = runDoctor(fakeHome);
    expect(report.healthy).toBe(false);
    expect(report.exitCode).toBe(1);
    expect(report.status).toBe("fail");

    const claudeDiag = report.agentClients.find((c) => c.id === "claude_code")!;
    expect(claudeDiag.detected).toBe(true);
    expect(claudeDiag.configured).toBe(true);
    expect(claudeDiag.commandResolvable).toBe(false);
    expect(claudeDiag.mcpRegistered).toBe(false);
    expect(claudeDiag.skillInstalled).toBe(false);
    expect(claudeDiag.handshakeStatus).toBe("not_checked");
    expect(claudeDiag.status).toBe("fail");
  });

  it("distinguishes malformed config, invalid schema, missing skill, healthy setup, and unavailable runtime engine", () => {
    // 1. Malformed TOML in Codex
    const homeMalformed = makeTempDir("bla-doc-malformed-");
    mkdirSync(join(homeMalformed, ".codex"), { recursive: true });
    writeFileSync(join(homeMalformed, ".codex", "config.toml"), "[mcp_servers.bla\n", "utf8");
    const docMalformed = runDoctor(homeMalformed);
    expect(docMalformed.healthy).toBe(false);
    expect(docMalformed.exitCode).toBe(1);
    expect(docMalformed.agentClients.find((c) => c.id === "codex")?.configStatus).toBe("malformed");

    // 2. Wrong root schema key in VS Code (`mcpServers` instead of `servers`)
    const homeWrongSchema = makeTempDir("bla-doc-schema-");
    const vscodeDef = resolveSupportedAgentClients(homeWrongSchema).find((c) => c.id === "vscode")!;
    mkdirSync(join(vscodeDef.configPath, ".."), { recursive: true });
    writeFileSync(
      vscodeDef.configPath,
      JSON.stringify({ mcpServers: { bla: { command: "npx", args: [] } } }),
      "utf8",
    );
    const docWrongSchema = runDoctor(homeWrongSchema);
    expect(docWrongSchema.healthy).toBe(false);
    expect(docWrongSchema.agentClients.find((c) => c.id === "vscode")?.configStatus).toBe(
      "malformed",
    );

    // 3. Valid MCP config with resolvable command (`process.execPath`), but missing SKILL.md
    const homeNoSkill = makeTempDir("bla-doc-noskill-");
    writeFileSync(
      join(homeNoSkill, ".claude.json"),
      JSON.stringify({
        mcpServers: {
          bla: { command: process.execPath, args: ["dist/cli.js", "mcp"] },
        },
      }),
      "utf8",
    );
    const docNoSkill = runDoctor(homeNoSkill);
    expect(docNoSkill.healthy).toBe(false);
    const claudeNoSkill = docNoSkill.agentClients.find((c) => c.id === "claude_code")!;
    expect(claudeNoSkill.configured).toBe(true);
    expect(claudeNoSkill.commandResolvable).toBe(true);
    expect(claudeNoSkill.skillInstalled).toBe(false);
    expect(claudeNoSkill.status).toBe("fail");

    // 4. Healthy setup with resolvable command and installed skill
    const homeHealthy = makeTempDir("bla-doc-healthy-");
    runSetup({
      homeDir: homeHealthy,
      clientIds: ["claude_code", "codex", "vscode", "opencode"],
      mcpCommand: process.execPath,
      mcpArgs: [resolve(process.cwd(), "dist/cli.js"), "mcp"],
      yes: true,
    });
    const docHealthy = runDoctor({
      homeDir: homeHealthy,
      verifyHandshake: true,
      // Isolate MCP/skill/handshake health from the Node sqlite runtime floor.
      sqliteAvailableOverride: true,
    });
    expect(docHealthy.healthy).toBe(true);
    expect(docHealthy.exitCode).toBe(0);
    const claudeHealthy = docHealthy.agentClients.find((c) => c.id === "claude_code")!;
    expect(claudeHealthy.status).toBe("pass");
    expect(claudeHealthy.handshakeStatus).toBe("verified");
    expect(claudeHealthy.handshakeVerified).toBe(true);

    // 5. Degraded/unavailable SQLite runtime engine
    const docNoSqlite = runDoctor({
      homeDir: homeHealthy,
      sqliteAvailableOverride: false,
    });
    expect(docNoSqlite.engines.sqliteRuntime).toBe("unavailable");
    expect(docNoSqlite.healthy).toBe(false);
    expect(docNoSqlite.exitCode).toBe(1);
  });
});

describe("Issue #12: Release Version, Tag, Commit & Tarball Consistency + Dual Tarball Smoke Verification", () => {
  const validSha256 = "a".repeat(64);
  const altSha256 = "b".repeat(64);
  const headSha = "66be143f2ba81816186ca310513a90aa042e5940";
  const otherCommitSha = "1111111f2ba81816186ca310513a90aa042e5940";

  it("enforces version, dispatch input, trigger tag, existing tag commit, and release asset SHA-256 consistency", () => {
    // 1. Matching configuration succeeds
    const plan = verifyReleaseConsistency({
      packageVersion: "1.1.0",
      identityVersion: "1.1.0",
      dispatchVersion: "1.1.0",
      triggerRef: "refs/tags/bla-agents-1.1.0",
      headSha,
      existingTagSha: headSha,
      tarballSha256: validSha256,
      existingReleaseAssetSha256: validSha256,
    });
    expect(plan.canonicalTag).toBe("bla-agents-1.1.0");
    expect(plan.tagAction).toBe("verify-existing-idempotent");
    expect(plan.releaseAssetAction).toBe("skip-identical");

    // 2. Mismatched workflow_dispatch version fails
    expect(() =>
      verifyReleaseConsistency({
        packageVersion: "1.1.0",
        dispatchVersion: "1.2.0",
        headSha,
        tarballSha256: validSha256,
      }),
    ).toThrowError(ReleaseConsistencyError);

    // 3. Mismatched v-tag fails
    expect(() =>
      verifyReleaseConsistency({
        packageVersion: "1.1.0",
        triggerRef: "refs/tags/v1.0.9",
        headSha,
        tarballSha256: validSha256,
      }),
    ).toThrowError(ReleaseConsistencyError);

    // 4. Existing tag pointing to a different commit fails
    expect(() =>
      verifyReleaseConsistency({
        packageVersion: "1.1.0",
        headSha,
        existingTagSha: otherCommitSha,
        tarballSha256: validSha256,
      }),
    ).toThrowError(ReleaseConsistencyError);

    // 5. Existing release asset with different SHA-256 fails (no clobber)
    expect(() =>
      verifyReleaseConsistency({
        packageVersion: "1.1.0",
        headSha,
        existingTagSha: headSha,
        tarballSha256: validSha256,
        existingReleaseAssetSha256: altSha256,
      }),
    ).toThrowError(ReleaseConsistencyError);

    // 6. Dual-package retry plan: primary already published, alias failed previously
    const retryPlan = planNpmPublishRetry({
      primaryPublished: true,
      aliasPublished: false,
      primaryTarballSha256: validSha256,
      publishedPrimarySha256: validSha256,
      aliasTarballSha256: altSha256,
    });
    expect(retryPlan.primaryAction).toBe("skip-already-published");
    expect(retryPlan.aliasAction).toBe("publish");
    expect(retryPlan.shouldPublishPrimary).toBe(false);
    expect(retryPlan.shouldPublishAlias).toBe(true);
  });

  it.skipIf(!isNodeSqliteAvailable())("packs both bla-agents and bla-shield tarballs and verifies exports, 3 bin entrypoints, and read-only doctor in clean temp dirs", () => {
    const outDir = makeTempDir("bla-release-pack-");
    const packed = packDualReleaseTarballs(process.cwd(), outDir);

    expect(existsSync(packed.primary.tarballPath)).toBe(true);
    expect(existsSync(packed.alias.tarballPath)).toBe(true);
    expect(existsSync(packed.sha256SumsPath)).toBe(true);

    const sumsText = readFileSync(packed.sha256SumsPath, "utf8");
    expect(sumsText).toContain(`${packed.primary.sha256}  ${packed.primary.tarballFilename}`);
    expect(sumsText).toContain(`${packed.alias.sha256}  ${packed.alias.tarballFilename}`);

    for (const artifact of [packed.primary, packed.alias]) {
      const unpackDir = makeTempDir(`bla-unpack-${artifact.packageName}-`);
      const tarRes = spawnSync("tar", ["-xzf", artifact.tarballPath, "-C", unpackDir], {
        stdio: "pipe",
      });
      expect(tarRes.status).toBe(0);
      symlinkSync(
        join(process.cwd(), "node_modules"),
        join(unpackDir, "node_modules"),
        "dir",
      );

      const pkgRoot = join(unpackDir, "package");
      const pkgManifest = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")) as {
        name: string;
        version: string;
        bin: Record<string, string>;
        exports: Record<string, { default?: string; import?: string; types: string }>;
      };

      expect(pkgManifest.name).toBe(artifact.packageName);
      expect(pkgManifest.version).toBe(BLA_IDENTITY.version);

      // Verify all 3 bin entrypoints exist in the packed artifact
      expect(Object.keys(pkgManifest.bin).sort()).toEqual(["bla", "bla-agents", "bla-shield"]);
      for (const relBin of Object.values(pkgManifest.bin)) {
        expect(existsSync(join(pkgRoot, relBin))).toBe(true);
      }

      // Verify exports (`.` and `./bundler`) exist in the packed artifact
      const rootEntry = pkgManifest.exports["."]!.default ?? pkgManifest.exports["."]!.import!;
      const bundlerEntry =
        pkgManifest.exports["./bundler"]!.default ?? pkgManifest.exports["./bundler"]!.import!;
      expect(existsSync(join(pkgRoot, rootEntry))).toBe(true);
      expect(existsSync(join(pkgRoot, pkgManifest.exports["."]!.types))).toBe(true);
      expect(existsSync(join(pkgRoot, bundlerEntry))).toBe(true);
      expect(existsSync(join(pkgRoot, pkgManifest.exports["./bundler"]!.types))).toBe(true);

      // Verify read-only `doctor --json` and MCP `initialize` against unpacked dist/cli.js
      const docRun = spawnSync(
        process.execPath,
        [join(pkgRoot, "dist/cli.js"), "doctor", "--json"],
        {
          encoding: "utf8",
          timeout: 5000,
          env: { ...process.env, HOME: unpackDir },
        },
      );
      expect(docRun.status).toBe(0);
      const docJson = JSON.parse(docRun.stdout) as { blaVersion: string; healthy: boolean };
      expect(docJson.blaVersion).toBe(BLA_IDENTITY.version);
      expect(docJson.healthy).toBe(true);

      // Verify MCP initialize against unpacked dist/cli.js
      const mcpInit = spawnSync(
        process.execPath,
        [join(pkgRoot, "dist/cli.js"), "mcp"],
        {
          input: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) + "\n",
          encoding: "utf8",
          timeout: 5000,
        },
      );
      expect(mcpInit.stdout.trim()).toContain('"protocolVersion":"2024-11-05"');
    }
  });
});
