import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync,
  symlinkSync, truncateSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../src/cli.js";
import { auditTarget } from "../src/engine/auditor.js";
import { runShowcaseBenchmark } from "../src/engine/benchmark.js";
import { defendTarget } from "../src/engine/defender.js";
import { hardenProject } from "../src/engine/harden.js";
import { resolveApplyStateDirectory } from "../src/engine/harden-apply.js";
import { protectTarget } from "../src/engine/protector.js";
import { getRedteamReport, REDTEAM_REPORT_JSON } from "../src/engine/rea-observability.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { initBlaConfig } from "../src/core/config.js";
import { inspectReleaseExposure } from "../src/core/release-exposure.js";
import { createStdioLineProcessor, handleMcpRequest, type McpEngineHandlers } from "../src/mcp/server.js";
import { getClientConfigAdapter, resolveSupportedAgentClients } from "../src/setup/clients.js";
import { runDoctor } from "../src/setup/doctor.js";
import { getInstallManifestPath, runSetup, runUninstall } from "../src/setup/setup.js";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import { formatSetupReport } from "../src/ui/reporter.js";

vi.mock("../src/engine/benchmark.js", () => ({ runShowcaseBenchmark: vi.fn() }));

const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const directories: string[] = [];
function scratch(root = tmpdir()) {
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, "bla-cli-mcp-"));
  directories.push(dir);
  return dir;
}

function write(path: string, content: string) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  return path;
}

function runBuiltCli(args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; input?: Buffer | string } = {}) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    encoding: "utf8", timeout: 20_000, ...options,
  });
  expect(result.error).toBeUndefined();
  return result;
}

async function call(name: string, args: Record<string, unknown> = {}, handlers?: McpEngineHandlers) {
  const response = await handleMcpRequest({
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args },
  }, handlers);
  expect(response?.error).toBeUndefined();
  return response?.result as {
    isError: boolean;
    content: { text: string }[];
    structuredContent: Record<string, unknown>;
  };
}

const handlers: McpEngineHandlers = {
  auditTarget, defendTarget, hardenProject, protectTarget, verifyTarget, runShowcaseBenchmark,
  emitCompileTimeNativeHeader, initBlaConfig, inspectReleaseExposure, runDoctor,
};

const redteamFixture = {
  schema: "bla-redteam-rea/v1", status: "measured", generatedAt: "test", pairs: [],
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("doctor local self-test", () => {
  it("uses only the installed CLI and keeps both client and project launchers unverified", async () => {
    const root = scratch();
    const projectMarker = join(root, "project-executed");
    const clientMarker = join(root, "client-executed");
    const preloadMarker = join(root, "preload-executed");
    const preload = write(join(root, "preload.mjs"),
      `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(preloadMarker)}, "executed");`);
    const registration = (marker: string) => ({
      mcpServers: {
        bla: {
          command: process.execPath,
          args: ["-e", `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed")`],
        },
      },
    });
    const home = scratch();
    write(join(home, ".claude.json"), JSON.stringify(registration(clientMarker)));
    write(join(root, ".mcp.json"), JSON.stringify(registration(projectMarker)));
    vi.stubEnv("NODE_OPTIONS", `--import=${preload}`);

    const result = await call("bla_doctor", { directory: root, home_dir: home, verify_handshake: true });
    expect(result.structuredContent).toMatchObject({
      localMcpHandshake: "verified",
      agentClients: [{ id: "claude_code", handshakeStatus: "not_checked" }],
      projectRegistrations: [{
        relativePath: ".mcp.json", handshakeStatus: "not_checked",
        issues: [expect.stringContaining("unverified")],
      }],
    });
    for (const marker of [projectMarker, clientMarker, preloadMarker]) expect(existsSync(marker)).toBe(false);
  });
});

describe("REA report admission", () => {
  it("rejects unauthorized paths, non-reports, symlinks, and large files", async () => {
    const outside = scratch();
    const state = scratch(process.env.BLA_STATE_DIR!);
    const outsideReport = write(join(outside, "report.json"), JSON.stringify(redteamFixture));
    const secret = write(join(state, "credentials.json"), '{"password":"private-test-sentinel"}');
    const malformed = write(join(state, "malformed.json"), '{"private-test-sentinel":');
    const valid = write(join(state, "valid.json"), JSON.stringify(redteamFixture));
    const oversize = write(join(state, "large.json"), "{}");
    truncateSync(oversize, 9 * 1024 * 1024);
    symlinkSync(valid, join(state, "link.json"));
    symlinkSync(outside, join(state, "linked-directory"), "dir");

    for (const reportPath of [outsideReport, secret, malformed, oversize, join(state, "link.json"),
      join(state, "linked-directory", "report.json"), state]) {
      const result = await call("bla_redteam_report", { report_path: reportPath });
      expect(result.isError, reportPath).toBe(true);
      expect(result.structuredContent.report).toBeUndefined();
      expect(result.content[0]?.text).not.toContain("private-test-sentinel");
    }
  });

  it.skipIf(process.platform === "win32")("rejects a FIFO before opening it", () => {
    const path = join(scratch(process.env.BLA_STATE_DIR!), "report.json");
    expect(spawnSync("mkfifo", [path]).status).toBe(0);
    expect(getRedteamReport({ reportPath: path })).toMatchObject({ status: "fail", executed: false });
  });

  it("projects the schema and rejects malformed outcome rows", async () => {
    const state = scratch(process.env.BLA_STATE_DIR!);
    const outcome = (phase: string) => ({
      format: "wasm_module", phase, status: "ok", inputBytes: 8, budgetHit: false,
      errorName: null, errorMessage: null, budgetName: null, redactionOrAmbiguity: null,
      metrics: { validates: true, privateSettings: { password: "hidden" } },
    });
    const result = await call("bla_redteam_report", {
      report_path: write(join(state, "valid.json"), JSON.stringify({
        ...redteamFixture,
        privateSettings: { password: "hidden" },
        reaProvenance: { commit: "abc", additional: "hidden" },
        pairs: [{
          format: "wasm_module", before: outcome("before"), after: outcome("after"),
          sampleMeta: { exportDecoysInjected: 1, password: "hidden" },
          blaLimits: { WASM_INTERFACE_REPRESENTATION_BYTES: 100, password: "hidden" },
        }],
      })),
    });
    expect(result.isError).toBe(false);
    expect(result.structuredContent.report).toMatchObject({
      schema: redteamFixture.schema, status: redteamFixture.status,
      reaProvenance: { commit: "abc" },
      pairs: [{ after: { metrics: { validates: true } }, sampleMeta: { exportDecoysInjected: 1 } }],
    });
    expect(result.content[0]?.text).not.toContain("hidden");
    const invalidRows = await call("bla_redteam_report", {
      report_path: write(join(state, "invalid-rows.json"), JSON.stringify({
        ...redteamFixture, pairs: [{ format: "wasm_module", after: {} }],
      })),
    });
    expect(invalidRows.isError).toBe(true);
    expect(invalidRows.structuredContent.report).toBeUndefined();
  });

  it("rejects a caller-selected live checkout and derives the live report path from the harness", async () => {
    const root = scratch();
    const trustedRoot = join(root, "operator-rea");
    const callerRoot = join(root, "other-rea");
    write(join(callerRoot, "dist", "go", "GoBinaryImage.js"), "// unused fixture");
    const override = write(join(root, "unrelated.json"), JSON.stringify(redteamFixture));
    vi.stubEnv("REA_ROOT", undefined);
    expect(await call("bla_redteam_report", { execute: true, rea_root: callerRoot })).toMatchObject({
      isError: true, content: [{ text: expect.stringContaining("REA_ROOT") }],
    });
    vi.stubEnv("REA_ROOT", trustedRoot);

    expect(await call("bla_redteam_report", { execute: true, rea_root: callerRoot })).toMatchObject({
      isError: true, content: [{ text: expect.stringContaining("REA_ROOT") }],
    });
    const result = await call("bla_redteam_report", { execute: true, report_path: override });
    expect(result.structuredContent).toMatchObject({
      status: "unverified", executed: false, reaRoot: trustedRoot, reportPath: REDTEAM_REPORT_JSON,
    });
    expect(getRedteamReport({ execute: true, reaRoot: trustedRoot, reportPath: override }).reportPath)
      .toBe(REDTEAM_REPORT_JSON);
  });
});

describe("MCP framing and tool verdicts", () => {
  it("recovers from invalid envelopes and validates ids before dispatch", () => {
    const result = runBuiltCli(["mcp"], { input: [
      "null", "[]", "true", '"string"', '{"jsonrpc":"2.0","method":"ping","id":{}}',
      '{"jsonrpc":"2.0","method":"ping","id":null}',
      '{"jsonrpc":"2.0","method":"ping","id":"good"}', "",
    ].join("\n") });
    expect(result.status).toBe(0);
    const messages = result.stdout.trim().split("\n").map((line) => JSON.parse(line));
    expect(messages.slice(0, 5)).toEqual(Array(5).fill({
      jsonrpc: "2.0", id: null,
      error: { code: -32600, message: expect.stringContaining("Invalid Request") },
    }));
    expect(messages.slice(5)).toEqual([
      { jsonrpc: "2.0", id: null, result: {} },
      { jsonrpc: "2.0", id: "good", result: {} },
    ]);
  });

  it("holds a multiline byte-counted body across chunks", () => {
    const messages: string[] = [];
    const processor = createStdioLineProcessor({ onLine: (line) => messages.push(line) });
    const body = '{\n  "jsonrpc": "2.0",\n  "id": "雪",\n  "method": "ping"\n}';
    const splitAt = body.indexOf("雪") + 1;
    processor.push(`Content-Length: ${Buffer.byteLength(body)}\r\nContent-Type: application/json\r\n\r`);
    processor.push(`\n${body.slice(0, splitAt)}`);
    expect(messages).toEqual([]);
    processor.push(body.slice(splitAt, -1));
    expect(messages).toEqual([]);
    processor.push(body.slice(-1) + '\n{"jsonrpc":"2.0","method":"ping","id":4}\n');
    expect(messages).toEqual([body, '{"jsonrpc":"2.0","method":"ping","id":4}']);
  });

  it("ignores malformed cancellation notifications before changing the harden queue", () => {
    const root = scratch();
    write(join(root, "dist", "one.cjs"), "exports.value = 42;\n");
    const cancel = (jsonrpc: string, params: unknown, id?: number) => ({
      jsonrpc, id, method: "notifications/cancelled", params,
    });
    const harden = (id: number) => ({
      jsonrpc: "2.0", id, method: "tools/call",
      params: {
        name: "bla_harden",
        arguments: { directory: root, output_directory: join(root, `.mirror-${id}`), intensity: "stealth" },
      },
    });
    const requests = [
      harden(1), cancel("1.0", { requestId: 1 }),
      cancel("2.0", { requestId: 1, reason: {} }),
      cancel("2.0", { requestId: 1 }, 8),
      harden(2),
      ...Array.from({ length: 14 }, (_, i) => ({ jsonrpc: "2.0", id: 20 + i, method: "ping" })),
      cancel("2.0", { requestId: 2, reason: "valid cancellation" }),
    ];
    const result = runBuiltCli(["mcp"], { input: requests.map((value) => JSON.stringify(value)).join("\n") + "\n" });
    expect(result.status).toBe(0);
    const messages = result.stdout.trim().split("\n").map((line) => JSON.parse(line));
    expect(messages.find(({ id }) => id === 1)?.result?.structuredContent).toMatchObject({ overallSuccess: true });
    expect(messages.find(({ id }) => id === 2)?.result?.structuredContent).toMatchObject({ cancelled: true });
    expect(messages.find(({ id }) => id === 8)?.error?.code).toBe(-32600);
    expect(messages.find(({ id }) => id === 33)?.error?.code).toBe(-32000);
  });

  it("sets isError on structural verification and defense failures and enforces pinned verification", async () => {
    const target = write(join(scratch(), "app.cjs"), "exports.value = 42;\n");
    const verification = vi.fn<typeof verifyTarget>();
    verification.mockImplementation(() => ({ ...verifyTarget(target), overallPassed: false }));
    const result = await call("bla_verify", { target_path: target }, { ...handlers, verifyTarget: verification });
    expect(result).toMatchObject({ isError: true, structuredContent: { overallPassed: false } });

    const failDefense = (...args: Parameters<typeof defendTarget>) => ({
      ...defendTarget(...args), overallSuccess: false,
    });
    const defended = await call("bla_defend", { input_path: target, intensity: "stealth" },
      { ...handlers, defendTarget: failDefense });
    expect(defended).toMatchObject({ isError: true, structuredContent: { overallSuccess: false } });

    const passing = () => ({ ...verifyTarget(target), overallPassed: true });
    for (const missing of [{}, { public_key_path: target }, { manifest_path: target }]) {
      const pinned = await call("bla_verify", {
        target_path: target, require_pinned_key: true, ...missing,
      }, { ...handlers, verifyTarget: passing });
      expect(pinned).toMatchObject({
        isError: true, structuredContent: { manifestVerification: { ok: false, reason: expect.stringContaining("require_pinned_key") } },
      });
    }
  });

  it("accepts a valid pinned signature and keeps structural failure independent", async () => {
    const root = scratch();
    const target = write(join(root, "app.cjs"), "exports.value = 42;\n");
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const signingKey = write(join(root, "private.pem"), privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const pinnedKey = write(join(root, "public.pem"), publicKey.export({ type: "spki", format: "pem" }).toString());
    const defended = defendTarget({
      inputPath: target, intensity: "stealth", emitManifest: true,
      signManifest: true, manifestSigningKeyPath: signingKey,
    });
    const args = {
      target_path: defended.outputPath, manifest_path: defended.manifestPath,
      public_key_path: pinnedKey, require_pinned_key: true,
    };
    for (const overallPassed of [true, false]) {
      const verified = await call("bla_verify", args, {
        ...handlers, verifyTarget: () => ({ ...defended.verification, overallPassed }),
      });
      expect(verified).toMatchObject({
        isError: !overallPassed,
        structuredContent: { overallPassed, manifestVerification: { ok: true, pinned: true } },
      });
    }
  });

  it("includes manifests, summary and coverage in overwrite confirmation even with no old artifact", async () => {
    const root = scratch();
    write(join(root, "dist", "main.cjs"), "exports.value = 42;\n");
    write(join(root, ".blarc"), '{"emitManifest":true,"selfSeal":true}');
    const mirror = join(root, ".mirror");
    const manifest = write(join(mirror, "dist", "main.cjs.bla-manifest.json"), "old manifest");
    const summary = write(join(mirror, "bla-harden-summary.json"), "old summary");
    const coverage = write(join(mirror, "integrity-coverage.json"), "old coverage");
    const result = await call("bla_harden", { directory: root, output_directory: mirror, intensity: "stealth" });
    expect(result).toMatchObject({
      isError: true, structuredContent: {
        status: "confirmation_required", wouldOverwrite: expect.arrayContaining([manifest, summary, coverage]),
      },
    });
    expect(readFileSync(manifest, "utf8")).toBe("old manifest");
    expect(readFileSync(summary, "utf8")).toBe("old summary");
    expect(readFileSync(coverage, "utf8")).toBe("old coverage");
    expect(existsSync(join(mirror, "dist", "main.cjs"))).toBe(false);
  });

  it("checks promoted manifests plus auxiliary files in a custom apply staging directory", async () => {
    const root = scratch();
    const input = write(join(root, "dist", "app.cjs"), "exports.value = 42;\n");
    const promotedManifest = write(`${input}.bla-manifest.json`, "previous promoted manifest");
    const mirror = join(root, ".mirror");
    const oldArtifact = write(join(mirror, "dist", "app.cjs"), "previous staged output");
    const stagedManifest = write(`${oldArtifact}.bla-manifest.json`, "previous staged manifest");
    const summary = write(join(mirror, "bla-harden-summary.json"), "previous summary");
    const result = await call("bla_harden", {
      directory: root, output_directory: mirror, apply: true, emit_manifest: true, intensity: "stealth",
    });
    expect(result).toMatchObject({
      isError: true, structuredContent: {
        status: "confirmation_required",
        wouldOverwrite: expect.arrayContaining([input, promotedManifest, oldArtifact, stagedManifest, summary]),
      },
    });
    expect(readFileSync(promotedManifest, "utf8")).toBe("previous promoted manifest");
    expect(readFileSync(stagedManifest, "utf8")).toBe("previous staged manifest");
  });

  it("returns a failed benchmark verdict on both entry points and prints the report", async () => {
    vi.mocked(runShowcaseBenchmark).mockResolvedValue({
      timestamp: "test", blaVersion: "test", aggregateTokenMultiplier: 1, aggregateCostMultiplier: 1,
      cases: [{
        id: "test", reaShowcaseReference: "test", title: "Test case", format: "javascript", tokenMultiplier: 1, costMultiplier: 1,
        functionalCheckPassed: false,
        before: {
          exposureScore: 1, examinationStatus: "complete", obligationNodes: 0,
          estimatedTokens: 1, estimatedCostUsd: 0, estimatedSeconds: 0, agentOutcome: "test",
        },
        after: {
          exposureScore: 1, examinationStatus: "limited", triggeredLimits: [], obligationNodes: 0,
          estimatedTokens: 1, estimatedCostUsd: 0, estimatedSeconds: 0, agentOutcome: "test",
        },
      }],
    });
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    expect(await runCli(["benchmark"])).toBe(2);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("1 of 1 runtime checks failed"));
    expect(await call("bla_benchmark")).toMatchObject({
      isError: true, structuredContent: { cases: [{ functionalCheckPassed: false }] },
    });
  });
});

describe("restore and setup writes", () => {
  it("previews restoration and sidecar removal while retaining the original backup", () => {
    const root = scratch();
    const input = write(join(root, "dist", "app.cjs"), "exports.result = 'original';\n");
    const hardened = hardenProject({ directory: root, apply: true, intensity: "stealth", emitManifest: true });
    expect(hardened.apply?.status).toBe("applied");
    const stateFile = join(resolveApplyStateDirectory(root), "apply-state.json");
    const state = readFileSync(stateFile);
    const backup = join(hardened.apply!.backupDirectory!, "dist", "app.cjs");
    const promoted = readFileSync(input);
    const manifest = `${input}.bla-manifest.json`;
    expect(existsSync(manifest)).toBe(true);

    const preview = runBuiltCli(["harden", root, "--restore", "--dry-run", "--json"]);
    expect(preview.status).toBe(0);
    expect(JSON.parse(preview.stdout)).toMatchObject({
      status: "planned", restored: ["dist/app.cjs"], removed: ["dist/app.cjs.bla-manifest.json"],
    });
    expect(readFileSync(input)).toEqual(promoted);
    expect(readFileSync(stateFile)).toEqual(state);
    expect(readFileSync(backup, "utf8")).toBe("exports.result = 'original';\n");
    expect(existsSync(manifest)).toBe(true);
    expect(runBuiltCli(["harden", root, "--restore"]).status).toBe(0);
    expect(readFileSync(input, "utf8")).toBe("exports.result = 'original';\n");
    expect(existsSync(manifest)).toBe(false);
  });

  it("rejects inline Codex server tables without touching the file and removes descendant tables on uninstall", () => {
    const home = scratch();
    const configPath = join(home, ".codex", "config.toml");
    const opts = { homeDir: home, env: {}, clientIds: ["codex"], yes: true, force: true };
    for (const inline of [
      'mcp_servers = { other = { command = "node" } }\n',
      '"mcp_servers" = {}\n',
      '[mcp_servers]\nbla = { command = "node" }\n',
    ]) {
      write(configPath, inline);
      const result = runSetup(opts);
      expect(result.status).toBe("error");
      expect(result.actions[0]?.error).toMatch(/inline table|inline or dotted assignment/);
      expect(readFileSync(configPath, "utf8")).toBe(inline);
      expect(existsSync(`${configPath}.bla-backup`)).toBe(false);
    }
    write(configPath, [
      '[mcp_servers.bla]', 'command = "bla"', 'args = ["mcp"]',
      '[mcp_servers.blah]', 'command = "other"',
      '[mcp_servers . "bla" . env]', 'TOKEN = "local"',
      '[mcp_servers.blah.env]', 'PATH = "retained"',
      '[mcp_servers.bla.env.deep]', 'nested = true',
    ].join("\n") + "\n");
    expect(runUninstall(opts).removedClients).toEqual(["codex"]);
    expect(readFileSync(configPath, "utf8")).toBe(
      '[mcp_servers.blah]\ncommand = "other"\n[mcp_servers.blah.env]\nPATH = "retained"\n',
    );
  });

  it.skipIf(process.platform === "win32")("preserves config permissions and creates private recovery files", () => {
    const home = scratch();
    const config = write(join(home, ".claude.json"), '{"mcpServers":{}}\n');
    chmodSync(config, 0o600);
    const options = { homeDir: home, clientIds: ["claude_code"], yes: true };
    expect(runSetup(options).status).toBe("applied");
    for (const path of [config, `${config}.bla-backup`, getInstallManifestPath(home)]) {
      expect(statSync(path).mode & 0o777).toBe(0o600);
    }
    expect(runUninstall(options).removedClients).toEqual(["claude_code"]);
    expect(statSync(config).mode & 0o777).toBe(0o600);
  });

  it("keeps a config edit that arrives after setup reads it", () => {
    const home = scratch();
    const config = write(join(home, ".claude.json"), '{"mcpServers":{}}\n');
    const adapter = getClientConfigAdapter("json-mcpServers");
    const upsert = adapter.upsertServer.bind(adapter);
    const changed = '{"mcpServers":{},"newSetting":true}\n';
    vi.spyOn(adapter, "upsertServer").mockImplementationOnce((...args) => {
      writeFileSync(config, changed);
      return upsert(...args);
    });
    const result = runSetup({ homeDir: home, clientIds: ["claude_code"], yes: true });
    expect(result.actions[0]).toMatchObject({
      status: "error", error: expect.stringContaining("Config changed since it was read"),
    });
    expect(readFileSync(config, "utf8")).toBe(changed);
    expect(existsSync(`${config}.bla-backup`)).toBe(false);
  });

  it("reports disabled entries explicitly and preserves the caller's setting with force", () => {
    const home = scratch();
    write(join(home, ".claude.json"), '{"mcpServers":{"bla":{"command":"node","disabled":true}}}');
    write(join(home, ".codex", "config.toml"), '[mcp_servers.bla]\ncommand = "node"\nenabled = false\n');
    const result = runSetup({
      homeDir: home, env: {}, clientIds: ["claude_code", "codex"], yes: true, force: true,
    });
    expect(result.actions).toMatchObject([{ mcpEnabled: false }, { mcpEnabled: false }]);
    expect(result.message).toContain("Preserved 2 disabled");
    expect(formatSetupReport(result)).toContain("DISABLED (preserved)");
    expect(readFileSync(join(home, ".claude.json"), "utf8")).toContain('"disabled": true');
    expect(readFileSync(join(home, ".codex", "config.toml"), "utf8")).toContain("enabled = false");
  });

  it("uses configured client homes, renders partial errors, and exits nonzero from CLI setup", () => {
    const home = scratch();
    const codex = join(home, "custom-codex");
    const xdg = join(home, "custom-xdg");
    const appdata = join(home, "custom-appdata");
    const env = { ...process.env, HOME: home, USERPROFILE: home, CODEX_HOME: codex, XDG_CONFIG_HOME: xdg, APPDATA: appdata };
    const clients = resolveSupportedAgentClients(home, "win32", env);
    expect(clients.find(({ id }) => id === "vscode")?.configPath).toBe(join(appdata, "Code", "User", "mcp.json"));
    expect(clients.find(({ id }) => id === "codex")?.skillDirectory).toBe(join(codex, "skills", "blind-llm-agents"));
    expect(resolveSupportedAgentClients(home, "linux", {}).find(({ id }) => id === "codex")?.configPath)
      .toBe(join(home, ".codex", "config.toml"));
    const invalid = write(join(xdg, "opencode", "opencode.json"), "{");
    const setup = runBuiltCli(["setup", "--yes", "--client", "codex", "--client", "opencode"], { env });
    expect(setup.status).toBe(1);
    expect(setup.stdout).toContain("PARTIAL");
    expect(setup.stdout).toContain("Malformed OpenCode configuration");
    expect(setup.stdout).not.toContain("PLANNED (Preview)");
    expect(existsSync(join(codex, "config.toml"))).toBe(true);

    const doc = runBuiltCli(["doctor", "--json"], { cwd: home, env });
    const diagnostic = JSON.parse(doc.stdout);
    expect(diagnostic.agentClients).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "codex", configPath: join(codex, "config.toml"), configured: true }),
      expect.objectContaining({ id: "opencode", configPath: invalid, configStatus: "malformed" }),
    ]));
  });
});
