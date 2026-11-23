import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getDatabaseSyncClass } from "../core/sqlite-runtime.js";
import { BLA_IDENTITY, REA_INTERNAL_LIMITS } from "../identity.js";
import { protectZipOrApkBuffer } from "../shields/formats/archive.js";
import { generateAndroidR8Counter } from "../shields/formats/android-r8.js";
import { packAsarBuffer } from "../shields/formats/asar.js";
import { protectErlangBeamBuffer } from "../shields/formats/erlang-beam.js";
import { protectEvmBytecodeBuffer } from "../shields/formats/evm-bytecode.js";
import { protectAndroidDexBuffer } from "../shields/formats/mobile-game.js";
import {
  buildSafetensorsBuffer,
  protectGgufBuffer,
  protectSafetensorsBuffer,
} from "../shields/formats/model.js";
import { protectNativeBinary } from "../shields/formats/native.js";
import { protectPythonSource } from "../shields/formats/python.js";
import { protectWasmBinary } from "../shields/formats/wasm.js";
import { transformJavaScriptWithBlaShield } from "../shields/javascript/ast-shield.js";
import {
  readClientMcpConfig,
  resolveSupportedAgentClients,
  type ClientConfigFormat,
  type SupportedAgentClientId,
} from "./clients.js";
import {
  readInstallManifest,
  resolveBundledSkillBundle,
  resolveBundledSkillContent,
} from "./setup.js";

export type EngineHealthStatus = "ready" | "degraded" | "unavailable";
export type DoctorClientCheckState = "pass" | "warn" | "fail" | "not_checked";
export type DoctorConfigStatus =
  | "valid"
  | "missing"
  | "malformed"
  | "invalid_entry"
  | "not_configured";
export type DoctorHandshakeStatus = "verified" | "failed" | "not_checked";
export type DoctorSkillStatus = "installed" | "missing" | "modified";

export interface DoctorClientDiagnostic {
  readonly id: SupportedAgentClientId;
  readonly displayName: string;
  readonly format: ClientConfigFormat;
  readonly configPath: string;
  readonly skillPath: string;
  readonly detected: boolean;
  readonly installed: boolean;
  readonly configured: boolean;
  readonly configStatus: DoctorConfigStatus;
  readonly command: string | null;
  readonly args: readonly string[];
  readonly commandResolvable: boolean;
  readonly command_resolvable: boolean;
  /**
   * Release the client launches (`bla-agents@<version>` in its MCP entry), or
   * null when the entry does not pin one.
   */
  readonly pinnedVersion: string | null;
  /** True when `pinnedVersion` is not the release running this check. */
  readonly versionSkew: boolean;
  readonly handshakeStatus: DoctorHandshakeStatus;
  readonly handshakeVerified: boolean;
  readonly handshake_verified: boolean;
  readonly mcpRegistered: boolean;
  readonly skillInstalled: boolean;
  readonly skillStatus: DoctorSkillStatus;
  /** Supporting bundle files (references/appendices) absent next to SKILL.md. */
  readonly skillMissingFiles: readonly string[];
  /** Supporting bundle files whose sha256 differs from the bundled/recorded copy. */
  readonly skillModifiedFiles: readonly string[];
  readonly status: DoctorClientCheckState;
  readonly issues: readonly string[];
}

/**
 * A BLA MCP entry found in a config file that lives in the project (and is
 * usually checked in), as opposed to the per-user client configs.
 */
export interface DoctorProjectRegistration {
  /** Project-relative config file, for example `.mcp.json`. */
  readonly relativePath: string;
  readonly configPath: string;
  /** The client that reads this file. */
  readonly client: string;
  readonly configStatus: "valid" | "malformed" | "invalid_entry";
  readonly command: string | null;
  readonly args: readonly string[];
  readonly commandResolvable: boolean;
  /** Release the entry pins (`bla-agents@x.y.z` in its arguments), when it pins one. */
  readonly pinnedVersion: string | null;
  readonly versionSkew: boolean;
  readonly handshakeStatus: DoctorHandshakeStatus;
  readonly status: "pass" | "warn" | "fail";
  readonly issues: readonly string[];
}

/**
 * Project-scoped MCP config files the supported clients read. `bla setup`
 * never writes these; teams check them in so everyone opening the project
 * gets the server.
 */
const PROJECT_SCOPED_MCP_CONFIGS: ReadonlyArray<{
  readonly relativePath: string;
  readonly client: string;
  readonly format: ClientConfigFormat;
}> = Object.freeze([
  { relativePath: ".mcp.json", client: "Claude Code", format: "json-mcpServers" },
  { relativePath: ".cursor/mcp.json", client: "Cursor", format: "json-mcpServers" },
  { relativePath: ".vscode/mcp.json", client: "VS Code", format: "json-vscode" },
  { relativePath: ".gemini/settings.json", client: "Gemini CLI", format: "json-mcpServers" },
  { relativePath: ".codex/config.toml", client: "Codex", format: "toml-codex" },
  { relativePath: "opencode.json", client: "OpenCode", format: "json-opencode" },
] as const);

export interface DoctorOptions {
  readonly homeDir?: string;
  /**
   * Project to check for project-scoped MCP configs (`.mcp.json`,
   * `.cursor/mcp.json`, `.vscode/mcp.json`, …). Not checked when absent.
   */
  readonly projectDirectory?: string;
  readonly platform?: NodeJS.Platform;
  readonly env?: NodeJS.ProcessEnv;
  readonly pathEnv?: string;
  readonly verifyHandshake?: boolean;
  readonly handshakeTimeoutMs?: number;
  readonly sqliteAvailableOverride?: boolean;
}

export interface DoctorDiagnosticReport {
  readonly healthy: boolean;
  readonly exitCode: 0 | 1;
  readonly status: "pass" | "warn" | "fail";
  readonly blaVersion: string;
  readonly nodeVersion: string;
  readonly platform: string;
  readonly arch: string;
  /** Initialize result from the installed CLI. Registration commands are inspected only. */
  readonly localMcpHandshake?: "verified" | "failed";
  readonly engines: {
    readonly javascriptAstShield: EngineHealthStatus;
    readonly electronAsarPacker: EngineHealthStatus;
    readonly wasmBinaryShield: EngineHealthStatus;
    readonly pythonPycMarshalShield: EngineHealthStatus;
    readonly nativeElfMachoPeShield: EngineHealthStatus;
    readonly zipApkArchiveShield: EngineHealthStatus;
    readonly aiModelShield: EngineHealthStatus;
    readonly erlangBeamShield: EngineHealthStatus;
    readonly evmBytecodeShield: EngineHealthStatus;
    readonly androidDexR8Shield: EngineHealthStatus;
    readonly sqliteRuntime: EngineHealthStatus;
    readonly astParser: EngineHealthStatus;
    readonly asarPacker: EngineHealthStatus;
    readonly wasmLeb128: EngineHealthStatus;
    readonly pythonMarshal: EngineHealthStatus;
    readonly nativeBinary: EngineHealthStatus;
  };
  readonly reaLimitsTargeted: typeof REA_INTERNAL_LIMITS;
  readonly agentClients: readonly DoctorClientDiagnostic[];
  readonly clients: readonly DoctorClientDiagnostic[];
  /** BLA entries in the project's own MCP config files. Absent when there are none. */
  readonly projectRegistrations?: readonly DoctorProjectRegistration[];
  readonly issues: readonly string[];
  /** What to do about the state found, most important first. Absent when nothing is needed. */
  readonly nextSteps?: readonly string[];
}

/** `bla-agents@3.4.1` / `blind-llm-agents@3.4.1` in an MCP entry's arguments. */
export function pinnedBlaVersionOf(args: readonly string[]): string | null {
  for (const arg of args) {
    for (const name of [BLA_IDENTITY.packageName, BLA_IDENTITY.packageAlias]) {
      const at = arg.lastIndexOf(`${name}@`);
      if (at === -1) continue;
      const version = arg.slice(at + name.length + 1).trim();
      if (/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) return version;
    }
  }
  return null;
}

function sha256Hex(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function isExecutableFile(filePath: string, platform: NodeJS.Platform): boolean {
  try {
    if (!existsSync(filePath)) return false;
    const st = statSync(filePath);
    if (!st.isFile()) return false;
    if (platform !== "win32") {
      accessSync(filePath, constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

export function isCommandResolvable(
  command: string | null | undefined,
  pathEnv: string = process.env.PATH ?? "",
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (!command || typeof command !== "string") return false;
  const trimmed = command.trim();
  if (trimmed.length === 0) return false;

  // Path-qualified executable
  if (trimmed.includes("/") || trimmed.includes("\\")) {
    return isExecutableFile(trimmed, platform);
  }

  const dirs = pathEnv
    .split(delimiter)
    .map((d) => d.trim())
    .filter((d) => d.length > 0);

  const extensions =
    platform === "win32"
      ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD")
          .split(";")
          .map((e) => e.trim())
          .filter(Boolean)
      : [""];

  for (const dir of dirs) {
    if (platform === "win32" && !trimmed.includes(".")) {
      for (const ext of extensions) {
        if (isExecutableFile(join(dir, `${trimmed}${ext}`), platform)) {
          return true;
        }
      }
    }
    if (isExecutableFile(join(dir, trimmed), platform)) {
      return true;
    }
  }

  return false;
}

/**
 * Budget for the MCP `initialize` probe. A cold Node start plus a loaded machine
 * used to miss the older 8s budget and report a healthy setup as unhealthy, so
 * the default is generous and can be overridden per call or via
 * `BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS`.
 */
export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 15_000;

export function resolveHandshakeTimeoutMs(explicit?: number): number {
  if (explicit !== undefined && Number.isFinite(explicit) && explicit > 0) {
    return Math.floor(explicit);
  }
  const fromEnv = Number(process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) {
    return Math.floor(fromEnv);
  }
  return DEFAULT_HANDSHAKE_TIMEOUT_MS;
}

export function probeLocalMcpHandshake(
  timeoutMs: number = DEFAULT_HANDSHAKE_TIMEOUT_MS,
): boolean {
  try {
    const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    const distCli = join(packageRoot, "dist", "cli.js");
    if (!existsSync(distCli)) return false;

    const initRequest =
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "bla-doctor-probe", version: BLA_IDENTITY.version },
        },
      }) + "\n";

    const proc = spawnSync(process.execPath, [distCli, "mcp"], {
      cwd: packageRoot,
      // In particular, never inherit NODE_OPTIONS, NODE_PATH, or loader settings.
      env: process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {},
      input: initRequest,
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });

    if (proc.error || proc.status !== 0 || !proc.stdout) return false;
    const lines = proc.stdout
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    for (const line of lines) {
      const parsed = JSON.parse(line) as {
        jsonrpc?: string;
        id?: number;
        result?: { serverInfo?: { name?: string } };
      };
      if (parsed.jsonrpc === "2.0" && parsed.id === 1 && parsed.result?.serverInfo?.name === BLA_IDENTITY.mcpServerName) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

const ENGINE_ALIAS_KEYS: ReadonlySet<string> = new Set([
  "astParser",
  "asarPacker",
  "wasmLeb128",
  "pythonMarshal",
  "nativeBinary",
]);

function checkEngines(sqliteOverride?: boolean): DoctorDiagnosticReport["engines"] {
  let javascriptAstShield: EngineHealthStatus = "ready";
  try {
    const out = transformJavaScriptWithBlaShield("const __blaProbe = 1;\n", {
      intensity: "stealth",
      seed: "doctor-probe",
    });
    if (!out || typeof out.code !== "string" || out.code.length === 0) {
      javascriptAstShield = "unavailable";
    }
  } catch {
    javascriptAstShield = "unavailable";
  }

  const electronAsarPacker: EngineHealthStatus =
    typeof packAsarBuffer === "function" ? "ready" : "unavailable";

  let wasmBinaryShield: EngineHealthStatus = "ready";
  try {
    const minimalWasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const res = protectWasmBinary(minimalWasm);
    if (!res || res.buffer.byteLength < 8) {
      wasmBinaryShield = "unavailable";
    }
  } catch {
    wasmBinaryShield = "unavailable";
  }

  let pythonPycMarshalShield: EngineHealthStatus = "ready";
  try {
    const pyOut = protectPythonSource("def _probe():\n    return 1\n", {
      intensity: "stealth",
      seed: "doctor-probe",
    });
    if (!pyOut || typeof pyOut.code !== "string" || pyOut.code.length === 0) {
      pythonPycMarshalShield = "unavailable";
    }
  } catch {
    pythonPycMarshalShield = "unavailable";
  }

  const nativeElfMachoPeShield: EngineHealthStatus =
    typeof protectNativeBinary === "function" ? "ready" : "unavailable";

  const zipApkArchiveShield: EngineHealthStatus =
    typeof protectZipOrApkBuffer === "function" ? "ready" : "unavailable";
  const androidDexR8Shield: EngineHealthStatus =
    typeof protectAndroidDexBuffer === "function" &&
    typeof generateAndroidR8Counter === "function"
      ? "ready"
      : "unavailable";

  let aiModelShield: EngineHealthStatus = "ready";
  try {
    const safetensors = buildSafetensorsBuffer(
      { w: { dtype: "F32", shape: [2], data_offsets: [0, 8] } },
      Buffer.alloc(8, 0),
    );
    const stRes = protectSafetensorsBuffer(safetensors, {
      intensity: "stealth",
      seed: "doctor-probe",
    });
    // An empty buffer is not a valid probe anymore: protectGgufBuffer fails
    // closed on non-GGUF input. Probe with a minimal valid v3 header instead.
    const emptyGguf = Buffer.alloc(24, 0);
    emptyGguf.write("GGUF", 0, "ascii");
    emptyGguf.writeUInt32LE(3, 4);
    const ggufRes = protectGgufBuffer(emptyGguf, {
      intensity: "stealth",
      seed: "doctor-probe",
    });
    if (stRes.buffer.byteLength === 0 || ggufRes.buffer.byteLength === 0) {
      aiModelShield = "unavailable";
    }
  } catch {
    aiModelShield = "unavailable";
  }

  let erlangBeamShield: EngineHealthStatus = "ready";
  try {
    const u32 = (n: number): Buffer => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n >>> 0);
      return b;
    };
    const chunk = (name: string, payload: Buffer): Buffer =>
      Buffer.concat([Buffer.from(name, "latin1"), u32(payload.length), payload]);
    const atoms = ["bla_probe", "module_info"];
    const atomBody = Buffer.concat([
      u32(atoms.length),
      ...atoms.map((a) => Buffer.concat([Buffer.from([a.length]), Buffer.from(a, "utf8")])),
    ]);
    const code = Buffer.concat([u32(16), u32(0), u32(169), u32(4), u32(2), Buffer.from("code")]);
    const form = Buffer.concat([
      Buffer.from("BEAM", "latin1"),
      chunk("AtU8", atomBody),
      chunk("Code", code),
    ]);
    const beam = Buffer.concat([Buffer.from("FOR1", "latin1"), u32(form.length), form]);
    const res = protectErlangBeamBuffer(beam, { intensity: "stealth", seed: "doctor-probe" });
    if (res.buffer.byteLength < beam.byteLength) {
      erlangBeamShield = "unavailable";
    }
  } catch {
    erlangBeamShield = "unavailable";
  }

  let evmBytecodeShield: EngineHealthStatus = "ready";
  try {
    const res = protectEvmBytecodeBuffer(Buffer.from([0x60, 0x00, 0x00]), {
      intensity: "stealth",
      seed: "doctor-probe",
    });
    if (res.buffer.byteLength < 3) {
      evmBytecodeShield = "unavailable";
    }
  } catch {
    evmBytecodeShield = "unavailable";
  }

  let sqliteRuntime: EngineHealthStatus = "ready";
  if (typeof sqliteOverride === "boolean") {
    sqliteRuntime = sqliteOverride ? "ready" : "unavailable";
  } else {
    try {
      const DbClass = getDatabaseSyncClass();
      if (typeof DbClass !== "function") {
        sqliteRuntime = "unavailable";
      }
    } catch {
      sqliteRuntime = "unavailable";
    }
  }

  return {
    javascriptAstShield,
    electronAsarPacker,
    wasmBinaryShield,
    pythonPycMarshalShield,
    nativeElfMachoPeShield,
    zipApkArchiveShield,
    aiModelShield,
    erlangBeamShield,
    evmBytecodeShield,
    androidDexR8Shield,
    sqliteRuntime,
    astParser: javascriptAstShield,
    asarPacker: electronAsarPacker,
    wasmLeb128: wasmBinaryShield,
    pythonMarshal: pythonPycMarshalShield,
    nativeBinary: nativeElfMachoPeShield,
  };
}

/**
 * BLA entries in the project's own MCP config files. A file that is absent or
 * does not mention BLA is not reported; a per-user config that happens to sit
 * under the project directory (doctor run from the home directory) is skipped,
 * since the client list already covers it.
 */
function inspectProjectRegistrations(
  projectDirectory: string,
  userConfigPaths: ReadonlySet<string>,
  pathEnv: string,
  platform: NodeJS.Platform,
  verifyHandshake: boolean,
): DoctorProjectRegistration[] {
  const out: DoctorProjectRegistration[] = [];
  for (const candidate of PROJECT_SCOPED_MCP_CONFIGS) {
    const configPath = resolve(projectDirectory, ...candidate.relativePath.split("/"));
    if (userConfigPaths.has(configPath)) continue;
    const readRes = readClientMcpConfig(configPath, candidate.format, BLA_IDENTITY.mcpServerName);
    if (readRes.status === "missing" || readRes.status === "not_configured") continue;

    const issues: string[] = [];
    if (readRes.status === "malformed") {
      // Only worth a line when the file is about BLA at all; clients differ in
      // how much non-JSON (comments, trailing commas) they tolerate, so this
      // is a warning, not a verdict.
      let mentionsBla = false;
      try {
        const raw = readFileSync(configPath, "utf8");
        mentionsBla =
          raw.includes(BLA_IDENTITY.packageName) || raw.includes(BLA_IDENTITY.packageAlias);
      } catch {
        mentionsBla = false;
      }
      if (!mentionsBla) continue;
      issues.push(
        `${candidate.relativePath} could not be parsed, so its BLA entry was not checked${readRes.error ? ` (${readRes.error})` : ""}`,
      );
      out.push({
        relativePath: candidate.relativePath,
        configPath,
        client: candidate.client,
        configStatus: "malformed",
        command: null,
        args: [],
        commandResolvable: false,
        pinnedVersion: null,
        versionSkew: false,
        handshakeStatus: "not_checked",
        status: "warn",
        issues,
      });
      continue;
    }

    if (readRes.status === "invalid_entry" || readRes.entry === null) {
      issues.push(
        readRes.error ??
          `Invalid '${BLA_IDENTITY.mcpServerName}' MCP entry in ${candidate.relativePath}`,
      );
      out.push({
        relativePath: candidate.relativePath,
        configPath,
        client: candidate.client,
        configStatus: "invalid_entry",
        command: null,
        args: [],
        commandResolvable: false,
        pinnedVersion: null,
        versionSkew: false,
        handshakeStatus: "not_checked",
        status: "fail",
        issues,
      });
      continue;
    }

    const command = readRes.entry.command;
    const args = readRes.entry.args;
    const commandResolvable = isCommandResolvable(command, pathEnv, platform);
    if (!commandResolvable) {
      issues.push(
        `${candidate.relativePath} starts BLA with '${command}', which is not resolvable on disk or PATH`,
      );
    }
    const pinnedVersion = pinnedBlaVersionOf(args);
    const versionSkew = pinnedVersion !== null && pinnedVersion !== BLA_IDENTITY.version;
    if (versionSkew) {
      issues.push(
        `${candidate.relativePath} launches ${BLA_IDENTITY.packageName}@${pinnedVersion}, but this is ${BLA_IDENTITY.packageName} ${BLA_IDENTITY.version}; change the version in that file (setup does not rewrite project-scoped configs)`,
      );
    }
    if (verifyHandshake) {
      issues.push("Project launcher handshake unverified; doctor only self-tests the installed BLA CLI.");
    }
    out.push({
      relativePath: candidate.relativePath,
      configPath,
      client: candidate.client,
      configStatus: "valid",
      command,
      args,
      commandResolvable,
      pinnedVersion,
      versionSkew,
      handshakeStatus: "not_checked",
      status: !commandResolvable ? "fail" : versionSkew ? "warn" : "pass",
      issues,
    });
  }
  return out;
}

export function runDoctor(homeDirOrOptions?: string | DoctorOptions): DoctorDiagnosticReport {
  const options: DoctorOptions =
    typeof homeDirOrOptions === "string"
      ? { homeDir: homeDirOrOptions }
      : (homeDirOrOptions ?? {});

  const home = options.homeDir ?? homedir();
  const platform = options.platform ?? process.platform;
  const pathEnv = options.pathEnv ?? options.env?.PATH ?? process.env.PATH ?? "";
  const clients = resolveSupportedAgentClients(home, platform, options.env);
  const manifest = readInstallManifest(home);
  const bundledSkillSha256 = sha256Hex(resolveBundledSkillContent());
  const bundledSupportFiles = resolveBundledSkillBundle().filter(
    (f) => f.relativePath !== "SKILL.md",
  );

  const engines = checkEngines(options.sqliteAvailableOverride);
  const globalIssues: string[] = [];
  const localMcpHandshake = options.verifyHandshake
    ? probeLocalMcpHandshake(resolveHandshakeTimeoutMs(options.handshakeTimeoutMs))
      ? "verified"
      : "failed"
    : undefined;
  if (localMcpHandshake === "failed") {
    globalIssues.push("The installed BLA CLI did not pass its local MCP initialize self-test.");
  }

  for (const [engineName, status] of Object.entries(engines)) {
    if (ENGINE_ALIAS_KEYS.has(engineName)) continue;
    if (status === "unavailable") {
      globalIssues.push(`Engine '${engineName}' is unavailable in current runtime (${process.version})`);
    }
  }

  const agentStatuses: DoctorClientDiagnostic[] = clients.map((c) => {
    const clientIssues: string[] = [];
    const skillPath = join(c.skillDirectory, "SKILL.md");
    const readRes = readClientMcpConfig(c.configPath, c.format, BLA_IDENTITY.mcpServerName);

    const configStatus: DoctorConfigStatus = readRes.status;
    const configured = configStatus === "valid" && readRes.entry !== null;
    const command = readRes.entry?.command ?? null;
    const args = readRes.entry?.args ?? [];

    if (configStatus === "malformed") {
      clientIssues.push(
        readRes.error ?? `Malformed configuration file for ${c.displayName} at '${c.configPath}'`,
      );
    } else if (configStatus === "invalid_entry") {
      clientIssues.push(
        readRes.error ?? `Invalid '${BLA_IDENTITY.mcpServerName}' MCP entry for ${c.displayName}`,
      );
    }

    const commandResolvable =
      configured && command !== null ? isCommandResolvable(command, pathEnv, platform) : false;

    if (configured && !commandResolvable) {
      clientIssues.push(
        `Configured MCP command '${command}' for ${c.displayName} is not resolvable on disk or PATH`,
      );
    }

    // A client pinned to another release runs that release's tools next to
    // whatever skill is on disk — the agent then follows a playbook for
    // parameters its server does not have (or the reverse).
    const pinnedVersion = configured ? pinnedBlaVersionOf(args) : null;
    const versionSkew = pinnedVersion !== null && pinnedVersion !== BLA_IDENTITY.version;
    if (versionSkew) {
      clientIssues.push(
        `${c.displayName} launches ${BLA_IDENTITY.packageName}@${pinnedVersion}, but this is ${BLA_IDENTITY.packageName} ${BLA_IDENTITY.version}; re-run \`npx ${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version} setup --yes\` so its MCP entry and skill come from the same release`,
      );
    }

    let skillInstalled = false;
    let skillStatus: DoctorSkillStatus = "missing";
    if (existsSync(skillPath)) {
      try {
        const rawSkill = readFileSync(skillPath, "utf8");
        if (rawSkill.trim().length > 0) {
          skillInstalled = true;
          const currentSha = sha256Hex(rawSkill);
          const manifestRec = manifest.clients[c.id];
          if (
            currentSha === bundledSkillSha256 ||
            (manifestRec && manifestRec.writtenSkillSha256 === currentSha)
          ) {
            skillStatus = "installed";
          } else {
            skillStatus = "modified";
          }
        }
      } catch {
        skillInstalled = false;
        skillStatus = "missing";
      }
    }

    if (configured && !skillInstalled) {
      clientIssues.push(`MCP server is configured for ${c.displayName}, but SKILL.md is missing at '${skillPath}'`);
    }

    // Full-bundle integrity: SKILL.md links into references/ etc., so a
    // half-installed bundle silently breaks the agent guide.
    const skillMissingFiles: string[] = [];
    const skillModifiedFiles: string[] = [];
    if (skillInstalled) {
      const recorded = manifest.clients[c.id]?.writtenSkillFiles;
      for (const file of bundledSupportFiles) {
        const full = join(c.skillDirectory, ...file.relativePath.split("/"));
        if (!existsSync(full)) {
          skillMissingFiles.push(file.relativePath);
          continue;
        }
        try {
          const sha = sha256Hex(readFileSync(full, "utf8"));
          if (sha !== file.sha256 && sha !== recorded?.[file.relativePath]) {
            skillModifiedFiles.push(file.relativePath);
          }
        } catch {
          skillMissingFiles.push(file.relativePath);
        }
      }
      if (skillMissingFiles.length > 0) {
        clientIssues.push(
          `Skill bundle for ${c.displayName} is incomplete (missing: ${skillMissingFiles.join(", ")}); re-run \`bla setup --yes\``,
        );
      }
    }

    if (configured && options.verifyHandshake) {
      clientIssues.push("Client launcher handshake unverified; doctor only self-tests the installed BLA CLI.");
    }
    const mcpRegistered = configured && commandResolvable;

    let status: DoctorClientCheckState = "not_checked";
    if (configStatus === "malformed" || configStatus === "invalid_entry") {
      status = "fail";
    } else if (configured) {
      if (
        !commandResolvable ||
        !skillInstalled ||
        skillMissingFiles.length > 0
      ) {
        status = "fail";
      } else if (skillStatus === "modified" || skillModifiedFiles.length > 0 || versionSkew) {
        status = "warn";
      } else {
        status = "pass";
      }
    } else {
      status = "not_checked";
    }

    for (const issue of clientIssues) {
      globalIssues.push(`[${c.id}] ${issue}`);
    }

    return {
      id: c.id,
      displayName: c.displayName,
      format: c.format,
      configPath: c.configPath,
      skillPath,
      detected: c.detected,
      installed: c.detected,
      configured,
      configStatus,
      command,
      args,
      commandResolvable,
      command_resolvable: commandResolvable,
      pinnedVersion,
      versionSkew,
      handshakeStatus: "not_checked",
      handshakeVerified: false,
      handshake_verified: false,
      mcpRegistered,
      skillInstalled,
      skillStatus,
      skillMissingFiles,
      skillModifiedFiles,
      status,
      issues: clientIssues,
    };
  });

  const projectRegistrations =
    options.projectDirectory !== undefined
      ? inspectProjectRegistrations(
          resolve(options.projectDirectory),
          new Set(clients.map((c) => resolve(c.configPath))),
          pathEnv,
          platform,
          options.verifyHandshake === true,
        )
      : [];
  for (const reg of projectRegistrations) {
    for (const issue of reg.issues) {
      globalIssues.push(`[project:${reg.relativePath}] ${issue}`);
    }
  }

  const anyEngineUnavailable = Object.values(engines).some((s) => s === "unavailable");
  const anyClientFailed =
    agentStatuses.some((c) => c.status === "fail") ||
    projectRegistrations.some((r) => r.status === "fail");
  const anyClientWarn =
    agentStatuses.some((c) => c.status === "warn") ||
    projectRegistrations.some((r) => r.status === "warn");

  const healthy = !anyEngineUnavailable && !anyClientFailed && localMcpHandshake !== "failed";
  const overallStatus: DoctorDiagnosticReport["status"] = !healthy
    ? "fail"
    : anyClientWarn
      ? "warn"
      : "pass";

  const nextSteps: string[] = [];
  const setupCommand = `npx ${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version} setup --yes`;
  const configuredClients = agentStatuses.filter((c) => c.configured);
  const usableProjectRegistrations = projectRegistrations.filter(
    (r) => r.configStatus === "valid" && r.commandResolvable,
  );
  if (configuredClients.length === 0) {
    const detected = agentStatuses.filter((c) => c.detected).map((c) => c.displayName);
    if (usableProjectRegistrations.length > 0) {
      // Registered where the team put it. Saying "not registered" here sends
      // the agent off to register a second copy.
      nextSteps.push(
        `BLA is registered for this project only (${usableProjectRegistrations.map((r) => `${r.relativePath} → ${r.client}`).join(", ")}): an agent opened in this directory gets the MCP tools, the server's own instructions carry the core playbook, and the full guide is readable as the MCP resource bla://skill/SKILL.md. For other projects, and to install the skill in the client itself, run \`${setupCommand}\`.`,
      );
    } else {
      nextSteps.push(
        detected.length > 0
          ? `No coding agent has the BLA MCP server registered yet (detected: ${detected.join(", ")}). Run \`${setupCommand}\`, then restart the agent.`
          : `No supported coding agent was detected for this user. Install one, or register BLA by hand: command \`npx\`, args \`-y ${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version} mcp\`.`,
      );
    }
  }
  const brokenProjectRegistrations = projectRegistrations.filter((r) => r.status !== "pass");
  if (brokenProjectRegistrations.length > 0) {
    nextSteps.push(
      `Fix the project-scoped entry in ${brokenProjectRegistrations.map((r) => r.relativePath).join(", ")} by hand — setup only writes per-user configs. A working entry: command \`npx\`, args \`-y ${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version} mcp\`. Restart the agent afterwards.`,
    );
  }
  if (agentStatuses.some((c) => c.status === "fail" || c.versionSkew)) {
    nextSteps.push(
      `Re-run \`${setupCommand}\` to repair the registrations listed in issues, then restart the agent so it reloads the MCP server and skill.`,
    );
  }
  if (anyEngineUnavailable) {
    nextSteps.push(
      `An engine is unavailable on Node ${process.version}: use Node ^22.23.4 or >=24 (SQLite needs node:sqlite).`,
    );
  }
  if (
    !options.verifyHandshake &&
    (configuredClients.some((c) => c.commandResolvable) || usableProjectRegistrations.length > 0)
  ) {
    nextSteps.push(
      "Registrations were read from disk only. Pass --verify-handshake (MCP: verify_handshake: true) to self-test the installed BLA CLI with an MCP initialize request.",
    );
  }

  return {
    healthy,
    exitCode: healthy ? 0 : 1,
    status: overallStatus,
    blaVersion: BLA_IDENTITY.version,
    nodeVersion: process.version,
    platform: `${platform}-${process.arch}`,
    arch: process.arch,
    ...(localMcpHandshake !== undefined ? { localMcpHandshake } : {}),
    engines,
    reaLimitsTargeted: REA_INTERNAL_LIMITS,
    agentClients: agentStatuses,
    clients: agentStatuses,
    ...(projectRegistrations.length > 0 ? { projectRegistrations } : {}),
    issues: globalIssues,
    ...(nextSteps.length > 0 ? { nextSteps } : {}),
  };
}
