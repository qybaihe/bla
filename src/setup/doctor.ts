import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getDatabaseSyncClass } from "../core/sqlite-runtime.js";
import { BLA_IDENTITY, REA_INTERNAL_LIMITS } from "../identity.js";
import { protectZipOrApkBuffer } from "../shields/formats/archive.js";
import { packAsarBuffer } from "../shields/formats/asar.js";
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

export interface DoctorOptions {
  readonly homeDir?: string;
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
  readonly engines: {
    readonly javascriptAstShield: EngineHealthStatus;
    readonly electronAsarPacker: EngineHealthStatus;
    readonly wasmBinaryShield: EngineHealthStatus;
    readonly pythonPycMarshalShield: EngineHealthStatus;
    readonly nativeElfMachoPeShield: EngineHealthStatus;
    readonly zipApkArchiveShield: EngineHealthStatus;
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
  readonly issues: readonly string[];
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

function probeLocalMcpHandshake(
  command: string,
  args: readonly string[],
  timeoutMs: number = 8000,
): boolean {
  try {
    const thisDir = dirname(fileURLToPath(import.meta.url));
    const distCli = resolve(thisDir, "../../dist/cli.js");

    let execCmd = command;
    let execArgs = [...args];

    // Never execute arbitrary unknown commands or network `npx` downloads during doctor probes.
    // Only allow trusted local Node/BLA invocations.
    const baseCmd = command.split(/[/\\]/).pop() ?? "";
    if (baseCmd === "npx" || baseCmd === "npx.cmd") {
      if (!existsSync(distCli)) {
        return false;
      }
      execCmd = process.execPath;
      execArgs = [distCli, "mcp"];
    } else if (
      baseCmd !== "node" &&
      baseCmd !== "node.exe" &&
      command !== process.execPath &&
      baseCmd !== "bla" &&
      baseCmd !== "bla-agents" &&
      baseCmd !== "bla-shield"
    ) {
      return false;
    }

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

    const proc = spawnSync(execCmd, execArgs, {
      input: initRequest,
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });

    if (proc.error || !proc.stdout) return false;
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
      if (parsed.jsonrpc === "2.0" && parsed.id === 1 && parsed.result?.serverInfo?.name === "bla") {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

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
    sqliteRuntime,
    astParser: javascriptAstShield,
    asarPacker: electronAsarPacker,
    wasmLeb128: wasmBinaryShield,
    pythonMarshal: pythonPycMarshalShield,
    nativeBinary: nativeElfMachoPeShield,
  };
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

  for (const [engineName, status] of Object.entries(engines)) {
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

    let handshakeStatus: DoctorHandshakeStatus = "not_checked";
    let handshakeVerified = false;
    if (options.verifyHandshake && configured && commandResolvable && command !== null) {
      handshakeVerified = probeLocalMcpHandshake(command, args, options.handshakeTimeoutMs ?? 8000);
      handshakeStatus = handshakeVerified ? "verified" : "failed";
      if (!handshakeVerified) {
        clientIssues.push(`MCP stdio initialize handshake failed for ${c.displayName}`);
      }
    }

    const mcpRegistered =
      configured && commandResolvable && handshakeStatus !== "failed";

    let status: DoctorClientCheckState = "not_checked";
    if (configStatus === "malformed" || configStatus === "invalid_entry") {
      status = "fail";
    } else if (configured) {
      if (
        !commandResolvable ||
        !skillInstalled ||
        skillMissingFiles.length > 0 ||
        handshakeStatus === "failed"
      ) {
        status = "fail";
      } else if (skillStatus === "modified" || skillModifiedFiles.length > 0) {
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
      handshakeStatus,
      handshakeVerified,
      handshake_verified: handshakeVerified,
      mcpRegistered,
      skillInstalled,
      skillStatus,
      skillMissingFiles,
      skillModifiedFiles,
      status,
      issues: clientIssues,
    };
  });

  const anyEngineUnavailable = Object.values(engines).some((s) => s === "unavailable");
  const anyClientFailed = agentStatuses.some((c) => c.status === "fail");
  const anyClientWarn = agentStatuses.some((c) => c.status === "warn");

  const healthy = !anyEngineUnavailable && !anyClientFailed;
  const overallStatus: DoctorDiagnosticReport["status"] = !healthy
    ? "fail"
    : anyClientWarn
      ? "warn"
      : "pass";

  return {
    healthy,
    exitCode: healthy ? 0 : 1,
    status: overallStatus,
    blaVersion: BLA_IDENTITY.version,
    nodeVersion: process.version,
    platform: `${platform}-${process.arch}`,
    arch: process.arch,
    engines,
    reaLimitsTargeted: REA_INTERNAL_LIMITS,
    agentClients: agentStatuses,
    clients: agentStatuses,
    issues: globalIssues,
  };
}
