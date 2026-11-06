import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { BLA_IDENTITY } from "../identity.js";
import {
  getClientConfigAdapter,
  normalizeClientId,
  resolveSupportedAgentClients,
  type AgentClientDefinition,
  type ClientConfigFormat,
  type McpServerRegistration,
  type SupportedAgentClientId,
} from "./clients.js";

export type ClientSelectionSource = "explicit" | "auto-discovered" | "default-all";
export type SetupSelectionMode = "explicit" | "discovered" | "all-default";

export interface PlannedSetupAction {
  readonly clientId: SupportedAgentClientId;
  readonly displayName: string;
  readonly format: ClientConfigFormat;
  readonly configPath: string;
  readonly backupPath: string | null;
  readonly skillPath: string;
  readonly mcpCommand: string;
  readonly mcpArgs: readonly string[];
  readonly clientDetected: boolean;
  readonly selectionSource: ClientSelectionSource;
  readonly status: "planned" | "applied" | "error" | "conflict";
  readonly applied: boolean;
  readonly error?: string;
}

export type ClientSetupResult = PlannedSetupAction;

export interface SetupRunOptions {
  readonly clientIds?: readonly (SupportedAgentClientId | string)[];
  readonly clients?: readonly (SupportedAgentClientId | string)[];
  readonly allDetected?: boolean;
  readonly onlyDetected?: boolean;
  readonly includeUndetected?: boolean;
  readonly dryRun?: boolean;
  readonly yes?: boolean;
  readonly force?: boolean;
  readonly homeDir?: string;
  readonly platform?: NodeJS.Platform;
  readonly env?: NodeJS.ProcessEnv;
  readonly mcpCommand?: string;
  readonly mcpArgs?: readonly string[];
}

export type SetupOptions = SetupRunOptions;

export interface SetupRunResult {
  readonly status: "planned" | "applied" | "error" | "conflict" | "partial";
  readonly actions: readonly PlannedSetupAction[];
  readonly results: readonly PlannedSetupAction[];
  readonly discoveredClients: readonly SupportedAgentClientId[];
  readonly explicitClients: readonly SupportedAgentClientId[];
  readonly selectionMode: SetupSelectionMode;
  readonly manifestPath: string | null;
  readonly message: string;
}

export type SetupReport = SetupRunResult;

export interface InstalledClientRecord {
  readonly clientId: SupportedAgentClientId;
  readonly configPath: string;
  readonly format: ClientConfigFormat;
  readonly configExistedBefore: boolean;
  readonly backupPath: string | null;
  readonly backupSha256: string | null;
  readonly writtenConfigSha256: string;
  readonly writtenEntry: McpServerRegistration;
  readonly writtenEntryHash: string;
  readonly skillPath: string;
  readonly skillDirectory: string;
  readonly skillExistedBefore: boolean;
  readonly skillDirectoryExistedBefore: boolean;
  readonly writtenSkillSha256: string;
  /**
   * Supporting skill bundle files (e.g. `references/counter-rea-matrix.md`)
   * written next to SKILL.md, keyed by POSIX relative path → sha256.
   * Absent on manifests written before full-bundle installs.
   */
  readonly writtenSkillFiles?: Readonly<Record<string, string>>;
  readonly installedAt: string;
}

export interface BlaInstallManifest {
  readonly version: 1;
  readonly updatedAt: string;
  readonly clients: Record<string, InstalledClientRecord>;
}

export interface ClientUninstallResult {
  readonly clientId: SupportedAgentClientId;
  readonly configPath: string;
  readonly skillPath: string;
  readonly mcpRemoved: boolean;
  readonly skillRemoved: boolean;
  readonly status: "removed" | "noop" | "conflict" | "error";
  readonly conflictReason?: string;
  readonly error?: string;
}

export interface UninstallRunOptions {
  readonly homeDir?: string;
  readonly platform?: NodeJS.Platform;
  readonly env?: NodeJS.ProcessEnv;
  readonly clientIds?: readonly (SupportedAgentClientId | string)[];
  readonly clients?: readonly (SupportedAgentClientId | string)[];
  readonly force?: boolean;
}

export interface UninstallRunResult {
  readonly removedClients: readonly string[];
  readonly results: readonly ClientUninstallResult[];
  readonly conflicts: readonly ClientUninstallResult[];
}

function sha256Hex(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function hashMcpEntry(entry: McpServerRegistration): string {
  return sha256Hex(
    JSON.stringify({
      command: entry.command,
      args: [...entry.args],
    }),
  );
}

function isBlaOwnedMcpEntry(entry: McpServerRegistration): boolean {
  const cmd = entry.command.trim();
  const joinedArgs = entry.args.join(" ");
  if (
    cmd === "bla" ||
    cmd === "bla-agents" ||
    cmd === "bla-shield" ||
    cmd.endsWith("/bla") ||
    cmd.endsWith("\\bla") ||
    cmd.endsWith("/bla-agents") ||
    cmd.endsWith("\\bla-agents") ||
    cmd.endsWith("/bla-shield") ||
    cmd.endsWith("\\bla-shield")
  ) {
    return true;
  }
  if (
    joinedArgs.includes(BLA_IDENTITY.packageName) ||
    joinedArgs.includes(BLA_IDENTITY.packageAlias) ||
    joinedArgs.includes("dist/cli.js") ||
    joinedArgs.includes("src/cli.ts")
  ) {
    return true;
  }
  return false;
}

function writeFileAtomicSync(targetPath: string, content: string | Buffer): void {
  const dir = dirname(targetPath);
  mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.bla-tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    writeFileSync(tmpPath, content, { flag: "wx" });
    renameSync(tmpPath, targetPath);
  } catch (err) {
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // Ignore cleanup failure
    }
    throw err;
  }
}

export function getInstallManifestPath(home: string = homedir()): string {
  return join(home, ".bla", "install-manifest.json");
}

export function readInstallManifest(home: string = homedir()): BlaInstallManifest {
  const manifestPath = getInstallManifestPath(home);
  if (!existsSync(manifestPath)) {
    return {
      version: 1,
      updatedAt: new Date(0).toISOString(),
      clients: {},
    };
  }
  try {
    const parsed = JSON.parse(readFileSync(manifestPath, "utf8")) as Partial<BlaInstallManifest>;
    if (
      parsed &&
      parsed.version === 1 &&
      typeof parsed.clients === "object" &&
      parsed.clients !== null &&
      !Array.isArray(parsed.clients)
    ) {
      return {
        version: 1,
        updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date().toISOString(),
        clients: { ...parsed.clients } as Record<string, InstalledClientRecord>,
      };
    }
  } catch {
    // Corrupted manifest falls back to empty state
  }
  return {
    version: 1,
    updatedAt: new Date(0).toISOString(),
    clients: {},
  };
}

function writeInstallManifest(home: string, manifest: BlaInstallManifest): string {
  const manifestPath = getInstallManifestPath(home);
  const updated: BlaInstallManifest = {
    version: 1,
    updatedAt: new Date().toISOString(),
    clients: manifest.clients,
  };
  writeFileAtomicSync(manifestPath, JSON.stringify(updated, null, 2) + "\n");
  return manifestPath;
}

/** One file of the installable skill bundle (SKILL.md + references/appendices). */
export interface BundledSkillFile {
  /** POSIX path relative to the skill directory, e.g. `references/counter-rea-matrix.md`. */
  readonly relativePath: string;
  readonly content: string;
  readonly sha256: string;
}

const SKILL_ENTRY_FILE = "SKILL.md";

function resolveBundledSkillDirectory(): string | null {
  try {
    const thisDir = dirname(fileURLToPath(import.meta.url));
    const candidate = resolve(thisDir, "../../.agents/skills/blind-llm-agents");
    if (existsSync(join(candidate, SKILL_ENTRY_FILE))) return candidate;
  } catch {
    // fall through to inline fallback
  }
  return null;
}

function inlineFallbackSkill(): string {
  return [
    "---",
    "name: blind-llm-agents",
    "description: Audit, protect, and verify software artifacts (JavaScript/TypeScript, Electron ASAR, WebAssembly, Python, and Native Binaries) against AI reverse-engineering agents like REA using BLA.",
    "---",
    "",
    "# BLA: Blind LLM Agents (Counter-REA Defense Shield)",
    "",
    "Use BLA (`bla_audit`, `bla_protect`, `bla_verify`, `bla_benchmark`, `bla_emit_headers`) whenever the user wants to:",
    "1. Audit how exposed an application, bundle, ASAR, WASM, Python `.pyc`, or native binary is to AI reverse-engineering tools (`rea`).",
    "2. Protect build artifacts before release by injecting Algorithmic Tarpits, REA Semantic Budget Breakers, Electron IPC Ambiguity, Honey Source Maps, and Architectural Chaff.",
    "3. Verify defense effectiveness and calculate attacker Token & Cost Amplification.",
  ].join("\n");
}

export function resolveBundledSkillContent(): string {
  const dir = resolveBundledSkillDirectory();
  if (dir) return readFileSync(join(dir, SKILL_ENTRY_FILE), "utf8");
  return inlineFallbackSkill();
}

function collectSkillFiles(root: string, dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) collectSkillFiles(root, full, out);
    else if (entry.isFile()) out.push(relative(root, full).split(sep).join("/"));
  }
}

/**
 * Full installable skill bundle: SKILL.md first, then every supporting file
 * (references/, format appendices) so relative links in SKILL.md resolve after
 * `bla setup`. Falls back to the inline SKILL.md when the package tree is absent.
 */
export function resolveBundledSkillBundle(): readonly BundledSkillFile[] {
  const dir = resolveBundledSkillDirectory();
  if (!dir) {
    const content = inlineFallbackSkill();
    return [{ relativePath: SKILL_ENTRY_FILE, content, sha256: sha256Hex(content) }];
  }
  const rels: string[] = [];
  collectSkillFiles(dir, dir, rels);
  rels.sort((a, b) => (a === SKILL_ENTRY_FILE ? -1 : b === SKILL_ENTRY_FILE ? 1 : a.localeCompare(b)));
  return rels.map((rel) => {
    const content = readFileSync(join(dir, ...rel.split("/")), "utf8");
    return { relativePath: rel, content, sha256: sha256Hex(content) };
  });
}

export const generateBlaSkillMarkdown = resolveBundledSkillContent;

function removeOwnedSkillSupportFiles(
  skillDirectory: string,
  recorded: Readonly<Record<string, string>> | undefined,
  bundled: ReadonlyMap<string, string>,
  force: boolean,
): void {
  const rels = new Set<string>([...Object.keys(recorded ?? {}), ...bundled.keys()]);
  const touchedDirs = new Set<string>();
  for (const rel of rels) {
    const full = join(skillDirectory, ...rel.split("/"));
    if (!existsSync(full)) continue;
    const current = sha256Hex(readFileSync(full));
    if (force || current === recorded?.[rel] || current === bundled.get(rel)) {
      unlinkSync(full);
      touchedDirs.add(dirname(full));
    }
  }
  // Deepest first so nested appendix dirs collapse before their parents.
  for (const dir of [...touchedDirs].sort((a, b) => b.length - a.length)) {
    let cur = dir;
    while (cur.startsWith(skillDirectory) && cur !== skillDirectory) {
      if (!existsSync(cur) || readdirSync(cur).length > 0) break;
      rmdirSync(cur);
      cur = dirname(cur);
    }
  }
}

export function runSetup(options: SetupRunOptions = {}): SetupRunResult {
  const home = options.homeDir ?? homedir();
  const allClients = resolveSupportedAgentClients(home, options.platform, options.env);
  const discoveredClients = allClients.filter((c) => c.detected).map((c) => c.id);

  const requestedList = options.clientIds ?? options.clients;
  const explicitClients: SupportedAgentClientId[] = [];
  if (requestedList && requestedList.length > 0) {
    for (const rawId of requestedList) {
      const norm = normalizeClientId(String(rawId));
      if (norm && !explicitClients.includes(norm)) {
        explicitClients.push(norm);
      }
    }
  }

  let selected: AgentClientDefinition[];
  let selectionMode: SetupSelectionMode;
  let selectionSource: ClientSelectionSource;

  if (requestedList && requestedList.length > 0) {
    const set = new Set(explicitClients);
    selected = allClients.filter((c) => set.has(c.id));
    selectionMode = "explicit";
    selectionSource = "explicit";
  } else if (options.includeUndetected) {
    selected = [...allClients];
    selectionMode = "all-default";
    selectionSource = "default-all";
  } else {
    selected = allClients.filter((c) => c.detected);
    selectionMode = "discovered";
    selectionSource = "auto-discovered";
  }

  const mcpCommand = options.mcpCommand ?? "npx";
  // Pin the registered version to the BLA that is running setup so agent startup
  // never fetches a mutable `latest` tag from the registry (supply-chain hardening).
  const mcpArgs = options.mcpArgs ? [...options.mcpArgs] : ["-y", `${BLA_IDENTITY.packageName}@${BLA_IDENTITY.version}`, "mcp"];

  const isDryRunOrPlanOnly = options.dryRun === true || options.yes === false;
  if (isDryRunOrPlanOnly) {
    const plannedActions: PlannedSetupAction[] = selected.map((c) => ({
      clientId: c.id,
      displayName: c.displayName,
      format: c.format,
      configPath: c.configPath,
      backupPath: existsSync(c.configPath) ? `${c.configPath}.bla-backup` : null,
      skillPath: join(c.skillDirectory, "SKILL.md"),
      mcpCommand,
      mcpArgs,
      clientDetected: c.detected,
      selectionSource,
      status: "planned",
      applied: false,
    }));

    return {
      status: "planned",
      actions: plannedActions,
      results: plannedActions,
      discoveredClients,
      explicitClients,
      selectionMode,
      manifestPath: null,
      message: options.dryRun
        ? `Dry-run complete: ${plannedActions.length} agent client(s) planned. Run with --yes to apply.`
        : `Planned setup for ${plannedActions.length} agent client(s). Pass --yes to write MCP registrations and skills.`,
    };
  }

  const skillContent = resolveBundledSkillContent();
  const expectedSkillSha256 = sha256Hex(skillContent);
  const supportSkillFiles = resolveBundledSkillBundle().filter(
    (f) => f.relativePath !== SKILL_ENTRY_FILE,
  );
  const writtenSkillFiles: Record<string, string> = Object.fromEntries(
    supportSkillFiles.map((f) => [f.relativePath, f.sha256]),
  );
  const manifest = readInstallManifest(home);
  const updatedManifestClients: Record<string, InstalledClientRecord> = { ...manifest.clients };
  const completedActions: PlannedSetupAction[] = [];
  let anyApplied = false;
  let anyError = false;
  let anyConflict = false;

  for (const client of selected) {
    const adapter = getClientConfigAdapter(client.format);
    const skillPath = join(client.skillDirectory, "SKILL.md");
    const backupPathCandidate = `${client.configPath}.bla-backup`;
    const configExistedBefore = existsSync(client.configPath);
    const skillDirectoryExistedBefore = existsSync(client.skillDirectory);
    const skillExistedBefore = existsSync(skillPath);

    let existingRawContent: string | null = null;
    if (configExistedBefore) {
      try {
        existingRawContent = readFileSync(client.configPath, "utf8");
      } catch (err) {
        anyError = true;
        completedActions.push({
          clientId: client.id,
          displayName: client.displayName,
          format: client.format,
          configPath: client.configPath,
          backupPath: null,
          skillPath,
          mcpCommand,
          mcpArgs,
          clientDetected: client.detected,
          selectionSource,
          status: "error",
          applied: false,
          error: `Permission or I/O error reading '${client.configPath}': ${err instanceof Error ? err.message : String(err)}`,
        });
        continue;
      }

      const readRes = adapter.readServer(existingRawContent, BLA_IDENTITY.mcpServerName);
      if (readRes.status === "malformed") {
        anyError = true;
        completedActions.push({
          clientId: client.id,
          displayName: client.displayName,
          format: client.format,
          configPath: client.configPath,
          backupPath: null,
          skillPath,
          mcpCommand,
          mcpArgs,
          clientDetected: client.detected,
          selectionSource,
          status: "error",
          applied: false,
          error: readRes.error ?? `Malformed configuration file: '${client.configPath}'`,
        });
        continue;
      }

      if (readRes.status === "invalid_entry" && !options.force) {
        const prevManifestRecord = updatedManifestClients[client.id];
        if (!prevManifestRecord) {
          anyError = true;
          completedActions.push({
            clientId: client.id,
            displayName: client.displayName,
            format: client.format,
            configPath: client.configPath,
            backupPath: null,
            skillPath,
            mcpCommand,
            mcpArgs,
            clientDetected: client.detected,
            selectionSource,
            status: "error",
            applied: false,
            error:
              readRes.error ??
              `Invalid existing '${BLA_IDENTITY.mcpServerName}' MCP entry in '${client.configPath}'`,
          });
          continue;
        }
      }

      if (readRes.status === "valid" && readRes.entry && !options.force) {
        const prevManifestRecord = updatedManifestClients[client.id];
        const entryHash = hashMcpEntry(readRes.entry);
        const ownedByManifest = prevManifestRecord?.writtenEntryHash === entryHash;
        const ownedBySignature = isBlaOwnedMcpEntry(readRes.entry);
        const matchesRequested =
          readRes.entry.command === mcpCommand &&
          JSON.stringify(readRes.entry.args) === JSON.stringify(mcpArgs);
        if (!ownedByManifest && !ownedBySignature && !matchesRequested) {
          anyConflict = true;
          completedActions.push({
            clientId: client.id,
            displayName: client.displayName,
            format: client.format,
            configPath: client.configPath,
            backupPath: null,
            skillPath,
            mcpCommand,
            mcpArgs,
            clientDetected: client.detected,
            selectionSource,
            status: "conflict",
            applied: false,
            error: `Existing non-BLA MCP server '${BLA_IDENTITY.mcpServerName}' in '${client.configPath}'; refusing to overwrite without force`,
          });
          continue;
        }
      }
    }

    // Check skillPath ownership BEFORE writing config or skill
    if (skillExistedBefore && !options.force) {
      let existingSkillContent: Buffer;
      try {
        existingSkillContent = readFileSync(skillPath);
      } catch (err) {
        anyError = true;
        completedActions.push({
          clientId: client.id,
          displayName: client.displayName,
          format: client.format,
          configPath: client.configPath,
          backupPath: null,
          skillPath,
          mcpCommand,
          mcpArgs,
          clientDetected: client.detected,
          selectionSource,
          status: "error",
          applied: false,
          error: `Failed to read existing skill file '${skillPath}': ${err instanceof Error ? err.message : String(err)}`,
        });
        continue;
      }

      const currentSkillHash = sha256Hex(existingSkillContent);
      const ownedByAnyManifestClient = Object.values(updatedManifestClients).some(
        (rec) => rec.skillPath === skillPath && rec.writtenSkillSha256 === currentSkillHash,
      );
      if (currentSkillHash !== expectedSkillSha256 && !ownedByAnyManifestClient) {
        anyConflict = true;
        completedActions.push({
          clientId: client.id,
          displayName: client.displayName,
          format: client.format,
          configPath: client.configPath,
          backupPath: null,
          skillPath,
          mcpCommand,
          mcpArgs,
          clientDetected: client.detected,
          selectionSource,
          status: "conflict",
          applied: false,
          error: `Existing custom or user-modified SKILL.md at '${skillPath}'; refusing to overwrite without force`,
        });
        continue;
      }
    }

    // Prepare new config content via client adapter before touching disk
    const registration: McpServerRegistration = {
      command: mcpCommand,
      args: mcpArgs,
    };

    let nextConfigContent: string;
    try {
      nextConfigContent = adapter.upsertServer(
        existingRawContent,
        BLA_IDENTITY.mcpServerName,
        registration,
      );
    } catch (err) {
      anyError = true;
      completedActions.push({
        clientId: client.id,
        displayName: client.displayName,
        format: client.format,
        configPath: client.configPath,
        backupPath: null,
        skillPath,
        mcpCommand,
        mcpArgs,
        clientDetected: client.detected,
        selectionSource,
        status: "error",
        applied: false,
        error: err instanceof Error ? err.message : String(err),
      });
      continue;
    }

    // Non-clobbering backup: ONLY create `${configPath}.bla-backup` if it does not already exist!
    let recordedBackupPath: string | null = null;
    let recordedBackupSha256: string | null = null;
    let configWritten = false;
    try {
      if (configExistedBefore && existingRawContent !== null) {
        recordedBackupPath = backupPathCandidate;
        if (!existsSync(backupPathCandidate)) {
          writeFileAtomicSync(backupPathCandidate, existingRawContent);
          recordedBackupSha256 = sha256Hex(existingRawContent);
        } else {
          recordedBackupSha256 = sha256Hex(readFileSync(backupPathCandidate));
        }
      }

      writeFileAtomicSync(client.configPath, nextConfigContent);
      configWritten = true;
      writeFileAtomicSync(skillPath, skillContent);
      for (const file of supportSkillFiles) {
        writeFileAtomicSync(join(client.skillDirectory, ...file.relativePath.split("/")), file.content);
      }
    } catch (err) {
      // Roll the config back when the skill write failed after a successful
      // config write — never leave a half-installed registration (config
      // pointing at BLA with no skill file).
      if (configWritten) {
        try {
          if (configExistedBefore && existingRawContent !== null) {
            writeFileAtomicSync(client.configPath, existingRawContent);
          } else {
            unlinkSync(client.configPath);
          }
        } catch {
          // Best effort: the original failure is still reported below.
        }
      }
      anyError = true;
      completedActions.push({
        clientId: client.id,
        displayName: client.displayName,
        format: client.format,
        configPath: client.configPath,
        backupPath: recordedBackupPath,
        skillPath,
        mcpCommand,
        mcpArgs,
        clientDetected: client.detected,
        selectionSource,
        status: "error",
        applied: false,
        error: `Failed to write configuration or skill for '${client.id}': ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }

    const prevRecord = updatedManifestClients[client.id];
    updatedManifestClients[client.id] = {
      clientId: client.id,
      configPath: client.configPath,
      format: client.format,
      configExistedBefore: prevRecord ? prevRecord.configExistedBefore : configExistedBefore,
      backupPath: recordedBackupPath ?? prevRecord?.backupPath ?? null,
      backupSha256: recordedBackupSha256 ?? prevRecord?.backupSha256 ?? null,
      writtenConfigSha256: sha256Hex(nextConfigContent),
      writtenEntry: registration,
      writtenEntryHash: hashMcpEntry(registration),
      skillPath,
      skillDirectory: client.skillDirectory,
      skillExistedBefore: prevRecord ? prevRecord.skillExistedBefore : skillExistedBefore,
      skillDirectoryExistedBefore: prevRecord
        ? prevRecord.skillDirectoryExistedBefore
        : skillDirectoryExistedBefore,
      writtenSkillSha256: expectedSkillSha256,
      writtenSkillFiles,
      installedAt: new Date().toISOString(),
    };

    anyApplied = true;
    completedActions.push({
      clientId: client.id,
      displayName: client.displayName,
      format: client.format,
      configPath: client.configPath,
      backupPath: recordedBackupPath,
      skillPath,
      mcpCommand,
      mcpArgs,
      clientDetected: client.detected,
      selectionSource,
      status: "applied",
      applied: true,
    });
  }

  let manifestPath: string | null = null;
  if (anyApplied) {
    manifestPath = writeInstallManifest(home, {
      version: 1,
      updatedAt: new Date().toISOString(),
      clients: updatedManifestClients,
    });
  }

  let overallStatus: SetupRunResult["status"] = "applied";
  if (anyError || anyConflict) {
    if (anyApplied) {
      overallStatus = "partial";
    } else if (anyConflict && !anyError) {
      overallStatus = "conflict";
    } else {
      overallStatus = "error";
    }
  }

  const appliedCount = completedActions.filter((a) => a.applied).length;
  return {
    status: overallStatus,
    actions: completedActions,
    results: completedActions,
    discoveredClients,
    explicitClients,
    selectionMode,
    manifestPath,
    message:
      overallStatus === "applied"
        ? `Configured BLA MCP server and skill for ${appliedCount} agent client(s). Restart your agent to load BLA tools, then run bla_harden . (or: Harden my software against REA).`
        : `Completed setup with status '${overallStatus}' (${appliedCount}/${completedActions.length} applied).`,
  };
}

export function runUninstall(options: UninstallRunOptions = {}): UninstallRunResult {
  const home = options.homeDir ?? homedir();
  const allClients = resolveSupportedAgentClients(home, options.platform, options.env);
  const requestedList = options.clientIds ?? options.clients;

  let targetClients: readonly AgentClientDefinition[] = allClients;
  if (requestedList && requestedList.length > 0) {
    const normalizedSet = new Set<SupportedAgentClientId>();
    for (const rawId of requestedList) {
      const norm = normalizeClientId(String(rawId));
      if (norm) normalizedSet.add(norm);
    }
    targetClients = allClients.filter((c) => normalizedSet.has(c.id));
  }

  const manifest = readInstallManifest(home);
  const remainingManifestClients: Record<string, InstalledClientRecord> = { ...manifest.clients };
  const bundledSkillHash = sha256Hex(resolveBundledSkillContent());
  const bundledSupportHashes = new Map(
    resolveBundledSkillBundle()
      .filter((f) => f.relativePath !== SKILL_ENTRY_FILE)
      .map((f) => [f.relativePath, f.sha256] as const),
  );

  const removedClients: string[] = [];
  const results: ClientUninstallResult[] = [];
  const conflicts: ClientUninstallResult[] = [];

  for (const client of targetClients) {
    const adapter = getClientConfigAdapter(client.format);
    const skillPath = join(client.skillDirectory, "SKILL.md");
    const manifestRecord = remainingManifestClients[client.id];

    let mcpRemoved = false;
    let skillRemoved = false;
    let conflictReason: string | undefined;
    let errorMsg: string | undefined;

    // 1. Check and remove MCP registration if owned by BLA
    if (existsSync(client.configPath)) {
      let rawConfig: string | null = null;
      try {
        rawConfig = readFileSync(client.configPath, "utf8");
      } catch (err) {
        errorMsg = `Failed to read '${client.configPath}': ${err instanceof Error ? err.message : String(err)}`;
      }

      if (rawConfig !== null) {
        const readRes = adapter.readServer(rawConfig, BLA_IDENTITY.mcpServerName);
        if (readRes.status === "malformed") {
          conflictReason =
            readRes.error ?? `Malformed configuration at '${client.configPath}'; refusing to modify`;
        } else if (readRes.status === "invalid_entry") {
          if (manifestRecord || options.force) {
            try {
              const rem = adapter.removeServer(rawConfig, BLA_IDENTITY.mcpServerName);
              if (rem.removed) {
                writeFileAtomicSync(client.configPath, rem.content);
                mcpRemoved = true;
              }
            } catch (err) {
              errorMsg = err instanceof Error ? err.message : String(err);
            }
          } else {
            conflictReason =
              readRes.error ??
              `Invalid non-BLA entry '${BLA_IDENTITY.mcpServerName}' in '${client.configPath}'; refusing to remove`;
          }
        } else if (readRes.status === "valid" && readRes.entry) {
          const entryHash = hashMcpEntry(readRes.entry);
          const ownedByManifest = manifestRecord?.writtenEntryHash === entryHash;
          const ownedBySignature = isBlaOwnedMcpEntry(readRes.entry);
          if (!ownedByManifest && !ownedBySignature && !options.force) {
            conflictReason = `MCP entry '${BLA_IDENTITY.mcpServerName}' in '${client.configPath}' was not installed by BLA; preserving custom entry`;
          } else {
            try {
              const rem = adapter.removeServer(rawConfig, BLA_IDENTITY.mcpServerName);
              if (rem.removed) {
                writeFileAtomicSync(client.configPath, rem.content);
                mcpRemoved = true;
              }
            } catch (err) {
              errorMsg = err instanceof Error ? err.message : String(err);
            }
          }
        }
      }
    }

    // If MCP removal succeeded (or config had no conflicting BLA entry), check skill removal
    const canRemoveManifestRecord = !conflictReason && !errorMsg;
    if (canRemoveManifestRecord && manifestRecord) {
      delete remainingManifestClients[client.id];
    }

    // Check if another still-installed client in manifest (or another client not targeted in this uninstall) shares `skillPath`
    const targetIdsSet = new Set(targetClients.map((c) => c.id));
    const sharedByOtherRemainingManifestClient = Object.values(remainingManifestClients).some(
      (rec) => rec.clientId !== client.id && rec.skillPath === skillPath && !targetIdsSet.has(rec.clientId),
    );

    if (!sharedByOtherRemainingManifestClient && existsSync(skillPath)) {
      try {
        const currentSkillSha = sha256Hex(readFileSync(skillPath));
        const ownedByThisManifest =
          manifestRecord !== undefined && manifestRecord.writtenSkillSha256 === currentSkillSha;
        const ownedByAnyManifest = Object.values(manifest.clients).some(
          (rec) => rec.skillPath === skillPath && rec.writtenSkillSha256 === currentSkillSha,
        );
        const ownedByFallbackUnmodified =
          manifestRecord === undefined && mcpRemoved && currentSkillSha === bundledSkillHash;

        if (ownedByThisManifest || ownedByAnyManifest || ownedByFallbackUnmodified || options.force) {
          unlinkSync(skillPath);
          skillRemoved = true;
          // Remove supporting bundle files BLA wrote (unmodified only), then
          // prune their now-empty subdirectories.
          removeOwnedSkillSupportFiles(
            client.skillDirectory,
            manifestRecord?.writtenSkillFiles,
            bundledSupportHashes,
            options.force === true,
          );
          // Only remove `client.skillDirectory` if it is now completely empty!
          if (existsSync(client.skillDirectory)) {
            const remainingFiles = readdirSync(client.skillDirectory);
            if (remainingFiles.length === 0) {
              rmdirSync(client.skillDirectory);
            }
          }
        } else if (manifestRecord !== undefined || mcpRemoved) {
          conflictReason =
            conflictReason ??
            `Skill file '${skillPath}' was modified after installation; preserving user changes`;
        } else {
          conflictReason =
            conflictReason ??
            `Skill file '${skillPath}' is not owned by BLA; preserving custom skill`;
        }
      } catch (err) {
        errorMsg =
          errorMsg ??
          `Failed to inspect or remove skill '${skillPath}': ${err instanceof Error ? err.message : String(err)}`;
      }
    }

    if (mcpRemoved) {
      removedClients.push(client.id);
    }

    const itemStatus: ClientUninstallResult["status"] = errorMsg
      ? "error"
      : conflictReason
        ? "conflict"
        : mcpRemoved || skillRemoved
          ? "removed"
          : "noop";

    const itemResult: ClientUninstallResult = {
      clientId: client.id,
      configPath: client.configPath,
      skillPath,
      mcpRemoved,
      skillRemoved,
      status: itemStatus,
      ...(conflictReason ? { conflictReason } : {}),
      ...(errorMsg ? { error: errorMsg } : {}),
    };

    results.push(itemResult);
    if (itemStatus === "conflict" || itemStatus === "error") {
      conflicts.push(itemResult);
    }
  }

  // Persist updated manifest if it existed or has remaining records
  const manifestPath = getInstallManifestPath(home);
  if (existsSync(manifestPath) || Object.keys(remainingManifestClients).length > 0) {
    writeInstallManifest(home, {
      version: 1,
      updatedAt: new Date().toISOString(),
      clients: remainingManifestClients,
    });
  }

  return {
    removedClients,
    results,
    conflicts,
  };
}

export const uninstallSetup = runUninstall;
