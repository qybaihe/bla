import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { BLA_IDENTITY } from "../identity.js";

export type SupportedAgentClientId =
  | "claude_code"
  | "claude_desktop"
  | "cursor"
  | "codex"
  | "gemini_cli"
  | "windsurf"
  | "antigravity"
  | "vscode"
  | "opencode"
  | "copilot_cli";

export type AiClientId =
  | SupportedAgentClientId
  | "claude-code"
  | "claude-desktop"
  | "gemini-cli"
  | "copilot-cli";

export type ClientConfigFormat =
  | "json-mcpServers"
  | "json-vscode"
  | "json-opencode"
  | "toml-codex";

export interface McpServerRegistration {
  readonly command: string;
  readonly args: readonly string[];
  readonly type?: string;
  readonly enabled?: boolean;
}

export interface ConfigReadResult {
  readonly status: "valid" | "missing" | "malformed" | "invalid_entry" | "not_configured";
  readonly entry: McpServerRegistration | null;
  readonly rawEntry?: unknown;
  readonly disabled?: true;
  readonly error?: string;
  readonly otherServersCount: number;
}

export interface ClientConfigAdapter {
  readonly format: ClientConfigFormat;
  readServer(rawContent: string, serverName?: string): ConfigReadResult;
  upsertServer(
    rawContent: string | null,
    serverName: string,
    reg: McpServerRegistration,
  ): string;
  removeServer(
    rawContent: string,
    serverName: string,
  ): { readonly content: string; readonly removed: boolean };
}

export interface AgentClientDefinition {
  readonly id: SupportedAgentClientId;
  readonly displayName: string;
  readonly configPath: string;
  readonly skillDirectory: string;
  readonly detected: boolean;
  readonly format: ClientConfigFormat;
  readonly probePaths: readonly string[];
}

export interface ClientCompatibilityMatrixEntry {
  readonly clientId: SupportedAgentClientId;
  readonly displayName: string;
  readonly format: ClientConfigFormat;
  readonly rootKey: string;
  readonly configPathTemplate: string;
  readonly schemaVersion: string;
  readonly officialSpecUrl: string;
  readonly verificationMode: "automated-stdio-smoke" | "schema-and-fixture-verified";
  readonly verifiedClientVersion: string;
}

export const CLIENT_COMPATIBILITY_MATRIX: readonly ClientCompatibilityMatrixEntry[] = Object.freeze([
  {
    clientId: "claude_code",
    displayName: "Claude Code",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/.claude.json",
    schemaVersion: "claude-code-mcp-v1",
    officialSpecUrl: "https://docs.anthropic.com/en/docs/claude-code/mcp",
    verificationMode: "automated-stdio-smoke",
    verifiedClientVersion: "1.0.x (automated stdio protocol + schema fixture)",
  },
  {
    clientId: "claude_desktop",
    displayName: "Claude Desktop",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/Library/Application Support/Claude/claude_desktop_config.json",
    schemaVersion: "claude-desktop-mcp-v1",
    officialSpecUrl: "https://modelcontextprotocol.io/quickstart/user",
    verificationMode: "schema-and-fixture-verified",
    verifiedClientVersion: "0.9.x (GUI client — schema fixture verified, runtime unverified in headless CI)",
  },
  {
    clientId: "cursor",
    displayName: "Cursor",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/.cursor/mcp.json",
    schemaVersion: "cursor-mcp-v1",
    officialSpecUrl: "https://docs.cursor.com/context/model-context-protocol",
    verificationMode: "schema-and-fixture-verified",
    verifiedClientVersion: "0.48.x (GUI client — schema fixture verified, runtime unverified in headless CI)",
  },
  {
    clientId: "codex",
    displayName: "Codex CLI",
    format: "toml-codex",
    rootKey: "mcp_servers",
    configPathTemplate: "~/.codex/config.toml",
    schemaVersion: "codex-config-toml-v1",
    officialSpecUrl: "https://developers.openai.com/codex/mcp/",
    verificationMode: "automated-stdio-smoke",
    verifiedClientVersion: "0.1.x (TOML [mcp_servers.bla] spec + automated stdio smoke)",
  },
  {
    clientId: "gemini_cli",
    displayName: "Gemini CLI",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/.gemini/settings.json",
    schemaVersion: "gemini-cli-settings-v1",
    officialSpecUrl: "https://github.com/google-gemini/gemini-cli",
    verificationMode: "automated-stdio-smoke",
    verifiedClientVersion: "0.1.x (settings.json mcpServers + automated stdio smoke)",
  },
  {
    clientId: "antigravity",
    displayName: "Google Antigravity",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/.gemini/antigravity/mcp_config.json",
    schemaVersion: "antigravity-mcp-v1",
    officialSpecUrl: "https://idx.dev",
    verificationMode: "schema-and-fixture-verified",
    verifiedClientVersion: "2.0.x (mcpServers schema fixture verified)",
  },
  {
    clientId: "windsurf",
    displayName: "Windsurf",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/.codeium/windsurf/mcp_config.json",
    schemaVersion: "windsurf-mcp-v1",
    officialSpecUrl: "https://docs.windsurf.com/windsurf/mcp",
    verificationMode: "schema-and-fixture-verified",
    verifiedClientVersion: "1.6.x (GUI client — schema fixture verified, runtime unverified in headless CI)",
  },
  {
    clientId: "vscode",
    displayName: "VS Code",
    format: "json-vscode",
    rootKey: "servers",
    configPathTemplate: "<UserConfig>/Code/User/mcp.json",
    schemaVersion: "vscode-mcp-servers-v1",
    officialSpecUrl: "https://code.visualstudio.com/docs/agent-customization/mcp-servers",
    verificationMode: "schema-and-fixture-verified",
    verifiedClientVersion: "1.99+ (user-profile mcp.json 'servers' schema fixture verified; GUI runtime unverified in CI)",
  },
  {
    clientId: "opencode",
    displayName: "OpenCode",
    format: "json-opencode",
    rootKey: "mcp",
    configPathTemplate: "~/.config/opencode/opencode.json",
    schemaVersion: "opencode-mcp-local-v1",
    officialSpecUrl: "https://opencode.ai/docs/mcp-servers/",
    verificationMode: "automated-stdio-smoke",
    verifiedClientVersion: "0.1.x (opencode.json mcp.bla local command array + automated stdio smoke)",
  },
  {
    clientId: "copilot_cli",
    displayName: "GitHub Copilot CLI",
    format: "json-mcpServers",
    rootKey: "mcpServers",
    configPathTemplate: "~/.copilot/mcp-config.json",
    schemaVersion: "copilot-cli-mcp-v1",
    officialSpecUrl: "https://docs.github.com/en/copilot",
    verificationMode: "schema-and-fixture-verified",
    verifiedClientVersion: "1.0.x (mcpServers schema fixture verified)",
  },
]);

const CLIENT_ID_ALIASES: Readonly<Record<string, SupportedAgentClientId>> = Object.freeze({
  claude_code: "claude_code",
  "claude-code": "claude_code",
  claude_desktop: "claude_desktop",
  "claude-desktop": "claude_desktop",
  cursor: "cursor",
  codex: "codex",
  gemini_cli: "gemini_cli",
  "gemini-cli": "gemini_cli",
  windsurf: "windsurf",
  antigravity: "antigravity",
  vscode: "vscode",
  "vs-code": "vscode",
  opencode: "opencode",
  copilot_cli: "copilot_cli",
  "copilot-cli": "copilot_cli",
});

export function normalizeClientId(id: string): SupportedAgentClientId | null {
  return CLIENT_ID_ALIASES[id.trim().toLowerCase()] ?? null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Strip inline `#` comments outside quoted strings on a single TOML line.
 */
function stripTomlInlineComment(line: string): {
  readonly code: string;
  readonly unclosedQuote: boolean;
} {
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (inDouble) {
      if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }
    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      }
      continue;
    }
    if (ch === '"') {
      inDouble = true;
    } else if (ch === "'") {
      inSingle = true;
    } else if (ch === "#") {
      return { code: line.slice(0, i).trim(), unclosedQuote: false };
    }
  }
  return { code: line.trim(), unclosedQuote: inDouble || inSingle };
}

function parseTomlStringLiteral(raw: string): { readonly ok: true; readonly value: string } | { readonly ok: false } {
  const trimmed = raw.trim();
  if (trimmed.length < 2) return { ok: false };
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (typeof parsed === "string") {
        return { ok: true, value: parsed };
      }
    } catch {
      return { ok: false };
    }
    return { ok: false };
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    const inner = trimmed.slice(1, -1);
    if (inner.includes("'")) return { ok: false };
    return { ok: true, value: inner };
  }
  return { ok: false };
}

function parseTomlStringArray(raw: string): { readonly ok: true; readonly values: string[] } | { readonly ok: false } {
  const trimmed = raw.trim();
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) {
    return { ok: false };
  }
  const inner = trimmed.slice(1, -1).trim();
  if (inner.length === 0) {
    return { ok: true, values: [] };
  }

  const items: string[] = [];
  let current = "";
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  let depth = 0;

  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (inDouble) {
      current += ch;
      if (ch === "\\") escaped = true;
      else if (ch === '"') inDouble = false;
      continue;
    }
    if (inSingle) {
      current += ch;
      if (ch === "'") inSingle = false;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
    } else if (ch === "'") {
      inSingle = true;
      current += ch;
    } else if (ch === "[") {
      depth++;
      current += ch;
    } else if (ch === "]") {
      depth--;
      if (depth < 0) return { ok: false };
      current += ch;
    } else if (ch === "," && depth === 0) {
      const parsedItem = parseTomlStringLiteral(current);
      if (!parsedItem.ok) return { ok: false };
      items.push(parsedItem.value);
      current = "";
    } else {
      current += ch;
    }
  }

  if (inDouble || inSingle || depth !== 0) {
    return { ok: false };
  }

  if (current.trim().length > 0) {
    const parsedItem = parseTomlStringLiteral(current);
    if (!parsedItem.ok) return { ok: false };
    items.push(parsedItem.value);
  }

  return { ok: true, values: items };
}

/** Normalize bare and quoted TOML keys while retaining literal dots inside a segment. */
function normalizeTomlKey(key: string): string {
  const segment = /"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+/;
  const segments = key.match(new RegExp(segment.source, "g"));
  if (!segments || !new RegExp(`^(?:${segment.source})(?:\\s*\\.\\s*(?:${segment.source}))*$`).test(key)) {
    return key;
  }
  return segments.map((segment) => {
    const parsed = parseTomlStringLiteral(segment);
    const value = parsed.ok ? parsed.value : segment;
    return /^[A-Za-z0-9_-]+$/.test(value) ? value : JSON.stringify(value);
  }).join(".");
}

interface ParsedTomlSectionRange {
  readonly name: string;
  readonly headerLineIndex: number;
  readonly endLineIndex: number;
  readonly assignments: ReadonlyMap<string, string>;
}

function inspectCodexTomlDocument(
  rawToml: string,
):
  | {
      readonly ok: true;
      readonly lines: readonly string[];
      readonly sections: readonly ParsedTomlSectionRange[];
      readonly topLevelAssignments: ReadonlyMap<string, string>;
    }
  | {
      readonly ok: false;
      readonly error: string;
    } {
  const lines = rawToml.split(/\r?\n/);
  const sections: {
    name: string;
    headerLineIndex: number;
    endLineIndex: number;
    assignments: Map<string, string>;
  }[] = [];
  const topLevelAssignments = new Map<string, string>();
  let currentSection: {
    name: string;
    headerLineIndex: number;
    endLineIndex: number;
    assignments: Map<string, string>;
  } | null = null;

  let pendingKey: string | null = null;
  let pendingArrayBuffer = "";
  let bracketBalance = 0;
  let pendingMultilineQuote: '"""' | "'''" | null = null;
  let pendingMultilineKey: string | null = null;
  let pendingMultilineBuffer = "";

  const findClosingTripleQuote = (text: string, quote: '"""' | "'''"): number => {
    if (quote === "'''") {
      return text.indexOf("'''");
    }
    let escaped = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (text.startsWith('"""', i)) {
        return i;
      }
    }
    return -1;
  };

  const countArrayBracketsOutsideQuotes = (code: string): { delta: number; valid: boolean } => {
    let delta = 0;
    let inDouble = false;
    let inSingle = false;
    let escaped = false;
    for (let i = 0; i < code.length; i++) {
      const ch = code[i]!;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (inDouble) {
        if (ch === "\\") escaped = true;
        else if (ch === '"') inDouble = false;
        continue;
      }
      if (inSingle) {
        if (ch === "'") inSingle = false;
        continue;
      }
      if (ch === '"') inDouble = true;
      else if (ch === "'") inSingle = true;
      else if (ch === "[") delta++;
      else if (ch === "]") delta--;
    }
    return { delta, valid: !inDouble && !inSingle };
  };

  for (let idx = 0; idx < lines.length; idx++) {
    const rawLine = lines[idx]!;
    if (pendingMultilineQuote !== null && pendingMultilineKey !== null) {
      const closePos = findClosingTripleQuote(rawLine, pendingMultilineQuote);
      if (closePos < 0) {
        pendingMultilineBuffer += "\n" + rawLine;
        continue;
      }
      const afterClose = stripTomlInlineComment(rawLine.slice(closePos + 3));
      if (afterClose.unclosedQuote || afterClose.code.length > 0) {
        return {
          ok: false,
          error: `Malformed TOML multiline string trailing content at line ${idx + 1}`,
        };
      }
      pendingMultilineBuffer += "\n" + rawLine.slice(0, closePos + 3);
      const targetMap = currentSection ? currentSection.assignments : topLevelAssignments;
      targetMap.set(pendingMultilineKey, pendingMultilineBuffer);
      pendingMultilineQuote = null;
      pendingMultilineKey = null;
      pendingMultilineBuffer = "";
      continue;
    }

    // Check for TOML triple-quoted string assignments (`key = """...` or `key = '''...`)
    if (pendingKey === null && !rawLine.trimStart().startsWith("#") && !rawLine.trimStart().startsWith("[")) {
      const eqPos = rawLine.indexOf("=");
      if (eqPos > 0) {
        const candidateKey = rawLine.slice(0, eqPos).trim();
        const rhsTrimmed = rawLine.slice(eqPos + 1).trimStart();
        const tripleQuote: '"""' | "'''" | null = rhsTrimmed.startsWith('"""')
          ? '"""'
          : rhsTrimmed.startsWith("'''")
            ? "'''"
            : null;
        if (
          tripleQuote !== null &&
          (/^[A-Za-z0-9_.-]+$/.test(candidateKey) ||
            (candidateKey.startsWith('"') && candidateKey.endsWith('"')))
        ) {
          const afterOpen = rhsTrimmed.slice(3);
          const closePos = findClosingTripleQuote(afterOpen, tripleQuote);
          if (closePos >= 0) {
            const afterClose = stripTomlInlineComment(afterOpen.slice(closePos + 3));
            if (afterClose.unclosedQuote || afterClose.code.length > 0) {
              return {
                ok: false,
                error: `Malformed TOML triple-quoted string at line ${idx + 1}`,
              };
            }
            const targetMap = currentSection ? currentSection.assignments : topLevelAssignments;
            targetMap.set(candidateKey, rhsTrimmed.slice(0, 3 + closePos + 3));
            continue;
          }
          pendingMultilineQuote = tripleQuote;
          pendingMultilineKey = candidateKey;
          pendingMultilineBuffer = rhsTrimmed;
          continue;
        }
      }
    }

    const stripped = stripTomlInlineComment(rawLine);
    if (stripped.unclosedQuote) {
      return { ok: false, error: `Malformed TOML at line ${idx + 1}: unclosed string quote` };
    }
    const code = stripped.code;
    if (code.length === 0) continue;

    if (pendingKey !== null) {
      const bracketCheck = countArrayBracketsOutsideQuotes(code);
      if (!bracketCheck.valid) {
        return { ok: false, error: `Malformed TOML array at line ${idx + 1}` };
      }
      pendingArrayBuffer += " " + code;
      bracketBalance += bracketCheck.delta;
      if (bracketBalance < 0) {
        return { ok: false, error: `Malformed TOML at line ${idx + 1}: unexpected closing bracket` };
      }
      if (bracketBalance === 0) {
        const targetMap = currentSection ? currentSection.assignments : topLevelAssignments;
        targetMap.set(pendingKey, pendingArrayBuffer.trim());
        pendingKey = null;
        pendingArrayBuffer = "";
      }
      continue;
    }

    if (code.startsWith("[")) {
      if (!code.endsWith("]")) {
        return { ok: false, error: `Malformed TOML table header at line ${idx + 1}: '${code}'` };
      }
      const isArrayOfTables = code.startsWith("[[") && code.endsWith("]]");
      const tableName = (isArrayOfTables ? code.slice(2, -2) : code.slice(1, -1)).trim();
      if (tableName.length === 0 || tableName.includes("[") || tableName.includes("]")) {
        return { ok: false, error: `Invalid TOML table header at line ${idx + 1}: '${code}'` };
      }
      if (currentSection) {
        currentSection.endLineIndex = idx;
      }
      currentSection = {
        name: normalizeTomlKey(tableName),
        headerLineIndex: idx,
        endLineIndex: lines.length,
        assignments: new Map<string, string>(),
      };
      sections.push(currentSection);
      continue;
    }

    const eqIdx = code.indexOf("=");
    if (eqIdx <= 0) {
      return { ok: false, error: `Malformed TOML statement at line ${idx + 1}: '${code}'` };
    }

    const key = code.slice(0, eqIdx).trim();
    const val = code.slice(eqIdx + 1).trim();
    if (!/^[A-Za-z0-9_.-]+$/.test(key) && !(key.startsWith('"') && key.endsWith('"'))) {
      return { ok: false, error: `Invalid TOML key '${key}' at line ${idx + 1}` };
    }
    if (val.length === 0) {
      return { ok: false, error: `Empty TOML value for key '${key}' at line ${idx + 1}` };
    }

    if (val.startsWith("[")) {
      const bracketCheck = countArrayBracketsOutsideQuotes(val);
      if (!bracketCheck.valid || bracketCheck.delta < 0) {
        return { ok: false, error: `Malformed TOML array for key '${key}' at line ${idx + 1}` };
      }
      if (bracketCheck.delta > 0) {
        pendingKey = key;
        pendingArrayBuffer = val;
        bracketBalance = bracketCheck.delta;
        continue;
      }
    } else if (val.startsWith("{")) {
      if (!val.endsWith("}")) {
        return { ok: false, error: `Unclosed TOML inline table for key '${key}' at line ${idx + 1}` };
      }
    } else if (val.startsWith('"') || val.startsWith("'")) {
      const parsedStr = parseTomlStringLiteral(val);
      if (!parsedStr.ok) {
        return { ok: false, error: `Invalid TOML string literal for key '${key}' at line ${idx + 1}` };
      }
    } else if (
      val !== "true" &&
      val !== "false" &&
      !/^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(val) &&
      !/^\d{4}-\d{2}-\d{2}/.test(val)
    ) {
      return { ok: false, error: `Invalid TOML literal '${val}' for key '${key}' at line ${idx + 1}` };
    }

    const targetMap = currentSection ? currentSection.assignments : topLevelAssignments;
    targetMap.set(key, val);
  }

  if (pendingMultilineQuote !== null) {
    return {
      ok: false,
      error: `Malformed TOML: unclosed multiline string for key '${pendingMultilineKey}'`,
    };
  }
  if (pendingKey !== null || bracketBalance !== 0) {
    return { ok: false, error: `Malformed TOML: unclosed multiline array for key '${pendingKey}'` };
  }

  // Schema check: top-level `mcp_servers` cannot be a scalar or array
  const topLevelMcpServers = tomlAssignment(topLevelAssignments, "mcp_servers");
  if (topLevelMcpServers !== undefined && !topLevelMcpServers.startsWith("{")) {
    return {
      ok: false,
      error: "Invalid Codex config.toml schema: 'mcp_servers' must be a table, not a scalar or array",
    };
  }

  return {
    ok: true,
    lines,
    sections,
    topLevelAssignments,
  };
}

function tomlAssignment(assignments: ReadonlyMap<string, string>, key: string): string | undefined {
  for (const [name, value] of assignments) {
    if (normalizeTomlKey(name) === key) return value;
  }
  return undefined;
}

function codexUnsupportedMcpRepresentation(
  document: Extract<ReturnType<typeof inspectCodexTomlDocument>, { ok: true }>,
  serverName: string,
): string | undefined {
  if (tomlAssignment(document.topLevelAssignments, "mcp_servers") !== undefined) {
    return "Codex mcp_servers uses an inline table. Convert it to [mcp_servers.<name>] sections before editing with BLA.";
  }
  const target = `mcp_servers.${serverName}`;
  const parent = document.sections.find((section) => section.name === "mcp_servers");
  const definesTarget = (key: string, name: string) => key === name || key.startsWith(`${name}.`);
  if (
    [...document.topLevelAssignments.keys()].some((key) => definesTarget(normalizeTomlKey(key), target)) ||
    (parent && [...parent.assignments.keys()].some((key) => definesTarget(normalizeTomlKey(key), serverName)))
  ) {
    return `Codex ${target} uses an inline or dotted assignment. Convert it to a [${target}] section before editing with BLA.`;
  }
  return undefined;
}

export function readCodexTomlMcp(
  rawToml: string,
  serverName: string = BLA_IDENTITY.mcpServerName,
): ConfigReadResult {
  const inspected = inspectCodexTomlDocument(rawToml);
  if (!inspected.ok) {
    return {
      status: "malformed",
      entry: null,
      error: inspected.error,
      otherServersCount: 0,
    };
  }

  const unsupported = codexUnsupportedMcpRepresentation(inspected, serverName);
  if (unsupported) {
    return { status: "malformed", entry: null, error: unsupported, otherServersCount: 0 };
  }

  const targetTable = `mcp_servers.${serverName}`;
  let otherServersCount = 0;
  let targetSection: ParsedTomlSectionRange | undefined;

  for (const sec of inspected.sections) {
    if (sec.name === targetTable) {
      targetSection = sec;
    } else if (sec.name.startsWith("mcp_servers.")) {
      const remainder = sec.name.slice("mcp_servers.".length);
      if (remainder.length > 0 && !remainder.includes(".")) {
        otherServersCount++;
      }
    }
  }

  if (!targetSection) {
    if (inspected.sections.some((section) => section.name.startsWith(`${targetTable}.`))) {
      return { status: "invalid_entry", entry: null, error: `Codex [${targetTable}] has subtables but no command`, otherServersCount };
    }
    return {
      status: "not_configured",
      entry: null,
      otherServersCount,
    };
  }

  const rawCommand = tomlAssignment(targetSection.assignments, "command");
  if (rawCommand === undefined) {
    return {
      status: "invalid_entry",
      entry: null,
      error: `Codex [${targetTable}] is missing required 'command' string`,
      otherServersCount,
    };
  }

  const parsedCommand = parseTomlStringLiteral(rawCommand);
  if (!parsedCommand.ok || parsedCommand.value.trim().length === 0) {
    return {
      status: "invalid_entry",
      entry: null,
      error: `Codex [${targetTable}].command must be a non-empty string`,
      otherServersCount,
    };
  }

  let parsedArgs: string[] = [];
  const rawArgs = tomlAssignment(targetSection.assignments, "args");
  if (rawArgs !== undefined) {
    const arrRes = parseTomlStringArray(rawArgs);
    if (!arrRes.ok) {
      return {
        status: "invalid_entry",
        entry: null,
        error: `Codex [${targetTable}].args must be an array of strings`,
        otherServersCount,
      };
    }
    parsedArgs = arrRes.values;
  }

  if (tomlAssignment(targetSection.assignments, "enabled") === "false" ||
      tomlAssignment(targetSection.assignments, "disabled") === "true") {
    return {
      status: "invalid_entry",
      entry: null,
      disabled: true,
      error: `Codex [${targetTable}] is explicitly disabled`,
      otherServersCount,
    };
  }

  return {
    status: "valid",
    entry: {
      command: parsedCommand.value,
      args: parsedArgs,
    },
    rawEntry: Object.fromEntries(targetSection.assignments.entries()),
    otherServersCount,
  };
}

export function writeCodexTomlMcp(
  rawToml: string | null,
  serverName: string,
  reg: McpServerRegistration,
): string {
  const existing = rawToml ?? "";
  if (existing.trim().length > 0) {
    const inspected = inspectCodexTomlDocument(existing);
    if (!inspected.ok) {
      throw new Error(inspected.error);
    }
    const unsupported = codexUnsupportedMcpRepresentation(inspected, serverName);
    if (unsupported) throw new Error(unsupported);

    const targetTable = `mcp_servers.${serverName}`;
    const existingSection = inspected.sections.find((s) => s.name === targetTable);
    const preservedAssignments: string[] = [];
    if (existingSection) {
      for (const [k, v] of existingSection.assignments.entries()) {
        if (!["command", "args"].includes(normalizeTomlKey(k))) {
          preservedAssignments.push(`${k} = ${v}`);
        }
      }
    }

    const formattedSectionLines = [
      `[${targetTable}]`,
      `command = ${JSON.stringify(reg.command)}`,
      `args = [${reg.args.map((a) => JSON.stringify(a)).join(", ")}]`,
      ...preservedAssignments,
    ];

    if (existingSection) {
      // Preserve trailing comments before the next section header
      let replaceEnd = existingSection.endLineIndex;
      while (
        replaceEnd > existingSection.headerLineIndex + 1 &&
        (inspected.lines[replaceEnd - 1]!.trim() === "" ||
          inspected.lines[replaceEnd - 1]!.trim().startsWith("#"))
      ) {
        if (inspected.lines[replaceEnd - 1]!.trim().startsWith("#")) {
          break;
        }
        replaceEnd--;
      }
      const before = inspected.lines.slice(0, existingSection.headerLineIndex);
      const after = inspected.lines.slice(replaceEnd);
      const combined = [...before, ...formattedSectionLines, ...(after.length > 0 ? ["", ...after] : [])];
      return combined.join("\n").trimEnd() + "\n";
    }

    const trimmedExisting = existing.trimEnd();
    return `${trimmedExisting}\n\n${formattedSectionLines.join("\n")}\n`;
  }

  return [
    `[mcp_servers.${serverName}]`,
    `command = ${JSON.stringify(reg.command)}`,
    `args = [${reg.args.map((a) => JSON.stringify(a)).join(", ")}]`,
    "",
  ].join("\n");
}

export function removeCodexTomlMcp(
  rawToml: string,
  serverName: string = BLA_IDENTITY.mcpServerName,
): { readonly content: string; readonly removed: boolean } {
  const inspected = inspectCodexTomlDocument(rawToml);
  if (!inspected.ok) {
    throw new Error(inspected.error);
  }
  const unsupported = codexUnsupportedMcpRepresentation(inspected, serverName);
  if (unsupported) throw new Error(unsupported);
  const targetTable = `mcp_servers.${serverName}`;
  const sections = inspected.sections.filter(
    (section) => section.name === targetTable || section.name.startsWith(`${targetTable}.`),
  );
  if (sections.length === 0) return { content: rawToml, removed: false };

  const lines: string[] = [];
  let start = 0;
  for (const section of sections) {
    lines.push(...inspected.lines.slice(start, section.headerLineIndex));
    start = section.endLineIndex;
  }
  lines.push(...inspected.lines.slice(start));
  const joined = lines.join("\n").trimEnd();
  return {
    content: joined.length > 0 ? `${joined}\n` : "",
    removed: true,
  };
}

/**
 * Parses standard JSON or JSONC (`//` line comments, `/* ... *\/` block comments,
 * and trailing commas immediately before `}` or `]`), while preserving strict
 * rejection of unclosed braces, unclosed quotes, and invalid tokens.
 */
function parseJsonOrJsonc(rawContent: string): unknown {
  try {
    return JSON.parse(rawContent);
  } catch {
    // Fall through to JSONC comment + trailing-comma normalization
  }

  let noComments = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < rawContent.length; i++) {
    const ch = rawContent[i]!;
    if (inString) {
      noComments += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      noComments += ch;
      continue;
    }
    if (ch === "/" && rawContent[i + 1] === "/") {
      i += 2;
      while (i < rawContent.length && rawContent[i] !== "\n") i++;
      if (i < rawContent.length) noComments += "\n";
      continue;
    }
    if (ch === "/" && rawContent[i + 1] === "*") {
      const end = rawContent.indexOf("*/", i + 2);
      if (end < 0) {
        throw new SyntaxError("Unclosed JSONC block comment");
      }
      for (let j = i; j < end + 2; j++) {
        noComments += rawContent[j] === "\n" ? "\n" : " ";
      }
      i = end + 1;
      continue;
    }
    noComments += ch;
  }

  let cleaned = "";
  inString = false;
  escaped = false;
  for (let i = 0; i < noComments.length; i++) {
    const ch = noComments[i]!;
    if (inString) {
      cleaned += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      cleaned += ch;
      continue;
    }
    if (ch === ",") {
      let look = i + 1;
      while (look < noComments.length && /\s/.test(noComments[look]!)) {
        look++;
      }
      const nextCh = noComments[look];
      if (nextCh === "}" || nextCh === "]") {
        continue;
      }
    }
    cleaned += ch;
  }

  return JSON.parse(cleaned);
}

function createJsonMcpServersAdapter(): ClientConfigAdapter {
  return {
    format: "json-mcpServers",
    readServer(rawContent: string, serverName: string = BLA_IDENTITY.mcpServerName): ConfigReadResult {
      let parsed: unknown;
      try {
        parsed = parseJsonOrJsonc(rawContent);
      } catch (err) {
        return {
          status: "malformed",
          entry: null,
          error: `Malformed JSON configuration: ${err instanceof Error ? err.message : String(err)}`,
          otherServersCount: 0,
        };
      }
      if (!isPlainObject(parsed)) {
        return {
          status: "malformed",
          entry: null,
          error: "Invalid configuration schema: root value must be a JSON object",
          otherServersCount: 0,
        };
      }
      if (parsed.mcpServers === undefined) {
        return {
          status: "not_configured",
          entry: null,
          otherServersCount: 0,
        };
      }
      if (!isPlainObject(parsed.mcpServers)) {
        return {
          status: "malformed",
          entry: null,
          error: "Invalid configuration schema: 'mcpServers' must be a JSON object",
          otherServersCount: 0,
        };
      }
      const servers = parsed.mcpServers;
      const otherServersCount = Object.keys(servers).filter((k) => k !== serverName).length;
      if (!(serverName in servers)) {
        return {
          status: "not_configured",
          entry: null,
          otherServersCount,
        };
      }
      const rawEntry = servers[serverName];
      if (!isPlainObject(rawEntry)) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid MCP server entry '${serverName}': must be a JSON object`,
          otherServersCount,
        };
      }
      if (typeof rawEntry.command !== "string" || rawEntry.command.trim().length === 0) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid MCP server entry '${serverName}': 'command' must be a non-empty string`,
          otherServersCount,
        };
      }
      let args: string[] = [];
      if (rawEntry.args !== undefined) {
        if (!Array.isArray(rawEntry.args) || !rawEntry.args.every((a) => typeof a === "string")) {
          return {
            status: "invalid_entry",
            entry: null,
            rawEntry,
            error: `Invalid MCP server entry '${serverName}': 'args' must be an array of strings`,
            otherServersCount,
          };
        }
        args = [...rawEntry.args];
      }
      if (rawEntry.disabled === true || rawEntry.enabled === false) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          disabled: true,
          error: `MCP server entry '${serverName}' is disabled`,
          otherServersCount,
        };
      }
      return {
        status: "valid",
        entry: {
          command: rawEntry.command,
          args,
        },
        rawEntry,
        otherServersCount,
      };
    },
    upsertServer(rawContent: string | null, serverName: string, reg: McpServerRegistration): string {
      let root: Record<string, unknown> = {};
      if (rawContent !== null && rawContent.trim().length > 0) {
        let parsed: unknown;
        try {
          parsed = parseJsonOrJsonc(rawContent);
        } catch (err) {
          throw new Error(
            `Malformed JSON configuration: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        if (!isPlainObject(parsed)) {
          throw new Error("Invalid configuration schema: root value must be a JSON object");
        }
        if (parsed.mcpServers !== undefined && !isPlainObject(parsed.mcpServers)) {
          throw new Error("Invalid configuration schema: 'mcpServers' must be a JSON object");
        }
        root = { ...parsed };
      }
      const existingServers = isPlainObject(root.mcpServers) ? { ...root.mcpServers } : {};
      const prevEntry = isPlainObject(existingServers[serverName])
        ? { ...existingServers[serverName] }
        : {};
      existingServers[serverName] = {
        ...prevEntry,
        command: reg.command,
        args: [...reg.args],
      };
      root.mcpServers = existingServers;
      return JSON.stringify(root, null, 2) + "\n";
    },
    removeServer(rawContent: string, serverName: string): { readonly content: string; readonly removed: boolean } {
      let parsed: unknown;
      try {
        parsed = parseJsonOrJsonc(rawContent);
      } catch (err) {
        throw new Error(
          `Malformed JSON configuration: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (!isPlainObject(parsed)) {
        throw new Error("Invalid configuration schema: root value must be a JSON object");
      }
      if (parsed.mcpServers !== undefined && !isPlainObject(parsed.mcpServers)) {
        throw new Error("Invalid configuration schema: 'mcpServers' must be a JSON object");
      }
      if (!isPlainObject(parsed.mcpServers) || !(serverName in parsed.mcpServers)) {
        return { content: rawContent, removed: false };
      }
      const nextServers = { ...parsed.mcpServers };
      delete nextServers[serverName];
      const nextRoot: Record<string, unknown> = { ...parsed, mcpServers: nextServers };
      return {
        content: JSON.stringify(nextRoot, null, 2) + "\n",
        removed: true,
      };
    },
  };
}

function createJsonVscodeAdapter(): ClientConfigAdapter {
  return {
    format: "json-vscode",
    readServer(rawContent: string, serverName: string = BLA_IDENTITY.mcpServerName): ConfigReadResult {
      let parsed: unknown;
      try {
        parsed = parseJsonOrJsonc(rawContent);
      } catch (err) {
        return {
          status: "malformed",
          entry: null,
          error: `Malformed VS Code mcp.json: ${err instanceof Error ? err.message : String(err)}`,
          otherServersCount: 0,
        };
      }
      if (!isPlainObject(parsed)) {
        return {
          status: "malformed",
          entry: null,
          error: "Invalid VS Code mcp.json schema: root value must be a JSON object",
          otherServersCount: 0,
        };
      }
      if (parsed.servers === undefined) {
        if ("mcpServers" in parsed) {
          return {
            status: "malformed",
            entry: null,
            error: "Invalid VS Code user-profile mcp.json schema: expected root key 'servers', found 'mcpServers'",
            otherServersCount: 0,
          };
        }
        return {
          status: "not_configured",
          entry: null,
          otherServersCount: 0,
        };
      }
      if (!isPlainObject(parsed.servers)) {
        return {
          status: "malformed",
          entry: null,
          error: "Invalid VS Code mcp.json schema: 'servers' must be a JSON object",
          otherServersCount: 0,
        };
      }
      const servers = parsed.servers;
      const otherServersCount = Object.keys(servers).filter((k) => k !== serverName).length;
      if (!(serverName in servers)) {
        return {
          status: "not_configured",
          entry: null,
          otherServersCount,
        };
      }
      const rawEntry = servers[serverName];
      if (!isPlainObject(rawEntry)) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid VS Code MCP server entry '${serverName}': must be a JSON object`,
          otherServersCount,
        };
      }
      if (rawEntry.type !== undefined && rawEntry.type !== "stdio") {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid VS Code MCP server entry '${serverName}': 'type' must be 'stdio'`,
          otherServersCount,
        };
      }
      if (typeof rawEntry.command !== "string" || rawEntry.command.trim().length === 0) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid VS Code MCP server entry '${serverName}': 'command' must be a non-empty string`,
          otherServersCount,
        };
      }
      let args: string[] = [];
      if (rawEntry.args !== undefined) {
        if (!Array.isArray(rawEntry.args) || !rawEntry.args.every((a) => typeof a === "string")) {
          return {
            status: "invalid_entry",
            entry: null,
            rawEntry,
            error: `Invalid VS Code MCP server entry '${serverName}': 'args' must be an array of strings`,
            otherServersCount,
          };
        }
        args = [...rawEntry.args];
      }
      if (rawEntry.enabled === false || rawEntry.disabled === true) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          disabled: true,
          error: `VS Code MCP entry '${serverName}' is disabled`,
          otherServersCount,
        };
      }
      return {
        status: "valid",
        entry: {
          type: "stdio",
          command: rawEntry.command,
          args,
        },
        rawEntry,
        otherServersCount,
      };
    },
    upsertServer(rawContent: string | null, serverName: string, reg: McpServerRegistration): string {
      let root: Record<string, unknown> = {};
      if (rawContent !== null && rawContent.trim().length > 0) {
        let parsed: unknown;
        try {
          parsed = parseJsonOrJsonc(rawContent);
        } catch (err) {
          throw new Error(
            `Malformed VS Code mcp.json: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        if (!isPlainObject(parsed)) {
          throw new Error("Invalid VS Code mcp.json schema: root value must be a JSON object");
        }
        if (parsed.servers !== undefined && !isPlainObject(parsed.servers)) {
          throw new Error("Invalid VS Code mcp.json schema: 'servers' must be a JSON object");
        }
        root = { ...parsed };
      }
      const existingServers = isPlainObject(root.servers) ? { ...root.servers } : {};
      const prevEntry = isPlainObject(existingServers[serverName])
        ? { ...existingServers[serverName] }
        : {};
      existingServers[serverName] = {
        ...prevEntry,
        type: "stdio",
        command: reg.command,
        args: [...reg.args],
      };
      root.servers = existingServers;
      return JSON.stringify(root, null, 2) + "\n";
    },
    removeServer(rawContent: string, serverName: string): { readonly content: string; readonly removed: boolean } {
      let parsed: unknown;
      try {
        parsed = parseJsonOrJsonc(rawContent);
      } catch (err) {
        throw new Error(
          `Malformed VS Code mcp.json: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (!isPlainObject(parsed)) {
        throw new Error("Invalid VS Code mcp.json schema: root value must be a JSON object");
      }
      if (parsed.servers !== undefined && !isPlainObject(parsed.servers)) {
        throw new Error("Invalid VS Code mcp.json schema: 'servers' must be a JSON object");
      }
      if (!isPlainObject(parsed.servers) || !(serverName in parsed.servers)) {
        return { content: rawContent, removed: false };
      }
      const nextServers = { ...parsed.servers };
      delete nextServers[serverName];
      const nextRoot: Record<string, unknown> = { ...parsed, servers: nextServers };
      return {
        content: JSON.stringify(nextRoot, null, 2) + "\n",
        removed: true,
      };
    },
  };
}

function createJsonOpencodeAdapter(): ClientConfigAdapter {
  return {
    format: "json-opencode",
    readServer(rawContent: string, serverName: string = BLA_IDENTITY.mcpServerName): ConfigReadResult {
      let parsed: unknown;
      try {
        parsed = parseJsonOrJsonc(rawContent);
      } catch (err) {
        return {
          status: "malformed",
          entry: null,
          error: `Malformed OpenCode configuration: ${err instanceof Error ? err.message : String(err)}`,
          otherServersCount: 0,
        };
      }
      if (!isPlainObject(parsed)) {
        return {
          status: "malformed",
          entry: null,
          error: "Invalid OpenCode configuration schema: root value must be a JSON object",
          otherServersCount: 0,
        };
      }
      if (parsed.mcp === undefined) {
        if ("mcpServers" in parsed) {
          return {
            status: "malformed",
            entry: null,
            error: "Invalid OpenCode configuration schema: expected root key 'mcp', found 'mcpServers'",
            otherServersCount: 0,
          };
        }
        return {
          status: "not_configured",
          entry: null,
          otherServersCount: 0,
        };
      }
      if (!isPlainObject(parsed.mcp)) {
        return {
          status: "malformed",
          entry: null,
          error: "Invalid OpenCode configuration schema: 'mcp' must be a JSON object",
          otherServersCount: 0,
        };
      }
      const mcp = parsed.mcp;
      const otherServersCount = Object.keys(mcp).filter((k) => k !== serverName).length;
      if (!(serverName in mcp)) {
        return {
          status: "not_configured",
          entry: null,
          otherServersCount,
        };
      }
      const rawEntry = mcp[serverName];
      if (!isPlainObject(rawEntry)) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid OpenCode MCP entry '${serverName}': must be a JSON object`,
          otherServersCount,
        };
      }
      if (rawEntry.type !== "local") {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid OpenCode MCP entry '${serverName}': 'type' must be 'local'`,
          otherServersCount,
        };
      }
      if (
        !Array.isArray(rawEntry.command) ||
        rawEntry.command.length === 0 ||
        !rawEntry.command.every((c) => typeof c === "string" && c.length > 0) ||
        rawEntry.command[0].trim().length === 0
      ) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid OpenCode MCP entry '${serverName}': 'command' must be a non-empty string array`,
          otherServersCount,
        };
      }
      if (rawEntry.enabled !== undefined && typeof rawEntry.enabled !== "boolean") {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          error: `Invalid OpenCode MCP entry '${serverName}': 'enabled' must be a boolean`,
          otherServersCount,
        };
      }
      if (rawEntry.enabled === false || rawEntry.disabled === true) {
        return {
          status: "invalid_entry",
          entry: null,
          rawEntry,
          disabled: true,
          error: `OpenCode MCP entry '${serverName}' is disabled`,
          otherServersCount,
        };
      }
      const cmdArray = rawEntry.command as string[];
      return {
        status: "valid",
        entry: {
          type: "local",
          command: cmdArray[0]!,
          args: cmdArray.slice(1),
          enabled: rawEntry.enabled ?? true,
        },
        rawEntry,
        otherServersCount,
      };
    },
    upsertServer(rawContent: string | null, serverName: string, reg: McpServerRegistration): string {
      let root: Record<string, unknown> = {};
      if (rawContent !== null && rawContent.trim().length > 0) {
        let parsed: unknown;
        try {
          parsed = parseJsonOrJsonc(rawContent);
        } catch (err) {
          throw new Error(
            `Malformed OpenCode configuration: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        if (!isPlainObject(parsed)) {
          throw new Error("Invalid OpenCode configuration schema: root value must be a JSON object");
        }
        if (parsed.mcp !== undefined && !isPlainObject(parsed.mcp)) {
          throw new Error("Invalid OpenCode configuration schema: 'mcp' must be a JSON object");
        }
        root = { ...parsed };
      }
      const existingMcp = isPlainObject(root.mcp) ? { ...root.mcp } : {};
      const prevEntry = isPlainObject(existingMcp[serverName])
        ? { ...existingMcp[serverName] }
        : {};
      existingMcp[serverName] = {
        ...prevEntry,
        type: "local",
        command: [reg.command, ...reg.args],
        enabled: reg.enabled ?? (typeof prevEntry.enabled === "boolean" ? prevEntry.enabled : true),
      };
      root.mcp = existingMcp;
      return JSON.stringify(root, null, 2) + "\n";
    },
    removeServer(rawContent: string, serverName: string): { readonly content: string; readonly removed: boolean } {
      let parsed: unknown;
      try {
        parsed = parseJsonOrJsonc(rawContent);
      } catch (err) {
        throw new Error(
          `Malformed OpenCode configuration: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (!isPlainObject(parsed)) {
        throw new Error("Invalid OpenCode configuration schema: root value must be a JSON object");
      }
      if (parsed.mcp !== undefined && !isPlainObject(parsed.mcp)) {
        throw new Error("Invalid OpenCode configuration schema: 'mcp' must be a JSON object");
      }
      if (!isPlainObject(parsed.mcp) || !(serverName in parsed.mcp)) {
        return { content: rawContent, removed: false };
      }
      const nextMcp = { ...parsed.mcp };
      delete nextMcp[serverName];
      const nextRoot: Record<string, unknown> = { ...parsed, mcp: nextMcp };
      return {
        content: JSON.stringify(nextRoot, null, 2) + "\n",
        removed: true,
      };
    },
  };
}

function createTomlCodexAdapter(): ClientConfigAdapter {
  return {
    format: "toml-codex",
    readServer(rawContent: string, serverName: string = BLA_IDENTITY.mcpServerName): ConfigReadResult {
      return readCodexTomlMcp(rawContent, serverName);
    },
    upsertServer(rawContent: string | null, serverName: string, reg: McpServerRegistration): string {
      return writeCodexTomlMcp(rawContent, serverName, reg);
    },
    removeServer(rawContent: string, serverName: string): { readonly content: string; readonly removed: boolean } {
      return removeCodexTomlMcp(rawContent, serverName);
    },
  };
}

const ADAPTERS: Readonly<Record<ClientConfigFormat, ClientConfigAdapter>> = Object.freeze({
  "json-mcpServers": createJsonMcpServersAdapter(),
  "json-vscode": createJsonVscodeAdapter(),
  "json-opencode": createJsonOpencodeAdapter(),
  "toml-codex": createTomlCodexAdapter(),
});

const CLIENT_FORMAT_MAP: Readonly<Record<SupportedAgentClientId, ClientConfigFormat>> = Object.freeze({
  claude_code: "json-mcpServers",
  claude_desktop: "json-mcpServers",
  cursor: "json-mcpServers",
  codex: "toml-codex",
  gemini_cli: "json-mcpServers",
  antigravity: "json-mcpServers",
  windsurf: "json-mcpServers",
  vscode: "json-vscode",
  opencode: "json-opencode",
  copilot_cli: "json-mcpServers",
});

export function getClientConfigAdapter(
  clientOrFormat: SupportedAgentClientId | ClientConfigFormat | AgentClientDefinition | string,
): ClientConfigAdapter {
  if (typeof clientOrFormat === "object" && clientOrFormat !== null && "format" in clientOrFormat) {
    return ADAPTERS[clientOrFormat.format];
  }
  if (typeof clientOrFormat === "string") {
    if (clientOrFormat in ADAPTERS) {
      return ADAPTERS[clientOrFormat as ClientConfigFormat];
    }
    const normalized = normalizeClientId(clientOrFormat);
    if (normalized) {
      return ADAPTERS[CLIENT_FORMAT_MAP[normalized]];
    }
  }
  return ADAPTERS["json-mcpServers"];
}

export function readClientMcpConfig(
  configPath: string,
  format: ClientConfigFormat,
  serverName: string = BLA_IDENTITY.mcpServerName,
): ConfigReadResult {
  if (!existsSync(configPath)) {
    return {
      status: "missing",
      entry: null,
      otherServersCount: 0,
    };
  }
  let rawContent: string;
  try {
    rawContent = readFileSync(configPath, "utf8");
  } catch (err) {
    return {
      status: "malformed",
      entry: null,
      error: `Failed to read configuration file '${configPath}': ${err instanceof Error ? err.message : String(err)}`,
      otherServersCount: 0,
    };
  }
  return getClientConfigAdapter(format).readServer(rawContent, serverName);
}

export function resolveSupportedAgentClients(
  home: string = homedir(),
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): readonly AgentClientDefinition[] {
  const winAppData = env.APPDATA?.trim() ? env.APPDATA : join(home, "AppData", "Roaming");
  const xdgConfigHome = env.XDG_CONFIG_HOME?.trim() ? env.XDG_CONFIG_HOME : join(home, ".config");

  const claudeDesktopDir =
    platform === "darwin"
      ? join(home, "Library", "Application Support", "Claude")
      : platform === "win32"
        ? join(winAppData, "Claude")
        : join(xdgConfigHome, "Claude");

  const vscodeDir =
    platform === "darwin"
      ? join(home, "Library", "Application Support", "Code", "User")
      : platform === "win32"
        ? join(winAppData, "Code", "User")
        : join(xdgConfigHome, "Code", "User");

  const codexDir = env.CODEX_HOME?.trim() || join(home, ".codex");
  const opencodeDir = join(xdgConfigHome, "opencode");

  const rawDefs: {
    id: SupportedAgentClientId;
    displayName: string;
    configPath: string;
    format: ClientConfigFormat;
    probePaths: readonly string[];
    skillDirectory: string;
  }[] = [
    {
      id: "claude_code",
      displayName: "Claude Code",
      configPath: join(home, ".claude.json"),
      format: "json-mcpServers",
      // Never probe `dirname(configPath)` because for `~/.claude.json` that is `home` itself!
      probePaths: [join(home, ".claude.json"), join(home, ".claude")],
      skillDirectory: join(home, ".claude", "skills", "blind-llm-agents"),
    },
    {
      id: "claude_desktop",
      displayName: "Claude Desktop",
      configPath: join(claudeDesktopDir, "claude_desktop_config.json"),
      format: "json-mcpServers",
      probePaths: [join(claudeDesktopDir, "claude_desktop_config.json"), claudeDesktopDir],
      skillDirectory: join(home, ".agents", "skills", "blind-llm-agents"),
    },
    {
      id: "cursor",
      displayName: "Cursor",
      configPath: join(home, ".cursor", "mcp.json"),
      format: "json-mcpServers",
      probePaths: [join(home, ".cursor", "mcp.json"), join(home, ".cursor")],
      skillDirectory: join(home, ".cursor", "skills", "blind-llm-agents"),
    },
    {
      id: "codex",
      displayName: "Codex CLI",
      configPath: join(codexDir, "config.toml"),
      format: "toml-codex",
      probePaths: [join(codexDir, "config.toml"), codexDir],
      skillDirectory: join(codexDir, "skills", "blind-llm-agents"),
    },
    {
      id: "gemini_cli",
      displayName: "Gemini CLI",
      configPath: join(home, ".gemini", "settings.json"),
      format: "json-mcpServers",
      probePaths: [join(home, ".gemini", "settings.json"), join(home, ".gemini")],
      skillDirectory: join(home, ".gemini", "skills", "blind-llm-agents"),
    },
    {
      id: "antigravity",
      displayName: "Google Antigravity",
      configPath: join(home, ".gemini", "antigravity", "mcp_config.json"),
      format: "json-mcpServers",
      probePaths: [
        join(home, ".gemini", "antigravity", "mcp_config.json"),
        join(home, ".gemini", "antigravity"),
      ],
      skillDirectory: join(home, ".gemini", "antigravity", "skills", "blind-llm-agents"),
    },
    {
      id: "windsurf",
      displayName: "Windsurf",
      configPath: join(home, ".codeium", "windsurf", "mcp_config.json"),
      format: "json-mcpServers",
      probePaths: [
        join(home, ".codeium", "windsurf", "mcp_config.json"),
        join(home, ".codeium", "windsurf"),
      ],
      skillDirectory: join(home, ".agents", "skills", "blind-llm-agents"),
    },
    {
      id: "vscode",
      displayName: "VS Code",
      configPath: join(vscodeDir, "mcp.json"),
      format: "json-vscode",
      probePaths: [join(vscodeDir, "mcp.json"), vscodeDir],
      skillDirectory: join(home, ".agents", "skills", "blind-llm-agents"),
    },
    {
      id: "opencode",
      displayName: "OpenCode",
      configPath: join(opencodeDir, "opencode.json"),
      format: "json-opencode",
      probePaths: [join(opencodeDir, "opencode.json"), opencodeDir],
      skillDirectory: join(home, ".agents", "skills", "blind-llm-agents"),
    },
    {
      id: "copilot_cli",
      displayName: "GitHub Copilot CLI",
      configPath: join(home, ".copilot", "mcp-config.json"),
      format: "json-mcpServers",
      probePaths: [join(home, ".copilot", "mcp-config.json"), join(home, ".copilot")],
      skillDirectory: join(home, ".agents", "skills", "blind-llm-agents"),
    },
  ];

  return rawDefs.map((def) => ({
    id: def.id,
    displayName: def.displayName,
    configPath: def.configPath,
    skillDirectory: def.skillDirectory,
    format: def.format,
    probePaths: def.probePaths,
    detected: def.probePaths.some((p) => existsSync(p)),
  }));
}

export function detectInstalledClients(
  home: string = homedir(),
  platform: NodeJS.Platform = process.platform,
  env?: NodeJS.ProcessEnv,
): SupportedAgentClientId[] {
  return resolveSupportedAgentClients(home, platform, env)
    .filter((c) => c.detected)
    .map((c) => c.id);
}
