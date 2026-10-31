import { BLA_IDENTITY } from "../identity.js";
import { initBlaConfig } from "../core/config.js";
import { inspectReleaseExposure } from "../core/release-exposure.js";
import type { ProtectionIntensity } from "../core/types.js";
import { auditTarget } from "../engine/auditor.js";
import { protectTarget } from "../engine/protector.js";
import { verifyTarget } from "../engine/verifier.js";
import { defendTarget } from "../engine/defender.js";
import { hardenProject } from "../engine/harden.js";
import { runShowcaseBenchmark } from "../engine/benchmark.js";
import {
  emitCompileTimeNativeHeader,
  type NativeHeaderLanguage,
} from "../shields/formats/headers.js";
import { runDoctor } from "../setup/doctor.js";

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export interface McpPropertySchema {
  readonly type: "string" | "boolean" | "number";
  readonly description?: string;
  readonly enum?: readonly string[];
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: "object";
    readonly properties: Readonly<Record<string, McpPropertySchema | undefined>>;
    readonly required?: readonly string[];
    readonly additionalProperties?: boolean;
  };
}

export interface McpPromptArgumentDefinition {
  readonly name: string;
  readonly description: string;
  readonly required: boolean;
}

export interface McpPromptDefinition {
  readonly name: string;
  readonly description: string;
  readonly arguments: readonly McpPromptArgumentDefinition[];
}

export interface McpEngineHandlers {
  readonly hardenProject: typeof hardenProject;
  readonly defendTarget: typeof defendTarget;
  readonly auditTarget: typeof auditTarget;
  readonly protectTarget: typeof protectTarget;
  readonly verifyTarget: typeof verifyTarget;
  readonly runShowcaseBenchmark: typeof runShowcaseBenchmark;
  readonly emitCompileTimeNativeHeader: typeof emitCompileTimeNativeHeader;
  readonly runDoctor: typeof runDoctor;
  readonly inspectReleaseExposure: typeof inspectReleaseExposure;
  readonly initBlaConfig: typeof initBlaConfig;
}

const DEFAULT_ENGINE_HANDLERS: McpEngineHandlers = Object.freeze({
  hardenProject,
  defendTarget,
  auditTarget,
  protectTarget,
  verifyTarget,
  runShowcaseBenchmark,
  emitCompileTimeNativeHeader,
  runDoctor,
  inspectReleaseExposure,
  initBlaConfig,
});

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  "2024-11-05",
  "2025-03-26",
] as const);

export const BLA_MCP_TOOLS: readonly McpToolDefinition[] = Object.freeze([
  {
    name: "bla_harden",
    description:
      "DEFAULT one-sentence Counter-REA hardening. Auto-discovers build outputs (dist/, build/, out/, release/, .asar, native binaries, .wasm, .py/.pyc, .sqlite, .safetensors/.gguf, .dex, .class, etc.), detects each artifact's format, and runs the full audit→defend→verify pipeline with the bankrupt profile. Pass just a project or build directory (default: cwd). Prefer this over bla_defend when the user says 'harden my software' without naming a specific file.",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Project or build directory to harden (default: current working directory)",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Protection intensity preset (default: bankrupt)",
        },
        emit_manifest: {
          type: "boolean",
          description: "Opt-in: emit an unsigned .bla-manifest.json attestation (not ed25519-signed) per artifact. Default false.",
        },
        llm_directives: {
          type: "boolean",
          description: "Opt-in risky LLM directive layers (fake COPPA/medical notices, dual-use imitation, AI chat markers). Default false.",
        },
        seed: {
          type: "string",
          description: "Optional deterministic seed; when omitted, BLA uses/persists a per-project random seed in .blarc",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_defend",
    description:
      "One-click Counter-REA full defense hardening pipeline. Runs release source-map exposure inspection, 16-vector REA vulnerability audit, Resource-Exhaustion + Model-Misjudgment shield injection (default: bankrupt preset), and mathematical invariant verification in a single call.",
    inputSchema: {
      type: "object",
      properties: {
        input_path: {
          type: "string",
          description: "Path to the artifact or directory to harden against REA",
        },
        output_path: {
          type: "string",
          description: "Optional output path for the hardened artifact",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Protection intensity preset (default: bankrupt)",
        },
        emit_manifest: {
          type: "boolean",
          description: "Opt-in: emit an unsigned .bla-manifest.json attestation (not ed25519-signed) next to the hardened artifact. Default false.",
        },
        llm_directives: {
          type: "boolean",
          description: "Opt-in risky LLM directive layers (fake COPPA/medical notices, dual-use imitation, AI chat markers). Default false.",
        },
        seed: {
          type: "string",
          description: "Optional deterministic seed; when omitted, BLA uses/persists a per-project random seed in .blarc",
        },
      },
      required: ["input_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_audit",
    description:
      "Pre-flight REA exposure and vulnerability audit. Simulates REA static/semantic passes on a target file or directory (JS/TS, Electron .asar, WASM, Python .py/.pyc, Native ELF/Mach-O/PE, ZIP/APK) and estimates attacker Claude/GPT token and dollar cost.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the artifact or directory to audit",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_protect",
    description:
      "Injects BLA's multi-layer adversarial defense shield (Algorithmic Tarpit, REA Semantic Budget Breakers, Electron IPC Ambiguity, Honey Source Maps, and Architectural Chaff) into a target artifact.",
    inputSchema: {
      type: "object",
      properties: {
        input_path: {
          type: "string",
          description: "Path to the input artifact or directory",
        },
        output_path: {
          type: "string",
          description: "Optional output path for the protected artifact",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
          description: "Protection intensity preset (default: balanced)",
        },
        seed: {
          type: "string",
          description: "Optional deterministic seed; when omitted, BLA mints an ephemeral random seed (prefer project .blarc via CLI)",
        },
        llm_directives: {
          type: "boolean",
          description: "Opt-in risky LLM directive layers. Default false.",
        },
      },
      required: ["input_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_verify",
    description:
      "Verifies a BLA-protected artifact against REA's static/semantic resource limits, call-graph tarpit expansion, and token bankruptcy amplification.",
    inputSchema: {
      type: "object",
      properties: {
        target_path: {
          type: "string",
          description: "Path to the protected artifact to verify",
        },
        original_path: {
          type: "string",
          description: "Optional path to the unprotected original for amplification comparison",
        },
      },
      required: ["target_path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_benchmark",
    description:
      "Runs the Counter-REA Showcase Benchmark suite and returns Before vs. After metrics.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "bla_emit_headers",
    description:
      "Emits compile-time native defense headers for C/C++ (bla_shield.h), Rust (bla_shield.rs), or Go (bla_shield.go) to defeat Ghidra/Hopper/IDA and REA native binary analyzers.",
    inputSchema: {
      type: "object",
      properties: {
        language: {
          type: "string",
          enum: ["c", "rust", "go"],
          description: "Target native language (c, rust, or go)",
        },
        intensity: {
          type: "string",
          enum: ["stealth", "balanced", "maximum", "bankrupt"],
        },
      },
      required: ["language"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_doctor",
    description:
      "Checks readiness of all BLA protection engines and agent MCP registrations.",
    inputSchema: {
      type: "object",
      properties: {
        home_dir: {
          type: "string",
          description: "Optional home directory path to inspect",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "bla_inspect_release",
    description:
      "Read-only local source-map and symbol exposure scan for build directories and release artifacts.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to the build directory or artifact to inspect",
        },
        max_files: {
          type: "number",
          description: "Optional maximum number of files to scan",
        },
        max_total_bytes: {
          type: "number",
          description: "Optional maximum total bytes to scan",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "bla_init",
    description:
      "Creates a starter bla.config.json in a project directory for zero-argument `bla defend` workflows.",
    inputSchema: {
      type: "object",
      properties: {
        directory: {
          type: "string",
          description: "Target project directory (pass '.' explicitly for current directory)",
        },
        overwrite: {
          type: "boolean",
          description: "Overwrite an existing bla.config.json if present",
        },
      },
      required: ["directory"],
      additionalProperties: false,
    },
  },
]);

export const BLA_MCP_PROMPTS: readonly McpPromptDefinition[] = Object.freeze([
  {
    name: "bla-harden-project",
    description:
      "One-sentence Counter-REA hardening: discover every protectable build artifact under a project directory and run bla_harden (audit→defend→verify, bankrupt profile).",
    arguments: [
      {
        name: "directory",
        description: "Project or build directory (default: .)",
        required: false,
      },
    ],
  },
  {
    name: "shield-against-rea",
    description:
      "Audit a build artifact for REA exposure, apply BLA's adversarial shield, and verify the token bankruptcy factor.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the build artifact or directory",
        required: true,
      },
    ],
  },
  {
    name: "bla-hardening-workflow",
    description:
      "Step-by-step release hardening checklist using bla_inspect_release, bla_audit, bla_protect, and bla_verify.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the build artifact or directory",
        required: true,
      },
    ],
  },
  {
    name: "bla-counter-rea",
    description:
      "Evaluate REA reverse-engineering exposure and plan defensive hardening for a software artifact.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the build artifact or directory",
        required: true,
      },
    ],
  },
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateMcpToolCall(
  params: unknown,
):
  | {
      readonly ok: true;
      readonly tool: McpToolDefinition;
      readonly args: Record<string, unknown>;
    }
  | {
      readonly ok: false;
      readonly code: -32601 | -32602;
      readonly message: string;
    } {
  if (!isPlainObject(params)) {
    return {
      ok: false,
      code: -32602,
      message: "Invalid params: tool call params must be a JSON object",
    };
  }

  if (typeof params.name !== "string" || params.name.trim().length === 0) {
    return {
      ok: false,
      code: -32602,
      message: "Invalid params: tool 'name' must be a non-empty string",
    };
  }

  const tool = BLA_MCP_TOOLS.find((t) => t.name === params.name);
  if (!tool) {
    return {
      ok: false,
      code: -32602,
      message: `Invalid params: unknown BLA MCP tool '${params.name}'`,
    };
  }

  const rawArgs = params.arguments;
  const requiredFields = tool.inputSchema.required ?? [];

  if (rawArgs === undefined) {
    if (requiredFields.length > 0) {
      return {
        ok: false,
        code: -32602,
        message: `Invalid params for '${tool.name}': missing required arguments (${requiredFields.join(", ")})`,
      };
    }
    return { ok: true, tool, args: {} };
  }

  if (!isPlainObject(rawArgs)) {
    return {
      ok: false,
      code: -32602,
      message: `Invalid params for '${tool.name}': 'arguments' must be a JSON object`,
    };
  }

  // Reject unexpected properties when additionalProperties is false
  const allowedProps = tool.inputSchema.properties;
  for (const key of Object.keys(rawArgs)) {
    if (!(key in allowedProps)) {
      return {
        ok: false,
        code: -32602,
        message: `Invalid params for '${tool.name}': unknown argument '${key}'`,
      };
    }
  }

  // Validate required properties
  for (const reqKey of requiredFields) {
    if (!(reqKey in rawArgs) || rawArgs[reqKey] === undefined || rawArgs[reqKey] === null) {
      return {
        ok: false,
        code: -32602,
        message: `Invalid params for '${tool.name}': missing required argument '${reqKey}'`,
      };
    }
  }

  // Validate types, non-empty strings, numbers, booleans, and enums
  for (const [key, val] of Object.entries(rawArgs)) {
    if (val === undefined) continue;
    const propSchema = allowedProps[key];
    if (!propSchema) continue;

    if (propSchema.type === "string") {
      if (typeof val !== "string") {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a string, received ${val === null ? "null" : typeof val}`,
        };
      }
      if (val.trim().length === 0) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a non-empty string`,
        };
      }
      if (propSchema.enum && !propSchema.enum.includes(val)) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be one of [${propSchema.enum.join(", ")}], received '${val}'`,
        };
      }
    } else if (propSchema.type === "boolean") {
      if (typeof val !== "boolean") {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a boolean`,
        };
      }
    } else if (propSchema.type === "number") {
      if (typeof val !== "number" || !Number.isFinite(val) || val <= 0) {
        return {
          ok: false,
          code: -32602,
          message: `Invalid params for '${tool.name}': argument '${key}' must be a positive finite number`,
        };
      }
    }
  }

  return { ok: true, tool, args: rawArgs };
}

export async function handleMcpRequest(
  req: JsonRpcRequest,
  handlers: McpEngineHandlers = DEFAULT_ENGINE_HANDLERS,
): Promise<JsonRpcResponse | null> {
  if (!isPlainObject(req) || req.jsonrpc !== "2.0" || typeof req.method !== "string") {
    return {
      jsonrpc: "2.0",
      id: isPlainObject(req) && (typeof req.id === "string" || typeof req.id === "number") ? req.id : null,
      error: {
        code: -32600,
        message: "Invalid Request: expected JSON-RPC 2.0 request object",
      },
    };
  }

  // Notifications without an `id` do not produce a response
  if (req.id === undefined) {
    return null;
  }

  try {
    switch (req.method) {
      case "initialize": {
        if (req.params !== undefined && !isPlainObject(req.params)) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: initialize params must be an object",
            },
          };
        }
        const requestedVersion = req.params?.protocolVersion;
        if (requestedVersion !== undefined && typeof requestedVersion !== "string") {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: protocolVersion must be a string",
            },
          };
        }
        const negotiatedVersion =
          typeof requestedVersion === "string" &&
          (SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]).includes(requestedVersion)
            ? requestedVersion
            : "2024-11-05";

        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            protocolVersion: negotiatedVersion,
            capabilities: {
              tools: {},
              prompts: {},
            },
            serverInfo: {
              name: BLA_IDENTITY.mcpServerName,
              version: BLA_IDENTITY.version,
            },
          },
        };
      }

      case "ping":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {},
        };

      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            tools: BLA_MCP_TOOLS,
          },
        };

      case "prompts/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            prompts: BLA_MCP_PROMPTS,
          },
        };

      case "prompts/get": {
        if (!isPlainObject(req.params) || typeof req.params.name !== "string") {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: prompts/get requires a string 'name'",
            },
          };
        }
        const promptDef = BLA_MCP_PROMPTS.find((p) => p.name === req.params!.name);
        if (!promptDef) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: unknown prompt '${req.params.name}'`,
            },
          };
        }
        const promptArgs = req.params.arguments;
        if (!isPlainObject(promptArgs)) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: prompt '${promptDef.name}' requires an 'arguments' object`,
            },
          };
        }
        for (const argSpec of promptDef.arguments) {
          if (argSpec.required) {
            const val = promptArgs[argSpec.name];
            if (typeof val !== "string" || val.trim().length === 0) {
              return {
                jsonrpc: "2.0",
                id: req.id,
                error: {
                  code: -32602,
                  message: `Invalid params: prompt '${promptDef.name}' requires non-empty string argument '${argSpec.name}'`,
                },
              };
            }
          }
        }
        let promptText: string;
        if (promptDef.name === "bla-harden-project") {
          const directory =
            typeof promptArgs.directory === "string" && promptArgs.directory.trim().length > 0
              ? String(promptArgs.directory)
              : ".";
          promptText =
            `Harden my software against REA in one step: call bla_harden with { "directory": "${directory}" }. ` +
            `It auto-discovers build outputs, runs audit→defend→verify with the bankrupt profile on every artifact, and returns a per-artifact summary. ` +
            `Do not ask which files to protect — discover them.`;
        } else {
          const targetPath = String(promptArgs.target_path ?? ".");
          promptText =
            `Inspect and audit '${targetPath}' using bla_inspect_release and bla_audit, then review findings before applying bla_protect or bla_defend and verifying with bla_verify.`;
        }
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            description: promptDef.description,
            messages: [
              {
                role: "user",
                content: {
                  type: "text",
                  text: promptText,
                },
              },
            ],
          },
        };
      }

      case "tools/call": {
        const validated = validateMcpToolCall(req.params);
        if (!validated.ok) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: validated.code,
              message: validated.message,
            },
          };
        }

        const { tool, args } = validated;
        const name = tool.name;
        let payload: unknown;

        if (name === "bla_harden") {
          payload = handlers.hardenProject({
            directory:
              typeof args.directory === "string" && args.directory.trim().length > 0
                ? (args.directory as string)
                : process.cwd(),
            intensity:
              typeof args.intensity === "string"
                ? (args.intensity as ProtectionIntensity)
                : "bankrupt",
            emitManifest: Boolean(args.emit_manifest),
            llmDirectives: Boolean(args.llm_directives),
            ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
          });
        } else if (name === "bla_defend") {
          payload = handlers.defendTarget({
            inputPath: args.input_path as string,
            ...(typeof args.output_path === "string"
              ? { outputPath: args.output_path }
              : {}),
            intensity:
              typeof args.intensity === "string"
                ? (args.intensity as ProtectionIntensity)
                : "bankrupt",
            emitManifest: Boolean(args.emit_manifest),
            llmDirectives: Boolean(args.llm_directives),
            ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
          });
        } else if (name === "bla_audit") {
          payload = handlers.auditTarget(args.path as string);
        } else if (name === "bla_protect") {
          payload = handlers.protectTarget({
            inputPath: args.input_path as string,
            ...(typeof args.output_path === "string" ? { outputPath: args.output_path } : {}),
            ...(typeof args.intensity === "string"
              ? { intensity: args.intensity as ProtectionIntensity }
              : {}),
            ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
            llmDirectives: Boolean(args.llm_directives),
          });
        } else if (name === "bla_verify") {
          payload = handlers.verifyTarget(
            args.target_path as string,
            typeof args.original_path === "string" ? args.original_path : undefined,
          );
        } else if (name === "bla_benchmark") {
          payload = await handlers.runShowcaseBenchmark();
        } else if (name === "bla_emit_headers") {
          payload = handlers.emitCompileTimeNativeHeader(
            args.language as NativeHeaderLanguage,
            {
              ...(typeof args.intensity === "string"
                ? { intensity: args.intensity as ProtectionIntensity }
                : {}),
            },
          );
        } else if (name === "bla_doctor") {
          payload = handlers.runDoctor(
            typeof args.home_dir === "string" ? args.home_dir : undefined,
          );
        } else if (name === "bla_inspect_release") {
          payload = handlers.inspectReleaseExposure(args.path as string);
        } else if (name === "bla_init") {
          payload = handlers.initBlaConfig(
            args.directory as string,
            Boolean(args.overwrite),
          );
        }

        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify(payload, null, 2),
              },
            ],
            structuredContent: payload,
            isError: false,
          },
        };
      }

      default:
        return {
          jsonrpc: "2.0",
          id: req.id,
          error: {
            code: -32601,
            message: `Method not found: ${req.method}`,
          },
        };
    }
  } catch (err) {
    return {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        content: [
          {
            type: "text",
            text: err instanceof Error ? err.message : String(err),
          },
        ],
        isError: true,
      },
    };
  }
}

/**
 * Starts the BLA MCP server over stdio (supporting newline-delimited JSON-RPC 2.0).
 */
export function startMcpStdioServer(): void {
  let buffer = "";
  let processingQueue = Promise.resolve();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    let newlineIdx: number;
    while ((newlineIdx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newlineIdx).trim();
      buffer = buffer.slice(newlineIdx + 1);
      if (!line || line.startsWith("Content-Length:")) continue;
      processingQueue = processingQueue.then(async () => {
        try {
          const req = JSON.parse(line) as JsonRpcRequest;
          const res = await handleMcpRequest(req);
          if (res !== null) {
            process.stdout.write(JSON.stringify(res) + "\n");
          }
        } catch {
          const parseErr: JsonRpcResponse = {
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: "Parse error",
            },
          };
          process.stdout.write(JSON.stringify(parseErr) + "\n");
        }
      });
    }
  });
}
