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
import {
  buildWeavePlan,
  getWeaveDirectivesMarkdown,
  WEAVE_DECOY_DOC_PATH,
  WEAVE_DIRECTIVES_URI,
} from "../shields/weave/weave-decoy.js";

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
  readonly type: "string" | "boolean" | "number" | "array";
  readonly description?: string;
  readonly enum?: readonly string[];
  /** Present when type is "array" (JSON Schema items). */
  readonly items?: { readonly type: "string" | "boolean" | "number" };
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
        weave_decoys: {
          type: "boolean",
          description:
            "Opt-in weave-decoy entanglement: JS AST weave (always) + Python .py customer-def weave + .pyc co_consts TYPE_CODE weave. When false, Python stays warm-init/trailer-only. See bla://directives/weave-decoy. Default false.",
        },
        self_seal: {
          type: "boolean",
          description:
            "Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5). Injects a self-integrity preamble and entangles the opaque-predicate seed. Default false.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
          description:
            "WASM export names that must remain the public ABI when export rename runs at maximum/bankrupt (issue #40.3).",
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
        weave_decoys: {
          type: "boolean",
          description:
            "Opt-in weave-decoy entanglement (shared-state / entry-reachable decoys into customer paths; not dismissible noise). Python .py structural weave + .pyc co_consts CODE weave when true. Default false.",
        },
        self_seal: {
          type: "boolean",
          description:
            "Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5). Injects a self-integrity preamble and entangles the opaque-predicate seed. Default false.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
          description:
            "WASM export names that must remain the public ABI when export rename runs at maximum/bankrupt (issue #40.3).",
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
        weave_decoys: {
          type: "boolean",
          description:
            "Opt-in weave-decoy entanglement (shared-state / entry-reachable decoys into customer paths; not dismissible noise). Python .py structural weave + .pyc co_consts CODE weave when true. Default false.",
        },
        self_seal: {
          type: "boolean",
          description:
            "Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5). Injects a self-integrity preamble and entangles the opaque-predicate seed. Default false.",
        },
        wasm_preserve_exports: {
          type: "array",
          items: { type: "string" },
          description:
            "WASM export names that must remain the public ABI when export rename runs at maximum/bankrupt (issue #40.3).",
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
  {
    name: "bla_weave_plan",
    description:
      "Read-only weave-decoy planner: analyze a project or artifact, return bla-weave-plan/v1 JSON (principles, forbidden patterns, checklist, per-file maturity). Defensive only — no crack/RE steps. Prefer before bla_harden with weave_decoys:true.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Project directory or single artifact to analyze",
        },
        max_targets: {
          type: "number",
          description: "Optional cap on files to classify (default 48)",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
]);


export interface McpResourceDefinition {
  readonly uri: string;
  readonly name: string;
  readonly description: string;
  readonly mimeType: string;
}

export const BLA_MCP_RESOURCES: readonly McpResourceDefinition[] = Object.freeze([
  {
    uri: WEAVE_DIRECTIVES_URI,
    name: "weave-decoy-directives",
    description:
      "Chinese-friendly weave-decoy theory + executor checklist for Counter-REA agents (defensive only).",
    mimeType: "text/markdown",
  },
  {
    uri: "bla://docs/weave-decoy-mcp",
    name: "weave-decoy-doc",
    description: `Pointer to repository theory pack ${WEAVE_DECOY_DOC_PATH}`,
    mimeType: "text/markdown",
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
  {
    name: "bla-weave-decoy",
    description:
      "Plan weave-decoy hardening: read bla://directives/weave-decoy, call bla_weave_plan, then bla_harden with weave_decoys:true. Defensive only.",
    arguments: [
      {
        name: "target_path",
        description: "Path to the project or artifact",
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
              resources: {},
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

      case "resources/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            resources: BLA_MCP_RESOURCES,
          },
        };

      case "resources/read": {
        if (!isPlainObject(req.params) || typeof req.params.uri !== "string") {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: "Invalid params: resources/read requires a string 'uri'",
            },
          };
        }
        const uri = req.params.uri;
        const known = BLA_MCP_RESOURCES.find((r) => r.uri === uri);
        if (!known) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: unknown resource URI '${uri}'`,
            },
          };
        }
        const markdown = getWeaveDirectivesMarkdown();
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            contents: [
              {
                uri,
                mimeType: "text/markdown",
                text: markdown,
              },
            ],
          },
        };
      }

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
        // Arguments may be omitted entirely when the prompt has no required
        // arguments (e.g. bla-harden-project, whose directory is optional).
        // Only a present-but-malformed arguments value is an error.
        if (req.params.arguments !== undefined && !isPlainObject(req.params.arguments)) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32602,
              message: `Invalid params: prompt '${promptDef.name}' requires an 'arguments' object`,
            },
          };
        }
        const promptArgs: Record<string, unknown> = isPlainObject(req.params.arguments)
          ? req.params.arguments
          : {};
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
            `Harden my software against REA in one step: call bla_harden with { "directory": ${JSON.stringify(directory)} }. ` +
            `It auto-discovers build outputs, runs audit→defend→verify with the bankrupt profile on every artifact, and returns a per-artifact summary. ` +
            `Do not ask which files to protect — discover them. ` +
            `Defaults are safe: llm_directives, weave_decoys, self_seal and emit_manifest are off unless the user explicitly asks for them. ` +
            `Acceptance: bla_verify passes for each artifact; report defenseScore and any gaps, and do not present benchmark estimates as redteam evidence.`;
        } else if (promptDef.name === "bla-weave-decoy") {
          const targetPath =
            typeof promptArgs.target_path === "string" && promptArgs.target_path.trim().length > 0
              ? String(promptArgs.target_path)
              : ".";
          promptText =
            `Defensive weave-decoy only (no crack/RE): read resource ${WEAVE_DIRECTIVES_URI}, call bla_weave_plan with { "path": ${JSON.stringify(targetPath)} }, then bla_harden with { "directory": ${JSON.stringify(targetPath)}, "weave_decoys": true }. Do not add dismissible honeypot noise layers.`;
        } else if (promptDef.name === "shield-against-rea") {
          const targetPath = String(promptArgs.target_path ?? ".");
          promptText =
            `Shield ${targetPath} against REA, defensive only: (1) inspect and audit ${targetPath} with bla_inspect_release and bla_audit; ` +
            `(2) review the findings with the user before applying anything — choose bla_protect for a single shield pass (default balanced) or bla_defend for the full audit→protect→verify pipeline (default bankrupt), and state which one you chose; ` +
            `(3) verify with bla_verify and report its checks, defenseScore and gaps. ` +
            `Forbidden: inventing new MCP tools, cracking or reverse-engineering third-party software, and turning on llm_directives unless explicitly asked. ` +
            `Acceptance: bla_verify passes, or the failing checks are reported explicitly; do not present benchmark estimates as redteam evidence.`;
        } else if (promptDef.name === "bla-hardening-workflow") {
          const targetPath = String(promptArgs.target_path ?? ".");
          promptText =
            `Release-hardening checklist for ${targetPath}, in order: (1) bla_inspect_release for accidental .map sourcesContent and symbol leaks; ` +
            `(2) bla_audit for REA exposure and cost simulation; (3) bla_protect (single target) or bla_defend (full pipeline) — review audit findings first, do not skip to protect; ` +
            `(4) bla_verify, then report checks, defenseScore and gaps. ` +
            `For a project directory instead of a single artifact, prefer bla_harden. ` +
            `Note: lane-independence lint (lint-lanes) is CLI-only, not an MCP tool. ` +
            `Acceptance: every step is reported, including any skipped or warned stage; no step is claimed without its tool result.`;
        } else {
          // bla-counter-rea
          const targetPath = String(promptArgs.target_path ?? ".");
          promptText =
            `Evaluate REA exposure for ${targetPath} and plan defensive hardening, defensive only: (1) run bla_audit on ${targetPath} and summarise exposed vectors and recommended counters from existing tools only — do not invent new MCP tools; ` +
            `(2) propose a hardening plan that states the intensity, the output location and any WASM preserve-exports or self-seal choices, and flags signed-APK / signed-binary and high-risk llm_directives cases for explicit user confirmation; ` +
            `(3) only after the plan is reviewed, apply bla_protect or bla_defend and finish with bla_verify. ` +
            `Keep evidence honest: distinguish audit exposure, benchmark estimates and real redteam (redteam:rea) evidence — never present an estimate as a measured result. ` +
            `Acceptance: the plan lists vectors, counters, verification steps and open confirmations before any protect step runs.`;
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
            weaveDecoys: Boolean(args.weave_decoys),
            selfSeal: Boolean(args.self_seal),
            ...(Array.isArray(args.wasm_preserve_exports)
              ? {
                  wasmPreserveExports: (args.wasm_preserve_exports as unknown[])
                    .filter((x): x is string => typeof x === "string" && x.length > 0),
                }
              : {}),
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
            weaveDecoys: Boolean(args.weave_decoys),
            selfSeal: Boolean(args.self_seal),
            ...(Array.isArray(args.wasm_preserve_exports)
              ? {
                  wasmPreserveExports: (args.wasm_preserve_exports as unknown[])
                    .filter((x): x is string => typeof x === "string" && x.length > 0),
                }
              : {}),
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
            weaveDecoys: Boolean(args.weave_decoys),
            selfSeal: Boolean(args.self_seal),
            ...(Array.isArray(args.wasm_preserve_exports)
              ? {
                  wasmPreserveExports: (args.wasm_preserve_exports as unknown[])
                    .filter((x): x is string => typeof x === "string" && x.length > 0),
                }
              : {}),
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
        } else if (name === "bla_weave_plan") {
          payload = buildWeavePlan(args.path as string, {
            ...(typeof args.max_targets === "number"
              ? { maxTargets: args.max_targets }
              : {}),
          });
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
 * Largest single stdio line accepted before the client is treated as
 * misbehaving. Measured in UTF-16 code units (`String.length`, matching what
 * JavaScript reports as a string's "characters"), not bytes.
 */
export const MAX_STDIO_LINE_CHARS = 1_048_576;

export interface StdioLineProcessorHooks {
  readonly onLine: (line: string) => void;
  readonly onOversizedLine?: () => void;
}

export interface StdioLineProcessor {
  readonly push: (chunk: string) => void;
}

/**
 * Newline-delimited stdio line splitter with a hard per-line size cap so a
 * client that streams an unterminated giant line cannot grow the buffer without
 * bound. Blank lines and `Content-Length:` framing lines are skipped, matching
 * the previous server behavior.
 */
export function createStdioLineProcessor(hooks: StdioLineProcessorHooks): StdioLineProcessor {
  let buffer = "";
  let discarding = false;
  return {
    push(chunk: string): void {
      if (discarding) {
        // The remainder of an oversized line is still in flight; resume at its newline.
        const nl = chunk.indexOf("\n");
        if (nl < 0) return;
        discarding = false;
        buffer = chunk.slice(nl + 1);
      } else {
        buffer += chunk;
      }
      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        if (!line || line.startsWith("Content-Length:")) continue;
        if (line.length > MAX_STDIO_LINE_CHARS) {
          hooks.onOversizedLine?.();
          continue;
        }
        hooks.onLine(line);
      }
      if (buffer.length > MAX_STDIO_LINE_CHARS) {
        buffer = "";
        discarding = true;
        hooks.onOversizedLine?.();
      }
    },
  };
}

/**
 * Starts the BLA MCP server over stdio (supporting newline-delimited JSON-RPC 2.0).
 */
export function startMcpStdioServer(): void {
  let processingQueue = Promise.resolve();
  const processor = createStdioLineProcessor({
    onLine: (line: string) => {
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
    },
    onOversizedLine: () => {
      const parseErr: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: `Parse error: line exceeds ${MAX_STDIO_LINE_CHARS} character limit`,
        },
      };
      process.stdout.write(JSON.stringify(parseErr) + "\n");
    },
  });
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => processor.push(chunk));
}
