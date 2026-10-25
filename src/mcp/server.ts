import { BLA_IDENTITY } from "../identity.js";
import type { ProtectionIntensity } from "../core/types.js";
import { auditTarget } from "../engine/auditor.js";
import { protectTarget } from "../engine/protector.js";
import { verifyTarget } from "../engine/verifier.js";
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

export const BLA_MCP_TOOLS = Object.freeze([
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
          description: "Optional deterministic seed for reproducible builds",
        },
      },
      required: ["input_path"],
    },
  },
  {
    name: "bla_verify",
    description:
      "Reports local heuristic indicators and hypothetical amplification. Does not execute REA or runtime equivalence checks; empirical verification remains unverified.",
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
    },
  },
  {
    name: "bla_benchmark",
    description:
      "Runs eight synthetic fixtures with hypothetical cost estimates and explicitly bounded runtime samples. Does not run REA or any LLM.",
    inputSchema: {
      type: "object",
      properties: {},
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
    },
  },
  {
    name: "bla_doctor",
    description:
      "Checks readiness of all BLA protection engines and agent MCP registrations.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
]);

export async function handleMcpRequest(
  req: JsonRpcRequest,
): Promise<JsonRpcResponse | null> {
  // Notifications without an `id` do not produce a response
  if (req.id === undefined) {
    return null;
  }

  try {
    switch (req.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            protocolVersion: "2024-11-05",
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
            prompts: [
              {
                name: "shield-against-rea",
                description:
                  "Audit a build artifact for REA exposure, apply BLA's adversarial shield, and inspect hypothetical token amplification (not measured).",
                arguments: [
                  {
                    name: "target_path",
                    description: "Path to the build artifact or directory",
                    required: true,
                  },
                ],
              },
            ],
          },
        };

      case "tools/call": {
        const params = req.params ?? {};
        const name = String(params.name ?? "");
        const args = (params.arguments as Record<string, unknown> | undefined) ?? {};

        let payload: unknown;
        if (name === "bla_audit") {
          payload = auditTarget(String(args.path ?? ""));
        } else if (name === "bla_protect") {
          payload = protectTarget({
            inputPath: String(args.input_path ?? ""),
            ...(typeof args.output_path === "string" ? { outputPath: args.output_path } : {}),
            ...(typeof args.intensity === "string"
              ? { intensity: args.intensity as ProtectionIntensity }
              : {}),
            ...(typeof args.seed === "string" ? { seed: args.seed } : {}),
          });
        } else if (name === "bla_verify") {
          payload = verifyTarget(
            String(args.target_path ?? ""),
            typeof args.original_path === "string" ? args.original_path : undefined,
          );
        } else if (name === "bla_benchmark") {
          payload = await runShowcaseBenchmark();
        } else if (name === "bla_emit_headers") {
          payload = emitCompileTimeNativeHeader(
            (args.language as NativeHeaderLanguage) ?? "c",
            {
              ...(typeof args.intensity === "string"
                ? { intensity: args.intensity as ProtectionIntensity }
                : {}),
            },
          );
        } else if (name === "bla_doctor") {
          payload = runDoctor();
        } else {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32601,
              message: `Unknown BLA MCP tool: ${name}`,
            },
          };
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
 * Starts the BLA MCP server over stdio (supporting newline-delimited JSON-RPC).
 */
export function startMcpStdioServer(): void {
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", async (chunk: string) => {
    buffer += chunk;
    let newlineIdx: number;
    while ((newlineIdx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newlineIdx).trim();
      buffer = buffer.slice(newlineIdx + 1);
      if (!line || line.startsWith("Content-Length:")) continue;
      try {
        const req = JSON.parse(line) as JsonRpcRequest;
        const res = await handleMcpRequest(req);
        if (res !== null) {
          process.stdout.write(JSON.stringify(res) + "\n");
        }
      } catch {
        // Ignore unparseable line
      }
    }
  });
}
