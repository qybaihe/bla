#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { BLA_IDENTITY } from "./identity.js";
import type { ProtectionIntensity } from "./core/types.js";
import { inspectReleaseExposure } from "./core/release-exposure.js";
import { auditTarget } from "./engine/auditor.js";
import { protectTarget } from "./engine/protector.js";
import { verifyTarget } from "./engine/verifier.js";
import { runShowcaseBenchmark } from "./engine/benchmark.js";
import {
  emitCompileTimeNativeHeader,
  type NativeHeaderLanguage,
} from "./shields/formats/headers.js";
import { type SupportedAgentClientId } from "./setup/clients.js";
import { runSetup, runUninstall } from "./setup/setup.js";
import { runDoctor } from "./setup/doctor.js";
import { startMcpStdioServer } from "./mcp/server.js";
import {
  formatAuditReport,
  formatBanner,
  formatBenchmarkReport,
  formatDoctorReport,
  formatProtectionResult,
  formatSetupReport,
  formatVerificationReport,
} from "./ui/reporter.js";

function printHelp(): void {
  console.log(`${formatBanner()}

Usage:
  npx bla-shield <command> [options]
  bla <command> [options]

Commands:
  setup                       Configure agent MCP integrations & install the BLA skill
  audit <target>              Pre-flight REA exposure & vulnerability scan
  inspect-release <target>   Read-only local source-map disclosure observations
  protect <target>            Inject multi-layer Counter-REA adversarial shield
  verify <target> [original]  Verify Counter-REA defense invariants & token amplification
  benchmark                   Run the 8-target Counter-REA Showcase Benchmark suite
  emit-headers                Generate compile-time C/C++, Rust, or Go defense headers
  doctor                      Check readiness of BLA engines & agent registrations
  update                      Update global bla-shield installation & print setup refresh instructions
  uninstall                   Remove BLA MCP configuration & skill files
  mcp                         Start the BLA Model Context Protocol (MCP) server over stdio

Options:
  -o, --output <path>         Output file or directory path (for protect / emit-headers)
  --in-place                  Overwrite input target in-place (for protect)
  --intensity <preset>        Protection preset: stealth | balanced | maximum | bankrupt (default: balanced)
  --seed <seed>               Deterministic PRNG seed for reproducible protection
  --lang <c|rust|go>          Target language for emit-headers (default: c)
  --client <id>               Agent client ID for setup (repeatable: claude_code, cursor, codex, etc.)
  --all-detected              Configure all detected coding agents on this machine
  --dry-run                   Preview planned setup changes without writing files
  -y, --yes                   Approve setup actions without interactive confirmation
  --json                      Emit structured JSON output
  -v, --version               Print BLA version
  -h, --help                  Print this help guide
`);
}

interface ParsedCliArgs {
  readonly command: string;
  readonly positionals: string[];
  readonly output?: string;
  readonly inPlace: boolean;
  readonly intensity: ProtectionIntensity;
  readonly seed?: string;
  readonly lang: NativeHeaderLanguage;
  readonly clients: SupportedAgentClientId[];
  readonly allDetected: boolean;
  readonly dryRun: boolean;
  readonly yes: boolean;
  readonly json: boolean;
  readonly honeyMaps: boolean;
  readonly help: boolean;
  readonly version: boolean;
}

export function parseCliArgs(argv: readonly string[]): ParsedCliArgs {
  let command = "";
  const positionals: string[] = [];
  let output: string | undefined;
  let inPlace = false;
  let intensity: ProtectionIntensity = "balanced";
  let seed: string | undefined;
  let lang: NativeHeaderLanguage = "c";
  const clients: SupportedAgentClientId[] = [];
  let allDetected = false;
  let dryRun = false;
  let yes = false;
  let json = false;
  let honeyMaps = true;
  let help = false;
  let version = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "-h" || arg === "--help") {
      help = true;
    } else if (arg === "-v" || arg === "--version") {
      version = true;
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "-y" || arg === "--yes") {
      yes = true;
    } else if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg === "--all-detected") {
      allDetected = true;
    } else if (arg === "--in-place") {
      inPlace = true;
    } else if (arg === "--no-honey-maps") {
      honeyMaps = false;
    } else if (arg === "--mcp") {
      command = "mcp";
    } else if (arg === "--update") {
      command = "update";
    } else if ((arg === "-o" || arg === "--output") && i + 1 < argv.length) {
      output = argv[++i]!;
    } else if (arg === "--intensity" && i + 1 < argv.length) {
      const val = argv[++i]! as ProtectionIntensity;
      if (["stealth", "balanced", "maximum", "bankrupt"].includes(val)) {
        intensity = val;
      }
    } else if (arg === "--seed" && i + 1 < argv.length) {
      seed = argv[++i]!;
    } else if (arg === "--lang" && i + 1 < argv.length) {
      const val = argv[++i]! as NativeHeaderLanguage;
      if (["c", "rust", "go"].includes(val)) {
        lang = val;
      }
    } else if (arg === "--client" && i + 1 < argv.length) {
      clients.push(argv[++i]! as SupportedAgentClientId);
    } else if (!arg.startsWith("-")) {
      if (!command) command = arg;
      else positionals.push(arg);
    }
  }

  return {
    command,
    positionals,
    ...(output !== undefined ? { output } : {}),
    inPlace,
    intensity,
    ...(seed !== undefined ? { seed } : {}),
    lang,
    clients,
    allDetected,
    dryRun,
    yes,
    json,
    honeyMaps,
    help,
    version,
  };
}

export async function runCli(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const parsed = parseCliArgs(argv);

  if (parsed.version) {
    console.log(BLA_IDENTITY.version);
    return 0;
  }

  if (parsed.command === "mcp") {
    startMcpStdioServer();
    return 0;
  }

  if (parsed.help || !parsed.command) {
    printHelp();
    return 0;
  }

  try {
    switch (parsed.command) {
      case "setup": {
        const res = runSetup({
          ...(parsed.clients.length > 0 ? { clientIds: parsed.clients } : {}),
          allDetected: parsed.allDetected,
          dryRun: parsed.dryRun,
          yes: parsed.yes,
        });
        if (parsed.json) console.log(JSON.stringify(res, null, 2));
        else console.log(formatSetupReport(res));
        return 0;
      }

      case "doctor": {
        const doc = runDoctor();
        if (parsed.json) console.log(JSON.stringify(doc, null, 2));
        else console.log(formatDoctorReport(doc));
        return 0;
      }

      case "update": {
        const updateInfo = {
          currentVersion: BLA_IDENTITY.version,
          package: BLA_IDENTITY.packageName,
          refreshSetupCommand: "npx bla-shield@latest setup",
          globalUpdateCommand: "npm install --global bla-shield@latest",
        };
        if (parsed.json) {
          console.log(JSON.stringify(updateInfo, null, 2));
        } else {
          console.log(`${formatBanner()}\n\nBLA v${BLA_IDENTITY.version} update workflow:\n  • Global CLI update:   npm install --global bla-shield@latest\n  • Agent MCP refresh:   npx bla-shield@latest setup\n`);
        }
        return 0;
      }

      case "uninstall": {
        const res = runUninstall();
        if (parsed.json) console.log(JSON.stringify(res, null, 2));
        else console.log(`Removed BLA configuration from ${res.removedClients.length} client(s).`);
        return 0;
      }

      case "inspect-release": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <target> path for `bla inspect-release <target>`.");
          return 1;
        }
        const report = inspectReleaseExposure(target);
        // Structured output also avoids printing embedded source text or reference URLs.
        console.log(JSON.stringify(report, null, 2));
        return report.status === "partial" ? 2 : 0;
      }

      case "audit": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <target> path for `bla audit <target>`.");
          return 1;
        }
        const report = auditTarget(target);
        if (parsed.json) console.log(JSON.stringify(report, null, 2));
        else console.log(formatAuditReport(report));
        return 0;
      }

      case "protect": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <target> path for `bla protect <target>`.");
          return 1;
        }
        const res = protectTarget({
          inputPath: target,
          ...(parsed.output !== undefined ? { outputPath: parsed.output } : {}),
          inPlace: parsed.inPlace,
          intensity: parsed.intensity,
          ...(parsed.seed !== undefined ? { seed: parsed.seed } : {}),
          honeySourceMaps: parsed.honeyMaps,
        });
        if (parsed.json) console.log(JSON.stringify(res, null, 2));
        else console.log(formatProtectionResult(res));
        return 0;
      }

      case "verify": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <target> path for `bla verify <target> [original]`.");
          return 1;
        }
        const report = verifyTarget(target, parsed.positionals[1]);
        if (parsed.json) console.log(JSON.stringify(report, null, 2));
        else console.log(formatVerificationReport(report));
        return report.overallPassed ? 0 : 2;
      }

      case "benchmark": {
        const bench = await runShowcaseBenchmark();
        if (parsed.json) console.log(JSON.stringify(bench, null, 2));
        else console.log(formatBenchmarkReport(bench));
        return 0;
      }

      case "emit-headers": {
        const emitted = emitCompileTimeNativeHeader(parsed.lang, {
          intensity: parsed.intensity,
          ...(parsed.seed !== undefined ? { seed: parsed.seed } : {}),
        });
        if (parsed.output) {
          const outPath = resolve(parsed.output);
          writeFileSync(outPath, emitted.content, "utf8");
          if (parsed.json) {
            console.log(JSON.stringify({ ...emitted, outputPath: outPath }, null, 2));
          } else {
            console.log(`Emitted ${emitted.language.toUpperCase()} defense header to ${outPath} (${emitted.decoyFunctionsCount} decoy tarpit functions).`);
          }
        } else if (parsed.json) {
          console.log(JSON.stringify(emitted, null, 2));
        } else {
          console.log(emitted.content);
        }
        return 0;
      }

      default:
        console.error(`Unknown command: ${parsed.command}. Run "bla --help" for available commands.`);
        return 1;
    }
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

// Run when invoked directly
const isDirectExecution =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith("cli.js") ||
    process.argv[1].endsWith("cli.ts") ||
    process.argv[1].endsWith("bla") ||
    process.argv[1].endsWith("bla-shield"));

if (isDirectExecution) {
  runCli().then((code) => {
    if (process.argv[2] !== "mcp" && !process.argv.includes("--mcp")) {
      process.exitCode = code;
    }
  });
}
