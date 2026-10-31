#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { BLA_IDENTITY } from "./identity.js";
import { initBlaConfig, loadBlaConfig, resolveProjectSeed } from "./core/config.js";
import { inspectReleaseExposure } from "./core/release-exposure.js";
import { buildSarifReport } from "./core/sarif.js";
import type { ProtectionIntensity } from "./core/types.js";
import { auditTarget } from "./engine/auditor.js";
import { protectTarget } from "./engine/protector.js";
import { verifyTarget } from "./engine/verifier.js";
import { defendTarget } from "./engine/defender.js";
import { formatHardenProjectReport, hardenProject } from "./engine/harden.js";
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
  formatOneClickDefenseReport,
  formatProtectionResult,
  formatSetupReport,
  formatVerificationReport,
} from "./ui/reporter.js";

function printHelp(): void {
  console.log(`${formatBanner()}

Usage:
  npx bla-agents <command> [options]
  npx bla-shield <command> [options]
  bla <command> [options]

Quick start:
  npx bla-agents setup -y          # register bla_harden with your agent
  bla harden .                     # one-sentence Counter-REA hardening
  # or tell your agent: "Harden my software against REA"

Commands:
  setup                       Configure agent MCP integrations & install the BLA skill
  harden [dir]                DEFAULT: auto-discover build outputs under a project/build dir and bankrupt-harden all of them
  defend <target>             One-click full Counter-REA pipeline (inspect -> audit -> bankrupt protect -> verify)
  inspect-release <target>    Read-only local source-map & symbol exposure check
  audit <target>              Pre-flight REA exposure & vulnerability scan
  protect <target>            Inject multi-layer Counter-REA adversarial shield
  verify <target> [original]  Verify Counter-REA defense invariants & token amplification
  benchmark                   Run the 14-target Counter-REA Showcase Benchmark suite
  emit-headers                Generate compile-time C/C++, Rust, or Go defense headers
  doctor                      Check readiness of BLA engines & agent registrations
  update                      Update global bla-shield installation & print setup refresh instructions
  uninstall                   Remove BLA MCP configuration & skill files
  mcp                         Start the BLA Model Context Protocol (MCP) server over stdio

Options:
  -o, --output <path>         Output file or directory path (for protect / emit-headers)
  --in-place                  Overwrite input target in-place (for protect)
  --intensity <preset>        stealth | balanced | maximum | bankrupt
                            (harden/defend default: bankrupt; protect default: balanced)
  --seed <seed>               Deterministic PRNG seed (default: per-project random in .blarc)
  --manifest                  Emit unsigned .bla-manifest.json next to protected artifacts (opt-in)
  --llm-directives            Opt-in risky LLM directive layers (COPPA/medical bait, dual-use imitation, AI chat markers); OFF by default
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
  readonly configPath?: string;
  readonly inPlace: boolean;
  readonly intensity: ProtectionIntensity;
  readonly seed?: string;
  readonly manifest: boolean;
  readonly llmDirectives: boolean;
  readonly lang: NativeHeaderLanguage;
  readonly clients: SupportedAgentClientId[];
  readonly allDetected: boolean;
  readonly dryRun: boolean;
  readonly yes: boolean;
  readonly json: boolean;
  readonly sarif: boolean;
  readonly failUnder?: number;
  readonly honeyMaps: boolean;
  readonly help: boolean;
  readonly version: boolean;
}

export function parseCliArgs(argv: readonly string[]): ParsedCliArgs {
  let command = "";
  const positionals: string[] = [];
  let output: string | undefined;
  let configPath: string | undefined;
  let inPlace = false;
  let intensity: ProtectionIntensity = "balanced";
  let seed: string | undefined;
  let manifest = false;
  let llmDirectives = false;
  let lang: NativeHeaderLanguage = "c";
  const clients: SupportedAgentClientId[] = [];
  let allDetected = false;
  let dryRun = false;
  let yes = false;
  let json = false;
  let sarif = false;
  let failUnder: number | undefined;
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
    } else if (arg === "--sarif") {
      sarif = true;
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
    } else if (arg === "--manifest") {
      manifest = true;
    } else if (arg === "--llm-directives") {
      llmDirectives = true;
    } else if (arg === "--mcp") {
      command = "mcp";
    } else if (arg === "--update") {
      command = "update";
    } else if ((arg === "-o" || arg === "--output") && i + 1 < argv.length) {
      output = argv[++i]!;
    } else if ((arg === "-c" || arg === "--config") && i + 1 < argv.length) {
      configPath = argv[++i]!;
    } else if (arg === "--fail-under" && i + 1 < argv.length) {
      const n = Number(argv[++i]!);
      if (Number.isFinite(n)) failUnder = n;
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
    ...(configPath !== undefined ? { configPath } : {}),
    inPlace,
    intensity,
    ...(seed !== undefined ? { seed } : {}),
    manifest,
    llmDirectives,
    lang,
    clients,
    allDetected,
    dryRun,
    yes,
    json,
    sarif,
    ...(failUnder !== undefined ? { failUnder } : {}),
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
        return doc.healthy ? 0 : 1;
      }

      case "update": {
        const updateInfo = {
          currentVersion: BLA_IDENTITY.version,
          package: BLA_IDENTITY.packageName,
          packageAlias: BLA_IDENTITY.packageAlias,
          refreshSetupCommand: "npx bla-agents@latest setup",
          globalUpdateCommand: "npm install --global bla-agents@latest",
        };
        if (parsed.json) {
          console.log(JSON.stringify(updateInfo, null, 2));
        } else {
          console.log(`${formatBanner()}\n\nBLA v${BLA_IDENTITY.version} update workflow:\n  • Global CLI update:   npm install --global bla-agents@latest\n  • Agent MCP refresh:   npx bla-agents@latest setup\n`);
        }
        return 0;
      }

      case "uninstall": {
        const res = runUninstall();
        if (parsed.json) console.log(JSON.stringify(res, null, 2));
        else console.log(`Removed BLA configuration from ${res.removedClients.length} client(s).`);
        return 0;
      }

      case "init": {
        const dir = parsed.positionals[0] ?? process.cwd();
        const res = initBlaConfig(dir, parsed.inPlace);
        if (parsed.json) {
          console.log(JSON.stringify(res, null, 2));
        } else {
          console.log(
            res.created
              ? `Created ${res.configPath} (default input: "${res.config.input}", intensity: "${res.config.intensity}").`
              : `Config already exists at ${res.configPath}. Pass --in-place to overwrite.`,
          );
        }
        return 0;
      }

      case "inspect-release": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <target> path for `bla inspect-release <target>`.");
          return 1;
        }
        const report = inspectReleaseExposure(target);
        console.log(JSON.stringify(report, null, 2));
        return report.status === "complete" ? 0 : 2;
      }

      case "harden": {
        const loaded = loadBlaConfig(process.cwd(), parsed.configPath);
        const directory = parsed.positionals[0] ?? loaded.config.input ?? process.cwd();
        const explicitIntensity = argv.includes("--intensity")
          ? parsed.intensity
          : (loaded.config.intensity ?? "bankrupt");
        const resolved = resolveProjectSeed(
          typeof directory === "string" ? directory : process.cwd(),
          parsed.seed,
          parsed.configPath,
        );
        const report = hardenProject({
          directory,
          intensity: explicitIntensity,
          seed: resolved.seed,
          emitManifest: parsed.manifest || loaded.config.emitManifest === true,
          llmDirectives: parsed.llmDirectives || loaded.config.llmDirectives === true,
          ...(parsed.output !== undefined ? { outputDirectory: parsed.output } : {}),
        });
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(formatHardenProjectReport(report));
        }
        return report.overallSuccess || report.discoveredCount === 0 ? (report.discoveredCount === 0 ? 2 : 0) : 2;
      }

      case "defend": {
        const loaded = loadBlaConfig(process.cwd(), parsed.configPath);
        const target = parsed.positionals[0] ?? loaded.config.input;
        if (!target) {
          console.error("Error: Missing <target> path for `bla defend <target>`.");
          return 1;
        }
        const explicitIntensity = argv.includes("--intensity")
          ? parsed.intensity
          : (loaded.config.intensity ?? "bankrupt");
        const resolved = resolveProjectSeed(process.cwd(), parsed.seed, parsed.configPath);
        const report = defendTarget({
          inputPath: target,
          ...((parsed.output ?? loaded.config.output) !== undefined
            ? { outputPath: (parsed.output ?? loaded.config.output)! }
            : {}),
          inPlace: parsed.inPlace,
          intensity: explicitIntensity,
          seed: resolved.seed,
          emitManifest: parsed.manifest || loaded.config.emitManifest === true,
          llmDirectives: parsed.llmDirectives || loaded.config.llmDirectives === true,
        });
        if (parsed.sarif) {
          console.log(
            JSON.stringify(buildSarifReport(report.beforeAudit, report.releaseExposure), null, 2),
          );
        } else if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(formatOneClickDefenseReport(report));
        }
        const threshold = parsed.failUnder ?? loaded.config.minDefenseScore;
        if (threshold !== undefined && report.verification.defenseScore < threshold) {
          return 2;
        }
        return report.overallSuccess ? 0 : 2;
      }

      case "audit": {
        const loaded = loadBlaConfig(process.cwd(), parsed.configPath);
        const target = parsed.positionals[0] ?? loaded.config.input;
        if (!target) {
          console.error("Error: Missing <target> path for `bla audit <target>`.");
          return 1;
        }
        const report = auditTarget(target);
        if (parsed.sarif) {
          console.log(JSON.stringify(buildSarifReport(report), null, 2));
        } else if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(formatAuditReport(report));
        }
        return 0;
      }

      case "protect": {
        const loaded = loadBlaConfig(process.cwd(), parsed.configPath);
        const target = parsed.positionals[0] ?? loaded.config.input;
        if (!target) {
          console.error("Error: Missing <target> path for `bla protect <target>`.");
          return 1;
        }
        const resolved = resolveProjectSeed(process.cwd(), parsed.seed, parsed.configPath);
        const res = protectTarget({
          inputPath: target,
          ...((parsed.output ?? loaded.config.output) !== undefined
            ? { outputPath: (parsed.output ?? loaded.config.output)! }
            : {}),
          inPlace: parsed.inPlace,
          intensity: argv.includes("--intensity")
            ? parsed.intensity
            : (loaded.config.intensity ?? parsed.intensity),
          seed: resolved.seed,
          honeySourceMaps: parsed.honeyMaps,
          llmDirectives: parsed.llmDirectives || loaded.config.llmDirectives === true,
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
        if (parsed.failUnder !== undefined && report.defenseScore < parsed.failUnder) {
          return 2;
        }
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
    process.argv[1].endsWith("bla-agents") ||
    process.argv[1].endsWith("bla-shield"));

if (isDirectExecution) {
  runCli().then((code) => {
    if (process.argv[2] !== "mcp" && !process.argv.includes("--mcp")) {
      process.exitCode = code;
    }
  });
}
