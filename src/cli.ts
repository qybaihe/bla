#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { BLA_IDENTITY } from "./identity.js";
import {
  initBlaConfig,
  loadBlaConfig,
  resolveProjectSeed,
  type BlaProjectConfig,
} from "./core/config.js";
import { inspectReleaseExposure } from "./core/release-exposure.js";
import { buildSarifReport } from "./core/sarif.js";
import { verifyManifestFile } from "./core/manifest-verify.js";
import type { ProtectionIntensity } from "./core/types.js";
import { auditTarget } from "./engine/auditor.js";
import { protectTarget } from "./engine/protector.js";
import { verifyTarget } from "./engine/verifier.js";
import { defendTarget } from "./engine/defender.js";
import { formatHardenProjectReport, hardenProject } from "./engine/harden.js";
import { lintLaneIndependence } from "./engine/lane-independence-lint.js";
import { lintSealCommitmentFile } from "./engine/seal-commitment-lint.js";
import { lintWasmParamCarrierFile } from "./engine/wasm-param-carrier-lint.js";
import { lintPanelDeriveAbiFile } from "./engine/panel-derive-abi-lint.js";
import { lintJsAesUnwrapFile } from "./engine/js-aes-unwrap-lint.js";
import { lintJsWasmHydrateDumpFile } from "./engine/js-wasm-hydrate-dump-lint.js";
import { lintWasmXorMaskSidecarFile } from "./engine/wasm-xor-mask-sidecar-lint.js";
import { lintWasmSealXorKnownPlaintextFile } from "./engine/wasm-seal-xor-known-plaintext-lint.js";
import {
  scanPackagingGates,
  formatPackagingGatesReport,
} from "./engine/packaging-gates.js";
import { runShowcaseBenchmark } from "./engine/benchmark.js";
import {
  emitCompileTimeNativeHeader,
  type NativeHeaderLanguage,
} from "./shields/formats/headers.js";
import { type SupportedAgentClientId } from "./setup/clients.js";
import { runSetup, runUninstall } from "./setup/setup.js";
import { runDoctor } from "./setup/doctor.js";
import { startMcpStdioServer } from "./mcp/server.js";
import { buildWeavePlan, verifyWeaveTarget } from "./shields/weave/weave-decoy.js";
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
  lint [dir]                  DEFAULT packaging gate scan (all R1–R7 refuse lints + lanes/panel); exit 2 on refuse
  lint-lanes <file>           Heuristic ERROR if gate code looks lane-independent (issue #40.1); exit 2
  lint-wasm-params <file>    Heuristic ERROR if WASM embeds clear R3PARM/R3CIPH/R2SEAL-class carriers; exit 2
  lint-panel-derive <file>   Heuristic ERROR if stable __vaultPanelDerive_* / deriveLocal oracle remains; exit 2
  lint-js-aes-unwrap <file>  Heuristic ERROR if JS AES wrap-key + create*iv + fixed hdr unwrap; exit 2
  lint-js-wasm-hydrate-dump <file>  Heuristic ERROR if JS dumps WASM hydrate salt/rounds/cipher; exit 2
  lint-wasm-xor-mask-sidecar <file> Heuristic ERROR if WASM data has XOR-mask beside masked entitlement pack; exit 2
  lint-wasm-seal-xor-known-plaintext <wasm>  Heuristic ERROR if seal.revision is XOR known-plaintext in WASM pack; exit 2
  lint-seal <file>            Heuristic lint for plaintext/reversible seal sidecars (red-blue round-2); exit 2 on error
  protect <target>            Inject multi-layer Counter-REA adversarial shield
  verify <target> [original]  Verify Counter-REA defense invariants & token amplification
  weave-plan <target>         Emit AST-level surgical weave workorder (bla-weave-plan/v1)
  verify-weave <target>       Verify Agent-authored source weave & return agentActions (exit 2 on fail)
  benchmark                   Run the 14-target Counter-REA Showcase Benchmark suite
  emit-headers                Generate compile-time C/C++, Rust, or Go defense headers
  verify-manifest <file>      Verify a signed .bla-manifest.json (exit 2 when invalid)
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
  --manifest                  Emit .bla-manifest.json next to protected artifacts (opt-in; unsigned by default)
  --sign-manifest             Ed25519-sign the emitted manifest (implies --manifest; requires --manifest-key)
  --manifest-key <path>       Ed25519 private key PEM file used by --sign-manifest
  --public-key <path>         Trusted ed25519 public key PEM for verify-manifest
  --llm-directives            Opt-in risky LLM directive layers (COPPA/medical bait, dual-use imitation, AI chat markers); OFF by default
  --weave-decoys              Opt-in structural weave decoys (Python customer-def / .pyc co_consts weave; JS AST weave already on); OFF by default
  --self-seal                 Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5); OFF by default
  --sidecar-entangle          Opt-in sidecar/entry entanglement strip⇒fail for JS/Python (issue #40); OFF by default
  --wasm-preserve-exports <a,b>  Comma-separated WASM export names to keep as public ABI (issue #40.3)
  --allow-lane-independent    Allow harden/defend of lane-independent JS gates (issue #40.1); OFF by default
  --allow-plaintext-seal      Allow bankrupt harden despite plaintext/reversible seal JSON (round-2); OFF by default
  --allow-js-wasm-hydrate-dump  Allow bankrupt despite JS←WASM hydrate param-dump (round-5); OFF by default
  --allow-wasm-xor-mask-sidecar  Allow bankrupt despite WASM XOR-mask-beside-blob packs (round-6); OFF by default
  --allow-wasm-seal-xor-known-plaintext  Allow bankrupt despite seal.revision XOR known-plaintext packs (round-7); OFF by default
  --lang <c|rust|go>          Target language for emit-headers (default: c)
  --fail-under <n>            Exit 2 when the score fails the gate: defense score < n (defend/verify) or audit exposure score > n (audit)
  --client <id>               Agent client ID for setup (repeatable: claude_code, cursor, codex, etc.)
  --all-detected              Configure all detected coding agents on this machine
  --dry-run                   Preview planned setup/harden changes without writing files
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
  readonly signManifest: boolean;
  readonly manifestKey?: string;
  readonly publicKey?: string;
  readonly llmDirectives: boolean;
  readonly weaveDecoys: boolean;
  readonly selfSeal: boolean;
  readonly sidecarEntangle: boolean;
  readonly wasmPreserveExports: readonly string[];
  readonly allowLaneIndependentGates: boolean;
  readonly allowPlaintextSeal: boolean;
  readonly allowWasmClearParamCarriers: boolean;
  readonly allowStablePanelDeriveAbi: boolean;
  readonly allowJsAesUnwrap: boolean;
  readonly allowPanelOfflineOracle: boolean;
  readonly allowJsWasmHydrateDump: boolean;
  readonly allowWasmXorMaskSidecar: boolean;
  readonly allowWasmSealXorKnownPlaintext: boolean;
  readonly lang: NativeHeaderLanguage;
  readonly clients: SupportedAgentClientId[];
  readonly allDetected: boolean;
  readonly dryRun: boolean;
  readonly yes: boolean;
  readonly json: boolean;
  readonly sarif: boolean;
  readonly failUnder?: number;
  readonly argErrors: readonly string[];
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
  let signManifest = false;
  let manifestKey: string | undefined;
  let publicKey: string | undefined;
  let llmDirectives = false;
  let weaveDecoys = false;
  let selfSeal = false;
  let sidecarEntangle = false;
  let wasmPreserveExports: string[] = [];
  let allowLaneIndependentGates = false;
  let allowPlaintextSeal = false;
  let allowWasmClearParamCarriers = false;
  let allowStablePanelDeriveAbi = false;
  let allowJsAesUnwrap = false;
  let allowJsWasmHydrateDump = false;
  let allowWasmXorMaskSidecar = false;
  let allowWasmSealXorKnownPlaintext = false;
  let allowPanelOfflineOracle = false;
  let lang: NativeHeaderLanguage = "c";
  const clients: SupportedAgentClientId[] = [];
  const argErrors: string[] = [];
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
    } else if (arg === "--sign-manifest") {
      signManifest = true;
    } else if (arg === "--manifest-key" && i + 1 < argv.length) {
      manifestKey = argv[++i]!;
    } else if (arg === "--public-key" && i + 1 < argv.length) {
      publicKey = argv[++i]!;
    } else if (arg === "--llm-directives") {
      llmDirectives = true;
    } else if (arg === "--weave-decoys") {
      weaveDecoys = true;
    } else if (arg === "--self-seal") {
      selfSeal = true;
    } else if (arg === "--sidecar-entangle") {
      sidecarEntangle = true;
    } else if (arg === "--allow-lane-independent") {
      allowLaneIndependentGates = true;
    } else if (arg === "--allow-plaintext-seal") {
      allowPlaintextSeal = true;
    } else if (arg === "--allow-wasm-clear-params") {
      allowWasmClearParamCarriers = true;
    } else if (arg === "--allow-stable-panel-derive") {
      allowStablePanelDeriveAbi = true;
    } else if (arg === "--allow-js-aes-unwrap") {
      allowJsAesUnwrap = true;
    } else if (arg === "--allow-panel-offline-oracle") {
      allowPanelOfflineOracle = true;
    } else if (arg === "--allow-js-wasm-hydrate-dump") {
      allowJsWasmHydrateDump = true;
    } else if (arg === "--allow-wasm-xor-mask-sidecar") {
      allowWasmXorMaskSidecar = true;
    } else if (arg === "--allow-wasm-seal-xor-known-plaintext") {
      allowWasmSealXorKnownPlaintext = true;
    } else if (arg.startsWith("--wasm-preserve-exports=")) {
      wasmPreserveExports = arg
        .slice("--wasm-preserve-exports=".length)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (arg === "--wasm-preserve-exports" && i + 1 < argv.length) {
      wasmPreserveExports = argv[++i]!
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (arg === "--mcp") {
      command = "mcp";
    } else if (arg === "--update") {
      command = "update";
    } else if ((arg === "-o" || arg === "--output") && i + 1 < argv.length) {
      output = argv[++i]!;
    } else if ((arg === "-c" || arg === "--config") && i + 1 < argv.length) {
      configPath = argv[++i]!;
    } else if (arg === "--fail-under") {
      const raw = argv[++i];
      const n = raw === undefined ? Number.NaN : Number(raw);
      if (raw === undefined) {
        argErrors.push("--fail-under requires a value");
      } else if (!Number.isFinite(n) || n < 0 || n > 100) {
        argErrors.push(`--fail-under must be a number between 0 and 100 (received '${raw}')`);
      } else {
        failUnder = n;
      }
    } else if (arg === "--intensity") {
      const val = argv[++i];
      if (val === undefined) {
        argErrors.push("--intensity requires a value");
      } else if (!["stealth", "balanced", "maximum", "bankrupt"].includes(val)) {
        argErrors.push(`--intensity must be one of stealth, balanced, maximum, bankrupt (received '${val}')`);
      } else {
        intensity = val as ProtectionIntensity;
      }
    } else if (arg === "--seed") {
      const val = argv[++i];
      if (val === undefined || val.trim().length === 0) {
        argErrors.push("--seed requires a non-empty value");
      } else {
        seed = val;
      }
    } else if (arg === "--lang") {
      const val = argv[++i];
      if (val === undefined) {
        argErrors.push("--lang requires a value");
      } else if (!["c", "rust", "go"].includes(val)) {
        argErrors.push(`--lang must be one of c, rust, go (received '${val}')`);
      } else {
        lang = val as NativeHeaderLanguage;
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
    signManifest,
    ...(manifestKey !== undefined ? { manifestKey } : {}),
    ...(publicKey !== undefined ? { publicKey } : {}),
    llmDirectives,
    weaveDecoys,
    selfSeal,
    sidecarEntangle,
    wasmPreserveExports,
    allowLaneIndependentGates,
    allowPlaintextSeal,
    allowWasmClearParamCarriers,
    allowStablePanelDeriveAbi,
    allowJsAesUnwrap,
    allowPanelOfflineOracle,
    allowJsWasmHydrateDump,
    allowWasmXorMaskSidecar,
    allowWasmSealXorKnownPlaintext,
    lang,
    clients,
    allDetected,
    dryRun,
    yes,
    json,
    sarif,
    ...(failUnder !== undefined ? { failUnder } : {}),
    argErrors,
    honeyMaps,
    help,
    version,
  };
}

/** Merge CLI and .blarc WASM export preservation lists without duplicates. */
function mergeWasmPreserveExports(
  parsed: ParsedCliArgs,
  config: BlaProjectConfig,
): { wasmPreserveExports?: readonly string[] } {
  const merged = [
    ...new Set([...(config.wasmPreserveExports ?? []), ...parsed.wasmPreserveExports]),
  ];
  return merged.length > 0 ? { wasmPreserveExports: merged } : {};
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

  if (parsed.argErrors.length > 0) {
    for (const message of parsed.argErrors) console.error(`Error: ${message}`);
    return 1;
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
        // Dry-run must write zero bytes: skip seed persistence into .blarc.
        const seed = parsed.dryRun
          ? parsed.seed
          : resolveProjectSeed(
              typeof directory === "string" ? directory : process.cwd(),
              parsed.seed,
              parsed.configPath,
            ).seed;
        const report = hardenProject({
          directory,
          intensity: explicitIntensity,
          ...(seed !== undefined ? { seed } : {}),
          dryRun: parsed.dryRun,
          emitManifest: parsed.manifest || parsed.signManifest === true || loaded.config.emitManifest === true,
          ...(parsed.signManifest === true
            ? { signManifest: true, manifestSigningKeyPath: parsed.manifestKey ?? "" }
            : {}),
          llmDirectives: parsed.llmDirectives || loaded.config.llmDirectives === true,
          weaveDecoys: parsed.weaveDecoys || loaded.config.weaveDecoys === true,
          selfSeal: parsed.selfSeal || loaded.config.selfSeal === true,
          sidecarEntangle: parsed.sidecarEntangle || loaded.config.sidecarEntangle === true,
          ...mergeWasmPreserveExports(parsed, loaded.config),
          allowLaneIndependentGates:
            parsed.allowLaneIndependentGates ||
            loaded.config.allowLaneIndependentGates === true,
          allowPlaintextSeal:
            parsed.allowPlaintextSeal ||
            loaded.config.allowPlaintextSeal === true,
          allowWasmClearParamCarriers:
            parsed.allowWasmClearParamCarriers ||
            loaded.config.allowWasmClearParamCarriers === true,
          allowStablePanelDeriveAbi:
            parsed.allowStablePanelDeriveAbi ||
            loaded.config.allowStablePanelDeriveAbi === true,
          allowJsAesUnwrap:
            parsed.allowJsAesUnwrap ||
            loaded.config.allowJsAesUnwrap === true,
          allowPanelOfflineOracle:
            parsed.allowPanelOfflineOracle ||
            loaded.config.allowPanelOfflineOracle === true,
          allowJsWasmHydrateDump:
            parsed.allowJsWasmHydrateDump ||
            loaded.config.allowJsWasmHydrateDump === true,
          allowWasmXorMaskSidecar:
            parsed.allowWasmXorMaskSidecar ||
            loaded.config.allowWasmXorMaskSidecar === true,
          allowWasmSealXorKnownPlaintext:
            parsed.allowWasmSealXorKnownPlaintext ||
            loaded.config.allowWasmSealXorKnownPlaintext === true,
          ...(parsed.output !== undefined ? { outputDirectory: parsed.output } : {}),
        });
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(formatHardenProjectReport(report));
        }
        if (report.dryRun) return report.discoveredCount === 0 ? 2 : 0;
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
          emitManifest: parsed.manifest || parsed.signManifest === true || loaded.config.emitManifest === true,
          ...(parsed.signManifest === true
            ? { signManifest: true, manifestSigningKeyPath: parsed.manifestKey ?? "" }
            : {}),
          llmDirectives: parsed.llmDirectives || loaded.config.llmDirectives === true,
          weaveDecoys: parsed.weaveDecoys || loaded.config.weaveDecoys === true,
          selfSeal: parsed.selfSeal || loaded.config.selfSeal === true,
          sidecarEntangle: parsed.sidecarEntangle || loaded.config.sidecarEntangle === true,
          ...mergeWasmPreserveExports(parsed, loaded.config),
          allowLaneIndependentGates:
            parsed.allowLaneIndependentGates ||
            loaded.config.allowLaneIndependentGates === true,
          allowPlaintextSeal:
            parsed.allowPlaintextSeal ||
            loaded.config.allowPlaintextSeal === true,
          allowWasmClearParamCarriers:
            parsed.allowWasmClearParamCarriers ||
            loaded.config.allowWasmClearParamCarriers === true,
          allowStablePanelDeriveAbi:
            parsed.allowStablePanelDeriveAbi ||
            loaded.config.allowStablePanelDeriveAbi === true,
          allowJsAesUnwrap:
            parsed.allowJsAesUnwrap ||
            loaded.config.allowJsAesUnwrap === true,
          allowPanelOfflineOracle:
            parsed.allowPanelOfflineOracle ||
            loaded.config.allowPanelOfflineOracle === true,
          allowJsWasmHydrateDump:
            parsed.allowJsWasmHydrateDump ||
            loaded.config.allowJsWasmHydrateDump === true,
          allowWasmXorMaskSidecar:
            parsed.allowWasmXorMaskSidecar ||
            loaded.config.allowWasmXorMaskSidecar === true,
          allowWasmSealXorKnownPlaintext:
            parsed.allowWasmSealXorKnownPlaintext ||
            loaded.config.allowWasmSealXorKnownPlaintext === true,
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

      case "lint": {
        const target = parsed.positionals[0] ?? ".";
        const report = scanPackagingGates({
          directory: resolve(target),
          intensity: (parsed.intensity as "stealth" | "balanced" | "maximum" | "bankrupt") ?? "bankrupt",
          allowPlaintextSeal: parsed.allowPlaintextSeal,
          allowWasmClearParamCarriers: parsed.allowWasmClearParamCarriers,
          allowJsAesUnwrap: parsed.allowJsAesUnwrap,
          allowJsWasmHydrateDump: parsed.allowJsWasmHydrateDump,
          allowWasmXorMaskSidecar: parsed.allowWasmXorMaskSidecar,
          allowWasmSealXorKnownPlaintext: parsed.allowWasmSealXorKnownPlaintext,
          allowLaneIndependentGates: parsed.allowLaneIndependentGates,
          allowPanelOfflineOracle: parsed.allowPanelOfflineOracle,
          allowStablePanelDeriveAbi: parsed.allowStablePanelDeriveAbi,
          includeProtectTimeGates: true,
        });
        if (parsed.json) {
          // Strip heavy details.details raw blobs for CLI JSON by default — keep findings/blocking.
          const { details: _details, ...compact } = report;
          console.log(JSON.stringify({ ...compact, detailCounts: {
            seals: report.details.seals.length,
            wasmParams: report.details.wasmParams.length,
            jsAes: report.details.jsAes.length,
            jsHydrateDump: report.details.jsHydrateDump.length,
            wasmXorMask: report.details.wasmXorMask.length,
            wasmSealXor: report.details.wasmSealXor.length,
            lanes: report.details.lanes.length,
            panelDerive: report.details.panelDerive.length,
          } }, null, 2));
        } else {
          console.log(formatPackagingGatesReport(report));
        }
        return report.shouldRefuseBankrupt ? 2 : 0;
      }

      case "lint-lanes": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-lanes <file>`.");
          return 1;
        }
        const source = readFileSync(resolve(target), "utf8");
        const report = lintLaneIndependence(source);
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA lane-independence lint — ${resolve(target)}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.looksLaneIndependent ? 2 : 0;
      }
      case "lint-seal": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-seal <file>`.");
          return 1;
        }
        const report = lintSealCommitmentFile(resolve(target));
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA seal-commitment lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt || report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
      }
      case "lint-wasm-params": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-wasm-params <file>`.");
          return 1;
        }
        const report = lintWasmParamCarrierFile(resolve(target));
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA wasm-param-carrier lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary} @${f.offset}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt || report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
      }
      case "lint-panel-derive": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-panel-derive <file>`.");
          return 1;
        }
        const report = lintPanelDeriveAbiFile(resolve(target));
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA panel-derive ABI lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt ||
          report.shouldRewriteOrRefuse ||
          report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
      }
      case "lint-js-aes-unwrap": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-js-aes-unwrap <file>`.");
          return 1;
        }
        const report = lintJsAesUnwrapFile(resolve(target));
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA js-aes-unwrap lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt || report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
      }

      case "lint-js-wasm-hydrate-dump": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-js-wasm-hydrate-dump <file>`.");
          return 1;
        }
        const report = lintJsWasmHydrateDumpFile(resolve(target));
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA js-wasm-hydrate-dump lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt || report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
      }
      case "lint-wasm-xor-mask-sidecar": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <file> path for `bla lint-wasm-xor-mask-sidecar <file>`.");
          return 1;
        }
        const report = lintWasmXorMaskSidecarFile(resolve(target));
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA wasm-xor-mask-sidecar lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt || report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
      }


      case "lint-wasm-seal-xor-known-plaintext": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <wasm> path for `bla lint-wasm-seal-xor-known-plaintext <wasm>`.");
          return 1;
        }
        const sealArg = parsed.positionals[1];
        const report = lintWasmSealXorKnownPlaintextFile(resolve(target), sealArg ? resolve(sealArg) : undefined);
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`BLA wasm-seal-xor-known-plaintext lint — ${report.path}`);
          console.log(report.oneLineAdvice);
          for (const f of report.findings) {
            console.log(`  [${f.severity}] ${f.id}: ${f.summary}`);
            if (f.evidence) console.log(`    evidence: ${f.evidence}`);
          }
          if (report.findings.length === 0) {
            console.log("  (no findings)");
          }
        }
        return report.shouldRefuseBankrupt || report.findings.some((f) => f.severity === "error")
          ? 2
          : 0;
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
        // CI gating parity with defend/verify: exposureScore is 0 (fully shielded)
        // to 100 (completely exposed), so fail when it exceeds the threshold.
        if (parsed.failUnder !== undefined && report.exposureScore > parsed.failUnder) {
          return 2;
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
          weaveDecoys: parsed.weaveDecoys || loaded.config.weaveDecoys === true,
          selfSeal: parsed.selfSeal || loaded.config.selfSeal === true,
          sidecarEntangle: parsed.sidecarEntangle || loaded.config.sidecarEntangle === true,
          ...mergeWasmPreserveExports(parsed, loaded.config),
          allowLaneIndependentGates:
            parsed.allowLaneIndependentGates ||
            loaded.config.allowLaneIndependentGates === true,
          allowPlaintextSeal:
            parsed.allowPlaintextSeal ||
            loaded.config.allowPlaintextSeal === true,
          allowWasmClearParamCarriers:
            parsed.allowWasmClearParamCarriers ||
            loaded.config.allowWasmClearParamCarriers === true,
          allowStablePanelDeriveAbi:
            parsed.allowStablePanelDeriveAbi ||
            loaded.config.allowStablePanelDeriveAbi === true,
          allowJsAesUnwrap:
            parsed.allowJsAesUnwrap ||
            loaded.config.allowJsAesUnwrap === true,
          allowPanelOfflineOracle:
            parsed.allowPanelOfflineOracle ||
            loaded.config.allowPanelOfflineOracle === true,
          allowJsWasmHydrateDump:
            parsed.allowJsWasmHydrateDump ||
            loaded.config.allowJsWasmHydrateDump === true,
          allowWasmXorMaskSidecar:
            parsed.allowWasmXorMaskSidecar ||
            loaded.config.allowWasmXorMaskSidecar === true,
          allowWasmSealXorKnownPlaintext:
            parsed.allowWasmSealXorKnownPlaintext ||
            loaded.config.allowWasmSealXorKnownPlaintext === true,
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

      case "verify-manifest": {
        const target = parsed.positionals[0];
        if (!target) {
          console.error("Error: Missing <manifest> path for `bla verify-manifest <manifest> [--public-key <pem>]`.");
          return 1;
        }
        const result = verifyManifestFile(target, parsed.publicKey);
        if (parsed.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`${result.ok ? "VALID" : "INVALID"}: ${result.reason}`);
        }
        return result.ok ? 0 : 2;
      }

      case "weave-plan": {
        const target = parsed.positionals[0] ?? process.cwd();
        const plan = buildWeavePlan(target);
        console.log(JSON.stringify(plan, null, 2));
        return plan.overallStatus === "unsupported" ? 2 : 0;
      }

      case "verify-weave": {
        const target = parsed.positionals[0] ?? process.cwd();
        const report = verifyWeaveTarget(target);
        if (parsed.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`${report.overallPassed ? "PASSED" : "FAILED"} (weaveScore: ${report.weaveScore}/100): ${report.summary}`);
          for (const action of report.agentActions) {
            console.log(`  - [${action.priority}] ${action.file} (${action.checkId}): ${action.instruction}`);
          }
        }
        return report.overallPassed ? 0 : 2;
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
