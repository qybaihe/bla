#!/usr/bin/env node
/**
 * Empirical red-team harness: unhardened vs BLA-hardened samples against
 * real in-process REA parsers. Writes docs/redteam/empirical-rea-validation.{md,json}.
 */
import { spawnSync } from "node:child_process";
import {
  BLA_ROOT,
  REA_ROOT,
  resolveTsharkEnv,
  reaDistReady,
} from "./lib/paths.mjs";
import { buildSampleMatrix } from "./lib/samples.mjs";
import {
  loadReaProbes,
  probeGo,
  probeFlutterPool,
  probeBeam,
  probeEvm,
  probePcap,
  probeSafetensors,
  probeGguf,
  probePtx,
  probeAsar,
  probeWasm,
  probeSqlite,
  probeElectronFuses,
  probeJavascript,
  unverifiedAnalyzers,
} from "./lib/probes.mjs";
import { writeReports } from "./lib/report.mjs";

function tsharkVersion(env) {
  if (!env.available) return null;
  const r = spawnSync(env.bin, ["-v"], { encoding: "utf8", env: env.env });
  const line = (r.stdout || r.stderr || "").split("\n")[0] || "";
  return line.trim() || "tshark (version unknown)";
}

async function main() {
  if (!reaDistReady()) {
    // Honest agent-facing status: exit 0 keeps CI green when REA is optional,
    // but never imply a red-team pass. MCP bla_redteam_report uses the same word.
    console.log(
      "SKIP: sibling REA dist not ready (expected at ../rea or $REA_ROOT). " +
        "Red-team empirical gates require a local REA checkout; CI skips when absent.",
    );
    console.log(
      JSON.stringify({
        schema: "bla-redteam-rea/v1",
        status: "unverified",
        reason:
          "Sibling REA dist not ready — empirical redteam:rea did not run (not a pass).",
      }),
    );
    process.exit(0);
  }
  const tshark = resolveTsharkEnv();
  const { bla, intensity, seed, samples } = await buildSampleMatrix();
  const rea = await loadReaProbes();
  const limits = bla.REA_INTERNAL_LIMITS;

  const pairs = [];

  // Shared ELF: Go build-info + Flutter isolate pool
  {
    const s = samples.go_flutter_elf;
    const goBefore = await probeGo(rea, s.before, "before");
    const goAfter = await probeGo(rea, s.after, "after");
    pairs.push({
      format: "go_buildinfo",
      before: goBefore,
      after: goAfter,
      sampleMeta: s.meta,
      blaLimits: limits,
    });
    const flBefore = await probeFlutterPool(bla, s.before, "before", limits);
    const flAfter = await probeFlutterPool(bla, s.after, "after", limits);
    pairs.push({
      format: "flutter_pool",
      before: flBefore,
      after: flAfter,
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.erlang_beam;
    pairs.push({
      format: "erlang_beam",
      before: await probeBeam(rea, s.before, "before"),
      after: await probeBeam(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.evm_bytecode;
    pairs.push({
      format: "evm_bytecode",
      before: await probeEvm(rea, s.before, "before"),
      after: await probeEvm(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.pcap_capture;
    pairs.push({
      format: "pcap_capture",
      before: await probePcap(rea, s.before, "before"),
      after: await probePcap(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.safetensors;
    pairs.push({
      format: "safetensors",
      before: await probeSafetensors(rea, s.before, "before"),
      after: await probeSafetensors(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.gguf;
    pairs.push({
      format: "gguf",
      before: await probeGguf(rea, s.before, "before"),
      after: await probeGguf(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.gpu_ptx;
    pairs.push({
      format: "gpu_ptx",
      before: await probePtx(rea, s.before, "before"),
      after: await probePtx(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }


  {
    const s = samples.electron_asar;
    pairs.push({
      format: "electron_asar",
      before: await probeAsar(rea, s.before, "before"),
      after: await probeAsar(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.wasm_module;
    pairs.push({
      format: "wasm_module",
      before: await probeWasm(rea, bla, s.before, "before", s.meta),
      after: await probeWasm(rea, bla, s.after, "after", s.meta),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.sqlite_db;
    pairs.push({
      format: "sqlite_db",
      before: await probeSqlite(rea, bla, s.before, "before"),
      after: await probeSqlite(rea, bla, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.electron_fuses;
    pairs.push({
      format: "electron_fuses",
      before: await probeElectronFuses(rea, s.before, "before"),
      after: await probeElectronFuses(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  {
    const s = samples.javascript;
    pairs.push({
      format: "javascript",
      before: await probeJavascript(rea, s.before, "before"),
      after: await probeJavascript(rea, s.after, "after"),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  const run = {
    generatedAt: new Date().toLocaleString("en-CA", {
      timeZone: "Asia/Shanghai",
      hour12: false,
    }),
    blaRoot: BLA_ROOT,
    reaRoot: REA_ROOT,
    intensity,
    seed,
    nodeVersion: process.version,
    tshark: {
      available: tshark.available,
      version: tsharkVersion(tshark),
    },
    pairs,
    unverified: unverifiedAnalyzers(),
  };

  const { mdPath, jsonPath } = writeReports(run);

  // Console summary for CI / gates
  console.log("Empirical REA red-team complete");
  console.log(`  report: ${mdPath}`);
  console.log(`  json:   ${jsonPath}`);
  for (const pair of pairs) {
    const tag = pair.after.budgetHit
      ? `BUDGET ${pair.after.budgetName}`
      : pair.after.status;
    console.log(
      `  ${pair.format.padEnd(16)} before=${pair.before.status.padEnd(12)} after=${tag}  (${pair.before.inputBytes} → ${pair.after.inputBytes} B)`,
    );
  }
  const diverges = pairs.filter((p) => {
    // soft check: after should hit for go/flutter/beam/evm/pcap/gguf + asar/wasm/fuses
    // sqlite must-trip only when DatabaseSync.limits made the probe runnable
    const must = new Set([
      "go_buildinfo",
      "flutter_pool",
      "erlang_beam",
      "evm_bytecode",
      "pcap_capture",
      "gguf",
      "safetensors",
      "electron_asar",
      "wasm_module",
      "electron_fuses",
    ]);
    if (p.format === "sqlite_db") {
      if (
        p.after.status === "capability_gated" ||
        p.after.status === "skipped"
      )
        return false;
      return !p.after.budgetHit;
    }
    if (!must.has(p.format)) return false;
    if (p.format === "pcap_capture" && p.after.status === "skipped") return false;
    return !p.after.budgetHit;
  });
  if (diverges.length) {
    console.error(
      `WARNING: ${diverges.length} format(s) did not trip REA budgets: ${diverges.map((d) => d.format).join(", ")}`,
    );
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
