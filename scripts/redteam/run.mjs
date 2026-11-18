#!/usr/bin/env node
/**
 * Empirical red-team harness: unhardened vs BLA-hardened samples against
 * real in-process REA parsers. Writes docs/redteam/empirical-rea-validation.{md,json}.
 *
 * Exit codes:
 *   0  every probe that can run on this machine measured what BLA expects.
 *      (No REA checkout at all also exits 0 — it prints status "unverified" —
 *      so CI without REA stays green.)
 *   1  REA read a hardened sample it was expected to stop on, or the harness
 *      crashed for another reason.
 *   2  a probe could not call REA at all (a renamed export, a moved module).
 *      Nothing was measured for that format: the harness is out of date with
 *      this REA revision, which says nothing about the shield.
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
  probeJavascriptStrings,
  unverifiedAnalyzers,
  harnessErrors,
} from "./lib/probes.mjs";
import { writeReports } from "./lib/report.mjs";

const EXIT_DIVERGED = 1;
const EXIT_UNVERIFIED = 2;

function tsharkVersion(env) {
  if (!env.available) return null;
  const r = spawnSync(env.bin, ["-v"], { encoding: "utf8", env: env.env });
  const line = (r.stdout || r.stderr || "").split("\n")[0] || "";
  return line.trim() || "tshark (version unknown)";
}

/**
 * Whether REA read a hardened sample this format's plant is meant to stop it
 * on. go_buildinfo: a format error (truncated) is not a regression while REA
 * still cannot read it — only a clean read with no budget hit counts.
 */
function wasNotStopped(p) {
  // harness_error probes are unverified, not divergent
  if (p.after.status === "harness_error") return false;
  // soft check: after should hit for flutter/beam/pcap/gguf + asar/wasm/fuses
  // sqlite must-trip only when DatabaseSync.limits made the probe runnable
  const must = new Set([
    "flutter_pool",
    "erlang_beam",
    "pcap_capture",
    "gguf",
    "safetensors",
    "electron_asar",
    "wasm_module",
    "electron_fuses",
  ]);
  // javascript_strings: a known value in REA's result — at its default
  // budgets or at raised ones — means the string encoding was read through.
  if (p.format === "javascript_strings") {
    return !(
      p.after.metrics?.valuesHiddenAtDefaultBudgets === true &&
      p.after.metrics?.valuesHiddenAtRaisedBudgets === true
    );
  }
  // go_buildinfo: REA at 05be423 checks "string range is truncated" before
  // max_build_info_bytes, so the planted length is rejected as malformed
  // rather than as over budget. Either way REA reads no build info; only a
  // clean read with no budget hit means the plant stopped working.
  if (p.format === "go_buildinfo") {
    return p.after.status === "ok" && !p.after.budgetHit;
  }
  // evm_bytecode: the sample is padded to just under REA's input budget on
  // purpose. Over it, or within 8 KiB of it, is what the shield aims for.
  if (p.format === "evm_bytecode") {
    return !(p.after.budgetHit || p.after.metrics?.approachesLimit === true);
  }
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
}

/** Resolve REA commit hash and date, soft-fail to null. */
function resolveReaProvenance() {
  try {
    const hash = spawnSync("git", ["-C", REA_ROOT, "rev-parse", "HEAD"], {
      encoding: "utf8",
      timeout: 5000,
    });
    const date = spawnSync(
      "git",
      ["-C", REA_ROOT, "log", "-1", "--format=%ci"],
      { encoding: "utf8", timeout: 5000 },
    );
    if (hash.status === 0 && date.status === 0) {
      return {
        commit: (hash.stdout || "").trim(),
        date: (date.stdout || "").trim(),
      };
    }
  } catch {
    /* not a git checkout */
  }
  return { commit: null, date: null };
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
  // REA first: whether this checkout can be called at all is known before any
  // sample is built.
  let rea;
  try {
    rea = await loadReaProbes();
  } catch (err) {
    const reason = `the harness could not load REA's analyzers: ${err instanceof Error ? err.message : String(err)}`;
    console.error(
      `UNVERIFIED: ${reason}. Nothing was measured; scripts/redteam/lib/probes.mjs names REA modules this checkout does not have.`,
    );
    console.log(
      JSON.stringify({
        schema: "bla-redteam-rea/v1",
        status: "unverified",
        reason,
      }),
    );
    process.exit(EXIT_UNVERIFIED);
  }
  const { bla, intensity, seed, samples } = await buildSampleMatrix();
  const limits = bla.REA_INTERNAL_LIMITS;
  const reaProvenance = resolveReaProvenance();

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

  {
    const s = samples.javascript_strings;
    pairs.push({
      format: "javascript_strings",
      before: await probeJavascriptStrings(rea, s.before, "before", s.meta.values),
      after: await probeJavascriptStrings(rea, s.after, "after", s.meta.values),
      sampleMeta: s.meta,
      blaLimits: limits,
    });
  }

  // "measured": every probe that can run on this machine ran against REA.
  // "unverified": at least one probe could not call REA at all (a renamed
  // export, a moved module) — that format was not measured, whatever its row says.
  // Both sources, once each: a module that could not be loaded, and a probe
  // that threw something other than one of REA's own failures.
  const harnessFailureIndex = new Map();
  for (const failure of [
    ...harnessErrors(),
    ...pairs.flatMap((p) =>
      [p.before, p.after]
        .filter((outcome) => outcome.status === "harness_error")
        .map((outcome) => ({
          format: p.format,
          reason: `${outcome.errorName ?? "Error"}: ${outcome.errorMessage ?? "the probe could not call REA"}`,
        })),
    ),
  ]) {
    harnessFailureIndex.set(`${failure.format}\n${failure.reason}`, failure);
  }
  const harnessFailures = [...harnessFailureIndex.values()];
  const hasHarnessErrors = harnessFailures.length > 0;
  const overallStatus = hasHarnessErrors ? "unverified" : "measured";

  // Formats whose plant is meant to stop REA, where REA read the hardened
  // sample: the report records them, and the run exits 1.
  const notStopped = pairs.filter(wasNotStopped).map((p) => p.format);

  const run = {
    schema: "bla-redteam-rea/v1",
    status: overallStatus,
    generatedAt: new Date().toLocaleString("en-CA", {
      timeZone: "Asia/Shanghai",
      hour12: false,
    }),
    // The report is committed: where the two checkouts sat on the machine
    // that ran it is nobody's business and says nothing. REA is identified by
    // its commit (reaProvenance), BLA by the release this tree builds.
    blaRoot: ".",
    reaRoot: (process.env.REA_ROOT ?? "").trim() ? "$REA_ROOT" : "../rea",
    blaVersion: bla.BLA_VERSION ?? null,
    reaProvenance,
    intensity,
    seed,
    nodeVersion: process.version,
    tshark: {
      available: tshark.available,
      version: tsharkVersion(tshark),
      source: tshark.source,
    },
    pairs,
    notStopped,
    unverified: unverifiedAnalyzers(),
    harnessErrors: harnessFailures,
  };

  const { mdPath, jsonPath } = writeReports(run);

  // Console summary for CI / gates
  console.log(`Empirical REA red-team complete (status: ${overallStatus})`);
  console.log(`  REA: ${reaProvenance.commit ?? "unknown"} (${reaProvenance.date ?? "unknown"})`);
  console.log(`  report: ${mdPath}`);
  console.log(`  json:   ${jsonPath}`);
  for (const pair of pairs) {
    const tag = pair.after.status === "harness_error"
      ? "HARNESS_ERROR"
      : pair.after.budgetHit
        ? `BUDGET ${pair.after.budgetName}`
        : pair.after.status;
    console.log(
      `  ${pair.format.padEnd(16)} before=${pair.before.status.padEnd(12)} after=${tag}  (${pair.before.inputBytes} → ${pair.after.inputBytes} B)`,
    );
  }

  if (notStopped.length) {
    console.error(
      `WARNING: ${notStopped.length} format(s) did not trip REA budgets: ${notStopped.join(", ")}`,
    );
    process.exitCode = EXIT_DIVERGED;
  }
  if (hasHarnessErrors) {
    // Not a pass: these formats were not measured. Update the harness for
    // this REA revision instead of reading their rows.
    console.error(
      `UNVERIFIED: ${harnessFailures.length} harness error(s), the probe could not call REA: ${harnessFailures.map((e) => `${e.format} (${e.reason})`).join("; ")}`,
    );
    // A measured divergence outranks "not measured".
    if (process.exitCode !== EXIT_DIVERGED) process.exitCode = EXIT_UNVERIFIED;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(EXIT_DIVERGED);
});
