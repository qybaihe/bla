import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { REDTEAM_OUT_DIR, REDTEAM_REPORT_MD, REDTEAM_REPORT_JSON } from "./paths.mjs";

function fmtBytes(n) {
  if (n == null) return "—";
  if (n >= 1_048_576) return `${n} (${(n / 1_048_576).toFixed(2)} MiB)`;
  if (n >= 1024) return `${n} (${(n / 1024).toFixed(1)} KiB)`;
  return String(n);
}

function outcomeLine(o) {
  const bits = [
    `status=${o.status}`,
    o.budgetHit ? `budgetHit=${o.budgetName}` : "budgetHit=false",
  ];
  if (o.errorName) bits.push(`error=${o.errorName}: ${o.errorMessage}`);
  if (o.redactionOrAmbiguity) bits.push(`note=${o.redactionOrAmbiguity}`);
  return bits.join("; ");
}

function metricsBlock(metrics) {
  if (!metrics || Object.keys(metrics).length === 0) return "_no metrics_";
  return Object.entries(metrics)
    .map(([k, v]) => {
      const val =
        typeof v === "object" ? JSON.stringify(v) : String(v ?? "null");
      return `- \`${k}\`: ${val}`;
    })
    .join("\n");
}

/**
 * Compare empirical outcomes to BLA's internal estimates / planted flags.
 */
function compareToEstimates(pair) {
  const notes = [];
  const { format, before, after, sampleMeta, blaLimits } = pair;
  if (format === "go_buildinfo") {
    const expect = sampleMeta?.goTripsMax === true;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect
        ? `AGREE with BLA goBuildInfoExceedsLimit=${expect}`
        : `DIVERGE: BLA estimated trips=${expect}, empirical budgetHit=${hit}`,
    );
    if (expect && !hit && after.status === "error") {
      notes.push(
        `REA rejected the planted build-info before its size budget applied (${after.errorName}: ${after.errorMessage}). It still reads no build info from the hardened file, but this is a format rejection, not the budget the shield was sized for.`,
      );
    }
  }
  if (format === "flutter_pool") {
    const hit = after.budgetHit === true;
    notes.push(
      hit
        ? "AGREE: REA pool projection would truncate past MAX_POOL_URIS/TOKENS"
        : "DIVERGE: Flutter pool did NOT exceed REA caps — shield under-capacity",
    );
    if (after.metrics?.packageUriCount != null) {
      notes.push(
        `packageUriCount=${after.metrics.packageUriCount} (cap ${blaLimits.DART_MAX_POOL_URIS}), dartUriCount=${after.metrics.dartUriCount}, classLikeTokenCount=${after.metrics.classLikeTokenCount} (cap ${blaLimits.DART_MAX_POOL_TOKENS})`,
      );
    }
  }
  if (format === "erlang_beam") {
    const expect = sampleMeta?.exceedsDefaultChunkBudget === true;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect
        ? `AGREE with BLA exceedsDefaultChunkBudget=${expect}`
        : `DIVERGE: BLA estimated=${expect}, empirical budgetHit=${hit} (${after.budgetName})`,
    );
  }
  if (format === "evm_bytecode") {
    const expect = sampleMeta?.approachesInputBudget === true;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect || (expect && after.metrics?.approachesLimit)
        ? `AGREE with BLA approachesInputBudget=${expect} (after=${fmtBytes(after.inputBytes)}, limit=${fmtBytes(blaLimits.EVM_INPUT_BYTES)})`
        : `DIVERGE: BLA approaches=${expect}, empirical budgetHit=${hit}`,
    );
  }
  if (format === "pcap_capture") {
    const expect = sampleMeta?.exceedsTsharkJsonBudget === true;
    const hit = after.budgetHit === true;
    const est = sampleMeta?.estimatedTsharkJsonBytes;
    const real = after.metrics?.tsharkJsonBytes;
    notes.push(
      `BLA estimate=${fmtBytes(est)}; empirical tshark JSON=${fmtBytes(real)}`,
    );
    if (after.status === "skipped") {
      notes.push("SKIPPED: tshark unavailable — estimate not empirically confirmed");
    } else if (hit === expect) {
      notes.push(`AGREE with BLA exceedsTsharkJsonBudget=${expect}`);
    } else {
      notes.push(
        `DIVERGE: BLA estimated exceed=${expect}, empirical budgetHit=${hit}`,
      );
    }
  }
  if (format === "safetensors") {
    notes.push(
      sampleMeta?.triggeredJsonNestingBreaker === false ||
        sampleMeta?.triggeredJsonNestingBreaker == null
        ? "EXPECTED: safetensors does NOT trip MODEL_JSON_NESTING (HF validity red line); canaries only"
        : "UNEXPECTED: nesting breaker on safetensors",
    );
    notes.push(
      after.budgetHit
        ? `empirical budgetHit=${after.budgetName}`
        : "empirical: header parse succeeded (no nesting breaker)",
    );
  }
  if (format === "gguf") {
    const expect = sampleMeta?.triggeredMetadataNestingBreaker === true;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect
        ? `AGREE with BLA triggeredMetadataNestingBreaker=${expect}`
        : `DIVERGE: BLA nesting=${expect}, empirical budgetHit=${hit} (${after.budgetName ?? after.errorName})`,
    );
  }
  if (format === "gpu_ptx") {
    notes.push(
      "PTX is text-scanned only; REA GPU object decode needs native tooling (not empirically verified for fatbin/SPIR-V)",
    );
  }
  if (format === "electron_asar") {
    const expect = sampleMeta?.exceedsDefaultAdmission === true;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect
        ? `AGREE with BLA exceedsDefaultAdmission=${expect} (header after metrics=${after.metrics?.headerBytes ?? after.errorMessage})`
        : `DIVERGE: BLA exceedsDefaultAdmission=${expect}, empirical budgetHit=${hit} (${after.budgetName ?? after.errorName})`,
    );
  }
  if (format === "wasm_module") {
    const expect = sampleMeta?.exceedsRepresentationBudget === true;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect
        ? `AGREE with BLA exceedsRepresentationBudget=${expect} (projected=${sampleMeta?.projectedInterfaceChargeBytes})`
        : `DIVERGE: BLA exceeds=${expect}, empirical budgetHit=${hit}`,
    );
    notes.push(
      after.metrics?.wabtAvailable
        ? "Wabt E2E (wasm-validate / wasm-objdump / wasm2wat) ran via WabtArtifactProvider; interface state + budget issues recorded"
        : "Wabt tools absent — soft-skipped to in-process WasmInterfaceBudget with projected descriptors",
    );
  }
  if (format === "javascript_strings") {
    const names = Object.keys(sampleMeta?.values ?? {});
    const line = (run) =>
      `${run.budgetMultiplier}x budgets (${run.ms} ms, coverage=${run.coverage}, limits=[${(run.limits ?? []).join(", ")}]): ` +
      names
        .map((name) => {
          const n = run.recovered?.[name] ?? 0;
          return `${name} ${n === 0 ? "not in REA's result" : n === 1 ? "RECOVERED" : `one of ${n} candidates`}`;
        })
        .join("; ");
    for (const run of before.metrics?.budgetRuns ?? []) {
      if (run.budgetMultiplier === 1) notes.push(`unhardened, ${line(run)}`);
    }
    for (const run of after.metrics?.budgetRuns ?? []) notes.push(`hardened, ${line(run)}`);
    notes.push(
      after.metrics?.valuesHiddenAtDefaultBudgets === true &&
        after.metrics?.valuesHiddenAtRaisedBudgets === true
        ? "AGREE: no known value reaches REA's result, with its budgets raised or not"
        : "DIVERGE: REA's result holds a known value — the string encoding was read through",
    );
    notes.push(
      "REA's JavaScript budgets are per-call inputs (semantic_precision); a sample that only trips the defaults is read by whoever raises them, which is why this row measures both.",
    );
  }
  if (format === "sqlite_db") {
    notes.push(
      after.status === "capability_gated"
        ? "NOTED: REA SQLite inspection capability-gated on Node <24.15; BLA honey/canary evidence recorded"
        : after.budgetHit
          ? `empirical budgetHit=${after.budgetName}`
          : `empirical status=${after.status}; honeyTables=${after.metrics?.blaHoneyTables}`,
    );
    if ((sampleMeta?.honeyTablesInjected ?? 0) > 0) {
      notes.push(
        `AGREE: BLA honeyTablesInjected=${sampleMeta.honeyTablesInjected}, canaryTokens=${sampleMeta.canaryTokensEmbedded}`,
      );
    }
  }
  if (format === "electron_fuses") {
    const expect = (sampleMeta?.electronFuseSentinelsInjected ?? 0) > 32;
    const hit = after.budgetHit === true;
    notes.push(
      hit === expect
        ? `AGREE: decoy sentinels ${sampleMeta?.electronFuseSentinelsInjected} > maximumSentinelsPerSlice=32`
        : `DIVERGE: injected=${sampleMeta?.electronFuseSentinelsInjected}, empirical budgetHit=${hit} (${after.budgetName ?? after.errorName})`,
    );
  }
  // Before should generally NOT hit budgets
  if (before.budgetHit && format !== "gpu_ptx") {
    notes.push(
      `WARN: unhardened sample unexpectedly hit budget (${before.budgetName})`,
    );
  }
  return notes;
}

export function buildReportDocument(run) {
  const lines = [];
  lines.push("# Empirical REA red-team validation");
  lines.push("");
  lines.push(`Generated: ${run.generatedAt} (Asia/Shanghai)`);
  lines.push(`BLA: \`bla-agents ${run.blaVersion ?? "(unknown version)"}\` (working tree at \`${run.blaRoot}\`)`);
  lines.push(`REA root: \`${run.reaRoot}\``);
  if (run.reaProvenance?.commit) {
    lines.push(`REA commit: \`${run.reaProvenance.commit}\` (${run.reaProvenance.date ?? "unknown"})`);
  }
  lines.push(
    run.status === "measured"
      ? "Harness: **measured** — every probe that can run on this machine called REA itself (rows marked `skipped` name the tool that was missing)."
      : `Harness: **${run.status ?? "unknown"}** — at least one probe could not call REA (see \`harnessErrors\`); those formats were not measured.`,
  );
  lines.push(`Intensity: \`${run.intensity}\` · seed: \`${run.seed}\``);
  lines.push(`Node: \`${run.nodeVersion}\``);
  lines.push(`tshark: ${run.tshark.available ? `\`${run.tshark.version}\`` : "not available"}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(
    "| Format | Before status | After status | Budget hit (after) | vs BLA estimate |",
  );
  lines.push("|---|---|---|---|---|");
  for (const pair of run.pairs) {
    const cmp = compareToEstimates(pair);
    const agree = cmp.some((c) => c.startsWith("AGREE"))
      ? "agree"
      : cmp.some((c) => c.startsWith("DIVERGE"))
        ? "diverge"
        : cmp.some((c) => c.startsWith("SKIPPED") || c.startsWith("EXPECTED") || c.startsWith("PTX") || c.startsWith("NOTED") || c.startsWith("Full Wabt"))
          ? "noted"
          : "—";
    lines.push(
      `| ${pair.format} | ${pair.before.status} | ${pair.after.status} | ${pair.after.budgetHit ? pair.after.budgetName : "no"} | ${agree} |`,
    );
  }
  lines.push("");
  lines.push("## Per-format empirical outcomes");
  lines.push("");
  for (const pair of run.pairs) {
    lines.push(`### ${pair.format}`);
    lines.push("");
    lines.push(`- Input before: ${fmtBytes(pair.before.inputBytes)}`);
    lines.push(`- Input after: ${fmtBytes(pair.after.inputBytes)}`);
    lines.push(`- Before: ${outcomeLine(pair.before)}`);
    lines.push(`- After: ${outcomeLine(pair.after)}`);
    lines.push("");
    lines.push("**Before metrics**");
    lines.push("");
    lines.push(metricsBlock(pair.before.metrics));
    lines.push("");
    lines.push("**After metrics**");
    lines.push("");
    lines.push(metricsBlock(pair.after.metrics));
    lines.push("");
    lines.push("**Estimate comparison**");
    lines.push("");
    for (const n of compareToEstimates(pair)) {
      lines.push(`- ${n}`);
    }
    lines.push("");
  }
  lines.push("## Analyzers NOT empirically verified on this box");
  lines.push("");
  for (const u of run.unverified) {
    lines.push(`- **${u.analyzer}** — ${u.reason}`);
  }
  lines.push("");
  lines.push("## Method");
  lines.push("");
  lines.push(
    "Harness lives under `scripts/redteam/`. For each in-process REA analyzer, it builds a representative sample, runs the real REA parser on the unhardened bytes, hardens via BLA (`protect*` APIs / mapped plants), re-runs REA, and records budget/redaction/error outcomes. Flutter pool projection uses a faithful replica of REA's private `projectStringPool` (same caps, slack, identifier rules). PCAP uses a real user-local tshark when present.",
  );
  lines.push("");
  return lines.join("\n");
}

export function writeReports(run) {
  mkdirSync(REDTEAM_OUT_DIR, { recursive: true });
  const md = buildReportDocument(run);
  writeFileSync(REDTEAM_REPORT_MD, md, "utf8");
  writeFileSync(REDTEAM_REPORT_JSON, JSON.stringify(run, null, 2), "utf8");
  return { mdPath: REDTEAM_REPORT_MD, jsonPath: REDTEAM_REPORT_JSON };
}
