import { spawnSync } from "node:child_process";
import {
  closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readSync, realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { REA_INTERNAL_LIMITS } from "../identity.js";
import { resolveBlaStateRoot } from "../core/output-registry.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
export const BLA_PACKAGE_ROOT = resolve(MODULE_DIR, "../..");

/** Resolve sibling REA checkout the same way scripts/verify-rea-constants.mjs does. */
export function resolveReaRoot(override?: string): string {
  const fromArg = (override ?? "").trim();
  const fromEnv = (process.env.REA_ROOT ?? "").trim();
  return resolve(fromArg || fromEnv || join(BLA_PACKAGE_ROOT, "..", "rea"));
}

export function reaCheckoutPresent(reaRoot = resolveReaRoot()): boolean {
  return (
    reaRoot !== BLA_PACKAGE_ROOT &&
    existsSync(reaRoot) &&
    existsSync(join(reaRoot, "src"))
  );
}

export function reaDistReady(reaRoot = resolveReaRoot()): boolean {
  return existsSync(join(reaRoot, "dist", "go", "GoBinaryImage.js"));
}

/** Cap harness chatter so MCP stdio JSON cannot blow the line limit. */
const MAX_OBSERVABILITY_STREAM_CHARS = 32_768;

function clipObservabilityStream(text: string): string {
  if (text.length <= MAX_OBSERVABILITY_STREAM_CHARS) return text;
  return `${text.slice(0, MAX_OBSERVABILITY_STREAM_CHARS)}\n…[truncated]`;
}

/**
 * - `pass` / `fail`: a live harness ran (drift check, or redteam with execute:true).
 * - `available`: an on-disk empirical report was read without re-running REA
 *   (not live proof — agents must not treat this as a fresh red-team pass).
 * - `unverified`: required inputs missing; never a silent success.
 */
export type ReaObservabilityStatus = "pass" | "fail" | "unverified" | "available";

export interface ReaDriftReport {
  readonly schema: "bla-rea-drift/v1";
  readonly status: ReaObservabilityStatus;
  readonly reaRoot: string;
  readonly blaRoot: string;
  readonly exitCode: number | null;
  readonly reason?: string;
  readonly stdout: string;
  readonly stderr: string;
  /** True when this is not empirical red-team evidence. */
  readonly notRedTeamEvidence: true;
}

/**
 * Thin wrapper around `scripts/verify-rea-constants.mjs`.
 * Absent REA → explicit `unverified` (never a silent pass).
 * Present REA → spawn the harness; exit 0 → pass, else fail.
 */
export function runReaDriftCheck(options: {
  readonly reaRoot?: string;
  readonly timeoutMs?: number;
} = {}): ReaDriftReport {
  const blaRoot = BLA_PACKAGE_ROOT;
  const reaRoot = resolveReaRoot(options.reaRoot);
  const base = {
    schema: "bla-rea-drift/v1" as const,
    reaRoot,
    blaRoot,
    notRedTeamEvidence: true as const,
  };

  if (!reaCheckoutPresent(reaRoot)) {
    return {
      ...base,
      status: "unverified",
      exitCode: null,
      reason: `Sibling REA checkout not found at ${reaRoot} (set REA_ROOT or place REA next to BLA). Drift check cannot run.`,
      stdout: "",
      stderr: "",
    };
  }

  const script = join(blaRoot, "scripts", "verify-rea-constants.mjs");
  if (!existsSync(script)) {
    return {
      ...base,
      status: "unverified",
      exitCode: null,
      reason: `Drift harness missing: ${script}`,
      stdout: "",
      stderr: "",
    };
  }

  const result = spawnSync(process.execPath, [script], {
    cwd: blaRoot,
    encoding: "utf8",
    env: { ...process.env, REA_ROOT: reaRoot },
    timeout: options.timeoutMs ?? 120_000,
  });

  const stdout = clipObservabilityStream(result.stdout ?? "");
  const stderr = clipObservabilityStream(result.stderr ?? "");
  if (result.error) {
    return {
      ...base,
      status: "unverified",
      exitCode: result.status,
      reason: `Failed to spawn drift harness: ${result.error.message}`,
      stdout,
      stderr,
    };
  }

  const exitCode = result.status ?? 1;
  return {
    ...base,
    status: exitCode === 0 ? "pass" : "fail",
    exitCode,
    ...(exitCode === 0
      ? {}
      : { reason: "REA constant drift detected (see stdout)" }),
    stdout,
    stderr,
  };
}

export const REDTEAM_REPORT_JSON = join(
  BLA_PACKAGE_ROOT,
  "docs",
  "redteam",
  "empirical-rea-validation.json",
);

/**
 * `scripts/redteam/run.mjs` exits with this when a probe could not call REA at
 * all. Nothing was measured for that format, so it is not a verdict on a shield.
 */
const REDTEAM_EXIT_UNVERIFIED = 2;

// The checked-in empirical report is about 3 MiB. Bound both the file read
// and the size of diagnostic detail returned to the caller.
const MAX_REDTEAM_FILE_BYTES = 8 * 1024 * 1024;
const MAX_REDTEAM_ROWS = 64;
const REDTEAM_OUTCOME_STATUSES = new Set([
  "ok", "error", "harness_error", "rejected_pre_worker", "skipped",
  "budget_rejected", "capability_gated",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reportText(value: string): string {
  return value.length <= 512 ? value : `${value.slice(0, 512)}…`;
}

function readAuthorizedRedteamFile(path: string, roots: readonly string[]): string {
  // Accept both the configured spelling and the physical spelling of each root
  // (e.g. /var and /private/var on macOS). Reject symlinks below that root.
  for (const root of roots) {
    if (!existsSync(root)) continue;
    const physicalRoot = realpathSync(root);
    for (const spelling of new Set([root, physicalRoot])) {
      const rel = relative(spelling, path);
      if (!rel || isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) continue;
      const segments = rel.split(sep);
      let file = physicalRoot;
      for (const [index, part] of segments.entries()) {
        file = join(file, part);
        const status = lstatSync(file);
        const expectedType = index === segments.length - 1 ? status.isFile() : status.isDirectory();
        if (!expectedType) throw new Error("Report path must use regular files and directories without symlinks.");
      }
      const fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      try {
        const st = fstatSync(fd);
        if (realpathSync(file) !== file || !st.isFile()) {
          throw new Error("Report path must resolve to a regular file within an authorized root.");
        }
        const onDisk = lstatSync(file);
        if (onDisk.dev !== st.dev || onDisk.ino !== st.ino) {
          throw new Error("Report changed while opening it.");
        }
        if (st.size > MAX_REDTEAM_FILE_BYTES) throw new Error("Report exceeds the 8 MiB size limit.");
        const buf = Buffer.alloc(st.size);
        let offset = 0;
        while (offset < buf.length) {
          const count = readSync(fd, buf, offset, buf.length - offset, offset);
          if (count === 0) throw new Error("Report changed while reading it.");
          offset += count;
        }
        const after = fstatSync(fd);
        if (after.size !== st.size || after.mtimeMs !== st.mtimeMs || after.ctimeMs !== st.ctimeMs) {
          throw new Error("Report changed while reading it.");
        }
        return buf.toString("utf8");
      } finally {
        closeSync(fd);
      }
    }
  }
  throw new Error("Report path is outside the workspace, BLA package, and BLA state roots.");
}

function invalidRedteamSchema(): never {
  throw new Error("Report must match the bla-redteam-rea/v1 empirical report schema.");
}

const REDTEAM_METRICS: ReadonlyMap<string, readonly string[]> = new Map(Object.entries({
  go_buildinfo: ["hasBuildInfo", "encoding", "goVersion", "moduleTextBytes"],
  flutter_pool: [
    "isolateBytes", "packageUriCount", "dartUriCount", "classLikeTokenCount",
    "printableRunCount", "collectionCapped", "reportWouldCap",
  ],
  erlang_beam: ["chunkCount", "atomCount", "limitations"],
  evm_bytecode: [
    "inputBytes", "inputBytesLimit", "inputBytesLimitSource", "approachesLimit", "exceedsLimit",
    "carrierBytes", "carrierError", "metadataError",
  ],
  pcap_capture: [
    "tsharkSource", "reaRunsPcapOnThisHost", "reaTsharkFieldCount", "tsharkStatus",
    "tsharkJsonBytes", "tsharkDnsPassJsonBytes", "tsharkFullDissectionJsonBytes", "tsharkJsonLimit",
    "exceedsTsharkJsonBudget", "dnsPassExceedsTsharkJsonBudget", "stderrHead", "reaPacketCount",
    "reaPartial", "reaProtocolCount", "reaHttpRequestUriCount", "reaDnsQueryCount", "reaDnsLimitations",
  ],
  safetensors: ["tensorCount", "metadataCount", "limitations"],
  gguf: ["version", "tensorCount", "metadataCount", "limitations"],
  gpu_ptx: ["entryCount", "textBytes", "note"],
  electron_asar: ["headerBytes", "archiveBytes", "jsonBytes", "listingEntries", "listingPathBytes"],
  wasm_module: [
    "validates", "sectionCount", "customSectionNames", "exportNames", "exportCount", "importCount",
    "projectedChargeBytes", "representationBudget", "descriptorCount", "exportDecoysInjected",
    "exceedsRepresentationBudget", "wabtAvailable", "wabtValidation", "wabtExportForms", "wabtWatBytes",
    "wabtInterfaceEntries", "wabtInterfaceState", "wabtInterfaceIssues", "wabtError", "wabtSkipped",
    "chargeWhenTripped", "chargedBytes",
  ],
  sqlite_db: [
    "blaHoneyTables", "blaTableCount", "blaProtected", "hasGeneratedTrapColumns", "blaInspectError",
    "nodeSqliteLimits", "nodeVersion", "reaTables", "reaTableNames", "reaLimitations",
    "reaHoneyTablesVisible", "trapColumnFailure",
  ],
  electron_fuses: ["sentinelCount", "sliceCount"],
  javascript: [
    "parseStatus", "parseErrorCount", "visitedAstNodes", "staticCoverage", "staticLimits", "semCoverage",
    "semOmittedCount", "semLimits", "semanticResourceLimits", "unknownFindings", "referenceCount",
    "endpointCount", "routeCount", "semBindingCount", "semCallableCount", "semReferenceCount",
    "semExpressionFlowsTruncated", "limitations",
  ],
  javascript_strings: ["valuesHiddenAtDefaultBudgets", "valuesHiddenAtRaisedBudgets"],
}));

const REDTEAM_SAMPLE_FIELDS = [
  "mappedGo", "mappedFlutter", "goTripsMax", "atomsInjected", "chunksInjected",
  "exceedsDefaultChunkBudget", "approachesInputBudget", "afterBytes", "estimatedTsharkJsonBytes",
  "exceedsTsharkJsonBudget", "packetsInjected", "answerFloodPackets", "entriesInjected",
  "triggeredJsonNestingBreaker", "canaryTokensEmbedded", "error", "triggeredMetadataNestingBreaker",
  "decoyFiles", "estimatedHeaderBytes", "exceedsDefaultAdmission", "customSectionsAdded",
  "interfaceDescriptorsEmbedded", "projectedInterfaceChargeBytes", "exceedsRepresentationBudget",
  "exportDecoysInjected", "honeyTablesInjected", "electronFuseSentinelsInjected",
  "decoyFunctionsInjected", "aliasSelectionStatesCreated", "primitiveCandidateBranchesCreated",
];

function optionalReportText(value: unknown): string | undefined {
  return typeof value === "string" ? reportText(value) : undefined;
}

type DiagnosticValue = string | number | boolean | null | readonly string[];

function selectDiagnostics(input: Record<string, unknown>, keys: readonly string[]): Record<string, DiagnosticValue> {
  const fields: Record<string, DiagnosticValue> = {};
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string") fields[key] = reportText(value);
    else if (value === null || typeof value === "number" || typeof value === "boolean") fields[key] = value;
    else if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
      fields[key] = value.slice(0, 16).map(reportText);
    }
  }
  return fields;
}

function projectMetrics(value: Record<string, unknown>, format: string) {
  const metrics = selectDiagnostics(value, REDTEAM_METRICS.get(format) ?? []);
  const metadata = value.solidityMetadata;
  if (format === "evm_bytecode" && isRecord(metadata)) {
    const version = metadata.compiler_version;
    return {
      ...metrics,
      solidityMetadata: {
        ...selectDiagnostics(metadata, ["profile", "status", "bytecode_offset", "cbor_bytes", "diagnostic"]),
        ...(isRecord(version) ? { compiler_version: selectDiagnostics(version, ["representation", "value"]) } : {}),
      },
    };
  }
  if (format === "javascript_strings" && Array.isArray(value.budgetRuns)) {
    const budgetRuns = reportRows(value.budgetRuns).map((run) => {
      if (!isRecord(run)) invalidRedteamSchema();
      return {
        ...selectDiagnostics(run, ["budgetMultiplier", "ms", "coverage", "limits"]),
        ...(isRecord(run.recovered) ? { recovered: selectDiagnostics(run.recovered, ["endpoint", "channel", "digest"]) } : {}),
      };
    });
    return { ...metrics, budgetRuns };
  }
  return metrics;
}

function projectOutcome(value: unknown, format: string, phase: "before" | "after") {
  if (
    !isRecord(value) || value.format !== format || value.phase !== phase ||
    typeof value.status !== "string" || !REDTEAM_OUTCOME_STATUSES.has(value.status) ||
    typeof value.inputBytes !== "number" || !Number.isSafeInteger(value.inputBytes) ||
    value.inputBytes < 0 || typeof value.budgetHit !== "boolean" ||
    ![value.errorName, value.errorMessage, value.budgetName, value.redactionOrAmbiguity].every(
      (field) => field === null || typeof field === "string",
    ) || !isRecord(value.metrics)
  ) invalidRedteamSchema();
  return {
    format,
    phase,
    inputBytes: value.inputBytes,
    status: value.status,
    errorName: optionalReportText(value.errorName) ?? null,
    errorMessage: optionalReportText(value.errorMessage) ?? null,
    budgetHit: value.budgetHit,
    budgetName: optionalReportText(value.budgetName) ?? null,
    redactionOrAmbiguity: optionalReportText(value.redactionOrAmbiguity) ?? null,
    metrics: projectMetrics(value.metrics, format),
  };
}

function reportRows(value: unknown): readonly unknown[] {
  if (!Array.isArray(value) || value.length > MAX_REDTEAM_ROWS) invalidRedteamSchema();
  return value;
}

function projectReportNotes(value: unknown, key: "format" | "analyzer") {
  return reportRows(value ?? []).map((item) => {
    if (!isRecord(item) || typeof item[key] !== "string" || typeof item.reason !== "string") {
      invalidRedteamSchema();
    }
    return { [key]: reportText(item[key]), reason: reportText(item.reason) };
  });
}

function projectRedteamReport(raw: string) {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    // JSON.parse errors can contain excerpts of the rejected file.
    invalidRedteamSchema();
  }
  if (
    !isRecord(value) || value.schema !== "bla-redteam-rea/v1" ||
    (value.status !== "measured" && value.status !== "unverified")
  ) invalidRedteamSchema();
  const pairs = reportRows(value.pairs).map((pair) => {
    if (!isRecord(pair) || typeof pair.format !== "string" || !/^[a-z][a-z0-9_]*$/.test(pair.format)) {
      invalidRedteamSchema();
    }
    return {
      format: reportText(pair.format),
      before: projectOutcome(pair.before, pair.format, "before"),
      after: projectOutcome(pair.after, pair.format, "after"),
      ...(isRecord(pair.sampleMeta) ? { sampleMeta: selectDiagnostics(pair.sampleMeta, REDTEAM_SAMPLE_FIELDS) } : {}),
      ...(isRecord(pair.blaLimits) ? { blaLimits: selectDiagnostics(pair.blaLimits, Object.keys(REA_INTERNAL_LIMITS)) } : {}),
    };
  });
  const notStopped = reportRows(value.notStopped ?? []).map((format) => {
    if (typeof format !== "string") invalidRedteamSchema();
    return reportText(format);
  });
  const reaProvenance = isRecord(value.reaProvenance) ? value.reaProvenance : {};
  const tshark = isRecord(value.tshark) ? value.tshark : {};
  return {
    schema: value.schema,
    status: value.status,
    generatedAt: optionalReportText(value.generatedAt),
    blaVersion: optionalReportText(value.blaVersion),
    nodeVersion: optionalReportText(value.nodeVersion),
    intensity: optionalReportText(value.intensity),
    reaProvenance: {
      commit: typeof reaProvenance.commit === "string" ? reportText(reaProvenance.commit) : null,
      date: typeof reaProvenance.date === "string" ? reportText(reaProvenance.date) : null,
    },
    ...(typeof tshark.available === "boolean" ? {
      tshark: {
        available: tshark.available,
        version: typeof tshark.version === "string" ? reportText(tshark.version) : null,
        source: typeof tshark.source === "string" ? reportText(tshark.source) : null,
      },
    } : {}),
    pairs,
    notStopped,
    unverified: projectReportNotes(value.unverified, "analyzer"),
    harnessErrors: projectReportNotes(value.harnessErrors, "format"),
  };
}

export interface RedteamReportResult {
  readonly schema: "bla-redteam-report/v1";
  readonly status: ReaObservabilityStatus;
  readonly reaRoot: string;
  readonly blaRoot: string;
  readonly reportPath: string;
  readonly reason?: string;
  readonly report?: ReturnType<typeof projectRedteamReport>;
  readonly executed: boolean;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Read (and optionally re-run) the empirical REA red-team report.
 * - Default: return the on-disk JSON when present (`status: available` — not a live pass).
 * - `execute: true`: spawn `scripts/redteam/run.mjs` when REA dist is ready (`pass`/`fail`).
 * - Missing report AND missing/unready REA → explicit `unverified`.
 * - The harness could not call REA for a probe (this run, or the run that wrote
 *   the report on disk) → `unverified`: that is the harness being out of date
 *   with the REA checkout, not REA reading a hardened sample (`fail`).
 */
export function getRedteamReport(options: {
  readonly reaRoot?: string;
  readonly execute?: boolean;
  readonly timeoutMs?: number;
  readonly reportPath?: string;
} = {}): RedteamReportResult {
  const blaRoot = BLA_PACKAGE_ROOT;
  const reaRoot = resolveReaRoot(options.reaRoot);
  const reportPath = options.execute === true ? REDTEAM_REPORT_JSON : resolve(options.reportPath ?? REDTEAM_REPORT_JSON);
  const base = {
    schema: "bla-redteam-report/v1" as const,
    reaRoot,
    blaRoot,
    reportPath,
  };

  let stdout = "";
  let stderr = "";
  let executed = false;
  if (options.execute === true) {
    if (!reaDistReady(reaRoot)) {
      return {
        ...base,
        status: "unverified",
        executed: false,
        exitCode: null,
        reason: `REA dist not ready at ${join(reaRoot, "dist")} — cannot execute redteam:rea. Build sibling REA or omit execute to read a prior report.`,
        stdout: "",
        stderr: "",
      };
    }
    const script = join(blaRoot, "scripts", "redteam", "run.mjs");
    if (!existsSync(script)) {
      return {
        ...base,
        status: "unverified",
        executed: false,
        exitCode: null,
        reason: `Red-team harness missing: ${script}`,
        stdout: "",
        stderr: "",
      };
    }
    const result = spawnSync(process.execPath, [script], {
      cwd: blaRoot,
      encoding: "utf8",
      env: { ...process.env, REA_ROOT: reaRoot },
      timeout: options.timeoutMs ?? 600_000,
    });
    stdout = clipObservabilityStream(result.stdout ?? "");
    stderr = clipObservabilityStream(result.stderr ?? "");
    if (result.error) {
      return {
        ...base,
        status: "unverified",
        executed: false,
        exitCode: result.status,
        reason: `Failed to spawn red-team harness: ${result.error.message}`,
        stdout,
        stderr,
      };
    }
    executed = true;
    const exitCode = result.status ?? 1;
    if (exitCode === REDTEAM_EXIT_UNVERIFIED) {
      return {
        ...base,
        status: "unverified",
        executed,
        exitCode,
        reason:
          "redteam:rea could not call REA for at least one probe (stderr names the format and the missing export or module). The harness is out of date with this REA checkout; nothing was measured for those formats, and this is not a verdict on a shield.",
        stdout,
        stderr,
      };
    }
    if (exitCode !== 0) {
      return {
        ...base,
        status: "fail",
        executed,
        exitCode,
        reason:
          "redteam:rea exited non-zero: REA read a hardened sample it was expected to stop on, or the harness crashed (see stderr)",
        stdout,
        stderr,
      };
    }
    // The harness also exits zero when it skips the run. Only accept output
    // when this invocation confirmed it wrote the fixed report path.
    if (!stdout.split(/\r?\n/).includes(`  json:   ${REDTEAM_REPORT_JSON}`)) {
      return {
        ...base, status: "unverified", executed, exitCode,
        reason: "The red-team harness exited without writing a new empirical report.", stdout, stderr,
      };
    }
  }

  try {
    const roots = executed ? [blaRoot] : [process.cwd(), blaRoot, resolveBlaStateRoot()];
    const report = projectRedteamReport(readAuthorizedRedteamFile(reportPath, roots));
    if (report.status === "unverified") {
      const errors = report.harnessErrors;
      const named = errors.slice(0, 8).map((item) => `${item.format} (${item.reason.slice(0, 160)})`);
      const which = named.length > 0 ? `: ${named.join("; ")}` : "";
      return {
        ...base, status: "unverified", executed, exitCode: executed ? 0 : null,
        reason: `The harness could not call REA for ${errors.length || "at least one"} probe${errors.length > 1 ? "s" : ""}${which}. Those formats were not measured.`,
        report, stdout, stderr,
      };
    }
    const reason = report.notStopped.length > 0
      ? `In the run that wrote this report, REA read the hardened sample of ${report.notStopped.slice(0, 8).join(", ")}, which BLA's plant is meant to stop it on (that run exited 1). Read those rows before relying on that shield.`
      : undefined;
    return {
      ...base, status: executed ? "pass" : "available", executed, exitCode: executed ? 0 : null,
      ...(reason !== undefined ? { reason } : {}), report, stdout, stderr,
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        ...base, status: "unverified", executed, exitCode: executed ? 0 : null,
        reason: `No empirical report at ${reportPath}.`, stdout, stderr,
      };
    }
    return {
      ...base, status: "fail", executed, exitCode: executed ? 0 : null,
      reason: err instanceof Error ? err.message : String(err), stdout, stderr,
    };
  }
}
