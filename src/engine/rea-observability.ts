import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

/**
 * A report written by a run in which a probe could not call REA says so in its
 * own `status`. Reading it back must not turn that into "available".
 */
function describeUnmeasuredReport(report: unknown): string | null {
  if (typeof report !== "object" || report === null) return null;
  const record = report as { status?: unknown; harnessErrors?: unknown };
  if (record.status !== "unverified") return null;
  const errors = Array.isArray(record.harnessErrors) ? record.harnessErrors : [];
  const named = errors.slice(0, 8).map((entry) => {
    const item = (typeof entry === "object" && entry !== null ? entry : {}) as {
      format?: unknown;
      reason?: unknown;
    };
    const format = typeof item.format === "string" ? item.format : "unknown format";
    const reason = typeof item.reason === "string" ? ` (${item.reason.slice(0, 160)})` : "";
    return `${format}${reason}`;
  });
  const which = named.length > 0 ? `: ${named.join("; ")}` : "";
  return `This report was written by a run in which the harness could not call REA for ${errors.length > 0 ? String(errors.length) : "at least one"} probe${errors.length > 1 ? "s" : ""}${which}. Those formats were not measured — their rows are not evidence about the shield.`;
}

/**
 * The formats whose plant is meant to stop REA, where REA read the hardened
 * sample in the run that wrote the report (`notStopped`; that run exited 1).
 */
function describeNotStopped(report: unknown): string | null {
  if (typeof report !== "object" || report === null) return null;
  const formats = (report as { notStopped?: unknown }).notStopped;
  if (!Array.isArray(formats)) return null;
  const named = formats.filter((format): format is string => typeof format === "string");
  if (named.length === 0) return null;
  return `In the run that wrote this report, REA read the hardened sample of ${named.slice(0, 8).join(", ")}, which BLA's plant is meant to stop it on (that run exited 1). Read those rows before relying on that shield.`;
}

export interface RedteamReportResult {
  readonly schema: "bla-redteam-report/v1";
  readonly status: ReaObservabilityStatus;
  readonly reaRoot: string;
  readonly blaRoot: string;
  readonly reportPath: string;
  readonly reason?: string;
  readonly report?: unknown;
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
  const reportPath = resolve(options.reportPath ?? REDTEAM_REPORT_JSON);
  const base = {
    schema: "bla-redteam-report/v1" as const,
    reaRoot,
    blaRoot,
    reportPath,
  };

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
    const stdout = clipObservabilityStream(result.stdout ?? "");
    const stderr = clipObservabilityStream(result.stderr ?? "");
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
    const exitCode = result.status ?? 1;
    if (exitCode === REDTEAM_EXIT_UNVERIFIED) {
      return {
        ...base,
        status: "unverified",
        executed: true,
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
        executed: true,
        exitCode,
        reason:
          "redteam:rea exited non-zero: REA read a hardened sample it was expected to stop on, or the harness crashed (see stderr)",
        stdout,
        stderr,
      };
    }
    // Fall through to read the freshly written report.
  }

  if (!existsSync(reportPath)) {
    const reaHint = reaDistReady(reaRoot)
      ? "REA dist is ready — pass execute:true to run the harness."
      : `REA dist not ready at ${reaRoot}; cannot fabricate a red-team report.`;
    return {
      ...base,
      status: "unverified",
      executed: false,
      exitCode: null,
      reason: `No empirical report at ${reportPath}. ${reaHint}`,
      stdout: "",
      stderr: "",
    };
  }

  try {
    const report: unknown = JSON.parse(readFileSync(reportPath, "utf8"));
    const executed = options.execute === true;
    const unmeasured = describeUnmeasuredReport(report);
    if (unmeasured !== null) {
      return {
        ...base,
        status: "unverified",
        executed,
        exitCode: executed ? 0 : null,
        reason: unmeasured,
        report,
        stdout: "",
        stderr: "",
      };
    }
    const notStopped = describeNotStopped(report);
    return {
      ...base,
      // Live execute → pass; plain on-disk read → available (not a fresh REA verdict).
      status: executed ? "pass" : "available",
      executed,
      exitCode: executed ? 0 : null,
      ...(notStopped !== null ? { reason: notStopped } : {}),
      report,
      stdout: "",
      stderr: "",
    };
  } catch (err) {
    return {
      ...base,
      status: "fail",
      executed: options.execute === true,
      exitCode: null,
      reason: `Report exists but is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      stdout: "",
      stderr: "",
    };
  }
}
