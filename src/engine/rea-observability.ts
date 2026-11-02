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
    if (exitCode !== 0) {
      return {
        ...base,
        status: "fail",
        executed: true,
        exitCode,
        reason: "redteam:rea exited non-zero",
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
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    const executed = options.execute === true;
    return {
      ...base,
      // Live execute → pass; plain on-disk read → available (not a fresh REA verdict).
      status: executed ? "pass" : "available",
      executed,
      exitCode: executed ? 0 : null,
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
