import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

/** File name of the project-level summary `hardenProject` writes. */
export const HARDEN_SUMMARY_FILE_NAME = "bla-harden-summary.json";

/** Current summary schema; v2 adds `runId`. */
export const HARDEN_SUMMARY_SCHEMA = "bla-harden-summary/v2";

/** Stable inputs that identify one harden run's planned work. */
export interface HardenRunIdentity {
  readonly blaVersion: string;
  readonly directory: string;
  readonly intensity: string;
  readonly weaveDecoys: boolean;
  readonly selfSeal: boolean;
  readonly artifacts: readonly {
    readonly relativePath: string;
    readonly format: string;
    readonly outputPath: string;
  }[];
}

/**
 * Deterministic, content-addressed run id: identical inputs and planned outputs
 * always yield the same id, so it can be recomputed and cross-checked later.
 * Unsigned — it proves consistency, not authorship.
 */
export function computeHardenRunId(identity: HardenRunIdentity): string {
  const artifacts = [...identity.artifacts]
    .map((a) => ({
      relativePath: a.relativePath,
      format: a.format,
      outputPath: a.outputPath,
    }))
    .sort((x, y) => (x.relativePath < y.relativePath ? -1 : x.relativePath > y.relativePath ? 1 : 0));
  const canonical = JSON.stringify({
    blaVersion: identity.blaVersion,
    directory: identity.directory,
    intensity: identity.intensity,
    weaveDecoys: identity.weaveDecoys,
    selfSeal: identity.selfSeal,
    artifacts,
  });
  return `bla-run-${createHash("sha256").update(canonical).digest("hex").slice(0, 24)}`;
}

export interface HardenRunSummary {
  readonly schema: string;
  readonly runId: string;
  readonly [key: string]: unknown;
}

export interface ReadHardenRunSummaryResult {
  readonly summaryPath: string;
  readonly runId: string;
  readonly runIdMatches: boolean | null;
  readonly summary: HardenRunSummary;
}

/**
 * Read back a persisted harden summary (file, or the directory holding it) and
 * optionally assert it belongs to `expectRunId`. Throws on a missing/unreadable
 * file, a non-summary JSON, a pre-v2 summary without `runId`, or an id mismatch,
 * so a bad lookup can never read as a successful correlation.
 */
export function readHardenRunSummary(
  location: string,
  expectRunId?: string,
): ReadHardenRunSummaryResult {
  const abs = resolve(location);
  if (!existsSync(abs)) {
    throw new Error(`Run summary not found: ${abs}`);
  }
  const summaryPath = statSync(abs).isDirectory() ? join(abs, HARDEN_SUMMARY_FILE_NAME) : abs;
  if (!existsSync(summaryPath)) {
    throw new Error(`Run summary not found: ${summaryPath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(summaryPath, "utf8"));
  } catch (err) {
    throw new Error(
      `Run summary is not valid JSON: ${summaryPath} (${err instanceof Error ? err.message : String(err)})`,
    );
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    typeof (parsed as { schema?: unknown }).schema !== "string" ||
    !(parsed as { schema: string }).schema.startsWith("bla-harden-summary/")
  ) {
    throw new Error(`Not a BLA harden summary: ${summaryPath}`);
  }
  const record = parsed as { schema: string; runId?: unknown };
  if (typeof record.runId !== "string" || record.runId.length === 0) {
    throw new Error(
      `Harden summary has no runId (schema ${record.schema}); re-run bla_harden to produce ${HARDEN_SUMMARY_SCHEMA}: ${summaryPath}`,
    );
  }
  const runId = record.runId;
  if (expectRunId !== undefined && expectRunId !== runId) {
    throw new Error(
      `Run id mismatch: expected ${expectRunId} but ${summaryPath} records ${runId}`,
    );
  }
  return {
    summaryPath,
    runId,
    runIdMatches: expectRunId === undefined ? null : true,
    summary: parsed as HardenRunSummary,
  };
}

/** sha256 hex of a file's bytes, for content-addressing single-artifact outputs. */
export function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/**
 * Deterministic run id for a single-artifact defend/protect run, bound to the
 * produced output bytes so a later re-hash can confirm the output is unchanged.
 */
export function computeArtifactRunId(input: {
  readonly tool: string;
  readonly inputPath: string;
  readonly outputPath: string;
  readonly outputSha256: string;
}): string {
  const canonical = JSON.stringify({
    tool: input.tool,
    inputPath: resolve(input.inputPath),
    outputPath: resolve(input.outputPath),
    outputSha256: input.outputSha256,
  });
  return `bla-run-${createHash("sha256").update(canonical).digest("hex").slice(0, 24)}`;
}
