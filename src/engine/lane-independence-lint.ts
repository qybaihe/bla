/**
 * Lane-independence footgun lint (issue #40.1).
 *
 * Heuristic, defensive-only warning when customer gate code looks like
 * independent per-lane checks (e.g. an array of single-byte compares combined
 * with a shallow AND/OR reduction). Meridian / good designs use chained
 * whole-key mixing so no per-lane oracle exists.
 *
 * This does NOT give reverse-engineering advice. It only flags a structural
 * pattern that historically collapses search cost.
 */

export const LANE_INDEPENDENCE_SCHEMA = "bla-lane-independence-lint/v1" as const;

export type LaneIndependenceFindingId =
  | "per-lane-byte-compare-array"
  | "independent-lane-and-reduce"
  | "indexed-lane-oracle-loop";

export interface LaneIndependenceFinding {
  readonly id: LaneIndependenceFindingId;
  readonly severity: "warn";
  readonly summary: string;
  readonly evidence: string;
}

export interface LaneIndependenceReport {
  readonly schema: typeof LANE_INDEPENDENCE_SCHEMA;
  readonly findings: readonly LaneIndependenceFinding[];
  readonly looksLaneIndependent: boolean;
  readonly oneLineAdvice: string;
}

const BYTE_COMPARE_ARRAY =
  /\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d+)\s*){3,}\]/;

const LANE_AND_REDUCE =
  /(?:lanes?|bytes?|parts?|chunks?)\s*(?:\.every\s*\(|\.all\s*\(|\.reduce\s*\([^)]*(?:&&|\band\b))/i;

/** `.every` / `.all` near a lanes[i]-style indexed compare — independent checks. */
const EVERY_INDEXED_LANE =
  /\.every\s*\([\s\S]{0,200}(?:lanes?|targets?|expect)\s*\[\s*[\w$]+\s*\]/i;

const INDEXED_ORACLE =
  /for\s*\(\s*(?:let|var|const)\s+\w+\s*=\s*0[^)]*\)\s*\{[^}]{0,200}(?:key|input|guess)\s*\[\s*\w+\s*\][^}]{0,120}===\s*(?:target|expect|lane|ref)/i;

/**
 * Scan UTF-8 source (JS/TS/Python-like) for lane-independence footguns.
 * Returns findings with severity "warn" only — never fails closed.
 */
export function lintLaneIndependence(source: string): LaneIndependenceReport {
  const findings: LaneIndependenceFinding[] = [];
  const text = source.length > 400_000 ? source.slice(0, 400_000) : source;

  if (BYTE_COMPARE_ARRAY.test(text) && /(?:key|guess|input|lane)/i.test(text)) {
    const m = text.match(BYTE_COMPARE_ARRAY);
    findings.push({
      id: "per-lane-byte-compare-array",
      severity: "warn",
      summary:
        "Literal multi-byte compare table near key/guess identifiers — may allow independent per-lane probes.",
      evidence: (m?.[0] ?? "").slice(0, 80),
    });
  }

  if (LANE_AND_REDUCE.test(text) || EVERY_INDEXED_LANE.test(text)) {
    const m = text.match(LANE_AND_REDUCE) ?? text.match(EVERY_INDEXED_LANE);
    findings.push({
      id: "independent-lane-and-reduce",
      severity: "warn",
      summary:
        "Lane/byte collection reduced with every/all/AND — suggests independent lane checks without whole-key mixing.",
      evidence: (m?.[0] ?? "").slice(0, 80),
    });
  }

  if (INDEXED_ORACLE.test(text)) {
    const m = text.match(INDEXED_ORACLE);
    findings.push({
      id: "indexed-lane-oracle-loop",
      severity: "warn",
      summary:
        "Indexed loop comparing key[i] to a per-lane target — classic independent-lane oracle shape.",
      evidence: (m?.[0] ?? "").slice(0, 120),
    });
  }

  return {
    schema: LANE_INDEPENDENCE_SCHEMA,
    findings,
    looksLaneIndependent: findings.length > 0,
    oneLineAdvice:
      findings.length === 0
        ? "No lane-independence footgun pattern detected (heuristic)."
        : "Prefer whole-key chained mixing (no per-lane oracle). See issue #40.1 / Meridian DESIGN — defensive guidance only.",
  };
}
