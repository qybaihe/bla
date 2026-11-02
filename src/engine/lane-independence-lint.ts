/**
 * Lane-independence footgun lint (issue #40.1 / red-blue round-1).
 *
 * Heuristic, defensive-only gate when customer gate code looks like
 * independent per-lane checks (e.g. an array of single-byte compares combined
 * with a shallow AND/OR reduction, or per-byte charCodeAt → wasm mix/seal).
 * Meridian / good designs use chained whole-key mixing so no per-lane oracle exists.
 *
 * Findings are severity **"error"** — CLI `bla lint-lanes` exits 2, and
 * harden/defend refuse the artifact unless `allowLaneIndependentGates` is set.
 * This does NOT give reverse-engineering advice.
 */

export const LANE_INDEPENDENCE_SCHEMA = "bla-lane-independence-lint/v1" as const;

export type LaneIndependenceFindingId =
  | "per-lane-byte-compare-array"
  | "independent-lane-and-reduce"
  | "indexed-lane-oracle-loop"
  | "per-byte-wasm-lane-oracle";

export type LaneIndependenceSeverity = "error";

export interface LaneIndependenceFinding {
  readonly id: LaneIndependenceFindingId;
  readonly severity: LaneIndependenceSeverity;
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
 * Per-byte charCodeAt fed into mix/seal (or similar) with an indexed target
 * compare — CrackMe v6 / independent WASM-lane shape (XOR or !== fold OK).
 */
const PER_BYTE_WASM_LANE =
  /charCodeAt\s*\(\s*\w+\s*\)[\s\S]{0,240}(?:mix|seal)\s*\([\s\S]{0,320}(?:LANE_TARGETS|laneTargets|targets?|lanes?)\s*\[\s*\w+/i;

/** Indexed XOR/OR fold of per-lane results without whole-key mixing. */
const INDEXED_XOR_LANE_FOLD =
  /for\s*\(\s*(?:let|var|const)\s+\w+[^)]*\)\s*\{[\s\S]{0,400}charCodeAt[\s\S]{0,400}\^\s*\((?:LANE_TARGETS|laneTargets|targets?|lanes?)\s*\[/i;

function finding(
  id: LaneIndependenceFindingId,
  summary: string,
  evidence: string,
): LaneIndependenceFinding {
  return {
    id,
    severity: "error",
    summary,
    evidence: evidence.slice(0, 120),
  };
}

/**
 * Scan UTF-8 source (JS/TS/Python-like) for lane-independence footguns.
 * Findings are severity "error" — callers decide whether to refuse (harden) or exit 2 (CLI).
 */
export function lintLaneIndependence(source: string): LaneIndependenceReport {
  const findings: LaneIndependenceFinding[] = [];
  const text = source.length > 400_000 ? source.slice(0, 400_000) : source;

  if (BYTE_COMPARE_ARRAY.test(text) && /(?:key|guess|input|lane)/i.test(text)) {
    const m = text.match(BYTE_COMPARE_ARRAY);
    // Round-2 blue: all-zero init arrays (e.g. pack buffers) are not compare tables.
    const lit = m?.[0] ?? "";
    const allZero = /^\[\s*0\s*(?:,\s*0\s*){3,}\]$/.test(lit);
    if (!allZero) {
      findings.push(
        finding(
          "per-lane-byte-compare-array",
          "Literal multi-byte compare table near key/guess identifiers — may allow independent per-lane probes.",
          lit,
        ),
      );
    }
  }

  if (LANE_AND_REDUCE.test(text) || EVERY_INDEXED_LANE.test(text)) {
    const m = text.match(LANE_AND_REDUCE) ?? text.match(EVERY_INDEXED_LANE);
    findings.push(
      finding(
        "independent-lane-and-reduce",
        "Lane/byte collection reduced with every/all/AND — suggests independent lane checks without whole-key mixing.",
        m?.[0] ?? "",
      ),
    );
  }

  if (INDEXED_ORACLE.test(text)) {
    const m = text.match(INDEXED_ORACLE);
    findings.push(
      finding(
        "indexed-lane-oracle-loop",
        "Indexed loop comparing key[i] to a per-lane target — classic independent-lane oracle shape.",
        m?.[0] ?? "",
      ),
    );
  }

  if (PER_BYTE_WASM_LANE.test(text) || INDEXED_XOR_LANE_FOLD.test(text)) {
    const m = text.match(PER_BYTE_WASM_LANE) ?? text.match(INDEXED_XOR_LANE_FOLD);
    findings.push(
      finding(
        "per-byte-wasm-lane-oracle",
        "Per-byte charCodeAt → mix/seal (or XOR fold) against indexed lane targets — independent 1-byte WASM lanes collapse under RE.",
        m?.[0] ?? "",
      ),
    );
  }

  return {
    schema: LANE_INDEPENDENCE_SCHEMA,
    findings,
    looksLaneIndependent: findings.length > 0,
    oneLineAdvice:
      findings.length === 0
        ? "No lane-independence footgun pattern detected (heuristic)."
        : "ERROR: Prefer whole-key chained mixing (no per-lane oracle). Harden refuses this gate unless allowLaneIndependentGates / --allow-lane-independent / allow_lane_independent. See issue #40.1 / Meridian DESIGN — defensive guidance only.",
  };
}

/** Formats where lane-independence lint applies before protect/defend/harden. */
export function formatSupportsLaneIndependenceLint(
  format: string,
): boolean {
  return format === "javascript" || format === "typescript";
}

/**
 * Build a refuse message for harden/defend when lane-independent gates are detected.
 */
export function laneIndependenceRefuseMessage(
  report: LaneIndependenceReport,
  inputPath: string,
): string {
  const ids = report.findings.map((f) => f.id).join(", ");
  return (
    `Refusing lane-independent gate at ${inputPath} [${ids}]. ` +
    `Prefer whole-key chained mixing. To override (intentional footgun / teaching fixture), ` +
    `pass allowLaneIndependentGates / --allow-lane-independent / allow_lane_independent:true.`
  );
}
