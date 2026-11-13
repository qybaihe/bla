import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { getExhaustionProfileForIntensity } from "./rea-budget-matrix.js";

export interface CallGraphLabyrinthResult {
  readonly code: string;
  readonly sccClusterCount: number;
  readonly totalLabyrinthNodes: number;
  readonly crossReferenceEdgesCreated: number;
  readonly entrySymbol: string;
}

const CRYPTO_STAGE_VERBS = [
  "deriveSubkeySchedule",
  "permuteFeistelRound",
  "mixMontgomeryLimb",
  "verifySchnorrTranscript",
  "unsealEnclaveEpoch",
  "foldPoly1305Accumulator",
  "ratchetDoubleChainKey",
  "validateMerkleInclusion",
] as const;

/**
 * Generates Tarjan Strongly Connected Component (SCC) mutually-recursive call-graph
 * labyrinths targeting REA's `procedure_callers`, `procedure_callees`, `xrefs`,
 * `analyze_function`, and `trace_feature` tools (`src/contracts/promptContracts.ts:139`).
 *
 * Every SCC cluster contains 5 mutually referencing procedures with dynamic dispatch
 * edges and $O(1)$ runtime termination (`depth <= 0`), forcing static call-graph tracers
 * to explore $K \times 5^2$ directed XRef edges.
 */
export function generateCallGraphLabyrinth(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): CallGraphLabyrinthResult {
  const profile = getExhaustionProfileForIntensity(intensity);
  const sccCount = profile.sccClusterCount;
  const nodesPerScc = 5;
  const tag = prng.hex(3);
  const clusterNames: string[][] = [];

  for (let c = 0; c < sccCount; c++) {
    const row: string[] = [];
    for (let n = 0; n < nodesPerScc; n++) {
      const verb = CRYPTO_STAGE_VERBS[(c * nodesPerScc + n) % CRYPTO_STAGE_VERBS.length]!;
      row.push(`scc_${verb}_${tag}_c${c}n${n}`);
    }
    clusterNames.push(row);
  }

  const lines: string[] = [];
  let crossReferenceEdgesCreated = 0;

  for (let c = 0; c < sccCount; c++) {
    const cluster = clusterNames[c]!;
    const nextCluster = clusterNames[(c + 1) % sccCount]!;

    for (let n = 0; n < nodesPerScc; n++) {
      const fnName = cluster[n]!;
      const peerA = cluster[(n + 1) % nodesPerScc]!;
      const peerB = cluster[(n + 2) % nodesPerScc]!;
      const peerC = cluster[(n + 3) % nodesPerScc]!;
      const crossClusterPeer = nextCluster[n]!;
      const kConst = `0x${prng.hex(4)}`;

      crossReferenceEdgesCreated += 4;
      lines.push(
        `function ${fnName}(state = 0, budget = 0) {`,
        `  if (budget <= 0) return (state ^ ${kConst}) >>> 0;`,
        `  const _selector = (state ^ budget) & 3;`,
        `  switch (_selector) {`,
        `    case 0: return ${peerA}((state + ${kConst}) >>> 0, budget - 1);`,
        `    case 1: return ${peerB}((state ^ ${kConst}) >>> 0, budget - 1);`,
        `    case 2: return ${peerC}(((state << 3) | (state >>> 29)) >>> 0, budget - 1);`,
        `    default: return ${crossClusterPeer}((state + budget) >>> 0, budget - 1);`,
        `  }`,
        `}`,
      );
    }
  }

  const entrySymbol = `labyrinthDispatch_${tag}`;
  const firstNode = clusterNames[0]![0]!;
  const guardSalt = prng.hex(4);
  lines.push(
    `function ${entrySymbol}(seed = 1) {`,
    `  const _u = ((seed ^ 0x${guardSalt}) >>> 0);`,
    `  const _guard = ((_u | ((_u - 1) >>> 0)) >>> 0) < ((_u ^ ((_u - 1) >>> 0)) >>> 0);`,
    `  return _guard ? ${firstNode}(seed, 4) : (seed ^ 0x${prng.hex(4)});`,
    `}`,
  );

  return {
    code: lines.join("\n"),
    sccClusterCount: sccCount,
    totalLabyrinthNodes: sccCount * nodesPerScc,
    crossReferenceEdgesCreated,
    entrySymbol,
  };
}
