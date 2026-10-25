import type { AgentCostEstimate, ReaSemanticSimulationResult } from "./types.js";

interface AgentModelPricing {
  readonly modelName: string;
  readonly inputUsdPerMillion: number;
  readonly outputUsdPerMillion: number;
  readonly contextWindowTokens: number;
  readonly secondsPerMcpRoundtrip: number;
}

const AGENT_MODELS: readonly AgentModelPricing[] = [
  {
    modelName: "Claude Opus 4 / Claude Code (Deep REA Loop)",
    inputUsdPerMillion: 15.0,
    outputUsdPerMillion: 75.0,
    contextWindowTokens: 200_000,
    secondsPerMcpRoundtrip: 7.5,
  },
  {
    modelName: "Claude Sonnet 4 / Cursor Agent",
    inputUsdPerMillion: 3.0,
    outputUsdPerMillion: 15.0,
    contextWindowTokens: 200_000,
    secondsPerMcpRoundtrip: 4.8,
  },
  {
    modelName: "OpenAI o3 / Codex CLI",
    inputUsdPerMillion: 10.0,
    outputUsdPerMillion: 40.0,
    contextWindowTokens: 200_000,
    secondsPerMcpRoundtrip: 6.2,
  },
];

/**
 * Hypothetical, uncalibrated cost model (no REA or agent is executed).
 * Pricing and timing are fixed scenario assumptions, not current quotes or measurements:
 * 1. Initial `analyze_javascript_application` / `open_binary` / `inspect_*` summary call
 * 2. Paging `inspect_analysis_view` across modules/functions (`limit: 16`)
 * 3. Calling `trace_application_feature` / `analyze_function` for each obligation node
 * 4. Retrying unresolved dynamic/ambiguous IPC channels & semantic resource-limit bailouts
 * 5. Accumulating context window history across every MCP tool call turn (`O(N^2)` cumulative input tokens)
 */
export function estimateAgentReverseEngineeringCosts(
  sim: ReaSemanticSimulationResult,
  byteSize: number,
): readonly AgentCostEstimate[] {
  const isShielded =
    sim.examinationStatus === "limited" ||
    sim.decoyFunctionsDetectedAsReal >= 5 ||
    sim.triggeredResourceLimits.length > 0;

  const baseSourceTokens = Math.max(350, Math.min(25_000, Math.ceil(byteSize / 3.8)));
  const obligationNodes = Math.max(1, sim.obligationLedgerNodes);

  if (!isShielded) {
    // Unprotected target: fast, linear 4-8 MCP calls, ~$0.11-$0.19 on Opus / ~$0.03 on Sonnet
    const totalMcpCalls = Math.max(3, Math.min(10, Math.ceil(obligationNodes * 1.2) + 2));
    const cumulativeInputTokens = baseSourceTokens * 2 + totalMcpCalls * 820;
    const outputTokens = 650 + totalMcpCalls * 210;

    return AGENT_MODELS.map((model) => {
      const inputUsd = (cumulativeInputTokens / 1_000_000) * model.inputUsdPerMillion;
      const outputUsd = (outputTokens / 1_000_000) * model.outputUsdPerMillion;
      const cost = Number(Math.max(0.02, inputUsd + outputUsd).toFixed(2));
      return {
        modelName: model.modelName,
        estimatedInputTokens: cumulativeInputTokens,
        estimatedOutputTokens: outputTokens,
        estimatedMcpToolCalls: totalMcpCalls,
        estimatedWallClockSeconds: Math.round(totalMcpCalls * model.secondsPerMcpRoundtrip),
        estimatedCostUsd: cost,
        evidenceBasis: "hypothetical-estimate",
        assumptions: "Fixed pricing, token and retry assumptions; not calibrated against agent runs.",
        contextWindowOverflowProbability: null,
        outcomeVerdict: "NOT_MEASURED",
      };
    });
  }

  // Protected target: Tarpit + Semantic Budget Breakers + Ambiguous IPC + Chaff
  const ambiguityRetries =
    Math.min(40, sim.ipcChannelsAmbiguousOrDynamic * 2) +
    sim.triggeredResourceLimits.length * 5 +
    Math.min(20, sim.decoyRoutesHarvested);

  const totalMcpCalls = Math.min(
    140,
    Math.max(32, Math.ceil(obligationNodes * 0.65) + ambiguityRetries),
  );

  // Each MCP turn adds ~3,400 tokens of decoy Evidence dossier & chaff into the sliding context window:
  const avgContextPerTurn = Math.min(
    165_000,
    18_000 + sim.decoyFunctionsDetectedAsReal * 1_650 + sim.architecturalChaffPayloads * 1_200,
  );

  const rawCumulativeInput =
    baseSourceTokens + totalMcpCalls * avgContextPerTurn;
  const rawOutputTokens =
    4_500 + totalMcpCalls * 780 + sim.decoyFunctionsDetectedAsReal * 320;

  return AGENT_MODELS.map((model) => {
    const inputUsd = (rawCumulativeInput / 1_000_000) * model.inputUsdPerMillion;
    const outputUsd = (rawOutputTokens / 1_000_000) * model.outputUsdPerMillion;
    const totalCostUsd = Number((inputUsd + outputUsd).toFixed(2));
    const wallClockSeconds = Math.round(totalMcpCalls * model.secondsPerMcpRoundtrip);

    return {
      modelName: model.modelName,
      estimatedInputTokens: rawCumulativeInput,
      estimatedOutputTokens: rawOutputTokens,
      estimatedMcpToolCalls: totalMcpCalls,
      estimatedWallClockSeconds: wallClockSeconds,
      estimatedCostUsd: Math.max(1.5, totalCostUsd),
      evidenceBasis: "hypothetical-estimate",
      assumptions: "Fixed pricing, token and retry assumptions; not calibrated against agent runs.",
      contextWindowOverflowProbability: null,
      outcomeVerdict: "NOT_MEASURED",
    };
  });
}
