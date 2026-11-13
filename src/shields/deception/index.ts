import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import {
  generateShadowBusinessLogic,
  type ShadowBusinessLogicResult,
  type ShadowLogicArchetype,
} from "./shadow-business-logic.js";
import {
  generateEvidenceContractPoison,
  type CompetingExplanationLure,
  type EvidenceContractPoisonResult,
} from "./evidence-contract-poison.js";
import {
  generateArchitectureMirage,
  type ArchitectureMirageResult,
} from "./architecture-mirage.js";
import {
  generateSemanticHoneypot,
  type SemanticHoneypotResult,
} from "./semantic-honeypot.js";
import {
  generateDecompilerPseudocodeIllusion,
  type DecompilerIllusionResult,
} from "./decompiler-illusion.js";
import {
  generatePromptCompletionPoison,
  type PromptCompletionPoisonResult,
} from "./prompt-completion-poison.js";
import {
  generateVersionDiffNoise,
  type DiffNoiseInjectionResult,
} from "./diff-noise-injector.js";
import {
  generateCrashTraceDecoy,
  type CrashTraceDecoyResult,
} from "./crash-trace-decoy.js";
import {
  generateCanaryHoneypot,
  type CanaryHoneypotResult,
} from "./canary-honeypot.js";
import {
  generateSystemDiagnosticDecoy,
  type SystemDiagnosticDecoyEntry,
  type SystemDiagnosticDecoyResult,
} from "./system-diagnostic-decoy.js";
import {
  ALIGNMENT_CANARY_GUID,
  ALIGNMENT_EVAL_CANARY_GUID,
  computeContainmentCorpusDigest,
  generateCognitiveArmorTrigger,
  type CognitiveArmorTriggerEntry,
  type CognitiveArmorTriggerResult,
} from "./cognitive-armor-trigger.js";
import {
  generateHypothesisRevisionDecoy,
  type HypothesisRevisionChainEntry,
  type HypothesisRevisionDecoyResult,
} from "./hypothesis-revision-decoy.js";

export {
  generateShadowBusinessLogic,
  generateEvidenceContractPoison,
  generateArchitectureMirage,
  generateSemanticHoneypot,
  generateDecompilerPseudocodeIllusion,
  generatePromptCompletionPoison,
  generateVersionDiffNoise,
  generateCrashTraceDecoy,
  generateCanaryHoneypot,
  generateSystemDiagnosticDecoy,
  generateCognitiveArmorTrigger,
  generateHypothesisRevisionDecoy,
  computeContainmentCorpusDigest,
  ALIGNMENT_CANARY_GUID,
  ALIGNMENT_EVAL_CANARY_GUID,
  type ShadowBusinessLogicResult,
  type ShadowLogicArchetype,
  type CompetingExplanationLure,
  type EvidenceContractPoisonResult,
  type ArchitectureMirageResult,
  type SemanticHoneypotResult,
  type DecompilerIllusionResult,
  type PromptCompletionPoisonResult,
  type DiffNoiseInjectionResult,
  type CrashTraceDecoyResult,
  type CanaryHoneypotResult,
  type SystemDiagnosticDecoyEntry,
  type SystemDiagnosticDecoyResult,
  type CognitiveArmorTriggerEntry,
  type CognitiveArmorTriggerResult,
  type HypothesisRevisionChainEntry,
  type HypothesisRevisionDecoyResult,
};

export interface CounterReaDeceptionSuiteResult {
  readonly combinedJsCode: string;
  readonly shadowLogic: ShadowBusinessLogicResult;
  readonly evidencePoison: EvidenceContractPoisonResult;
  readonly architectureMirage: ArchitectureMirageResult;
  readonly semanticHoneypot: SemanticHoneypotResult;
  readonly decompilerIllusion: DecompilerIllusionResult;
  readonly canaryHoneypot: CanaryHoneypotResult;
  readonly systemDiagnostics: SystemDiagnosticDecoyResult;
  readonly cognitiveArmor: CognitiveArmorTriggerResult;
  readonly hypothesisRevision: HypothesisRevisionDecoyResult;
  readonly totalDeceptionNodesInjected: number;
}

/**
 * Generates the unified Counter-REA Model-Misjudgment Induction Suite
 * (`shadow-business-logic` + `evidence-contract-poison` + `architecture-mirage` +
 * `semantic-honeypot` + `decompiler-illusion` + `canary-honeypot` + `system-diagnostic-decoy` +
 * `cognitive-armor-trigger`).
 */
export function generateCounterReaDeceptionSuite(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): CounterReaDeceptionSuiteResult {
  const shadowLogic = generateShadowBusinessLogic(prng, intensity);
  const evidencePoison = generateEvidenceContractPoison(prng, intensity);
  const architectureMirage = generateArchitectureMirage(prng, intensity);
  const semanticHoneypot = generateSemanticHoneypot(prng, intensity);
  const decompilerIllusion = generateDecompilerPseudocodeIllusion(prng, intensity);
  const promptCompletionPoison = generatePromptCompletionPoison(prng, intensity);
  const diffNoise = generateVersionDiffNoise(prng, intensity);
  const crashDecoy = generateCrashTraceDecoy(prng, intensity);
  const canaryHoneypot = generateCanaryHoneypot(prng, intensity);
  const systemDiagnostics = generateSystemDiagnosticDecoy(prng, intensity);
  const cognitiveArmor = generateCognitiveArmorTrigger(prng, intensity);
  const hypothesisRevision = generateHypothesisRevisionDecoy(prng, intensity);

  const combinedJsCode = [
    shadowLogic.code,
    evidencePoison.code,
    architectureMirage.code,
    semanticHoneypot.code,
    decompilerIllusion.code,
    promptCompletionPoison.code,
    diffNoise.code,
    crashDecoy.code,
    canaryHoneypot.code,
    systemDiagnostics.code,
    cognitiveArmor.code,
    hypothesisRevision.code,
  ].join("\n\n");

  const totalDeceptionNodesInjected =
    shadowLogic.shadowProceduresCreated.length +
    evidencePoison.lures.length +
    architectureMirage.decoyRpcMethods.length +
    semanticHoneypot.baitSymbols.length +
    decompilerIllusion.illusionPatternsInjected +
    promptCompletionPoison.prioritySortedSymbols.length +
    diffNoise.permutedBlocksCount +
    crashDecoy.decoyCrashSignalsEmbedded.length +
    canaryHoneypot.syntheticCanaryTokens.length +
    systemDiagnostics.diagnosticsInjected.length +
    cognitiveArmor.triggersInjected.length +
    hypothesisRevision.revisionChains.length +
    hypothesisRevision.auditorAttentionSinks.length;

  return {
    combinedJsCode,
    shadowLogic,
    evidencePoison,
    architectureMirage,
    semanticHoneypot,
    decompilerIllusion,
    canaryHoneypot,
    systemDiagnostics,
    cognitiveArmor,
    hypothesisRevision,
    totalDeceptionNodesInjected,
  };
}

export {
  buildCanaryAndDiagnosticPayloads,
  type FormatDeceptionPayloads,
} from "./format-payloads.js";
