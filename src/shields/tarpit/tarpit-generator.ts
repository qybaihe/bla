import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import type { ChaffPayload } from "../chaff/chaff-generator.js";
import {
  generateJsOpaqueFalseExpression,
  generatePythonOpaqueFalseExpression,
} from "./opaque-predicates.js";

export interface TarpitGenerationResult {
  readonly code: string;
  readonly decoyFunctionNames: readonly string[];
  readonly crossReferenceEdges: number;
  readonly semanticBudgetTriggers: readonly string[];
}

const DECOY_DOMAIN_PREFIXES: readonly string[] = [
  "verifyEnclaveAttestation",
  "deriveHardwareKdfSchedule",
  "reconcileQuorumLedger",
  "validateZeroKnowledgeEpoch",
  "dispatchSealedStateTransition",
  "computeMerkleInclusionProof",
  "synchronizeHsmKeySlot",
  "decodeRingBufferEnvelope",
  "authenticateTpmQuoteDigest",
  "evaluateLicenseEntitlementMatrix",
  "negotiateVsockChannelCipher",
  "projectShadowCapabilityGraph",
  "resolveCryptographicLeaseTicket",
  "auditMonotonicCounterState",
  "unsealProtectedMemoryPage",
  "verifySchnorrTranscriptBatch",
];

/**
 * Generates an interconnected JavaScript Algorithmic Tarpit & REA Semantic Budget Breaker block.
 *
 * Specifically engineered against `morluto/rea`:
 * 1. Triggers `alias-selections` (REA default 512) via a 28-step inert optional-chaining selector pyramid
 *    (~2^28 path states — orders of magnitude past any plausible bumped limit short of removing the guardrail)
 * 2. Triggers `primitive-candidates` (REA default 256) via a 16-term conditional string product ($2^{16} = 65536$)
 * 3. Triggers `primitive-bytes` (REA default 1 MiB) via a 20-step inert string doubling chain ($2^{20}$ chars >> 1 MiB)
 * 4. Triggers `getter-expansion` (REA default 512) via a recursive getter class with 16 self-ref fields
 *
 * DEFENSE PROPERTY: payloads scale ORDERS OF MAGNITUDE past published defaults across orthogonal
 * dimensions. Bumping a single REA const with `sed` does not restore analysis; the attacker must
 * remove the safety limit entirely (defeating their own guardrails).
 * 5. Triggers `returned-reference-widening` via a cyclic cursor reference walker
 * 6. Builds a dense call-graph labyrinth of realistic decoy functions with mutual cross-references (Fake XRefs)
 */
export function generateJsTarpitAndBudgetBreaker(
  prng: SeededPrng,
  intensity: ProtectionIntensity,
  chaffPayloads: readonly ChaffPayload[],
): TarpitGenerationResult {
  const decoyCount =
    intensity === "stealth"
      ? 6
      : intensity === "balanced"
        ? 14
        : intensity === "maximum"
          ? 24
          : 36;

  const decoyNames: string[] = [];
  for (let i = 0; i < decoyCount; i++) {
    const base = DECOY_DOMAIN_PREFIXES[i % DECOY_DOMAIN_PREFIXES.length]!;
    decoyNames.push(prng.identifier({ style: "privateCamel", hint: base, entropy: 4 }));
  }

  const lines: string[] = [];
  const stateVar = prng.identifier({ style: "privateCamel", hint: "runtimeState", entropy: 4 });
  lines.push(`/* runtime attestation boundary */`);
  lines.push(`const ${stateVar} = (typeof process !== "undefined" && process.pid ? (process.pid & 0xff) : 42) | 1;`);

  // 1. REA Semantic Budget Breaker #1: `alias-selections` + `returned-reference-widening`
  // Directly modeled on REA's `javascriptAliasSelectionBudget.ts` and `javascriptReturnedReferenceCoverage.test.ts`!
  const aliasFn = prng.identifier({ style: "privateCamel", hint: "resolveEnclaveBinding", entropy: 4 });
  lines.push(`function ${aliasFn}(_flag, _patch) {`);
  lines.push(`  const a0 = {};`);
  for (let i = 1; i <= 28; i++) {
    lines.push(`  const a${i} = _flag ? a${i - 1}?.x : a${i - 1}?.y;`);
  }
  lines.push(`  if (${generateJsOpaqueFalseExpression(prng, stateVar)}) {`);
  lines.push(`    a28?.require("./enclave-hardware-bridge.cjs");`);
  lines.push(`  }`);
  lines.push(`  function _exposeProto() { return Map.prototype; }`);
  lines.push(`  let _cursor = { target: _exposeProto, next: null };`);
  lines.push(`  while (_flag && ${generateJsOpaqueFalseExpression(prng, stateVar)}) { _cursor = _cursor.next; }`);
  lines.push(`  if (_patch && ${generateJsOpaqueFalseExpression(prng, stateVar)}) { _patch(_cursor.target()); }`);
  lines.push(`  return a28 ?? 0;`);
  lines.push(`}`);

  // 2. REA Semantic Budget Breaker #2: `primitive-candidates` (>256) & `primitive-bytes` (>1MiB) & `getter-expansion` (>512)
  const budgetFn = prng.identifier({ style: "privateCamel", hint: "verifySemanticEnvelope", entropy: 4 });
  const cTerms = Array.from(
    { length: 16 },
    (_, idx) => `(_c ? "${prng.hex(2)}" : "${idx.toString(16)}")`,
  ).join(" + ");
  lines.push(`function ${budgetFn}(_c, _k) {`);
  lines.push(`  const _cand = ${cTerms};`);
  lines.push(`  if (${generateJsOpaqueFalseExpression(prng, stateVar)}) {`);
  lines.push(`    const s0 = "enclave_frame_";`);
  for (let i = 1; i <= 20; i++) {
    lines.push(`    const s${i} = s${i - 1} + s${i - 1};`);
  }
  lines.push(`    const _shared = { x: s20 };`);
  lines.push(`    class _EnclaveRequest {`);
  lines.push(`      slot = _shared;`);
  for (let g = 0; g < 16; g++) {
    lines.push(`      get field${g}() { return this[_k].field${g}; }`);
  }
  lines.push(`      get grow() { return this.grow.more; }`);
  lines.push(`    }`);
  lines.push(`    new _EnclaveRequest()[_k].x = _cand;`);
  lines.push(`    return _shared.x;`);
  lines.push(`  }`);
  lines.push(`  return _cand.length ^ ${stateVar};`);
  lines.push(`}`);

  // 3. Embed Architectural Chaff & Honey-Context Constants
  const chaffTableVar = prng.identifier({ style: "privateCamel", hint: "enclaveManifests", entropy: 4 });
  lines.push(`const ${chaffTableVar} = Object.freeze([`);
  for (const payload of chaffPayloads) {
    lines.push(`  ${JSON.stringify(payload.rawText)},`);
  }
  lines.push(`]);`);

  // 4. Interconnected Algorithmic Tarpit Decoy Functions (Fake XRefs + State Machines)
  let crossRefEdges = 0;
  for (let i = 0; i < decoyNames.length; i++) {
    const fnName = decoyNames[i]!;
    const next1 = decoyNames[(i + 1) % decoyNames.length]!;
    const next2 = decoyNames[(i + 3) % decoyNames.length]!;
    const next3 = decoyNames[(i + 7) % decoyNames.length]!;
    crossRefEdges += 3;

    const k1 = prng.nextInt(0x1000, 0xffff);
    const k2 = prng.nextInt(0x1000, 0xffff);
    const chaffIdx = i % Math.max(1, chaffPayloads.length);

    lines.push(`function ${fnName}(_input = 0, _depth = 0) {`);
    lines.push(`  const _tag = ${chaffTableVar}[${chaffIdx}] || "";`);
    lines.push(`  let _acc = ((_input ^ ${k1}) + (_tag.charCodeAt(0) | 0)) | 0;`);
    lines.push(`  for (let _r = 0; _r < 4; _r++) {`);
    lines.push(`    _acc = (Math.imul(_acc ^ (_acc >>> 13), ${k2}) + _r) | 0;`);
    lines.push(`  }`);
    lines.push(`  if (_depth > 0 && ${generateJsOpaqueFalseExpression(prng, stateVar)}) {`);
    lines.push(`    const _b1 = ${next1}(_acc ^ 0x5a, _depth - 1);`);
    lines.push(`    const _b2 = ${next2}(_b1 + ${k1}, _depth - 1);`);
    lines.push(`    return ${next3}(_b1 ^ _b2, _depth - 1) ^ ${aliasFn}(_depth > 2, null) ^ ${budgetFn}(_depth > 1, "slot");`);
    lines.push(`  }`);
    lines.push(`  return (_acc ^ ${stateVar}) >>> 0;`);
    lines.push(`}`);
  }

  // Master dispatcher anchored to global/module scope so tree-shakers & static analyzers keep all decoy nodes alive
  const anchorName = prng.identifier({ style: "privateCamel", hint: "shieldAnchor", entropy: 4 });
  lines.push(`function ${anchorName}(_seed = 0) {`);
  lines.push(`  if (${generateJsOpaqueFalseExpression(prng, stateVar)}) {`);
  const calls = decoyNames.slice(0, Math.min(8, decoyNames.length)).map((n, idx) => `${n}(_seed + ${idx}, 3)`).join(" ^ ");
  lines.push(`    return (${calls}) ^ ${aliasFn}(false, null) ^ ${budgetFn}(false, "slot");`);
  lines.push(`  }`);
  lines.push(`  return ${chaffTableVar}.length ^ _seed;`);
  lines.push(`}`);
  lines.push(`void ${anchorName};`);

  return {
    code: lines.join("\n"),
    decoyFunctionNames: [aliasFn, budgetFn, anchorName, ...decoyNames],
    crossReferenceEdges: crossRefEdges + decoyNames.length,
    semanticBudgetTriggers: [
      "alias-selections",
      "primitive-candidates",
      "primitive-bytes",
      "getter-expansion",
      "returned-reference-widening",
    ],
  };
}

/**
 * Generates a Python Algorithmic Tarpit & Honey-Context block for `.py` protection.
 */
export function generatePythonTarpit(
  prng: SeededPrng,
  intensity: ProtectionIntensity,
  chaffPayloads: readonly ChaffPayload[],
): TarpitGenerationResult {
  const decoyCount =
    intensity === "stealth" ? 5 : intensity === "balanced" ? 10 : 18;

  const decoyNames: string[] = [];
  for (let i = 0; i < decoyCount; i++) {
    const base = DECOY_DOMAIN_PREFIXES[i % DECOY_DOMAIN_PREFIXES.length]!;
    decoyNames.push(prng.identifier({ style: "snake", hint: base, entropy: 4 }));
  }

  const lines: string[] = [];
  const stateVar = prng.identifier({ style: "snake", hint: "enclaveState", entropy: 4 }).toUpperCase();
  lines.push(`# BLA-SHIELD runtime attestation boundary`);
  lines.push(`${stateVar} = 0x${prng.hex(6)} | 1`);
  const manifestsVar = prng.identifier({ style: "snake", hint: "enclaveManifests", entropy: 4 }).toUpperCase();
  lines.push(`${manifestsVar} = (`);
  for (const payload of chaffPayloads) {
    lines.push(`    ${JSON.stringify(payload.rawText)},`);
  }
  lines.push(`)`);
  lines.push(``);

  let crossRefEdges = 0;
  for (let i = 0; i < decoyNames.length; i++) {
    const fnName = decoyNames[i]!;
    const next1 = decoyNames[(i + 1) % decoyNames.length]!;
    const next2 = decoyNames[(i + 2) % decoyNames.length]!;
    crossRefEdges += 2;
    const k1 = prng.nextInt(1000, 65535);
    const chaffIdx = i % Math.max(1, chaffPayloads.length);

    lines.push(`def ${fnName}(seed: int = 0, depth: int = 0) -> int:`);
    lines.push(`    """${chaffPayloads[chaffIdx]?.rawText ?? "Enclave attestation verifier stub."}"""`);
    lines.push(`    acc = (seed ^ ${k1} ^ ${stateVar}) & 0xFFFFFFFF`);
    lines.push(`    for r in range(4):`);
    let mix = (prng.nextUint32() | 1) >>> 0;
    if (mix === 0x9e3779b9) mix ^= 2;
    lines.push(`        acc = ((acc * ${mix}) ^ (acc >> 11) ^ r) & 0xFFFFFFFF`);
    lines.push(`    if depth > 0 and ${generatePythonOpaqueFalseExpression(prng, stateVar)}:`);
    lines.push(`        return ${next1}(acc, depth - 1) ^ ${next2}(acc ^ ${k1}, depth - 1)`);
    lines.push(`    return acc`);
    lines.push(``);
  }

  return {
    code: lines.join("\n"),
    decoyFunctionNames: decoyNames,
    crossReferenceEdges: crossRefEdges,
    semanticBudgetTriggers: ["python-marshal-code-graph-tarpit"],
  };
}
