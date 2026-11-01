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
  /** Python shared dict mutated by decoys / weave (absent for JS tarpit). */
  readonly sharedSlotName?: string;
  /** Python opaque-predicate seed / state int name. */
  readonly stateVarName?: string;
  /** Python module warm-init function name (skipped by customer-def weave). */
  readonly warmInitName?: string;
}

/** Mixed honey + mundane stems so a single TEE/TPM grep cannot dismiss the whole tarpit. */
const SCARE_DECOY_PREFIXES: readonly string[] = [
  "verifyEnclaveAttestation",
  "deriveHardwareKdfSchedule",
  "authenticateTpmQuoteDigest",
  "negotiateVsockChannelCipher",
  "synchronizeHsmKeySlot",
  "unsealProtectedMemoryPage",
];

const MUNDANE_DECOY_PREFIXES: readonly string[] = [
  "reconcileInvoiceBatch",
  "hydrateSessionCache",
  "flushTelemetryBuffer",
  "normalizeLocaleBundle",
  "scheduleBackoffRetry",
  "compactWalSegment",
  "projectCatalogFacet",
  "bindWorkerPoolSlot",
  "materializeReportCursor",
  "encodeTransportFrame",
  "observeMetricHistogram",
  "adaptGatewayPolicy",
  "reducePipelineShard",
  "captureAuditSample",
  "primeConnectionPool",
  "transformLookupVector",
];

/** @deprecated Prefer the split scare/mundane pools; kept for callers that iterate a flat list. */
const DECOY_DOMAIN_PREFIXES: readonly string[] = [
  ...SCARE_DECOY_PREFIXES,
  ...MUNDANE_DECOY_PREFIXES,
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
    const useScare = i % 3 === 0;
    const pool = useScare ? SCARE_DECOY_PREFIXES : MUNDANE_DECOY_PREFIXES;
    const base = pool[i % pool.length]!;
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
 *
 * Defense properties (WorkBuddy / REA peel resistance):
 * - No greppable `_bla_` / `BLA-SHIELD` markers in emitted names or banner comments.
 * - Decoy stems mix mundane app vocabulary with a minority of TEE scare names so a
 *   single `enclave|TPM2|Nitro` grep cannot discard the whole graph.
 * - Every decoy has a non-trivial always-executed body that mutates shared state and
 *   records peer edges; opaque-false branches keep deep recursion inert at runtime.
 * - A module-level warm initializer actually invokes every decoy once so static
 *   reachability / xref tools cannot dismiss them as unreferenced `pass` stubs.
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
    // ~1/3 scare stems (honey), ~2/3 mundane — avoids homogeneous enclave-only naming.
    const useScare = i % 3 === 0;
    const pool = useScare ? SCARE_DECOY_PREFIXES : MUNDANE_DECOY_PREFIXES;
    const base = pool[i % pool.length]!;
    decoyNames.push(prng.identifier({ style: "snake", hint: base, entropy: 4 }));
  }

  const lines: string[] = [];
  // Keep auditor phrase "runtime attestation boundary" but drop greppable BLA-SHIELD.
  const stateVar = prng
    .identifier({ style: "snake", hint: "runtimeState", entropy: 4 })
    .toUpperCase();
  const slotVar = prng
    .identifier({ style: "snake", hint: "sharedSlot", entropy: 4 })
    .toUpperCase();
  const manifestsVar = prng
    .identifier({ style: "snake", hint: "manifestTable", entropy: 4 })
    .toUpperCase();
  const warmName = prng.identifier({
    style: "snake",
    hint: "warmRuntimeBindings",
    entropy: 4,
  });

  lines.push(`# runtime attestation boundary`);
  lines.push(`${stateVar} = 0x${prng.hex(6)} | 1`);
  lines.push(`${slotVar}: dict = {"epoch": 0, "peer": 0, "tag": 0}`);
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
    const next2 = decoyNames[(i + 3) % decoyNames.length]!;
    const next3 = decoyNames[(i + 5) % decoyNames.length]!;
    crossRefEdges += 3;
    const k1 = prng.nextInt(1000, 65535);
    const k2 = prng.nextInt(1000, 65535);
    const chaffIdx = i % Math.max(1, chaffPayloads.length);
    const bodyVariant = i % 4;
    let mix = (prng.nextUint32() | 1) >>> 0;
    if (mix === 0x9e3779b9 || mix === 2654435769) mix ^= 2;

    const docstring =
      chaffPayloads[chaffIdx]?.rawText ??
      "Compatibility shim retained for ABI alignment.";

    lines.push(`def ${fnName}(seed: int = 0, depth: int = 0) -> int:`);
    lines.push(`    """${docstring}"""`);
    lines.push(`    tag = ${manifestsVar}[${chaffIdx} % len(${manifestsVar})]`);
    lines.push(`    acc = (seed ^ ${k1} ^ ${stateVar}) & 0xFFFFFFFF`);

    if (bodyVariant === 0) {
      lines.push(`    for r in range(5):`);
      lines.push(
        `        acc = ((acc * ${mix}) ^ (acc >> 11) ^ r ^ (ord(tag[r % len(tag)]) if tag else 0)) & 0xFFFFFFFF`,
      );
      lines.push(
        `        ${slotVar}["epoch"] = (${slotVar}.get("epoch", 0) ^ acc) & 0xFFFFFFFF`,
      );
    } else if (bodyVariant === 1) {
      lines.push(`    cursor = bytearray(8)`);
      lines.push(`    for r in range(4):`);
      lines.push(
        `        acc = ((acc * ${mix}) ^ (acc >> 7) ^ (r * ${k2})) & 0xFFFFFFFF`,
      );
      lines.push(`        cursor[r] = acc & 0xFF`);
      lines.push(`        cursor[7 - r] = (acc >> 8) & 0xFF`);
      lines.push(
        `    ${slotVar}["tag"] = int.from_bytes(cursor, "little") ^ ${slotVar}.get("tag", 0)`,
      );
    } else if (bodyVariant === 2) {
      lines.push(`    def _fold(local: int, rounds: int) -> int:`);
      lines.push(`        v = local & 0xFFFFFFFF`);
      lines.push(`        for r in range(rounds):`);
      lines.push(
        `            v = ((v * ${mix}) ^ (v >> 13) ^ r) & 0xFFFFFFFF`,
      );
      lines.push(`        return v`);
      lines.push(`    acc = _fold(acc ^ ${k2}, 4)`);
      lines.push(`    try:`);
      lines.push(
        `        ${slotVar}["peer"] = (${slotVar}.get("peer", 0) + acc) & 0xFFFFFFFF`,
      );
      lines.push(`    except Exception:`);
      lines.push(`        ${slotVar}["peer"] = acc`);
    } else {
      lines.push(
        `    window = [(acc ^ (i << 3)) & 0xFF for i in range(6)]`,
      );
      lines.push(`    for r, b in enumerate(window):`);
      lines.push(
        `        acc = ((acc * ${mix}) ^ b ^ (r * ${k2})) & 0xFFFFFFFF`,
      );
      lines.push(
        `    ${slotVar}["epoch"] = (${slotVar}.get("epoch", 0) ^ acc ^ len(tag)) & 0xFFFFFFFF`,
      );
    }

    // Always-executed peer name touch keeps xrefs dense even when depth==0.
    lines.push(
      `    ${slotVar}["peer"] = (${slotVar}.get("peer", 0) ^ hash(${next1}.__name__) ^ hash(${next2}.__name__)) & 0xFFFFFFFF`,
    );
    lines.push(
      `    if depth > 0 and ${generatePythonOpaqueFalseExpression(prng, stateVar)}:`,
    );
    lines.push(
      `        return ${next1}(acc, depth - 1) ^ ${next2}(acc ^ ${k1}, depth - 1) ^ ${next3}(acc ^ ${k2}, max(0, depth - 2))`,
    );
    lines.push(`    return acc ^ (${slotVar}.get("epoch", 0) & 0xFFFF)`);
    lines.push(``);
  }

  // Live module-level warm: every decoy is reachable from import-time init.
  lines.push(`def ${warmName}(_seed: int = 0) -> int:`);
  lines.push(`    acc = _seed & 0xFFFFFFFF`);
  for (let i = 0; i < decoyNames.length; i++) {
    lines.push(`    acc ^= ${decoyNames[i]}(acc ^ ${i + 1}, 0)`);
    crossRefEdges += 1;
  }
  lines.push(`    ${slotVar}["warm"] = acc`);
  lines.push(`    return acc`);
  lines.push(``);
  lines.push(`${warmName}(${stateVar} & 0xFF)`);
  lines.push(``);

  return {
    code: lines.join("\n"),
    decoyFunctionNames: [...decoyNames, warmName],
    crossReferenceEdges: crossRefEdges,
    semanticBudgetTriggers: ["python-marshal-code-graph-tarpit"],
    sharedSlotName: slotVar,
    stateVarName: stateVar,
    warmInitName: warmName,
  };
}
