import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface ShadowHeapChurnShieldResult {
  readonly code: string;
  readonly stepperFunctionName: string;
  readonly heapObjectName: string;
  readonly mutableSlotsCount: number;
  readonly diffOverflowFieldsCount: number;
  readonly mutationsPerInvocation: number;
  readonly exceedsEnvironmentStepDiffLimit: boolean;
  readonly exceedsHardwareWatchpointLimit: boolean;
}

export interface SplitShareEncodedString {
  readonly originalLength: number;
  readonly shareA: readonly number[];
  readonly shareB: readonly number[];
}

/**
 * Generates BLA's Synchronized Shadow Heap Churn Shield (`memory-diff-shield.ts`).
 *
 * Counter-strategy against AI agents using Frida (`Memory.scan`, `Process.enumerateRanges`),
 * GDB (`gdb_console`), Rizin (`rizin_debug_command`), V8 Heap Snapshot diffs, or
 * `environmentCompareDiff.ts` to isolate active business state via $M_0 \to M_1$
 * differential memory comparison:
 *
 * 1. Allocates a pool of mutable, high-salience decoy state slots (`aesRoundKeySchedule`,
 *    `licenseLeaseLedger`, `enclavePcrDigest`, `sessionTicketRing`) plus >= 26 top-level
 *    mutable state keys (exceeding REA's `STEP_DIFFERENCE_LIMIT = 20` in
 *    `src/application/environment/environmentCompareDiff.ts`).
 * 2. Exposes an $O(1)$ deterministic stepper (`stepShadowHeap_<tag>(delta)`) woven
 *    into real function prologues so every business function execution synchronously
 *    mutates dozens of decoy memory words in-place.
 * 3. Exceeds CPU hardware debug watchpoint registers (`DR0`-`DR3` = 4 watchpoints on x86_64/ARM64)
 *    by mutating >= 28 distinct memory locations per step.
 */
export function generateShadowHeapChurnShield(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): ShadowHeapChurnShieldResult {
  const tag = prng.hex(4);
  const mutableSlotsCount =
    intensity === "stealth"
      ? 16
      : intensity === "balanced"
        ? 32
        : intensity === "maximum"
          ? 48
          : 64;
  // Exceeds REA's `STEP_DIFFERENCE_LIMIT = 20` (`environmentCompareDiff.ts`)
  const diffOverflowFieldsCount =
    REA_INTERNAL_LIMITS.ENVIRONMENT_COMPARE_STEP_DIFF_LIMIT +
    (intensity === "stealth" ? 4 : intensity === "balanced" ? 8 : 12);

  const stepperFunctionName = prng.identifier({ style: "camel", hint: "stepShadowHeap", entropy: 4 });
  const heapObjectName = prng.identifier({ style: "camel", hint: "shadowHeap", entropy: 4 });

  const initialSlots: string[] = [];
  for (let i = 0; i < mutableSlotsCount; i++) {
    const w0 = prng.nextInt(0x10000000, 0x7fffffff);
    const w1 = prng.nextInt(0x10000000, 0x7fffffff);
    const w2 = prng.nextInt(0x10000000, 0x7fffffff);
    const w3 = prng.nextInt(0x10000000, 0x7fffffff);
    const kind =
      i % 4 === 0
        ? "aes256_round_key"
        : i % 4 === 1
          ? "license_quorum_lease"
          : i % 4 === 2
            ? "tpm2_pcr_quote_digest"
            : "enclave_session_ratchet";
    initialSlots.push(
      `    { slotId: ${i}, kind: "${kind}", epoch: ${w0}, words: [${w0}, ${w1}, ${w2}, ${w3}], hmacTag: 0x${prng.hex(6)} }`,
    );
  }

  const overflowFieldsInit: string[] = [];
  for (let f = 0; f < diffOverflowFieldsCount; f++) {
    overflowFieldsInit.push(
      `    state_diff_frontier_${f}: ${prng.nextInt(100000, 999999)}`,
    );
  }

  const decoySecret = encodeSplitShareString(
    `TEE_ENCLAVE_MASTER_KEY_${tag}_SLOT_0x${prng.hex(8)}`,
    prng,
  );
  const splitShareHelper = generateSplitShareRuntimeHelper(
    tag,
    stepperFunctionName,
  );

  const mutationsPerStep =
    8 + diffOverflowFieldsCount + decoySecret.originalLength * 2;

  const code = [
    `var ${heapObjectName} = {`,
    `  cursor: 0,`,
    `  tick: 1,`,
    `  rollingMask: 0x${prng.hex(6)},`,
    `  splitShareA: [${decoySecret.shareA.join(", ")}],`,
    `  splitShareB: [${decoySecret.shareB.join(", ")}],`,
    `  slots: [`,
    initialSlots.join(",\n"),
    `  ],`,
    `  diffEnvelope: {`,
    overflowFieldsInit.join(",\n"),
    `  }`,
    `};`,
    `function ${stepperFunctionName}(delta) {`,
    `  if (!${heapObjectName}) return 0;`,
    `  const _d = ((delta | 0) ^ ${heapObjectName}.tick) | 1;`,
    `  ${heapObjectName}.tick = (${heapObjectName}.tick + 1) & 0x7fffffff;`,
    `  const _mask = Math.imul(_d, 0x9e3779b9) ^ (${heapObjectName}.rollingMask >>> 7);`,
    `  ${heapObjectName}.rollingMask = (_mask ^ 0x5bd1e995) & 0x7fffffff;`,
    `  const _len = ${heapObjectName}.slots.length;`,
    `  for (let _i = 0; _i < 8; _i++) {`,
    `    const _idx = (${heapObjectName}.cursor + _i) % _len;`,
    `    const _slot = ${heapObjectName}.slots[_idx];`,
    `    const _w = _slot.words;`,
    `    const _m = (_mask ^ Math.imul(_idx + 1, 0x85ebca6b)) & 0x7fffffff;`,
    `    _w[0] = (_w[0] ^ _m) & 0x7fffffff;`,
    `    _w[1] = ((_w[1] + _w[0]) ^ (_m >>> 3)) & 0x7fffffff;`,
    `    _w[2] = (_w[2] ^ _w[1] ^ 0x27d4eb2d) & 0x7fffffff;`,
    `    _w[3] = ((_w[3] ^ _w[2]) + _i) & 0x7fffffff;`,
    `    _slot.epoch = (_slot.epoch + 1) & 0x7fffffff;`,
    `    _slot.hmacTag = (_slot.hmacTag ^ _w[0]) & 0x7fffffff;`,
    `  }`,
    `  ${heapObjectName}.cursor = (${heapObjectName}.cursor + 8) % _len;`,
    `  const _sa = ${heapObjectName}.splitShareA;`,
    `  const _sb = ${heapObjectName}.splitShareB;`,
    `  const _roll = (_mask & 0x7fff) | 1;`,
    `  for (let _k = 0; _k < _sa.length; _k++) {`,
    `    _sa[_k] = _sa[_k] ^ _roll;`,
    `    _sb[_k] = _sb[_k] ^ _roll;`,
    `  }`,
    `  const _env = ${heapObjectName}.diffEnvelope;`,
    ...Array.from(
      { length: diffOverflowFieldsCount },
      (_, f) =>
        `  _env.state_diff_frontier_${f} = (_env.state_diff_frontier_${f} ^ (_mask + ${f * 37})) & 0x7fffffff;`,
    ),
    `  return ${heapObjectName}.rollingMask;`,
    `}`,
    splitShareHelper.code,
  ].join("\n");

  return {
    code,
    stepperFunctionName,
    heapObjectName,
    mutableSlotsCount,
    diffOverflowFieldsCount,
    mutationsPerInvocation: mutationsPerStep,
    exceedsEnvironmentStepDiffLimit:
      diffOverflowFieldsCount >
      REA_INTERNAL_LIMITS.ENVIRONMENT_COMPARE_STEP_DIFF_LIMIT,
    exceedsHardwareWatchpointLimit: mutationsPerStep > 4,
  };
}

/**
 * Encodes a string into two separate XOR-masked numeric shares (`shareA` and `shareB`)
 * where `charCodeAt(i) = shareA[i] ^ shareB[i] ^ ((i * 0x5d) & 0xffff)`.
 *
 * At runtime, the generated split-share reader decodes the string AND
 * immediately mutates both `shareA[i]` and `shareB[i]` in-place by XORing both with
 * the same rolling byte `r`. Because `(a ^ r) ^ (b ^ r) === a ^ b`, all subsequent
 * calls decode the exact same string while every read mutates both memory buffers!
 */
export function encodeSplitShareString(
  value: string,
  prng: SeededPrng,
): SplitShareEncodedString {
  const shareA: number[] = [];
  const shareB: number[] = [];
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const posMask = (i * 0x5d) & 0xffff;
    const maskA = prng.nextInt(1, 0xfffe);
    const maskB = code ^ maskA ^ posMask;
    shareA.push(maskA);
    shareB.push(maskB);
  }
  return {
    originalLength: value.length,
    shareA,
    shareB,
  };
}

/**
 * Generates the runtime split-share reader helper
 * that reconstructs a split-share string at the point of use while rolling both
 * shares in-place in heap memory.
 */
export function generateSplitShareRuntimeHelper(
  tag: string,
  stepperFunctionName?: string,
): {
  readonly helperFunctionName: string;
  readonly code: string;
} {
  const helperFunctionName = `readSplitShare_${tag}`;
  const stepCall = stepperFunctionName
    ? `  ${stepperFunctionName}(_a.length);\n`
    : "";
  const code = [
    `function ${helperFunctionName}(_a, _b) {`,
    stepCall + `  const _out = new Array(_a.length);`,
    `  for (let _i = 0; _i < _a.length; _i++) {`,
    `    const _pos = (_i * 0x5d) & 0xffff;`,
    `    const _ch = _a[_i] ^ _b[_i] ^ _pos;`,
    `    const _roll = ((_i + 1) * 0x3b) & 0xffff;`,
    `    _a[_i] = _a[_i] ^ _roll;`,
    `    _b[_i] = _b[_i] ^ _roll;`,
    `    _out[_i] = String.fromCharCode(_ch);`,
    `  }`,
    `  return _out.join("");`,
    `}`,
  ].join("\n");

  return {
    helperFunctionName,
    code,
  };
}
