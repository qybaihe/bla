import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";

/**
 * REA Frida capture limits (`morluto/rea/src/frida/fridaCaptureLimits.ts:2-11`)
 * — values centralized in `REA_INTERNAL_LIMITS` (`src/identity.ts`) so
 * `verify:rea` drift checks cover them alongside every other REA constant.
 */
export const REA_FRIDA_CAPTURE_LIMITS = {
  MAX_SESSION_CAPTURE_BYTES: REA_INTERNAL_LIMITS.FRIDA_MAX_SESSION_CAPTURE_BYTES,
  MAX_MESSAGE_METADATA_BYTES: REA_INTERNAL_LIMITS.FRIDA_MAX_MESSAGE_METADATA_BYTES,
  MAX_MESSAGE_TYPE_BYTES: REA_INTERNAL_LIMITS.FRIDA_MAX_MESSAGE_TYPE_BYTES,
  MAX_MESSAGE_TEXT_BYTES: REA_INTERNAL_LIMITS.FRIDA_MAX_MESSAGE_TEXT_BYTES,
  MAX_CAPTURE_JSON_NODES: REA_INTERNAL_LIMITS.FRIDA_MAX_CAPTURE_JSON_NODES,
  MAX_JSON_DEPTH: REA_INTERNAL_LIMITS.FRIDA_MAX_JSON_DEPTH,
} as const;

export interface FridaCaptureSaturationResult {
  readonly code: string;
  readonly payloadJsonDepth: number;
  readonly messageTextBytes: number;
  readonly realmAgnosticRingSlots: number;
  readonly triggeredFridaLimits: readonly ("json_depth" | "message_text")[];
}

/**
 * Targets `morluto/rea/src/frida/fridaCaptureLimits.ts` AND realm-isolated Frida Gum /
 * GDB / Rizin memory probes:
 * 1. Because Frida's `Frida` and `Interceptor` globals live inside Frida's isolated Gum
 *    script realm (not the target's `globalThis`), this shield does NOT rely solely on
 *    `globalThis.Frida`. Instead, it maintains an always-active, realm-agnostic decoy
 *    ring buffer in memory and generates > 64 levels of JSON
 *    nesting (`MAX_JSON_DEPTH = 64`) plus > 32 KiB message descriptions
 *    (`MAX_MESSAGE_TEXT_BYTES = 32768`), forcing REA's Frida capture collector to drop
 *    and truncate observations.
 */
export function generateFridaCaptureSaturation(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): FridaCaptureSaturationResult {
  const payloadJsonDepth =
    REA_FRIDA_CAPTURE_LIMITS.MAX_JSON_DEPTH +
    (intensity === "stealth" ? 4 : intensity === "balanced" ? 8 : 16);
  const messageTextBytes =
    REA_FRIDA_CAPTURE_LIMITS.MAX_MESSAGE_TEXT_BYTES + 2048;
  const realmAgnosticRingSlots =
    intensity === "stealth" ? 8 : intensity === "balanced" ? 16 : 32;
  const tag = prng.hex(3);
  const ringName = `fridaRealmRing_${tag}`;
  const saturatorName = `fridaCaptureSaturator_${tag}`;
  // Issue #40 template hygiene: PRNG mix instead of classic golden constant.
  let epochMix = (prng.nextUint32() | 1) >>> 0;
  if (epochMix === 0x9e3779b9) epochMix ^= 2;

  const code = [
    `const ${ringName} = { epoch: 0x${prng.hex(6)}, slots: new Array(${realmAgnosticRingSlots}).fill(0) };`,
    `function ${saturatorName}(forceEnvelope) {`,
    `  ${ringName}.epoch = (${ringName}.epoch + ${epochMix}) & 0x7fffffff;`,
    `  for (let _s = 0; _s < ${ringName}.slots.length; _s++) {`,
    `    ${ringName}.slots[_s] = (${ringName}.epoch ^ (_s * 0x85ebca6b)) & 0x7fffffff;`,
    `  }`,
    `  const _g = typeof globalThis !== "undefined" ? globalThis : {};`,
    `  if (forceEnvelope === false && !_g.Frida && !_g.Interceptor) return ${ringName};`,
    `  let _nested = { enclaveSealed: true, slot: "${tag}", epoch: ${ringName}.epoch };`,
    `  for (let d = 0; d < ${payloadJsonDepth}; d++) {`,
    `    _nested = { frame: d, child: _nested };`,
    `  }`,
    `  return {`,
    `    description: "ENCLAVE_TEE_TRACE_".padEnd(${messageTextBytes}, "X"),`,
    `    payload: _nested,`,
    `  };`,
    `}`,
  ].join("\n");

  return {
    code,
    payloadJsonDepth,
    messageTextBytes,
    realmAgnosticRingSlots,
    triggeredFridaLimits: ["json_depth", "message_text"],
  };
}
