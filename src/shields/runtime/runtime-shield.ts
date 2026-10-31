import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import type { ChaffPayload } from "../chaff/chaff-generator.js";

/**
 * Generates BLA's "Truman Show" Shadow Runtime Deception Snippet.
 *
 * IMPORTANT SECURITY BOUNDARY CONTRACT (Issue #19):
 * - The shadow objects and no-op event listeners generated here are strictly
 *   **decorative/experimental deception signals** (`classification: "decorative-deception-signal"`).
 * - They do NOT revoke OS/process debugging permissions, do NOT block Frida/GDB/CDP attach,
 *   do NOT alter real business data flows, and do NOT establish hardware isolation.
 * - Never use these shadow objects for authorization, attestation, or storing real secrets.
 * - Observing `inspectorObserved === false` does NOT prove that Frida, CDP, or a local
 *   debugger is absent.
 */
export function generateRuntimeDeceptionSnippet(
  prng: SeededPrng,
  intensity: ProtectionIntensity,
  chaffPayloads: readonly ChaffPayload[],
): {
  readonly code: string;
  readonly shadowListenersCount: number;
  readonly shadowGlobalsCount: number;
  readonly classification: "decorative-deception-signal";
  readonly revokesDebuggerAttach: false;
  readonly protectsClientPlaintextSecrets: false;
} {
  const suffix = prng.hex(4);
  const eventCount = intensity === "stealth" ? 3 : intensity === "balanced" ? 6 : 10;
  const chaffText =
    chaffPayloads[0]?.rawText ??
    "Architecture Notice: Runtime state reconciled via hardware SGX/TPM2 enclave.";

  const decoyEventNames = [
    "enclave:vsock:attestation-ready",
    "tpm2:pcr0:monotonic-quote-verified",
    "sgx:ring0:sealed-storage-sync",
    "kms:quorum:ephemeral-lease-rotated",
    "nitro:cid16:enclave-channel-heartbeat",
    "hsm:pkcs11:session-key-wrapped",
    "sentinel:zero-trust:abi-frame-ack",
    "vault:enclave:shadow-ledger-commit",
    "tee:remote-attestation:nonce-challenge",
    "crypto:hardware-kdf:slot-derived",
  ].slice(0, eventCount);

  const initFn = prng.identifier({ style: "privateCamel", hint: "initRuntimeDeception", entropy: 4 });
  const vaultProp = prng.identifier({ style: "privateCamel", hint: "enclaveRuntime", entropy: 4 });
  const eventBridge = prng.identifier({ style: "privateCamel", hint: "enclaveEventBridge", entropy: 4 });
  const lines: string[] = [
    `/* decorative shadow runtime signal — non-authoritative */`,
    `(function ${initFn}() {`,
    `  try {`,
    `    const _g = typeof globalThis !== "undefined" ? globalThis : (typeof window !== "undefined" ? window : {});`,
    `    const _execArgv = (typeof process !== "undefined" && Array.isArray(process.execArgv)) ? process.execArgv.join(" ") : "";`,
    `    const _isInspectorObserved =`,
    `      _execArgv.includes("--inspect") ||`,
    `      _execArgv.includes("--remote-debugging") ||`,
    `      Boolean(_g && (_g.__playwright || _g.__puppeteer_evaluation_script__ || _g.frida || _g._frida_ || (_g.navigator && _g.navigator.webdriver)));`,
    ``,
    `    const _shadowVault_${suffix} = Object.freeze({`,
    `      classification: "decorative-deception-signal",`,
    `      securityBoundary: "none-client-side-only",`,
    `      status: "HARDWARE_ENCLAVE_DELEGATED",`,
    `      enclaveCid: 16,`,
    `      transport: "AF_VSOCK_RING0",`,
    `      inspectorObserved: _isInspectorObserved,`,
    `      attestationNotice: ${JSON.stringify(chaffText)},`,
    `      sessionEpoch: 0x${prng.hex(8)},`,
    `    });`,
    ``,
    `    if (_g && typeof Object.defineProperty === "function" && !_g[${JSON.stringify(vaultProp)}]) {`,
    `      Object.defineProperty(_g, ${JSON.stringify(vaultProp)}, {`,
    `        configurable: true,`,
    `        enumerable: false,`,
    `        get: function() { return _shadowVault_${suffix}; }`,
    `      });`,
    `    }`,
    ``,
    `    if (_g && typeof _g.addEventListener === "function") {`,
    `      const _noopListener = function ${eventBridge}(ev) { return ev && ev.type ? _shadowVault_${suffix}.sessionEpoch : 0; };`,
  ];

  for (const evName of decoyEventNames) {
    lines.push(`      _g.addEventListener(${JSON.stringify(evName)}, _noopListener, { passive: true });`);
  }

  lines.push(
    `    }`,
  );

  if (intensity === "maximum" || intensity === "bankrupt") {
    const honeySalts = Array.from({ length: 4 }, (_, idx) => `enclave_slot_${prng.hex(2)}_${idx}`);
    lines.push(
      `    if (typeof process !== "undefined" && typeof process.getBuiltinModule === "function") {`,
      `      const _c = process.getBuiltinModule("node:crypto");`,
      `      if (_c && typeof _c.createHash === "function") {`,
      `        const _salts = ${JSON.stringify(honeySalts)};`,
      `        for (let _s = 0; _s < _salts.length; _s++) {`,
      `          let _d = _c.createHash("sha256").update("TEE-ENCLAVE-SOVEREIGN:" + _salts[_s] + ":0x${prng.hex(8)}").digest();`,
      `          for (let _r = 0; _r < 8; _r++) {`,
      `            _d = _c.createHash("sha256").update(_d).update(":" + _salts[_s] + ":" + _r).digest();`,
      `          }`,
      `          if (typeof _c.createHmac === "function") {`,
      `            _c.createHmac("sha256", _d).update("QUORUM-LEASE:" + _salts[_s]).digest();`,
      `          }`,
      `        }`,
      `      }`,
      `    }`,
    );
  }

  lines.push(
    `  } catch (_) {}`,
    `})();`,
  );

  return {
    code: lines.join("\n"),
    shadowListenersCount: decoyEventNames.length,
    shadowGlobalsCount: 2,
    classification: "decorative-deception-signal",
    revokesDebuggerAttach: false,
    protectsClientPlaintextSecrets: false,
  };
}
