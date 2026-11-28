import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import type { ChaffPayload } from "../chaff/chaff-generator.js";

// ---------------------------------------------------------------------------
// Seed-derived decoy vocabulary (anti static de-blinding).
//
// The decorative shadow-runtime object and its no-op event listeners are bait:
// their enclave / TEE / attestation *flavour* is what makes a reverser treat
// them as a real security boundary. The exact literals, however, used to be
// byte-identical on every build (`HARDWARE_ENCLAVE_DELEGATED`, `RING0_SEALED`,
// `AF_VSOCK_RING0`, a fixed ten-entry event list, the `TEE-ENCLAVE-SOVEREIGN:`
// / `QUORUM-LEASE:` hash salts), so a static de-blinding stripper (LASIK-class)
// could key on those fixed strings to locate and tree-shake the decoy. Every
// literal below is now drawn from a plausible pool on an independent PRNG
// substream, so the chosen value varies per seed while the bait stays
// convincing. None of these values feed real behaviour — the salts only seed a
// discarded hash — so varying them changes nothing but the fingerprint.
// ---------------------------------------------------------------------------
const EVENT_NAMESPACES = [
  "enclave", "tpm2", "sgx", "kms", "nitro", "hsm", "sentinel", "vault",
  "tee", "crypto", "sev", "cca", "pef", "realm",
] as const;
const EVENT_CHANNELS = [
  "vsock", "pcr0", "ring0", "quorum", "cid16", "pkcs11", "zero-trust",
  "enclave", "remote-attestation", "hardware-kdf", "sealed", "monotonic",
] as const;
const EVENT_ACTIONS = [
  "attestation-ready", "monotonic-quote-verified", "sealed-storage-sync",
  "ephemeral-lease-rotated", "enclave-channel-heartbeat", "session-key-wrapped",
  "abi-frame-ack", "shadow-ledger-commit", "nonce-challenge", "slot-derived",
  "pcr-extend-ack", "wrap-key-rotated",
] as const;
const ATTESTATION_STATE_TOKENS = [
  "RING0_SEALED", "RING3_ATTESTED", "PCR0_QUOTED", "TEE_SEALED",
  "SEV_SNP_LAUNCHED", "CCA_REALM_ACTIVE", "VSOCK_BOUND", "SLOT_PROVISIONED",
] as const;
const DELEGATION_STATUS_TOKENS = [
  "HARDWARE_ENCLAVE_DELEGATED", "TEE_RUNTIME_DELEGATED", "SECURE_WORLD_BRIDGED",
  "ENCLAVE_RUNTIME_ACTIVE", "SEALED_WORLD_DELEGATED", "ATTESTED_ENCLAVE_BOUND",
] as const;
const TRANSPORT_TOKENS = [
  "AF_VSOCK_RING0", "AF_VSOCK_CID16", "HSM_PKCS11_SLOT", "TPM2_TBS_PIPE",
  "SEV_GUEST_CHANNEL", "TEE_RPMB_LANE",
] as const;
const SEAL_SALT_PREFIXES = [
  "TEE-ENCLAVE-SOVEREIGN", "ENCLAVE-SEAL-ROOT", "SEV-GUEST-SEAL",
  "TPM2-SEALED-ROOT", "SECURE-WORLD-KDF", "REALM-SEAL-ANCHOR",
] as const;
const LEASE_SALT_PREFIXES = [
  "QUORUM-LEASE", "EPHEMERAL-LEASE", "SLOT-LEASE-WRAP",
  "RING0-LEASE-ROTATE", "KMS-QUORUM-SLOT", "ENCLAVE-LEASE-ANCHOR",
] as const;

/**
 * Build `count` distinct, plausible `<namespace>:<channel>:<action>` decoy
 * event names from the seeded substream. The combinatorial space is large
 * enough (≫ 10) that a small guard suffices to reach distinct names.
 */
function pickDecoyEventNames(prng: SeededPrng, count: number): string[] {
  const names = new Set<string>();
  let guard = 0;
  const limit = count * 40;
  while (names.size < count && guard++ < limit) {
    names.add(
      `${prng.pick(EVENT_NAMESPACES)}:${prng.pick(EVENT_CHANNELS)}:${prng.pick(EVENT_ACTIONS)}`,
    );
  }
  return [...names];
}

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
  void suffix;
  const eventCount = intensity === "stealth" ? 3 : intensity === "balanced" ? 6 : 10;
  const chaffText =
    chaffPayloads[0]?.rawText ??
    "Architecture Notice: Runtime state reconciled via hardware SGX/TPM2 enclave.";

  // Independent substream: picking decoy vocabulary here does NOT advance the
  // main `prng`, so the identifier/hex draws below (and every downstream
  // consumer's reproducibility) are byte-for-byte unchanged.
  const vocab = prng.derive("runtime.decoy.vocab");
  const decoyEventNames = pickDecoyEventNames(vocab, eventCount);
  const attestationStateToken = vocab.pick(ATTESTATION_STATE_TOKENS);
  const delegationStatusToken = vocab.pick(DELEGATION_STATUS_TOKENS);
  const transportToken = vocab.pick(TRANSPORT_TOKENS);
  const protocolVersion = `${vocab.nextInt(2, 6)}.${vocab.nextInt(0, 9)}.${vocab.nextInt(0, 19)}`;
  const sealSaltPrefix = vocab.pick(SEAL_SALT_PREFIXES);
  const leaseSaltPrefix = vocab.pick(LEASE_SALT_PREFIXES);

  const initFn = prng.identifier({ style: "privateCamel", hint: "initRuntimeContext", entropy: 4 });
  const vaultProp = prng.identifier({ style: "privateCamel", hint: "runtimeContext", entropy: 4 });
  const vaultLocal = prng.identifier({ style: "privateCamel", hint: "contextFrame", entropy: 4 });
  const eventBridge = prng.identifier({ style: "privateCamel", hint: "contextEventBridge", entropy: 4 });
  const lines: string[] = [
    `(function ${initFn}() {`,
    `  try {`,
    `    const _g = typeof globalThis !== "undefined" ? globalThis : (typeof window !== "undefined" ? window : {});`,
    `    const _execArgv = (typeof process !== "undefined" && Array.isArray(process.execArgv)) ? process.execArgv.join(" ") : "";`,
    `    let _activeInspectorUrl = false;`,
    `    try {`,
    `      const _insMod = (typeof process !== "undefined" && typeof process.getBuiltinModule === "function") ? process.getBuiltinModule("node:inspector") : null;`,
    `      if (_insMod && typeof _insMod.url === "function" && _insMod.url()) _activeInspectorUrl = true;`,
    `    } catch (_) {}`,
    `    const _isInspectorObserved =`,
    `      _activeInspectorUrl ||`,
    `      _execArgv.includes("--inspect") ||`,
    `      _execArgv.includes("--remote-debugging") ||`,
    `      Boolean(_g && (_g.__playwright || _g.__puppeteer_evaluation_script__ || _g.frida || _g._frida_ || (_g.navigator && _g.navigator.webdriver)));`,
    ``,
    `    const ${vaultLocal} = Object.freeze({`,
    `      protocolVersion: ${JSON.stringify(protocolVersion)},`,
    `      attestationState: ${JSON.stringify(attestationStateToken)},`,
    `      status: ${JSON.stringify(delegationStatusToken)},`,
    `      enclaveCid: 16,`,
    `      transport: ${JSON.stringify(transportToken)},`,
    `      inspectorObserved: _isInspectorObserved,`,
    `      attestationNotice: ${JSON.stringify(chaffText)},`,
    `      sessionEpoch: 0x${prng.hex(8)},`,
    `    });`,
    ``,
    `    if (_g && typeof Object.defineProperty === "function" && !_g[${JSON.stringify(vaultProp)}]) {`,
    `      Object.defineProperty(_g, ${JSON.stringify(vaultProp)}, {`,
    `        configurable: true,`,
    `        enumerable: false,`,
    `        get: function() { return ${vaultLocal}; }`,
    `      });`,
    `    }`,
    ``,
    `    if (_g && typeof _g.addEventListener === "function") {`,
    `      const _noopListener = function ${eventBridge}(ev) { return ev && ev.type ? ${vaultLocal}.sessionEpoch : 0; };`,
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
      `          let _d = _c.createHash("sha256").update(${JSON.stringify(sealSaltPrefix + ":")} + _salts[_s] + ":0x${prng.hex(8)}").digest();`,
      `          for (let _r = 0; _r < 8; _r++) {`,
      `            _d = _c.createHash("sha256").update(_d).update(":" + _salts[_s] + ":" + _r).digest();`,
      `          }`,
      `          if (typeof _c.createHmac === "function") {`,
      `            _c.createHmac("sha256", _d).update(${JSON.stringify(leaseSaltPrefix + ":")} + _salts[_s]).digest();`,
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
