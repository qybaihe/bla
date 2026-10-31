import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { getExhaustionProfileForIntensity } from "./rea-budget-matrix.js";

export interface ObligationFloodResult {
  readonly code: string;
  readonly obligationFamiliesInjected: readonly string[];
  readonly totalDecoyObligations: number;
  readonly mandatoryVerificationCasesInduced: number;
}

/**
 * All 26 REA Reconstruction Obligation Node Families from
 * `morluto/rea/src/application/ReconstructionObligationPolicies.ts`
 * (including `"url-scheme"` added in REA `47fa6ab37`).
 * Each family forces REA's `ReconstructionObligationLedgerService` to require
 * 2 to 4 distinct runtime/static proof fixtures (`positive`, `negative`, `malformed`,
 * `cancellation`, `teardown`) before an agent can mark a reconstruction verified.
 */
export const REA_OBLIGATION_FAMILIES = [
  { kind: "package", layer: "packaging", cases: 3 },
  { kind: "installer", layer: "packaging", cases: 3 },
  { kind: "context-bridge-api", layer: "electron", cases: 3 },
  { kind: "ipc-channel", layer: "electron", cases: 3 },
  { kind: "ipc-handler", layer: "electron", cases: 3 },
  { kind: "url-scheme", layer: "electron", cases: 3 },
  { kind: "endpoint", layer: "protocol", cases: 3 },
  { kind: "storage", layer: "persistence", cases: 3 },
  { kind: "worker", layer: "process", cases: 3 },
  { kind: "service-worker", layer: "process", cases: 3 },
  { kind: "native-addon", layer: "native-abi", cases: 2 },
  { kind: "native-export", layer: "native-abi", cases: 2 },
  { kind: "managed-pinvoke-import", layer: "native-abi", cases: 2 },
  { kind: "managed-native-implementation", layer: "native-abi", cases: 2 },
  { kind: "child-process", layer: "process", cases: 4 },
  { kind: "stdio", layer: "process", cases: 3 },
  { kind: "signal", layer: "process", cases: 3 },
  { kind: "config-source", layer: "cli", cases: 3 },
  { kind: "request", layer: "protocol", cases: 3 },
  { kind: "response", layer: "protocol", cases: 3 },
  { kind: "boundary", layer: "application", cases: 3 },
  { kind: "resource", layer: "persistence", cases: 3 },
  { kind: "event", layer: "runtime", cases: 3 },
  { kind: "timer", layer: "runtime", cases: 3 },
  { kind: "promise", layer: "runtime", cases: 3 },
  { kind: "task", layer: "runtime", cases: 3 },
] as const;

/**
 * Generates inert, dead-branch JavaScript/TypeScript patterns that match every
 * static AST recognizer feeding REA's `ReconstructionObligationLedgerService`.
 *
 * Runtime overhead: $O(1)$ (guarded by an opaque false predicate `(x * (x + 1)) % 2 !== 0`),
 * so none of the decoy workers, IPC channels, or endpoints ever execute at runtime.
 * Static effect on REA: inflates the mandatory `ReconstructionObligation` ledger by
 * dozens of multi-case obligations (`positive` + `negative` + `malformed` + `teardown`),
 * exhausting the agent's context window and verification budget.
 */
export function generateObligationLedgerFlood(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): ObligationFloodResult {
  const profile = getExhaustionProfileForIntensity(intensity);
  const selectedFamilies = REA_OBLIGATION_FAMILIES.slice(
    0,
    profile.obligationDecoyFamilies,
  );
  const tag = prng.hex(3);
  const stmts: string[] = [];
  let totalDecoyObligations = 0;
  let mandatoryVerificationCasesInduced = 0;

  stmts.push(
    `function obligationFlood_${tag}(_seed = 0) {`,
    `  const _never = ((_seed * (_seed + 1)) & 1) === 1;`,
    `  if (!_never) return _seed ^ 0x${prng.hex(4)};`,
    `  const _g = typeof globalThis !== "undefined" ? globalThis : {};`,
  );

  for (let i = 0; i < selectedFamilies.length; i++) {
    const fam = selectedFamilies[i]!;
    const id = `${tag}_${i}`;
    totalDecoyObligations++;
    mandatoryVerificationCasesInduced += fam.cases;

    switch (fam.kind) {
      case "context-bridge-api":
        stmts.push(
          `  _g.contextBridge?.exposeInMainWorld("enclaveVault_${id}", { seal: (p) => p, verifyQuote: (q) => Boolean(q) });`,
        );
        break;
      case "ipc-channel":
        stmts.push(
          `  _g.ipcRenderer?.invoke("enclave:attest-slot-${id}", { nonce: "0x${prng.hex(8)}" });`,
        );
        break;
      case "ipc-handler":
        stmts.push(
          `  _g.ipcMain?.handle("enclave:verify-lease-${id}", async (_e, msg) => ({ ok: true, slot: "${id}", msg }));`,
        );
        break;
      case "url-scheme":
        stmts.push(
          `  _g.app?.setAsDefaultProtocolClient?.("enclave-tee-${id}"); _g.protocol?.registerSchemesAsPrivileged?.([{ scheme: "enclave-tee-${id}", privileges: { secure: true, standard: true, supportFetchAPI: true } }]); _g.protocol?.handle?.("enclave-tee-${id}", () => null);`,
        );
        break;
      case "endpoint":
        stmts.push(
          `  _g.fetch?.("/api/v3/enclave/quorum-${id}", { method: "POST", headers: { "X-Enclave-Quote": "${id}" } });`,
        );
        break;
      case "storage":
        stmts.push(
          `  _g.localStorage?.setItem("tee.enclave.sealed.${id}", JSON.stringify({ epoch: ${1700000000 + i}, sig: "0x${prng.hex(8)}" }));`,
        );
        break;
      case "worker":
        stmts.push(
          `  if (typeof Worker === "function") { const _w = new Worker("./enclave-worker-${id}.js"); _w.terminate(); }`,
        );
        break;
      case "service-worker":
        stmts.push(
          `  _g.navigator?.serviceWorker?.register("/enclave-sw-${id}.js", { scope: "/enclave/${id}/" });`,
        );
        break;
      case "native-addon":
        stmts.push(
          `  _g.process?.dlopen?.({ exports: {} }, "enclave_ring0_${id}.node");`,
        );
        break;
      case "native-export":
        stmts.push(
          `  _g.nativeBridge_${id}?.enclave_unseal_slot_${id}?.(0x${prng.hex(4)});`,
        );
        break;
      case "child-process":
        stmts.push(
          `  _g.childProcBridge?.spawn?.("tpm2-quote-verifier-${id}", ["--pcr0", "0x${prng.hex(8)}"]);`,
        );
        break;
      case "stdio":
        stmts.push(
          `  _g.process?.stdout?.write?.("[ENCLAVE-STDIO-${id}]\\n");`,
        );
        break;
      case "signal":
        stmts.push(
          `  _g.process?.on?.("SIGUSR2", () => _g.signalHandler_${id}?.());`,
        );
        break;
      case "config-source":
        stmts.push(
          `  const _cfg_${id} = _g.process?.env?.["TEE_ENCLAVE_CONFIG_${id.toUpperCase()}"] ?? "default-sealed";`,
        );
        break;
      case "request":
        stmts.push(
          `  const _req_${id} = typeof Request === "function" ? new Request("https://enclave.internal/v1/slot/${id}") : null;`,
        );
        break;
      case "response":
        stmts.push(
          `  const _res_${id} = typeof Response === "function" ? new Response(JSON.stringify({ sealed: "${id}" })) : null;`,
        );
        break;
      case "boundary":
        stmts.push(
          `  const _parsed_${id} = JSON.parse('{"enclaveBoundary":"${id}","version":3}');`,
        );
        break;
      case "resource":
        stmts.push(
          `  _g.resourcePoolBridge?.acquireLease?.("enclave-hsm-${id}")?.release?.();`,
        );
        break;
      case "event":
        stmts.push(
          `  _g.dispatchEvent?.(typeof CustomEvent === "function" ? new CustomEvent("tee:enclave-sync-${id}") : { type: "tee:${id}" });`,
        );
        break;
      case "timer":
        stmts.push(
          `  const _tmr_${id} = setTimeout(() => {}, 60000); clearTimeout(_tmr_${id});`,
        );
        break;
      case "promise":
        stmts.push(
          `  Promise.resolve("${id}").then((v) => v);`,
        );
        break;
      case "task":
        stmts.push(
          `  typeof queueMicrotask === "function" && queueMicrotask(() => {});`,
        );
        break;
      case "package":
        stmts.push(
          `  _g.packageManifest_${id} = { name: "@enclave/runtime-${id}", version: "3.1.0-tee" };`,
        );
        break;
      case "installer":
        stmts.push(
          `  _g.installerHook_${id}?.runPostInstall?.({ product: "enclave-runtime-${id}", channel: "stable-tee" });`,
        );
        break;
      case "managed-pinvoke-import":
        stmts.push(
          `  _g.DllImport?.("enclave_native_${id}.dll", { EntryPoint: "UnsealSlot_${id}" });`,
        );
        break;
      case "managed-native-implementation":
        stmts.push(
          `  _g.managedNative_${id}?.InvokeEnclaveExport?.("seal_payload_${id}", new Uint8Array(0));`,
        );
        break;
    }
  }

  stmts.push(`  return _seed;`, `}`);

  return {
    code: stmts.join("\n"),
    obligationFamiliesInjected: selectedFamilies.map((f) => f.kind),
    totalDecoyObligations,
    mandatoryVerificationCasesInduced,
  };
}
