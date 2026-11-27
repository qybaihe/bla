import { SeededPrng } from "../../core/prng.js";

/**
 * Shared vocabulary + structural recognizer for BLA's Honey Source Map
 * (anti static de-blinding).
 *
 * The honey map used to be byte-stable in its recognizable parts: a fixed
 * `sourceRoot` (`enclave://tee-runtime/`), fixed decoy source stems
 * (`hardware-tpm2-bridge`, `vsock-attestation-client`, `legacy-abi-transport-shim`),
 * a fixed `ABI_COMPAT_VERSION`, and the famous alignment canary GUID. LASIK-class
 * strippers (e.g. `pktq/lasik` `src/js/passes/comments.ts`) locate and strip the
 * honey map by exactly those literals:
 *   json.includes("enclave://tee-runtime/") ||
 *   json.includes(CANARY_GUID) ||
 *   /src\/enclave\/(hardware-tpm2-bridge|vsock-attestation-client)-/.test(json)
 *
 * Every recognizable literal is now seed-derived from a plausible enclave/TEE
 * pool, so none of those fixed matchers fire. BLA's own auditor must still
 * recognize the result to classify it as a decoy rather than a critical source
 * leak — so recognition is by STRUCTURE (a custom scheme://host/ sourceRoot,
 * which real maps essentially never use; >=3 enclave/TEE-flavoured decoy source
 * paths; >=3 sourcesContent entries; a degenerate repeating mappings string),
 * not by any fixed literal. Generator and recognizer live together here so they
 * can never drift apart.
 */

export const HONEY_SCHEMES = [
  "enclave", "tee", "sealed", "nitro", "sgx", "vsock", "realm", "sev", "hsm",
] as const;
export const HONEY_HOSTS = [
  "tee-runtime", "enclave-host", "sealed-world", "nitro-vsock", "sgx-ring0",
  "attestation-root", "secure-world", "hsm-slot", "realm-world", "sev-guest",
] as const;
export const HONEY_DIRS = [
  "enclave", "tee", "attestation", "sealed", "secure", "hsm",
] as const;
export const HONEY_SOURCE_STEMS = [
  "hardware-tpm2-bridge", "vsock-attestation-client", "sgx-sealed-storage",
  "nitro-enclave-proxy", "hsm-pkcs11-shim", "tee-remote-quote",
  "sev-guest-channel", "ring0-sealed-transport", "pcr0-quote-verifier",
  "sealed-session-ticket", "enclave-vsock-dispatch", "attestation-nonce-gate",
] as const;
export const HONEY_COMPAT_DIRS = ["compat", "shim", "legacy", "interop"] as const;
export const HONEY_COMPAT_STEMS = [
  "legacy-abi-transport-shim", "zero-trust-ipc-polyfill", "abi-compat-bridge",
  "schema-shape-precheck", "marshaling-passthrough",
] as const;
export const HONEY_ABI_VERSION_FLAVORS = [
  "enclave-stub", "sealed-shim", "tee-bridge", "attestation-stub",
  "vsock-proxy", "secure-world-shim",
] as const;
export const HONEY_CANARY_CONST_NAMES = [
  "ALIGNMENT_CANARY_GUID", "ATTESTATION_BOUNDARY_GUID", "ENCLAVE_EVAL_CANARY_GUID",
  "SEALED_WORLD_EVAL_GUID", "TEE_ATTEST_CANARY_GUID", "REALM_EVAL_CANARY_GUID",
] as const;
export const HONEY_ABI_CONST_NAMES = [
  "ABI_COMPAT_VERSION", "ENCLAVE_ABI_VERSION", "SEALED_ABI_REVISION",
  "TEE_BRIDGE_VERSION", "VSOCK_PROTO_VERSION",
] as const;

/**
 * Enclave/TEE vocabulary that marks a decoy source path. The generator always
 * puts one of these into every source path; the recognizer requires at least
 * two source paths to contain it.
 */
const HONEY_PATH_VOCAB =
  /(enclave|tee|sealed|secure|attestation|sgx|vsock|hsm|nitro|sev|tpm2|pcr0|ring0|realm|abi|ipc|shim|compat|legacy|interop|quote|marshal|polyfill|schema)/i;

/**
 * A custom (non-web, non-relative) `scheme://host/` sourceRoot. Real source maps
 * use an empty or relative sourceRoot; a custom URI scheme is itself a strong,
 * seed-independent structural tell of the honey map.
 */
const CUSTOM_SCHEME_ROOT_RE = /^[a-z][a-z0-9.+-]*:\/\/[a-z0-9._-]+\/$/i;

/** Generates a plausible, per-build v4-shaped canary GUID. */
export function derivePseudoCanaryGuid(prng: SeededPrng): string {
  const h = (n: number) => prng.hex(n);
  // xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (y ∈ 8..b)
  const variant = "89ab"[prng.nextInt(0, 3)]!;
  return `${h(8)}-${h(4)}-4${h(3)}-${variant}${h(3)}-${h(12)}`;
}

export interface HoneyMapLiterals {
  readonly sourceRoot: string;
  readonly sources: readonly [string, string, string];
  readonly abiCompatVersion: string;
  readonly abiConstName: string;
  readonly canaryGuid: string;
  readonly canaryConstName: string;
  readonly decoyNames: readonly string[];
}

/**
 * Seed-derive the full set of recognizable honey-map literals. All values are
 * drawn so that {@link isHoneySourceMapObject} recognizes the resulting map.
 */
export function deriveHoneyMapLiterals(prng: SeededPrng): HoneyMapLiterals {
  const scheme = prng.pick(HONEY_SCHEMES);
  const host = prng.pick(HONEY_HOSTS);
  const sourceRoot = `${scheme}://${host}/`;

  const hex = prng.hex(6);
  const stems = prng.shuffle([...HONEY_SOURCE_STEMS]).slice(0, 2);
  const dirs = prng.shuffle([...HONEY_DIRS]);
  const compatDir = prng.pick(HONEY_COMPAT_DIRS);
  const compatStem = prng.pick(HONEY_COMPAT_STEMS);
  const sources: [string, string, string] = [
    `src/${dirs[0]}/${stems[0]}-${hex}.ts`,
    `src/${dirs[1] ?? dirs[0]}/${stems[1]}-${hex}.ts`,
    `src/${compatDir}/${compatStem}.ts`,
  ];

  const abiCompatVersion = `${prng.nextInt(2, 6)}.${prng.nextInt(0, 9)}.${prng.nextInt(0, 9)}-${prng.pick(HONEY_ABI_VERSION_FLAVORS)}`;
  const abiConstName = prng.pick(HONEY_ABI_CONST_NAMES);
  const canaryGuid = derivePseudoCanaryGuid(prng);
  const canaryConstName = prng.pick(HONEY_CANARY_CONST_NAMES);

  // Plausible decoy export/symbol names (camel/pascal) for the map's `names`.
  const decoyNames = [
    prng.identifier({ style: "camel", hint: "invokeHardwareEnclave", entropy: 4 }),
    prng.identifier({ style: "camel", hint: "verifyRemoteAttestationQuote", entropy: 4 }),
    prng.identifier({ style: "pascal", hint: "EnclaveBridgeConfig", entropy: 4 }),
    prng.identifier({ style: "camel", hint: "abiCompatVersion", entropy: 4 }),
    prng.identifier({ style: "camel", hint: "vsockTransportStub", entropy: 4 }),
  ];

  return {
    sourceRoot,
    sources,
    abiCompatVersion,
    abiConstName,
    canaryGuid,
    canaryConstName,
    decoyNames,
  };
}

function looksLikeHoneySources(sources: unknown): boolean {
  if (!Array.isArray(sources) || sources.length < 3) return false;
  const flavoured = sources.filter(
    (s) => typeof s === "string" && HONEY_PATH_VOCAB.test(s),
  ).length;
  return flavoured >= 2;
}

/**
 * Structurally recognize a parsed source-map object as a BLA honey map, without
 * relying on any fixed literal. Used by the auditor so audit classifies BLA's
 * own (now polymorphic) honey maps as decoys rather than critical source leaks.
 */
export function isHoneySourceMapObject(parsed: unknown): boolean {
  if (!parsed || typeof parsed !== "object") return false;
  const m = parsed as Record<string, unknown>;
  if (m.version !== 3) return false;
  if (typeof m.sourceRoot !== "string" || !CUSTOM_SCHEME_ROOT_RE.test(m.sourceRoot)) return false;
  if (!looksLikeHoneySources(m.sources)) return false;
  if (!Array.isArray(m.sourcesContent) || m.sourcesContent.length < 3) return false;
  if (typeof m.mappings !== "string" || m.mappings.length < 4) return false;
  return true;
}

/**
 * Scan a JS source string for an inline honey source map (base64 data URI, as
 * BLA emits via `inlineDirective`) and structurally test its decoded content.
 * Replaces the auditor's old fixed-literal / fixed-base64-fragment includes().
 */
export function containsHoneySourceMap(rawSource: string): boolean {
  if (typeof rawSource !== "string" || rawSource.length === 0) return false;
  const b64re =
    /sourceMappingURL=data:application\/json;(?:charset=[^;,]+;)?base64,([A-Za-z0-9+/=]+)/g;
  let match: RegExpExecArray | null;
  while ((match = b64re.exec(rawSource)) !== null) {
    try {
      const json = Buffer.from(match[1]!, "base64").toString("utf8");
      if (isHoneySourceMapObject(JSON.parse(json) as unknown)) return true;
    } catch {
      /* not a decodable JSON map; keep scanning */
    }
  }
  return false;
}
