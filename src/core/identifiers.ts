import type { SeededPrng } from "./prng.js";

/**
 * Realistic identifier vocabulary for emitted shield artifacts.
 *
 * CRITICAL DEFENSIVE PROPERTY: every name drawn from this module must be
 * statistically indistinguishable from ordinary application identifiers.
 * No shared greppable substring (`_bla`, `$00_AAA`, `__bla_`, …) may appear
 * in the emitted artifact — a single `grep -v` must not be able to separate
 * injected noise from real code.
 */

const VERBS = Object.freeze([
  "resolve",
  "compute",
  "derive",
  "validate",
  "dispatch",
  "project",
  "reconcile",
  "normalize",
  "assemble",
  "compose",
  "evaluate",
  "schedule",
  "acquire",
  "release",
  "bind",
  "adapt",
  "mirror",
  "fold",
  "reduce",
  "expand",
  "encode",
  "decode",
  "seal",
  "unseal",
  "attest",
  "verify",
  "sync",
  "flush",
  "prime",
  "hydrate",
  "materialize",
  "capture",
  "emit",
  "observe",
  "trace",
  "probe",
  "sample",
  "filter",
  "transform",
  "allocate",
] as const);

const NOUNS = Object.freeze([
  "Ledger",
  "Envelope",
  "Session",
  "Ticket",
  "Digest",
  "Frame",
  "Cursor",
  "Handle",
  "Slot",
  "Epoch",
  "Quota",
  "Policy",
  "Manifest",
  "Bundle",
  "Shard",
  "Segment",
  "Vector",
  "Matrix",
  "Buffer",
  "Stream",
  "Channel",
  "Bridge",
  "Gateway",
  "Router",
  "Registry",
  "Catalog",
  "Index",
  "Cache",
  "Pool",
  "Queue",
  "Stack",
  "Tree",
  "Graph",
  "Node",
  "Edge",
  "Probe",
  "Sensor",
  "Metric",
  "Sample",
  "Record",
  "Entry",
  "Token",
  "Claim",
  "Scope",
  "Context",
  "Runtime",
  "Worker",
  "Service",
  "Client",
  "Provider",
] as const);

const ADJECTIVES = Object.freeze([
  "Active",
  "Pending",
  "Sealed",
  "Transient",
  "Durable",
  "Local",
  "Remote",
  "Shared",
  "Private",
  "Mutable",
  "Frozen",
  "Lazy",
  "Eager",
  "Inline",
  "Deferred",
  "Primary",
  "Secondary",
  "Nested",
  "Composite",
  "Sparse",
] as const);

const SNAKE_STEMS = Object.freeze([
  "session",
  "ledger",
  "envelope",
  "digest",
  "cursor",
  "handle",
  "epoch",
  "quota",
  "policy",
  "manifest",
  "bundle",
  "shard",
  "segment",
  "vector",
  "matrix",
  "buffer",
  "stream",
  "channel",
  "bridge",
  "gateway",
  "router",
  "registry",
  "catalog",
  "index",
  "cache",
  "pool",
  "queue",
  "probe",
  "metric",
  "sample",
  "record",
  "token",
  "claim",
  "scope",
  "context",
  "runtime",
  "worker",
  "service",
  "client",
  "provider",
  "slot",
  "frame",
  "ticket",
] as const);

export type IdentifierStyle =
  | "camel"
  | "pascal"
  | "snake"
  | "privateCamel"
  | "earlySort";

export interface RealisticIdentifierOptions {
  readonly style?: IdentifierStyle;
  /** Extra suffix entropy hex length (default 3). */
  readonly entropy?: number;
  /** Optional semantic stem forced into the name (still mixed with vocabulary). */
  readonly hint?: string;
}

const BASE36_CHARS = "0123456789abcdefghjkmnpqrstuvwxyz";
const NON_HEX_LETTERS = "ghjkmnpqrstuvwxyz";
const DOMAIN_SUFFIXES = Object.freeze([
  "Ctx",
  "Ref",
  "Ops",
  "Mgr",
  "Cfg",
  "Impl",
  "Spec",
  "View",
] as const);

/**
 * Draw an identifier entropy tail containing at least one non-hex base36
 * character (`g`–`z`), avoiding the uniform `_[0-9a-f]{3,4}` tag shape that
 * static deobfuscators fingerprint to separate injected globals from user code.
 */
function drawNaturalTag(prng: SeededPrng, entropy: number): string {
  const len = Math.max(2, entropy);
  const chars: string[] = [];
  const lead = NON_HEX_LETTERS[prng.nextInt(0, NON_HEX_LETTERS.length - 1)]!;
  chars.push(lead);
  for (let i = 1; i < len; i++) {
    chars.push(BASE36_CHARS[prng.nextInt(0, BASE36_CHARS.length - 1)]!);
  }
  return chars.join("");
}

/**
 * Draw a realistic identifier from a seeded distribution.
 * Guarantees: no `_bla`, `__bla`, `$00_AAA` substring; valid JS/TS/Python ident;
 * varies morphology across natural naming shapes with no uniform `_<hex>` tag.
 */
export function realisticIdentifier(
  prng: SeededPrng,
  options: RealisticIdentifierOptions = {},
): string {
  const style = options.style ?? "camel";
  const entropy = options.entropy ?? 3;
  const tag = drawNaturalTag(prng, entropy);
  const capTag = tag.charAt(0).toUpperCase() + tag.slice(1);
  const verb = prng.pick(VERBS);
  const noun = prng.pick(NOUNS);
  const adj = prng.pick(ADJECTIVES);
  // A hint leads the name in the camel / pascal styles, and callers derive it
  // from customer identifiers such as `$1`, `_0x1f` or `π2`. Whatever is left
  // after stripping must not start with a digit, or the result is not an
  // identifier at all; an emptied hint falls back to the vocabulary.
  const hint = options.hint
    ? options.hint
        .replace(/[^A-Za-z0-9_]/g, "")
        .replace(/^[0-9]+/, "")
        .slice(0, 24)
    : "";

  if (style === "snake") {
    const a = prng.pick(SNAKE_STEMS);
    const b = prng.pick(SNAKE_STEMS);
    const c = hint
      ? hint.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase()
      : prng.pick(SNAKE_STEMS);
    return `${a}_${b}_${c}_${tag}`;
  }

  if (style === "pascal") {
    const head = hint
      ? hint.charAt(0).toUpperCase() + hint.slice(1)
      : adj;
    return `${head}${noun}${capTag}`;
  }

  if (style === "privateCamel") {
    const body = hint
      ? hint.charAt(0).toLowerCase() + hint.slice(1)
      : verb;
    const shape = prng.nextInt(0, 2);
    if (shape === 0) return `_${body}${noun}${capTag}`;
    if (shape === 1) return `_${body}${adj}${noun}${prng.nextInt(10, 999)}${tag.slice(0, 2)}`;
    return `_${body}${noun}${prng.pick(DOMAIN_SUFFIXES)}${capTag}`;
  }

  if (style === "earlySort") {
    // `$` sorts before [A-Za-z_] in Unicode; vary the next chars so there is
    // NO shared greppable literal across the emitted set (unlike `$00_AAA`).
    const rank = drawNaturalTag(prng, 2);
    const body = hint
      ? hint.charAt(0).toUpperCase() + hint.slice(1)
      : `${adj}${noun}`;
    return `$${rank}${body}${capTag}`;
  }

  // camel (default): rotate across natural camelCase shapes without `_<hex>` tails.
  const body = hint
    ? hint.charAt(0).toLowerCase() + hint.slice(1)
    : verb;
  const shape = prng.nextInt(0, 3);
  if (shape === 0) return `${body}${adj}${noun}${capTag}`;
  if (shape === 1) return `${body}${adj}${noun}${prng.pick(DOMAIN_SUFFIXES)}${prng.nextInt(10, 999)}${tag.slice(0, 2)}`;
  if (shape === 2) return `${body}${noun}For${adj}${capTag}`;
  return `${body}${adj}${noun}V${prng.nextInt(1, 9)}${tag}`;
}

/**
 * Draw N unique realistic identifiers (retry on collision within the batch).
 */
export function realisticIdentifierBatch(
  prng: SeededPrng,
  count: number,
  options: RealisticIdentifierOptions = {},
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let guard = 0;
  while (out.length < count && guard < count * 16) {
    guard++;
    const name = realisticIdentifier(prng, options);
    if (seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  if (out.length < count) {
    throw new Error(`Failed to draw ${count} unique realistic identifiers`);
  }
  return out;
}

/** Shared honey-table names for SQLite (no `_bla_` prefix; probe looks these up by name). */
export const SQLITE_HONEY_TABLES = Object.freeze({
  keyHierarchy: "enclave_key_hierarchy",
  attestationLedger: "tpm2_attestation_ledger",
  sessionLeases: "zero_trust_session_leases",
  canaryTransport: "canary_transport_redaction",
  systemDiagnostic: "system_diagnostic_log",
  activeTopologyView: "v_enclave_active_topology",
} as const);

export const SQLITE_HONEY_TABLE_NAME_SET: ReadonlySet<string> = new Set(
  Object.values(SQLITE_HONEY_TABLES),
);

/** Forbidden greppable marker substrings that must NEVER appear in emitted artifacts. */
export const FORBIDDEN_EMITTED_MARKERS: readonly RegExp[] = Object.freeze([
  /_bla/i,
  /\$00_AAA/,
  /__bla/i,
]);

export function assertNoForbiddenMarkers(
  emitted: string,
  context = "emitted artifact",
): void {
  for (const re of FORBIDDEN_EMITTED_MARKERS) {
    if (re.test(emitted)) {
      throw new Error(
        `Forbidden marker ${re} found in ${context} — shield would be trivially strippable`,
      );
    }
  }
}
