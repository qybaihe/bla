import { SeededPrng } from "../../core/prng.js";

/**
 * Seed-derived comment vocabulary (anti static de-blinding).
 *
 * BLA overwrites every original source comment with a content-free replacement,
 * and emits a fixed "attestation boundary" banner over its tarpit / native
 * output. Both used fixed literals that LASIK-class strippers key on. From
 * `pktq/lasik` `src/js/fingerprints.ts`:
 *
 *   SCRAMBLED_COMMENT =
 *     /^\s*(?:(?:reconcile session epoch|derive ledger digest|normalize envelope
 *     frame|hydrate runtime cache|project quota policy) \([0-9a-f]{6}\)|runtime
 *     attestation boundary|decorative shadow runtime signal\b.*)\s*$/
 *
 * `comments.ts` bulk-strips every comment whose value matches. This module
 * replaces both families with seed-derived text:
 *
 * 1. Overwrite comments ({@link scrambleCommentText}) now read as ordinary,
 *    varied developer comments with no fixed shape and never the `<phrase>
 *    ([0-9a-f]{6})` form, so LASIK can neither bulk-match nor tell them apart
 *    from genuine comments. There is no BLA recognizer for these — they are
 *    pure information-destruction — so nothing needs to recognize them back.
 *
 * 2. The attestation banner ({@link deriveAttestationBanner}) is a BLA
 *    self-marker (tarpit / native header emit it; the pyc chaff detector and the
 *    weave maturity probe read it back). It is now drawn from a pool that
 *    EXCLUDES the fixed legacy phrase, and {@link looksLikeAttestationBanner}
 *    recognizes the whole pool plus the legacy phrase (so pre-existing artifacts
 *    still classify). LASIK's `runtime attestation boundary` literal no longer
 *    fires.
 */

// --- 1. Overwrite-comment vocabulary (no BLA recognizer) --------------------

const SC_SUBJECTS = [
  "payload", "request", "response", "session", "token bucket", "cache entry",
  "buffer", "config", "handler", "context", "record", "batch", "queue",
  "stream", "manifest", "descriptor", "frame", "chunk", "index", "snapshot",
] as const;
const SC_VERBS = [
  "normalize", "validate", "reconcile", "flush", "resolve", "coalesce",
  "dispatch", "rebalance", "prefetch", "memoize", "serialize", "throttle",
  "sanitize", "reindex", "warm", "drain",
] as const;
const SC_QUALIFIERS = [
  "before dispatch", "on the hot path", "for legacy clients",
  "behind the feature gate", "when the pool drains", "keyed by tenant",
  "under back-pressure", "during warm-up", "for idempotency", "on retry",
  "to keep ordering stable", "so replays stay deterministic",
] as const;
const SC_NOTES = [
  "kept for backward compatibility", "safe to inline once callers migrate",
  "hot path — avoid allocations here", "guarded by the config flag",
  "see the migration note in the tracker", "do not reorder with the flush below",
  "bounded by the retry budget", "idempotent by construction",
] as const;

/**
 * Produce a plausible, varied developer comment used to overwrite an original
 * comment. Never matches LASIK's SCRAMBLED_COMMENT (no `(hex6)` suffix, none of
 * the fixed phrases). Returns the inner text; the caller adds comment framing.
 */
export function scrambleCommentText(prng: SeededPrng): string {
  const shape = prng.nextInt(0, 3);
  const subject = prng.pick(SC_SUBJECTS);
  const verb = prng.pick(SC_VERBS);
  switch (shape) {
    case 0:
      return `${verb} the ${subject} ${prng.pick(SC_QUALIFIERS)}`;
    case 1:
      return `${subject} path: ${prng.pick(SC_NOTES)}`;
    case 2:
      return `TODO(${prng.hex(4)}): ${verb} ${subject} ${prng.pick(SC_QUALIFIERS)}`;
    default:
      return `${subject} — ${prng.pick(SC_NOTES)}`;
  }
}

// --- 2. Attestation banner self-marker (BLA recognizes this) ----------------

/** The pre-change banner, kept recognizable for pre-existing artifacts. */
export const LEGACY_ATTESTATION_BANNER = "runtime attestation boundary";

/** Pool of plausible attestation-flavoured banner phrases (excludes legacy). */
export const ATTESTATION_BANNER_PHRASES = [
  "sealed execution checkpoint",
  "attestation handshake marker",
  "runtime integrity checkpoint",
  "sealed state reconciliation point",
  "enclave transition boundary",
  "attestation epoch marker",
  "sealed runtime checkpoint",
  "attested transition boundary",
] as const;

/** Seed-select a per-build attestation banner phrase. */
export function deriveAttestationBanner(prng: SeededPrng): string {
  return prng.pick(ATTESTATION_BANNER_PHRASES);
}

const ATTESTATION_BANNER_RE = new RegExp(
  `(?:${[LEGACY_ATTESTATION_BANNER, ...ATTESTATION_BANNER_PHRASES]
    .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|")})`,
);

/**
 * Structural recognizer for BLA's attestation banner, matching the full pool
 * and the legacy phrase. Used by the pyc chaff detector and the weave probe in
 * place of the old fixed `includes("runtime attestation boundary")`.
 */
export function looksLikeAttestationBanner(text: string): boolean {
  return typeof text === "string" && ATTESTATION_BANNER_RE.test(text);
}
