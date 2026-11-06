/**
 * Plaintext seal sidecar / reversible public-commitment lint (red-blue round-2).
 *
 * Detects entitlement/seal JSON that ships salts + rounds + a short public
 * `revision` (custom reversible ARX/Feistel shape) and/or certificate ciphertext
 * as an offline oracle package. One-way digests (SHA-256 / HMAC / blake, …)
 * without invertible ARX parameters pass.
 *
 * Findings: reversible shapes are severity **"error"**; bare plaintext seal
 * packaging without a reversible digest is **"warning"**. Bankrupt harden
 * refuses error findings unless `allowPlaintextSeal` is set.
 *
 * DEFENSIVE ONLY — no inversion / crack advice.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { walkBounded } from "../core/walk.js";

export const SEAL_COMMITMENT_SCHEMA = "bla-seal-commitment-lint/v1" as const;

export type SealCommitmentFindingId =
  | "plaintext-seal-sidecar"
  | "reversible-public-commitment"
  | "seal-offline-oracle-package"
  | "public-materialization-seed"
  | "public-key-digest-oracle";

export type SealCommitmentSeverity = "warning" | "error";

export interface SealCommitmentFinding {
  readonly id: SealCommitmentFindingId;
  readonly severity: SealCommitmentSeverity;
  readonly summary: string;
  readonly evidence: string;
}

export interface SealCommitmentReport {
  readonly schema: typeof SEAL_COMMITMENT_SCHEMA;
  readonly path: string;
  readonly findings: readonly SealCommitmentFinding[];
  /** True when any finding is present. */
  readonly looksExposed: boolean;
  /** True when bankrupt harden should refuse (error findings). */
  readonly shouldRefuseBankrupt: boolean;
  readonly oneLineAdvice: string;
}

const ONE_WAY_ALGO =
  /^(?:sha-?256|sha-?384|sha-?512|sha-?3(?:-?(?:256|384|512))?|hmac(?:-?sha-?(?:256|512))?|blake2?b?(?:-?\d+)?|argon2id?|scrypt|pbkdf2)$/i;

const PUBLIC_SEED_FIELDS = [
  "seed",
  "materializationSeed",
  "materialization_seed",
  "hardenSeed",
  "harden_seed",
  "scheduleSeed",
  "schedule_seed",
] as const;

const PUBLIC_KEY_DIGEST_FIELDS = [
  "keySha256",
  "key_sha256",
  "keyDigest",
  "key_digest",
  "keyHash",
  "key_hash",
  "licenseKeySha256",
] as const;

const SEAL_NAME =
  /^(?:seal|license-seal|entitlement-seal|catalog-seal)(?:\.[\w-]+)*\.json$/i;

const SKIP_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  ".bla-hardened",
  "coverage",
  ".next",
  ".turbo",
  "vendor",
  "__pycache__",
]);

const MAX_WALK_DEPTH = 6;
const MAX_SEAL_FILES = 32;
const MAX_JSON_BYTES = 400_000;

function finding(
  id: SealCommitmentFindingId,
  severity: SealCommitmentSeverity,
  summary: string,
  evidence: string,
): SealCommitmentFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 160),
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function looksLikeSealFileName(fileName: string): boolean {
  const base = basename(fileName);
  if (SEAL_NAME.test(base)) return true;
  if (base.toLowerCase() === "seal.json") return true;
  if (/\.seal\.json$/i.test(base)) return true;
  return false;
}

function declaredOneWay(algorithm: string | undefined): boolean {
  if (!algorithm) return false;
  const trimmed = algorithm.trim();
  if (ONE_WAY_ALGO.test(trimmed)) return true;
  // Allow "sha256:" / "hmac-sha256:" prefixes on digest fields.
  if (ONE_WAY_ALGO.test(trimmed.replace(/:.*$/, ""))) return true;
  return false;
}

function isSha256Hex(value: string): boolean {
  return /^[0-9a-f]{64}$/i.test(value);
}

function isSha512Hex(value: string): boolean {
  return /^[0-9a-f]{128}$/i.test(value);
}

function hasInvertibleArxParams(obj: Record<string, unknown>): boolean {
  const rounds = asNumber(obj.rounds) ?? asNumber(obj.roundCount);
  const salt =
    asNumber(obj.scheduleSalt) ??
    asNumber(obj.schedule_salt) ??
    asNumber(obj.arxSalt) ??
    asNumber(obj.arx_salt);
  // Numeric public salt + round count is the classic invertible-ARX footgun shape.
  return rounds !== undefined && rounds >= 2 && salt !== undefined;
}

function revisionField(obj: Record<string, unknown>): string | undefined {
  return (
    asString(obj.revision) ??
    asString(obj.commitment) ??
    asString(obj.digest) ??
    asString(obj.expectedDigest) ??
    asString(obj.publicDigest)
  );
}

function looksSealShaped(obj: Record<string, unknown>, fileName: string): boolean {
  if (looksLikeSealFileName(fileName)) return true;
  const schema = asString(obj.schema) ?? asString(obj.$schema) ?? "";
  if (/seal|entitlement|license/i.test(schema)) return true;
  const keys = Object.keys(obj);
  const hit =
    keys.includes("revision") ||
    keys.includes("commitment") ||
    keys.includes("certificateCipherHex") ||
    keys.includes("certificate_cipher_hex");
  const saltish =
    keys.includes("scheduleSalt") ||
    keys.includes("schedule_salt") ||
    keys.includes("rounds");
  return hit && saltish;
}

/**
 * Lint a UTF-8 JSON (or JSON-ish) seal/catalog body.
 */
export function lintSealCommitmentSource(
  source: string,
  options: { readonly path?: string } = {},
): SealCommitmentReport {
  const pathLabel = options.path ?? "<memory>";
  const findings: SealCommitmentFinding[] = [];
  const text = source.length > MAX_JSON_BYTES ? source.slice(0, MAX_JSON_BYTES) : source;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      schema: SEAL_COMMITMENT_SCHEMA,
      path: pathLabel,
      findings: [],
      looksExposed: false,
      shouldRefuseBankrupt: false,
      oneLineAdvice: "Not JSON — seal-commitment lint skipped.",
    };
  }

  if (!isPlainObject(parsed)) {
    return {
      schema: SEAL_COMMITMENT_SCHEMA,
      path: pathLabel,
      findings: [],
      looksExposed: false,
      shouldRefuseBankrupt: false,
      oneLineAdvice: "JSON root is not an object — seal-commitment lint skipped.",
    };
  }

  if (!looksSealShaped(parsed, pathLabel)) {
    return {
      schema: SEAL_COMMITMENT_SCHEMA,
      path: pathLabel,
      findings: [],
      looksExposed: false,
      shouldRefuseBankrupt: false,
      oneLineAdvice: "No seal/entitlement sidecar shape detected.",
    };
  }

  const algorithm =
    asString(parsed.algorithm) ??
    asString(parsed.digestAlgorithm) ??
    asString(parsed.hash) ??
    asString(parsed.kdf);
  const revision = revisionField(parsed);
  const oneWay = declaredOneWay(algorithm);
  const invertible = hasInvertibleArxParams(parsed);
  const cipher =
    asString(parsed.certificateCipherHex) ??
    asString(parsed.certificate_cipher_hex) ??
    asString(parsed.certificateCipher) ??
    asString(parsed.cipherHex);

  // Plaintext seal sidecar sitting on disk is always an exposure signal.
  if (looksLikeSealFileName(pathLabel) || /seal|entitlement/i.test(asString(parsed.schema) ?? "")) {
    findings.push(
      finding(
        "plaintext-seal-sidecar",
        invertible || Boolean(cipher) ? "error" : "warning",
        "Plaintext seal/entitlement JSON sidecar — harden does not encrypt JSON carriers; prefer omit, encrypt, or bind under self-seal.",
        `keys=${Object.keys(parsed).slice(0, 12).join(",")}`,
      ),
    );
  }

  if (revision && invertible && !oneWay) {
    const shortCustom =
      !isSha256Hex(revision) && !isSha512Hex(revision) && /^[0-9a-f]+$/i.test(revision);
    // Even a 64-hex revision with scheduleSalt+rounds and no one-way algo is suspicious
    // (could be truncated custom ARX); treat as reversible when ARX params present.
    findings.push(
      finding(
        "reversible-public-commitment",
        "error",
        shortCustom
          ? "Public revision/commitment with scheduleSalt+rounds looks like a reversible ARX digest — prefer SHA-256/HMAC (one-way)."
          : "Public commitment paired with numeric scheduleSalt+rounds without a declared one-way algorithm — treat as reversible-commitment footgun.",
        `revision=${revision.slice(0, 20)}… rounds/salt present algorithm=${algorithm ?? "none"}`,
      ),
    );
  }

  if (cipher && revision && (invertible || !oneWay)) {
    findings.push(
      finding(
        "seal-offline-oracle-package",
        "error",
        "Seal packages revision/commitment together with certificate ciphertext in cleartext — offline oracle / forge surface.",
        `cipherLen=${cipher.length} revisionLen=${revision.length}`,
      ),
    );
  }

  // CrackMe v8 red team: a public materialization/harden seed lets an attacker
  // re-derive seed-scheduled salt/rounds/pad3/entropy pads and strip XOR masks
  // without reversing WASM. Warning (not refuse): the seed alone is not a prize.
  const seedKey = PUBLIC_SEED_FIELDS.find((k) => asString(parsed[k]) !== undefined);
  if (seedKey) {
    findings.push(
      finding(
        "public-materialization-seed",
        "warning",
        "Public seal carries the materialization/harden seed — seed-derived schedule (salt/rounds/pads) becomes known plaintext. Keep the crypto schedule seed private; publish only a non-cryptographic label.",
        `field=${seedKey}`,
      ),
    );
  }

  // A public digest of the secret key is an offline key verifier (accelerates
  // guessing; one-way, so warning). Keep only the prove-solve digest of the FLAG.
  const keyDigestKey = PUBLIC_KEY_DIGEST_FIELDS.find((k) => asString(parsed[k]) !== undefined);
  if (keyDigestKey) {
    findings.push(
      finding(
        "public-key-digest-oracle",
        "warning",
        "Public seal publishes a digest of the secret key — free offline key oracle. Omit it; keep flag/certificate digest for prove-solve.",
        `field=${keyDigestKey}`,
      ),
    );
  }

  // Deduplicate by id (keep highest severity).
  const byId = new Map<SealCommitmentFindingId, SealCommitmentFinding>();
  for (const f of findings) {
    const prev = byId.get(f.id);
    if (!prev || (prev.severity === "warning" && f.severity === "error")) {
      byId.set(f.id, f);
    }
  }
  const deduped = [...byId.values()];
  const shouldRefuseBankrupt = deduped.some((f) => f.severity === "error");

  return {
    schema: SEAL_COMMITMENT_SCHEMA,
    path: pathLabel,
    findings: deduped,
    looksExposed: deduped.length > 0,
    shouldRefuseBankrupt,
    oneLineAdvice:
      deduped.length === 0
        ? "No reversible seal-commitment footgun detected (heuristic)."
        : shouldRefuseBankrupt
          ? "ERROR: Plaintext/reversible seal sidecar. Use one-way digests; omit or encrypt seal JSON. Bankrupt harden refuses unless allowPlaintextSeal / --allow-plaintext-seal / allow_plaintext_seal. Defensive guidance only."
          : "WARNING: Seal-shaped JSON is plaintext beside the artifact — encrypt, omit, or bind under self-seal.",
  };
}

/**
 * Read a path and lint it as a seal/commitment sidecar.
 */
export function lintSealCommitmentFile(filePath: string): SealCommitmentReport {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    throw new Error(`seal-commitment target not found: ${abs}`);
  }
  const source = readFileSync(abs, "utf8");
  return lintSealCommitmentSource(source, { path: abs });
}

function walkSealCandidates(dir: string): string[] {
  return walkBounded(dir, {
    maxDepth: MAX_WALK_DEPTH,
    maxFiles: MAX_SEAL_FILES,
    skipDirs: SKIP_DIR_NAMES,
    skipHiddenDirs: true,
    accept: (_full, name) => looksLikeSealFileName(name),
  });
}

/**
 * Discover seal-named JSON files under a project/build directory and lint each.
 */
export function discoverAndLintSealSidecars(
  directory: string,
): readonly SealCommitmentReport[] {
  const abs = resolve(directory);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintSealCommitmentFile(abs)];
  }
  const candidates = walkSealCandidates(abs);
  // Also check common build output folder names one level down even if skipped
  // as deep roots — seal.json often sits next to dist artifacts at project root.
  return candidates.map((p) => lintSealCommitmentFile(p));
}

/**
 * Immediate-directory sibling seal files next to a protect target.
 */
export function findSiblingSealSidecars(directory: string): readonly string[] {
  const abs = resolve(directory);
  if (!existsSync(abs) || !statSync(abs).isDirectory()) return [];
  let entries;
  try {
    entries = readdirSync(abs, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isFile() && looksLikeSealFileName(e.name))
    .map((e) => join(abs, e.name));
}

export function sealCommitmentRefuseMessage(
  report: SealCommitmentReport,
  filePath: string,
): string {
  const ids = report.findings.filter((f) => f.severity === "error").map((f) => f.id).join(", ");
  return (
    `Refusing bankrupt harden/protect: plaintext/reversible seal sidecar at ${filePath}` +
    (ids ? ` [${ids}]` : "") +
    `. Use one-way SHA-256/HMAC commitments; omit or encrypt seal JSON. ` +
    `To override (lab fixture only), pass allowPlaintextSeal / --allow-plaintext-seal / allow_plaintext_seal:true.`
  );
}

/** Whether bankrupt intensity should enforce seal-sidecar refusal. */
export function intensityEnforcesSealRefusal(intensity: string): boolean {
  return intensity === "bankrupt";
}
