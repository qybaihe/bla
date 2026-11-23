import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

/**
 * Optional ed25519 signing for `.bla-manifest.json` attestation manifests.
 *
 * The manifest payload itself stays plain JSON; signing is additive so
 * unsigned manifests remain valid. A signed manifest embeds `signature` with
 * the SPKI public key and a base64 ed25519 signature over the canonical JSON
 * of the payload without the `signature` field.
 *
 * Honesty contract (matches defender.ts `attestationKind`):
 * - `attestationKind: "unsigned"` → no `signature` field, never claim signed.
 * - `attestationKind: "ed25519"` → `signature` present and verifiable.
 */
export interface ManifestSignature {
  readonly algorithm: "ed25519";
  /** SPKI public key (PEM) that verifies `value`. */
  readonly publicKey: string;
  /** base64 ed25519 signature over the canonical payload JSON. */
  readonly value: string;
  /**
   * Canonicalization used for `value`. `"sorted-keys-v1"` sorts object keys
   * recursively so a re-serialized manifest still verifies. Older manifests
   * without this field are verified using insertion-order JSON (legacy).
   */
  readonly canonicalization?: "sorted-keys-v1";
}

/** Deterministic JSON with recursively sorted object keys (arrays keep order). */
export function canonicalManifestJson(value: unknown): string {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("Manifest JSON numbers must be finite");
  }
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalManifestJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalManifestJson(v)}`).join(",")}}`;
}

export interface ManifestSigningKeyPair {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
}

/** Generate a fresh ed25519 keypair (PKCS8 private + SPKI public, PEM). */
export function generateManifestSigningKeyPair(): ManifestSigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: String(privateKey.export({ type: "pkcs8", format: "pem" })),
    publicKeyPem: String(publicKey.export({ type: "spki", format: "pem" })),
  };
}

/**
 * Sign a manifest payload. Returns the payload plus an embedded `signature`.
 * The signature covers the payload serialized with recursively sorted keys.
 */
export function signManifestPayload<T extends object>(
  payload: T,
  privateKeyPem: string,
): T & { readonly signature: ManifestSignature } {
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("Manifest signing requires an Ed25519 private key");
  }
  const canonical = canonicalManifestJson(payload);
  const value = cryptoSign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64");
  const publicKeyPem = String(
    createPublicKey(privateKey).export({ type: "spki", format: "pem" }),
  );
  return {
    ...payload,
    signature: { algorithm: "ed25519", publicKey: publicKeyPem, value, canonicalization: "sorted-keys-v1" },
  };
}

/**
 * Verify a manifest object's embedded ed25519 `signature`.
 *
 * When `expectedPublicKeyPem` is supplied, the embedded key must be the same
 * key (compared as normalized SPKI PEM). Without a pinned key, verification
 * only proves that whoever produced the manifest also produced the signature —
 * an attacker can re-sign a modified manifest with their own keypair.
 *
 * Returns false for unsigned manifests, malformed signatures, mismatches, or a
 * pinned-key mismatch — never throws.
 */
export function verifyManifestSignature(
  manifest: Record<string, unknown>,
  expectedPublicKeyPem?: string,
): boolean {
  const rawSignature = manifest.signature;
  if (rawSignature === undefined || rawSignature === null || typeof rawSignature !== "object") {
    return false;
  }
  const signature = rawSignature as Partial<ManifestSignature>;
  if (
    signature.algorithm !== "ed25519" ||
    typeof signature.publicKey !== "string" ||
    typeof signature.value !== "string" ||
    (signature.canonicalization !== undefined && signature.canonicalization !== "sorted-keys-v1")
  ) {
    return false;
  }
  try {
    const signatureBytes = Buffer.from(signature.value, "base64");
    if (signatureBytes.length !== 64) return false;
    const publicKey = createPublicKey(signature.publicKey);
    if (publicKey.asymmetricKeyType !== "ed25519") return false;
    if (expectedPublicKeyPem !== undefined) {
      const pinned = createPublicKey(expectedPublicKeyPem);
      if (pinned.asymmetricKeyType !== "ed25519") return false;
      const embeddedSpki = publicKey.export({ type: "spki", format: "der" });
      const pinnedSpki = pinned.export({ type: "spki", format: "der" });
      if (embeddedSpki.length !== pinnedSpki.length || !timingSafeEqual(embeddedSpki, pinnedSpki)) {
        return false;
      }
    }
    const { signature: _ignored, ...rest } = manifest;
    const canonical = signature.canonicalization === undefined
      ? JSON.stringify(rest, (_key, value: unknown) => {
          if (typeof value === "number" && !Number.isFinite(value)) {
            throw new TypeError("Manifest JSON numbers must be finite");
          }
          return value;
        })
      : canonicalManifestJson(rest);
    return cryptoVerify(null, Buffer.from(canonical, "utf8"), publicKey, signatureBytes);
  } catch {
    return false;
  }
}

/**
 * Resolve the signing private key PEM from an explicit path (required when
 * signing is requested — fail closed instead of silently emitting unsigned).
 */
export function readManifestSigningKeyOrThrow(keyPath: string): string {
  if (typeof keyPath !== "string" || keyPath.trim().length === 0) {
    throw new Error(
      "Manifest signing requires a private key path (CLI --manifest-key <path>, MCP manifest_key_path).",
    );
  }
  const resolved = isAbsolute(keyPath) ? keyPath : resolve(process.cwd(), keyPath);
  try {
    return readFileSync(resolved, "utf8");
  } catch {
    throw new Error(`Manifest signing key not readable: ${resolved}`);
  }
}
