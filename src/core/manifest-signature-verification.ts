import { createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";

export interface ManifestSignature {
  readonly algorithm: "ed25519";
  /** SPKI public key (PEM) that verifies `value`. */
  readonly publicKey: string;
  /** base64 ed25519 signature over the canonical payload JSON. */
  readonly value: string;
  /** Older signatures without this field use insertion-order JSON. */
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
