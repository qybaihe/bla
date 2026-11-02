import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

/**
 * Optional ed25519 signing for `.bla-manifest.json` attestation manifests.
 *
 * The manifest payload itself stays plain JSON; signing is additive so
 * unsigned manifests remain valid. A signed manifest embeds `signature` with
 * the SPKI public key and a base64 ed25519 signature over `JSON.stringify`
 * of the payload WITHOUT the `signature` field (key order preserved).
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
}

export interface ManifestSigningKeyPair {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
}

/** Generate a fresh ed25519 keypair (PKCS8 private + SPKI public, PEM). */
export function generateManifestSigningKeyPair(): ManifestSigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString("utf8"),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString("utf8"),
  };
}

/**
 * Sign a manifest payload. Returns the payload plus an embedded `signature`.
 * The signature covers `JSON.stringify(payload)` exactly as passed (caller
 * controls key insertion order; `signature` is always appended last).
 */
export function signManifestPayload<T extends object>(
  payload: T,
  privateKeyPem: string,
): T & { readonly signature: ManifestSignature } {
  const privateKey = createPrivateKey(privateKeyPem);
  const canonical = JSON.stringify(payload);
  const value = cryptoSign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64");
  const publicKeyPem = createPublicKey(privateKey)
    .export({ type: "spki", format: "pem" })
    .toString("utf8");
  return {
    ...payload,
    signature: { algorithm: "ed25519", publicKey: publicKeyPem, value },
  };
}

/**
 * Verify a manifest object's embedded ed25519 `signature`.
 * Returns false for unsigned manifests, malformed signatures, or mismatches —
 * never throws.
 */
export function verifyManifestSignature(manifest: Record<string, unknown>): boolean {
  const rawSignature = manifest.signature;
  if (rawSignature === undefined || rawSignature === null || typeof rawSignature !== "object") {
    return false;
  }
  const signature = rawSignature as Partial<ManifestSignature>;
  if (
    signature.algorithm !== "ed25519" ||
    typeof signature.publicKey !== "string" ||
    typeof signature.value !== "string"
  ) {
    return false;
  }
    try {
      const publicKey = createPublicKey(signature.publicKey);
      const { signature: _ignored, ...rest } = manifest;
      const canonical = JSON.stringify(rest);
      return cryptoVerify(null, Buffer.from(canonical, "utf8"), publicKey, Buffer.from(signature.value, "base64"));
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
