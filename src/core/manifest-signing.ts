import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { canonicalManifestJson, type ManifestSignature } from "./manifest-signature-verification.js";

// Keep the original signing API; consumers that only verify can import the
// implementation without pulling in private-key handling or key generation.
export { canonicalManifestJson, verifyManifestSignature, type ManifestSignature } from "./manifest-signature-verification.js";

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
