import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyManifestSignature } from "./manifest-signing.js";

export interface ManifestVerifyResult {
  /** Signature bytes are valid for the payload. */
  readonly ok: boolean;
  /** A signature object is present. */
  readonly signed: boolean;
  /** The caller supplied a trusted public key that matched the embedded key. */
  readonly pinned: boolean;
  readonly reason: string;
}

function normalizePublicKeyPem(pem: string): string {
  return createPublicKey(pem)
    .export({ type: "spki", format: "pem" })
    .toString("utf8");
}

/**
 * Verify a `.bla-manifest.json` file.
 *
 * Without `publicKeyPath`, this only proves the manifest was signed by the key
 * embedded in it (an attacker can re-sign their own edits). Supply
 * `publicKeyPath` to pin the trusted key.
 */
export function verifyManifestFile(
  manifestPath: string,
  publicKeyPath?: string,
): ManifestVerifyResult {
  let manifest: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(readFileSync(resolve(manifestPath), "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, signed: false, pinned: false, reason: "manifest must be a JSON object" };
    }
    manifest = parsed as Record<string, unknown>;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, signed: false, pinned: false, reason: `cannot read manifest: ${message}` };
  }

  const rawSignature = manifest.signature;
  const signed =
    rawSignature !== undefined &&
    rawSignature !== null &&
    typeof rawSignature === "object" &&
    typeof (rawSignature as { value?: unknown }).value === "string";
  if (!signed) {
    return { ok: false, signed: false, pinned: false, reason: "manifest is unsigned" };
  }

  let pinned = false;
  if (publicKeyPath !== undefined) {
    const embedded = (rawSignature as { publicKey?: unknown }).publicKey;
    if (typeof embedded !== "string") {
      return { ok: false, signed: true, pinned: false, reason: "manifest signature has no public key" };
    }
    try {
      const expected = normalizePublicKeyPem(readFileSync(resolve(publicKeyPath), "utf8"));
      const actual = normalizePublicKeyPem(embedded);
      pinned = true;
      if (expected !== actual) {
        return {
          ok: false,
          signed: true,
          pinned: true,
          reason: "manifest public key does not match the pinned --public-key",
        };
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, signed: true, pinned: false, reason: `cannot read pinned public key: ${message}` };
    }
  }

  const ok = verifyManifestSignature(manifest);
  return {
    ok,
    signed: true,
    pinned,
    reason: ok
      ? pinned
        ? "signature valid (pinned key)"
        : "signature valid (embedded key only — pass --public-key to authenticate)"
      : "signature invalid",
  };
}