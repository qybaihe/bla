import { createHash, createPublicKey } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { verifyManifestSignature } from "./manifest-signing.js";

export interface ManifestVerifyResult {
  /** Signature bytes (and artifact digest, when checked) are valid. */
  readonly ok: boolean;
  /** A signature object is present. */
  readonly signed: boolean;
  /** The caller supplied a trusted public key that matched the embedded key. */
  readonly pinned: boolean;
  /** True when the protected artifact file's SHA-256 was checked and matched `protectedSha256`. */
  readonly artifactVerified: boolean;
  readonly reason: string;
}

function normalizePublicKeyPem(pem: string): string {
  return String(
    createPublicKey(pem).export({ type: "spki", format: "pem" }),
  );
}

/**
 * Verify a `.bla-manifest.json` file.
 *
 * Without `publicKeyPath`, this only proves the manifest was signed by the key
 * embedded in it (an attacker can re-sign their own edits). Supply
 * `publicKeyPath` to pin the trusted key.
 *
 * When `artifactPath` is supplied — or when `<artifact>.bla-manifest.json` sits
 * adjacent to a regular file `<artifact>` — `protectedSha256` in the manifest is
 * also checked against the on-disk artifact bytes.
 */
export function verifyManifestFile(
  manifestPath: string,
  publicKeyPath?: string,
  artifactPath?: string,
): ManifestVerifyResult {
  const absManifest = resolve(manifestPath);
  let manifest: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(readFileSync(absManifest, "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        ok: false,
        signed: false,
        pinned: false,
        artifactVerified: false,
        reason: "manifest must be a JSON object",
      };
    }
    manifest = parsed as Record<string, unknown>;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      signed: false,
      pinned: false,
      artifactVerified: false,
      reason: `cannot read manifest: ${message}`,
    };
  }

  const rawSignature = manifest.signature;
  const signed =
    rawSignature !== undefined &&
    rawSignature !== null &&
    typeof rawSignature === "object" &&
    typeof (rawSignature as { value?: unknown }).value === "string";
  if (!signed) {
    return {
      ok: false,
      signed: false,
      pinned: false,
      artifactVerified: false,
      reason: "manifest is unsigned",
    };
  }

  let pinned = false;
  if (publicKeyPath !== undefined) {
    const embedded = (rawSignature as { publicKey?: unknown }).publicKey;
    if (typeof embedded !== "string") {
      return {
        ok: false,
        signed: true,
        pinned: false,
        artifactVerified: false,
        reason: "manifest signature has no public key",
      };
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
          artifactVerified: false,
          reason: "manifest public key does not match the pinned --public-key",
        };
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        signed: true,
        pinned: false,
        artifactVerified: false,
        reason: `cannot read pinned public key: ${message}`,
      };
    }
  }

  const sigOk = verifyManifestSignature(manifest);
  if (!sigOk) {
    return {
      ok: false,
      signed: true,
      pinned,
      artifactVerified: false,
      reason: "signature invalid",
    };
  }

  let resolvedArtifactPath: string | undefined;
  if (artifactPath !== undefined) {
    resolvedArtifactPath = resolve(artifactPath);
  } else if (
    absManifest.endsWith(".bla-manifest.json") &&
    manifest.detectedFormat !== "directory"
  ) {
    const adjacent = absManifest.slice(0, -".bla-manifest.json".length);
    try {
      if (existsSync(adjacent) && statSync(adjacent).isFile()) {
        resolvedArtifactPath = adjacent;
      }
    } catch {
      // Ignore inaccessible or non-file adjacent paths when not explicitly requested.
    }
  }

  let artifactVerified = false;
  if (resolvedArtifactPath !== undefined) {
    const expectedSha = manifest.protectedSha256;
    if (typeof expectedSha !== "string" || !/^[0-9a-f]{64}$/i.test(expectedSha)) {
      return {
        ok: false,
        signed: true,
        pinned,
        artifactVerified: false,
        reason: "manifest is missing a valid 64-hex protectedSha256 field for artifact verification",
      };
    }
    try {
      const st = statSync(resolvedArtifactPath);
      if (!st.isFile()) {
        return {
          ok: false,
          signed: true,
          pinned,
          artifactVerified: false,
          reason: `cannot read artifact: ${resolvedArtifactPath} is not a regular file`,
        };
      }
      const actualSha = createHash("sha256")
        .update(readFileSync(resolvedArtifactPath))
        .digest("hex");
      if (actualSha !== expectedSha.toLowerCase()) {
        return {
          ok: false,
          signed: true,
          pinned,
          artifactVerified: false,
          reason: `artifact SHA-256 mismatch (expected ${expectedSha.toLowerCase()}, got ${actualSha})`,
        };
      }
      artifactVerified = true;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        signed: true,
        pinned,
        artifactVerified: false,
        reason: `cannot read artifact: ${message}`,
      };
    }
  }

  const keyNote = pinned
    ? "pinned key"
    : "embedded key only — pass --public-key to authenticate";
  const artifactNote = artifactVerified ? ", artifact SHA-256 verified" : "";
  return {
    ok: true,
    signed: true,
    pinned,
    artifactVerified,
    reason: `signature valid (${keyNote}${artifactNote})`,
  };
}