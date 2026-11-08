import { createHash, createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
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
  /** True when a target artifact file was located on disk. */
  readonly artifactPresent?: boolean;
  /** SHA-256 hex digest of the artifact on disk, if inspected. */
  readonly artifactSha256?: string;
  /** True when artifactSha256 matches manifest.protectedSha256. */
  readonly artifactHashMatch?: boolean;
}

function normalizePublicKeyPem(pem: string): string {
  return String(
    createPublicKey(pem).export({ type: "spki", format: "pem" }),
  );
}

function computeSha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Verify a `.bla-manifest.json` file.
 *
 * Without `publicKeyPath`, this only proves the manifest was signed by the key
 * embedded in it (an attacker can re-sign their own edits). Supply
 * `publicKeyPath` to pin the trusted key.
 *
 * If `artifactPath` is provided (or if `manifestPath` ends in `.bla-manifest.json`
 * with an adjacent protected file on disk), the artifact's SHA-256 hash is
 * verified against `manifest.protectedSha256` to detect binary tampering.
 */
export function verifyManifestFile(
  manifestPath: string,
  publicKeyPath?: string,
  artifactPath?: string,
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
  if (!ok) {
    return {
      ok: false,
      signed: true,
      pinned,
      reason: "signature invalid",
    };
  }

  const absManifest = resolve(manifestPath);
  let resolvedArtifactPath: string | undefined;
  let isExplicitArtifact = false;

  if (artifactPath !== undefined && artifactPath.trim().length > 0) {
    resolvedArtifactPath = resolve(artifactPath);
    isExplicitArtifact = true;
  } else if (absManifest.endsWith(".bla-manifest.json")) {
    const adjacent = absManifest.slice(0, -".bla-manifest.json".length);
    if (existsSync(adjacent)) {
      resolvedArtifactPath = adjacent;
    }
  }

  if (resolvedArtifactPath !== undefined) {
    if (!existsSync(resolvedArtifactPath)) {
      if (isExplicitArtifact) {
        return {
          ok: false,
          signed: true,
          pinned,
          artifactPresent: false,
          reason: `artifact not found at ${resolvedArtifactPath}`,
        };
      }
    } else {
      let actualSha: string;
      try {
        actualSha = computeSha256(readFileSync(resolvedArtifactPath));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          ok: false,
          signed: true,
          pinned,
          artifactPresent: true,
          reason: `cannot read artifact: ${message}`,
        };
      }

      const expectedSha =
        typeof manifest.protectedSha256 === "string"
          ? manifest.protectedSha256
          : undefined;

      if (expectedSha !== undefined) {
        const matches = actualSha.toLowerCase() === expectedSha.toLowerCase();
        if (!matches) {
          return {
            ok: false,
            signed: true,
            pinned,
            artifactPresent: true,
            artifactSha256: actualSha,
            artifactHashMatch: false,
            reason: `protected artifact hash mismatch: expected ${expectedSha}, got ${actualSha} (tampered or mismatched artifact)`,
          };
        }
        return {
          ok: true,
          signed: true,
          pinned,
          artifactPresent: true,
          artifactSha256: actualSha,
          artifactHashMatch: true,
          reason: pinned
            ? "signature valid (pinned key) and artifact hash verified"
            : "signature valid (embedded key only — pass --public-key to authenticate) and artifact hash verified",
        };
      } else if (isExplicitArtifact) {
        return {
          ok: false,
          signed: true,
          pinned,
          artifactPresent: true,
          artifactSha256: actualSha,
          reason: "manifest missing protectedSha256 field",
        };
      }
    }
  }

  return {
    ok: true,
    signed: true,
    pinned,
    reason: pinned
      ? "signature valid (pinned key)"
      : "signature valid (embedded key only — pass --public-key to authenticate)",
  };
}