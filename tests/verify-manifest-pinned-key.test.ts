import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyManifestFile } from "../src/core/manifest-verify.js";
import {
  generateManifestSigningKeyPair,
  signManifestPayload,
} from "../src/core/manifest-signing.js";
import { parseCliArgs } from "../src/cli.js";

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "bla-manifest-pin-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function signedManifest(options: { withArtifact?: string } = {}) {
  const base = dir();
  const { privateKeyPem, publicKeyPem } = generateManifestSigningKeyPair();
  const payload: Record<string, unknown> = {
    schema: "bla-defense-manifest/v1",
    blaVersion: "3.2.5",
    detectedFormat: "javascript",
  };
  if (options.withArtifact) payload.protectedSha256 = "0".repeat(64);
  const signed = signManifestPayload(payload, privateKeyPem);
  const manifestPath = join(base, "app.js.bla-manifest.json");
  writeFileSync(manifestPath, JSON.stringify(signed, null, 2), "utf8");
  const keyPath = join(base, "trusted.pem");
  writeFileSync(keyPath, publicKeyPem, "utf8");
  return { manifestPath, keyPath };
}

describe("verify-manifest trusted-key gate", () => {
  it("still accepts an unpinned manifest by default", () => {
    const { manifestPath } = signedManifest();
    const result = verifyManifestFile(manifestPath);
    expect(result.ok).toBe(true);
    expect(result.pinned).toBe(false);
  });

  it("refuses an unpinned manifest when a pinned key is required", () => {
    const { manifestPath } = signedManifest();
    const result = verifyManifestFile(manifestPath, undefined, undefined, {
      requirePinnedKey: true,
    });
    expect(result.ok).toBe(false);
    expect(result.pinned).toBe(false);
    expect(result.reason).toMatch(/pinned public key is required/i);
  });

  it("accepts a manifest authenticated by the pinned key", () => {
    const { manifestPath, keyPath } = signedManifest();
    const result = verifyManifestFile(manifestPath, keyPath, undefined, {
      requirePinnedKey: true,
    });
    expect(result.ok).toBe(true);
    expect(result.pinned).toBe(true);
  });

  it("parses --require-pinned-key for the verify-manifest command", () => {
    const parsed = parseCliArgs(["verify-manifest", "app.js.bla-manifest.json", "--require-pinned-key"]);
    expect(parsed.command).toBe("verify-manifest");
    expect(parsed.requirePinnedKey).toBe(true);
    expect(parseCliArgs(["verify-manifest", "m.json"]).requirePinnedKey).toBe(false);
  });
});