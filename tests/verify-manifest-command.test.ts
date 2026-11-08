import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateManifestSigningKeyPair, signManifestPayload } from "../src/core/manifest-signing.js";
import { verifyManifestFile } from "../src/core/manifest-verify.js";
import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-verify-manifest-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("bla verify-manifest", () => {
  it("verifies a signed manifest with a pinned public key", () => {
    const dir = createTempDir();
    const pair = generateManifestSigningKeyPair();
    const manifestPath = join(dir, "manifest.json");
    const publicKeyPath = join(dir, "public.pem");
    const signed = signManifestPayload({ schema: "s", blaVersion: "2.1.0" }, pair.privateKeyPem);
    writeFileSync(manifestPath, JSON.stringify(signed, null, 2), "utf8");
    writeFileSync(publicKeyPath, pair.publicKeyPem, "utf8");

    const result = verifyManifestFile(manifestPath, publicKeyPath);
    expect(result).toMatchObject({ ok: true, signed: true, pinned: true });
  });

  it("rejects a manifest signed by a different key than the pinned one", () => {
    const dir = createTempDir();
    const trusted = generateManifestSigningKeyPair();
    const attacker = generateManifestSigningKeyPair();
    const manifestPath = join(dir, "manifest.json");
    const publicKeyPath = join(dir, "trusted.pem");
    writeFileSync(
      manifestPath,
      JSON.stringify(signManifestPayload({ a: 1 }, attacker.privateKeyPem)),
      "utf8",
    );
    writeFileSync(publicKeyPath, trusted.publicKeyPem, "utf8");

    const result = verifyManifestFile(manifestPath, publicKeyPath);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/does not match/);
  });

  it("rejects tampered and unsigned manifests", () => {
    const dir = createTempDir();
    const pair = generateManifestSigningKeyPair();
    const signed = signManifestPayload({ a: 1 }, pair.privateKeyPem);
    const tamperedPath = join(dir, "tampered.json");
    writeFileSync(tamperedPath, JSON.stringify({ ...signed, a: 2 }), "utf8");
    expect(verifyManifestFile(tamperedPath).ok).toBe(false);

    const unsignedPath = join(dir, "unsigned.json");
    writeFileSync(unsignedPath, JSON.stringify({ a: 1 }), "utf8");
    const unsigned = verifyManifestFile(unsignedPath);
    expect(unsigned).toMatchObject({ ok: false, signed: false });
    expect(unsigned.reason).toMatch(/unsigned/);
  });

  it("returns exit 0 for a valid manifest and 2 for an invalid one", async () => {
    const dir = createTempDir();
    const pair = generateManifestSigningKeyPair();
    const manifestPath = join(dir, "manifest.json");
    const publicKeyPath = join(dir, "public.pem");
    writeFileSync(
      manifestPath,
      JSON.stringify(signManifestPayload({ a: 1 }, pair.privateKeyPem)),
      "utf8",
    );
    writeFileSync(publicKeyPath, pair.publicKeyPem, "utf8");

    await expect(
      runCli(["verify-manifest", manifestPath, "--public-key", publicKeyPath, "--json"]),
    ).resolves.toBe(0);
    writeFileSync(manifestPath, JSON.stringify({ a: 1 }), "utf8");
    await expect(runCli(["verify-manifest", manifestPath, "--json"])).resolves.toBe(2);
  });

  it("verifies adjacent artifact hash and detects tampering", async () => {
    const dir = createTempDir();
    const pair = generateManifestSigningKeyPair();
    const artifactPath = join(dir, "bundle.js");
    const manifestPath = join(dir, "bundle.js.bla-manifest.json");
    const publicKeyPath = join(dir, "public.pem");

    const originalContent = 'console.log("hello world");';
    writeFileSync(artifactPath, originalContent, "utf8");
    writeFileSync(publicKeyPath, pair.publicKeyPem, "utf8");

    // Compute expected sha256
    const { createHash } = await import("node:crypto");
    const expectedSha = createHash("sha256").update(Buffer.from(originalContent)).digest("hex");

    const signed = signManifestPayload(
      {
        schema: "https://bla.tools/schemas/defense-manifest-v1.json",
        protectedSha256: expectedSha,
      },
      pair.privateKeyPem,
    );
    writeFileSync(manifestPath, JSON.stringify(signed, null, 2), "utf8");

    // 1. Valid adjacent artifact
    const validRes = verifyManifestFile(manifestPath, publicKeyPath);
    expect(validRes.ok).toBe(true);
    expect(validRes.artifactPresent).toBe(true);
    expect(validRes.artifactSha256).toBe(expectedSha);
    expect(validRes.artifactHashMatch).toBe(true);
    expect(validRes.reason).toMatch(/artifact hash verified/);

    await expect(
      runCli(["verify-manifest", manifestPath, "--public-key", publicKeyPath, "--json"]),
    ).resolves.toBe(0);

    // 2. Tampered artifact (signature over manifest is untouched, but artifact binary was modified)
    writeFileSync(artifactPath, 'console.log("tampered evil code");', "utf8");
    const tamperedRes = verifyManifestFile(manifestPath, publicKeyPath);
    expect(tamperedRes.ok).toBe(false);
    expect(tamperedRes.signed).toBe(true);
    expect(tamperedRes.pinned).toBe(true);
    expect(tamperedRes.artifactPresent).toBe(true);
    expect(tamperedRes.artifactHashMatch).toBe(false);
    expect(tamperedRes.reason).toMatch(/protected artifact hash mismatch/);

    await expect(
      runCli(["verify-manifest", manifestPath, "--public-key", publicKeyPath, "--json"]),
    ).resolves.toBe(2);
  });

  it("verifies explicitly provided artifact path via CLI", async () => {
    const dir = createTempDir();
    const pair = generateManifestSigningKeyPair();
    const customArtifactPath = join(dir, "custom.bin");
    const manifestPath = join(dir, "manifest.json"); // non-adjacent name
    const content = Buffer.from([1, 2, 3, 4, 5]);
    writeFileSync(customArtifactPath, content);

    const { createHash } = await import("node:crypto");
    const expectedSha = createHash("sha256").update(content).digest("hex");

    const signed = signManifestPayload(
      {
        protectedSha256: expectedSha,
      },
      pair.privateKeyPem,
    );
    writeFileSync(manifestPath, JSON.stringify(signed, null, 2), "utf8");

    // Valid explicit artifact path
    await expect(
      runCli(["verify-manifest", manifestPath, customArtifactPath, "--json"]),
    ).resolves.toBe(0);

    // Tampered explicit artifact
    writeFileSync(customArtifactPath, Buffer.from([9, 9, 9]));
    await expect(
      runCli(["verify-manifest", manifestPath, customArtifactPath, "--json"]),
    ).resolves.toBe(2);

    // Non-existent explicit artifact
    await expect(
      runCli(["verify-manifest", manifestPath, join(dir, "missing.bin"), "--json"]),
    ).resolves.toBe(2);
  });
});