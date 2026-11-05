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
});