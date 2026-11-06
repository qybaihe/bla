import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  generateManifestSigningKeyPair,
  readManifestSigningKeyOrThrow,
  signManifestPayload,
  verifyManifestSignature,
} from "../src/core/manifest-signing.js";
import { defendTarget } from "../src/engine/defender.js";

describe("manifest ed25519 signing", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-manifest-signing-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("generates a usable ed25519 keypair", () => {
    const pair = generateManifestSigningKeyPair();
    expect(pair.privateKeyPem).toContain("PRIVATE KEY");
    expect(pair.publicKeyPem).toContain("PUBLIC KEY");
  });

  it("signs and verifies a round trip, including JSON round trip", () => {
    const pair = generateManifestSigningKeyPair();
    const payload = { schema: "https://bla.tools/schemas/defense-manifest-v1.json", blaVersion: "1.2.3", items: [1, 2, 3] };
    const signed = signManifestPayload(payload, pair.privateKeyPem);
    expect(signed.signature.algorithm).toBe("ed25519");
    expect(signed.signature.publicKey).toContain("PUBLIC KEY");
    expect(verifyManifestSignature({ ...signed })).toBe(true);

    // Writing and re-reading the manifest must still verify (key order preserved).
    const parsed = JSON.parse(JSON.stringify(signed)) as Record<string, unknown>;
    expect(verifyManifestSignature(parsed)).toBe(true);
  });

  it("rejects tampered, unsigned, and forged manifests", () => {
    const pair = generateManifestSigningKeyPair();
    const signed = signManifestPayload({ a: 1 }, pair.privateKeyPem) as Record<string, unknown>;
    const signature = signed.signature as { algorithm: string; publicKey: string; value: string };

    expect(verifyManifestSignature({ ...signed, a: 2 })).toBe(false);
    expect(verifyManifestSignature({ a: 1 })).toBe(false);
    expect(verifyManifestSignature({ ...signed, signature: undefined })).toBe(false);

    const other = generateManifestSigningKeyPair();
    expect(
      verifyManifestSignature({
        ...signed,
        signature: { ...signature, publicKey: other.publicKeyPem },
      }),
    ).toBe(false);
    expect(
      verifyManifestSignature({
        ...signed,
        signature: { ...signature, value: Buffer.from("forged").toString("base64") },
      }),
    ).toBe(false);
  });

  it("reads the signing key from disk and fails closed on missing path", () => {
    const pair = generateManifestSigningKeyPair();
    const keyPath = path.join(dir, "manifest-key.pem");
    fs.writeFileSync(keyPath, pair.privateKeyPem);
    expect(readManifestSigningKeyOrThrow(keyPath)).toBe(pair.privateKeyPem);
    expect(() => readManifestSigningKeyOrThrow("")).toThrow(/private key path/);
    expect(() =>
      readManifestSigningKeyOrThrow(path.join(dir, "missing.pem")),
    ).toThrow(/not readable/);
  });

  it("defendTarget writes an ed25519-signed manifest when opted in", () => {
    const pair = generateManifestSigningKeyPair();
    const keyPath = path.join(dir, "signed-key.pem");
    fs.writeFileSync(keyPath, pair.privateKeyPem);

    const input = path.join(dir, "signed-app.js");
    const output = path.join(dir, "signed-app.shielded.js");
    fs.writeFileSync(input, "export const version = '1.0.0';\n", "utf8");

    const report = defendTarget({
      inputPath: input,
      outputPath: output,
      intensity: "stealth",
      emitManifest: true,
      signManifest: true,
      manifestSigningKeyPath: keyPath,
    });

    expect(report.manifestSigned).toBe(true);
    const manifestPath = `${output}.bla-manifest.json`;
    expect(report.manifestPath).toBe(manifestPath);

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    expect(manifest.attestationKind).toBe("ed25519");
    expect(manifest.signature).toBeDefined();
    expect(verifyManifestSignature(manifest)).toBe(true);
  });

  it("defendTarget emits an unsigned manifest without the signing opt-in", () => {
    const input = path.join(dir, "plain-app.js");
    const output = path.join(dir, "plain-app.shielded.js");
    fs.writeFileSync(input, "export const n = 7;\n", "utf8");

    const report = defendTarget({
      inputPath: input,
      outputPath: output,
      intensity: "stealth",
      emitManifest: true,
    });

    expect(report.manifestSigned).toBeUndefined();
    const manifest = JSON.parse(
      fs.readFileSync(`${output}.bla-manifest.json`, "utf8"),
    ) as Record<string, unknown>;
    expect(manifest.attestationKind).toBe("unsigned");
    expect(manifest.signature).toBeUndefined();
    expect(verifyManifestSignature(manifest)).toBe(false);
  });

  it("fails closed when signing without emitManifest or a key path", () => {
    const pair = generateManifestSigningKeyPair();
    const keyPath = path.join(dir, "fail-key.pem");
    fs.writeFileSync(keyPath, pair.privateKeyPem);
    const input = path.join(dir, "fail-app.js");
    fs.writeFileSync(input, "export const q = 1;\n", "utf8");

    expect(() =>
      defendTarget({ inputPath: input, intensity: "stealth", signManifest: true, manifestSigningKeyPath: keyPath }),
    ).toThrow(/emitManifest/);
    expect(() =>
      defendTarget({ inputPath: input, intensity: "stealth", emitManifest: true, signManifest: true }),
    ).toThrow(/private key path/);
    expect(() =>
      defendTarget({
        inputPath: input,
        intensity: "stealth",
        emitManifest: true,
        signManifest: true,
        manifestSigningKeyPath: path.join(dir, "no-such-key.pem"),
      }),
    ).toThrow(/not readable/);
  });

  it("pins verification to an expected public key", () => {
    const trusted = generateManifestSigningKeyPair();
    const attacker = generateManifestSigningKeyPair();
    const payload = { schema: "https://bla.tools/schemas/defense-manifest-v1.json", items: [1, 2] };

    const trustedManifest = signManifestPayload(payload, trusted.privateKeyPem);
    expect(verifyManifestSignature({ ...trustedManifest }, trusted.publicKeyPem)).toBe(true);
    expect(verifyManifestSignature({ ...trustedManifest }, attacker.publicKeyPem)).toBe(false);

    // A full re-sign with an attacker keypair must not pass a pinned check,
    // even though the embedded key verifies its own signature.
    const forged = signManifestPayload({ ...payload, items: [9, 9] }, attacker.privateKeyPem);
    expect(verifyManifestSignature({ ...forged })).toBe(true);
    expect(verifyManifestSignature({ ...forged }, trusted.publicKeyPem)).toBe(false);
  });

  it("verifies after object key reordering (sorted-key canonicalization)", () => {
    const pair = generateManifestSigningKeyPair();
    const signed = signManifestPayload(
      { schema: "s", blaVersion: "2.1.0", nested: { z: 1, a: 2 } },
      pair.privateKeyPem,
    ) as Record<string, unknown>;
    const reordered = {
      nested: { a: 2, z: 1 },
      blaVersion: "2.1.0",
      schema: "s",
      signature: signed.signature,
    };
    expect(verifyManifestSignature(reordered)).toBe(true);
  });

  it("still verifies legacy insertion-order signatures", () => {
    const pair = generateManifestSigningKeyPair();
    const privateKey = createPrivateKey(pair.privateKeyPem);
    const payload = { a: 1, b: { c: 2 } };
    const value = cryptoSign(
      null,
      Buffer.from(JSON.stringify(payload), "utf8"),
      privateKey,
    ).toString("base64");
    const legacy = {
      ...payload,
      signature: { algorithm: "ed25519", publicKey: pair.publicKeyPem, value },
    };
    expect(verifyManifestSignature(legacy)).toBe(true);
  });
});
