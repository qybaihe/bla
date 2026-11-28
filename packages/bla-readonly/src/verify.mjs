import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { verifyManifestSignature } from '../../../src/core/manifest-signature-verification.ts';

const CHUNK = 64 * 1024;
const SHA256 = /^[a-f\d]{64}$/i;
const publicPem = (s) => typeof s === 'string' &&
  /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\n-----END PUBLIC KEY-----$/.test(s.trim());
const sameFile = (a, b) => b.isFile() && a.dev === b.dev && a.ino === b.ino;
const stable = (a, b) => sameFile(a, b) && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;

// All paths come from the operator. Never resolve artifact paths from the
// manifest. Limit the read on the open descriptor, even if the file grows.
function readChunks(path, limit, consume) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile()) throw new Error('Expected a regular file, not a link, directory or device');
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const start = fstatSync(fd, { bigint: true });
    if (!sameFile(before, start)) throw new Error('Input changed before read');
    if (start.size > BigInt(limit)) throw new Error(`Input exceeds the ${limit}-byte limit`);
    let remaining = Number(start.size);
    const buf = Buffer.alloc(Math.min(CHUNK, remaining));
    while (remaining > 0) {
      const n = readSync(fd, buf, 0, Math.min(buf.length, remaining), null);
      if (!n) throw new Error('Input changed during read');
      consume(buf.subarray(0, n));
      remaining -= n;
    }
    if (!stable(start, fstatSync(fd, { bigint: true })) || !stable(start, lstatSync(path, { bigint: true }))) {
      throw new Error('Input changed during read');
    }
  } finally {
    closeSync(fd);
  }
}

function readText(path, limit) {
  const parts = [];
  readChunks(path, limit, part => parts.push(Buffer.from(part)));
  return Buffer.concat(parts).toString('utf8');
}

export function verifyArtifact(path, options) {
  let expected = options.sha256;
  const pinned = options.manifest !== undefined;
  const result = { method: pinned ? 'pinned-ed25519-manifest' : 'sha256', ok: false,
    signatureVerified: pinned ? false : null, artifactVerified: false };
  if (pinned) {
    const text = readText(options.manifest, 1024 * 1024);
    let manifest;
    try { manifest = JSON.parse(text); } catch { throw new Error('Manifest is not valid JSON'); }
    const key = readText(options.publicKey, 16 * 1024);
    if (!publicPem(key)) throw new Error('Expected a trusted SPKI public key (PUBLIC KEY PEM)');
    if (!manifest || Array.isArray(manifest) || !publicPem(manifest.signature?.publicKey) ||
        !verifyManifestSignature(manifest, key)) {
      return { ...result, reason: 'Missing or invalid signature, or public key does not match the trusted key' };
    }
    result.signatureVerified = true;
    expected = manifest.protectedSha256;
    if (typeof expected !== 'string' || !SHA256.test(expected)) {
      return { ...result, reason: 'Signed manifest has no valid protectedSha256' };
    }
  } else if (!SHA256.test(expected)) {
    throw new Error('--sha256 requires exactly 64 hexadecimal characters');
  }
  const hash = createHash('sha256');
  readChunks(path, Number.MAX_SAFE_INTEGER, part => hash.update(part));
  const actualSha256 = hash.digest('hex');
  const ok = actualSha256 === expected.toLowerCase();
  return { ...result, ok, artifactVerified: ok, actualSha256, ...(ok ? {} : { reason: 'Artifact SHA-256 mismatch' }) };
}
