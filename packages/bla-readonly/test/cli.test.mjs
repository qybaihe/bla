import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const cli = process.env.BLA_READONLY_TEST_BIN || fileURLToPath(new URL('../dist/cli.mjs', import.meta.url));
const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const mk = t => {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), 'bla-ro-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
function run(code, ...args) {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  assert.ifError(r.error); assert.equal(r.signal, null); assert.equal(r.status, code, r.stderr || r.stdout);
  return r;
}
const result = (code, ...args) => JSON.parse(run(code, ...args).stdout);
const keys = () => {
  const pair = generateKeyPairSync('ed25519');
  return { privateKey: pair.privateKey, pem: pair.publicKey.export({ type: 'spki', format: 'pem' }) };
};
const fixture = (t, legacy = false, payloadChanges = {}) => {
  const dir = mk(t), artifact = join(dir, 'artifact.bin'), manifest = join(dir, 'manifest.json'), key = join(dir, 'trusted.pem');
  const { privateKey, pem } = keys();
  const bytes = Buffer.from('\0immutable release\n');
  writeFileSync(artifact, bytes); writeFileSync(key, pem);
  const p = { z: 'test', protectedSha256: sha(bytes), a: 17, ...payloadChanges };
  const signingText = legacy ? JSON.stringify(p) : JSON.stringify(Object.fromEntries(Object.entries(p).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)));
  const signature = { algorithm: 'ed25519', publicKey: pem, value: sign(null, Buffer.from(signingText), privateKey).toString('base64') };
  if (!legacy) signature.canonicalization = 'sorted-keys-v1';
  writeFileSync(manifest, JSON.stringify({ ...p, signature }, null, 2));
  return { artifact, manifest, key, args: ['verify', artifact, '--manifest', manifest, '--public-key', key] };
};
function snapshot(path) {
  const s = lstatSync(path, { bigint: true });
  return [s.mode, s.mtimeNs, s.isDirectory()
    ? readdirSync(path).sort().map(name => [name, snapshot(join(path, name))]) : sha(readFileSync(path))];
}

test('only the read-only commands and exact version are advertised', () => {
  assert.equal(run(0, '--version').stdout.trim(), version);
  assert.match(run(0, '--help').stdout, /audit <file-or-directory>/);
  for (const command of ['harden', 'defend', 'protect', 'apply', 'restore', 'sign', 'mcp', 'update']) run(2, command);
});
test('audit counts embedded source without executing bundles or disclosing source, names or URLs', t => {
  const root = mk(t);
  writeFileSync(join(root, 'a.js'), 'throw new Error("never execute this file");\n//# sourceMappingURL=https://example.invalid/private.map');
  writeFileSync(join(root, 'a.map'), JSON.stringify({ version: 3, sources: ['hidden-name.ts'], sourcesContent: ['hidden text'] }));
  const before = snapshot(root), r = result(0, 'audit', root, '--json');
  assert.equal(r.status, 'complete'); assert.equal(r.filesInspected, 2);
  assert.deepEqual(r.findings.map(f => f.kind), ['unverified-map-reference', 'embedded-source-text']);
  assert.equal(r.findings[1].embeddedSourceBytes, 11); assert.equal(r.networkAccessed, false); assert.equal(r.targetModified, false);
  assert.doesNotMatch(JSON.stringify(r), /hidden|example\.invalid|private\.map/);
  assert.deepEqual(snapshot(root), before);
});
test('empty audit is complete; invalid and oversized maps report partial, not clean', t => {
  const root = mk(t); assert.equal(result(0, 'audit', root).findings.length, 0);
  writeFileSync(join(root, 'broken.map'), '{'); writeFileSync(join(root, 'large.map'), Buffer.alloc(2 * 1024 * 1024 + 1));
  const r = result(2, 'audit', root); assert.equal(r.status, 'partial'); assert.deepEqual(r.limitations.map(x => x.reason), ['invalid-source-map-json', 'read-size-limit']);
});
test('binary and empty artifacts verify; mismatch does not certify or modify the input', t => {
  const root = mk(t), file = join(root, 'release.bin');
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(3 * 65536 + 13, 0xf1)]) {
    writeFileSync(file, bytes); const before = snapshot(root);
    const r = result(0, 'verify', '--sha256', sha(bytes).toUpperCase(), file); assert.equal(r.artifactVerified, true); assert.equal(r.signatureVerified, null);
    const bad = result(1, 'verify', file, '--sha256', '0'.repeat(64)); assert.equal(bad.ok, false); assert.equal(bad.artifactVerified, false);
    assert.deepEqual(snapshot(root), before);
  }
});
for (const legacy of [false, true]) test(`pinned signature and digest are both checked (legacy=${legacy})`, t => {
  const { artifact, args } = fixture(t, legacy);
  assert.equal(result(0, ...args).signatureVerified, true);
  writeFileSync(artifact, 'changed'); const r = result(1, ...args);
  assert.equal(r.signatureVerified, true); assert.equal(r.artifactVerified, false); assert.equal(r.ok, false);
});
test('wrong key, unsigned payload, and edits to signed fields fail verification', t => {
  const { manifest, key, args } = fixture(t); const pinned = readFileSync(key);
  writeFileSync(key, keys().pem); assert.equal(result(1, ...args).signatureVerified, false); writeFileSync(key, pinned);
  const payload = JSON.parse(readFileSync(manifest)); payload.a++; writeFileSync(manifest, JSON.stringify(payload));
  assert.equal(result(1, ...args).signatureVerified, false);
  delete payload.signature; writeFileSync(manifest, JSON.stringify(payload)); assert.equal(result(1, ...args).ok, false);
});
test('signed payload with no digest is not a verified file', t => {
  const { args } = fixture(t, false, { protectedSha256: undefined }); const r = result(1, ...args);
  assert.equal(r.signatureVerified, true); assert.equal(r.artifactVerified, false);
});
test('explicit missing inputs, directories, malformed JSON and size limits fail closed', t => {
  const { artifact, manifest, key, args } = fixture(t);
  for (const file of [mk(t), join(mk(t), 'absent')]) assert.ok(JSON.parse(run(2, 'verify', file, '--sha256', '0'.repeat(64)).stderr).error);
  writeFileSync(key, Buffer.alloc(16 * 1024 + 1)); assert.match(run(2, ...args).stderr, /exceeds/);
  writeFileSync(manifest, Buffer.alloc(1024 * 1024 + 1)); assert.match(run(2, ...args).stderr, /exceeds/);
  writeFileSync(manifest, '{'); assert.match(run(2, ...args).stderr, /not valid JSON/);
  run(2, 'verify', artifact, '--sha256', 'not-a-digest');
});
test('selected file links are refused; nested audit links are skipped', t => {
  const dir = mk(t), other = mk(t), target = join(other, 'outside.map'), link = join(dir, 'link.map');
  writeFileSync(target, '{"version":3,"sourcesContent":["external"]}');
  try { symlinkSync(target, link, 'file'); } catch (e) { if (process.platform === 'win32' && e.code === 'EPERM') { t.skip('no symlink privilege'); return; } throw e; }
  assert.equal(result(2, 'audit', dir).filesInspected, 0); run(2, 'audit', link);
  assert.match(run(2, 'verify', link, '--sha256', sha(readFileSync(target))).stderr, /regular file/);
});
test('does not accept missing, mixed, repeated or writing options', t => {
  const { artifact, key, manifest } = fixture(t);
  for (const args of [[], ['--public-key', key], ['--manifest', manifest], ['--sha256','0'.repeat(64),'--manifest',manifest], ['--sha256','0'.repeat(64),'--sha256','1'.repeat(64)], ['--output',artifact]]) run(2, 'verify', artifact, ...args);
  run(2, 'audit', artifact, '--apply'); run(2, 'audit', artifact, artifact);
});
test('audit and pinned verification work with Node filesystem writes and subprocesses denied', t => {
  const { artifact, args } = fixture(t);
  const dir = mk(t); writeFileSync(join(dir, 'app.map'), '{"version":3}');
  const before = snapshot(artifact);
  for (const cmd of [['audit', dir], args]) {
    const r = spawnSync(process.execPath, ['--permission', '--allow-fs-read=*', cli, ...cmd], { encoding: 'utf8' });
    assert.ifError(r.error); assert.equal(r.status, 0, r.stderr);
    const report = JSON.parse(r.stdout);
    if (cmd[0] === 'verify') assert.equal(report.artifactVerified, true);
    else assert.equal(report.filesInspected, 1);
  }
  assert.deepEqual(snapshot(artifact), before);
});
test('JSON errors do not emit raw terminal controls', t => {
  const name = join(mk(t), 'missing-\x9b-red'); const r = run(2, 'audit', name); assert.ok(JSON.parse(r.stderr).error); assert.ok(!r.stderr.includes('\x9b'));
});
