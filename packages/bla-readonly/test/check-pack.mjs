import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('../', import.meta.url));
const pkg = JSON.parse(readFileSync(join(dir, 'package.json')));
const tmp = mkdtempSync(join(tmpdir(), 'bla-ro-pack-'));
// Invoked through npm run so this works with npm.cmd on Windows as well.
if (!process.env.npm_execpath) throw new Error('Run via npm run check:pack');
const npm = (args, cwd) => execFileSync(process.execPath, [process.env.npm_execpath, ...args], { cwd, encoding: 'utf8', env: {
  ...process.env, npm_config_offline: 'true', npm_config_cache: join(tmp, cwd === dir ? 'pack-cache' : 'install-cache'), npm_config_audit: 'false', npm_config_fund: 'false',
} });
const expected = ['LICENSE', 'README.md', 'dist/cli.mjs', 'package.json'];
function leaves(path, prefix = '') {
  return readdirSync(path, { withFileTypes: true }).flatMap(entry => {
    const name = `${prefix}${entry.name}`;
    if (entry.isDirectory()) return leaves(join(path, entry.name), `${name}/`);
    assert.ok(entry.isFile(), `Unexpected non-regular member ${name}`); return [name];
  }).sort();
}
try {
  execFileSync(process.execPath, [join(dir, 'build.mjs')], { stdio: 'inherit', cwd: dir });
  const [packed] = JSON.parse(npm(['pack', '--json', '--ignore-scripts', '--pack-destination', tmp], dir));
  assert.equal(packed.name, pkg.name); assert.equal(packed.version, pkg.version);
  assert.equal(packed.filename, `${pkg.name}-${pkg.version}.tgz`);
  assert.deepEqual(packed.files.map(f => f.path).sort(), expected);
  const tarball = join(tmp, packed.filename);
  const consumer = join(tmp, 'consumer'); mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), '{"name":"offline-smoke","version":"0.0.0","private":true}\n');
  npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', tarball], consumer);
  const modules = join(consumer, 'node_modules'), installed = join(modules, pkg.name);
  assert.deepEqual(readdirSync(modules).filter(n => !n.startsWith('.')), [pkg.name]);
  assert.deepEqual(leaves(installed), expected);
  const metadata = JSON.parse(readFileSync(join(installed, 'package.json')));
  for (const key of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundledDependencies']) assert.ok(!metadata[key], `Unexpected ${key}`);
  assert.deepEqual(Object.keys(metadata.bin), ['bla-readonly']);
  assert.deepEqual(Object.keys(metadata.scripts).sort(), ['build', 'check:pack', 'test']);
  const bin = join(installed, metadata.bin['bla-readonly']);
  const shim = join(modules, '.bin', process.platform === 'win32' ? 'bla-readonly.cmd' : 'bla-readonly');
  assert.ok(existsSync(shim));
  if (process.platform !== 'win32') {
    assert.ok(statSync(bin).mode & 0o111); assert.equal(execFileSync(shim, ['--version'], { encoding: 'utf8' }).trim(), pkg.version);
  }
  execFileSync(process.execPath, ['--test', join(dir, 'test/cli.test.mjs')], { cwd: consumer, stdio: 'inherit', env: { ...process.env, BLA_READONLY_TEST_BIN: bin } });
  const artifacts = join(dir, 'artifacts'); mkdirSync(artifacts, { recursive: true });
  const digest = createHash('sha256').update(readFileSync(tarball)).digest('hex');
  copyFileSync(tarball, join(artifacts, basename(tarball)));
  writeFileSync(join(artifacts, 'SHA256SUMS.txt'), `${digest}  ${packed.filename}\n`);
  console.log(`Verified ${packed.filename}: ${packed.entryCount} files, ${packed.size} bytes, SHA-256 ${digest}`);
} finally { rmSync(tmp, { recursive: true, force: true }); }
