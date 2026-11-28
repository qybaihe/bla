#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { inspectReleaseExposure } from '../../../src/core/release-exposure.ts';
import { verifyArtifact } from './verify.mjs';

const help = `bla-readonly — offline inspection, JSON output
  bla-readonly audit <file-or-directory>
  bla-readonly verify <file> --sha256 <64-hex-digest>
  bla-readonly verify <file> --manifest <BLA-manifest.json> --public-key <trusted.pem>
  bla-readonly --help | --version
Exit: 0 complete audit or verified match; 1 verification failed; 2 usage, I/O or partial audit.`;
// Keep JSON parseable without allowing filenames or error messages to inject
// terminal C1 controls or direction overrides. JSON.stringify escapes C0.
const json = data => JSON.stringify(data).replace(/[^\x20-\x7e]/g,
  c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));

function main([command, ...args]) {
  if (command === '--help' && args.length === 0) { console.log(help); return 0; }
  if (command === '--version' && args.length === 0) { console.log(__READONLY_VERSION__); return 0; }
  if (command !== 'audit' && command !== 'verify') throw new Error('Expected audit or verify; see --help');
  const options = { json: { type: 'boolean' } };
  if (command === 'verify') Object.assign(options, {
    sha256: { type: 'string' }, manifest: { type: 'string' }, 'public-key': { type: 'string' },
  });
  const { positionals, values, tokens } = parseArgs({ args, options, allowPositionals: true, strict: true, tokens: true });
  const flags = tokens.filter(t => t.kind === 'option').map(t => t.name);
  if (new Set(flags).size !== flags.length) throw new Error('Repeated options are not accepted');
  if (positionals.length !== 1 || !positionals[0]) throw new Error('Specify exactly one input path');
  if (command === 'audit') {
    const report = inspectReleaseExposure(positionals[0]);
    console.log(json(report));
    return report.status === 'complete' ? 0 : 2;
  }
  const { sha256, manifest, 'public-key': publicKey } = values;
  if (sha256 !== undefined ? manifest !== undefined || publicKey !== undefined : !manifest || !publicKey) {
    throw new Error('Use either --sha256, or both --manifest and --public-key');
  }
  const result = verifyArtifact(positionals[0], { sha256, manifest, publicKey });
  console.log(json(result));
  return result.ok ? 0 : 1;
}

try { process.exitCode = main(process.argv.slice(2)); }
catch (err) { console.error(json({ error: err.message })); process.exitCode = 2; }
