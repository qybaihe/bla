import { build } from 'esbuild';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const pkg = JSON.parse(readFileSync(new URL('package.json', import.meta.url), 'utf8'));
const entry = 'packages/bla-readonly/src/cli.mjs';
const inputs = new Set([entry, 'packages/bla-readonly/src/verify.mjs',
  'src/core/release-exposure.ts', 'src/core/manifest-signature-verification.ts']);
const builtins = new Set(['node:fs', 'node:path', 'node:crypto', 'node:util']);
const { metafile, outputFiles } = await build({
  absWorkingDir: root, entryPoints: [entry], outfile: 'packages/bla-readonly/dist/cli.mjs',
  bundle: true, treeShaking: true, platform: 'node', format: 'esm', target: 'node22',
  define: { __READONLY_VERSION__: JSON.stringify(pkg.version) },
  sourcemap: false, metafile: true, write: false,
});
// Admit the source closure, not a directory of prebuilt JS. A new dependency
// of a shared helper must be reviewed even if it currently tree-shakes away.
for (const path of Object.keys(metafile.inputs)) {
  if (!inputs.has(path.replaceAll('\\', '/'))) throw new Error(`Unapproved build input: ${path}`);
}
if (outputFiles.length !== 1) throw new Error('Expected one standalone CLI');
for (const { imports } of Object.values(metafile.outputs)) {
  for (const item of imports) {
    if (!item.external || !builtins.has(item.path)) throw new Error(`Unapproved runtime import: ${item.path}`);
  }
}
// Defense in depth: even an allowed source must not pull signing or key
// generation into the standalone verifier.
if (/\b(?:createPrivateKey|generateKeyPairSync|cryptoSign|signManifestPayload|readManifestSigningKeyOrThrow)\b/.test(outputFiles[0].text)) {
  throw new Error('Unexpected signing code in the read-only CLI');
}
mkdirSync(new URL('dist/', import.meta.url), { recursive: true });
writeFileSync(outputFiles[0].path, outputFiles[0].contents);
chmodSync(outputFiles[0].path, 0o755);
