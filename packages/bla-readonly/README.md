# bla-readonly

An offline CLI for source-map exposure audits and artifact verification. This is a **separate package and executable** from `bla-agents`. It does not execute inputs, rewrite releases, install agents, start a server, or fetch map references. It has no runtime dependencies or install hooks. Requires Node `^22.23.4 || >=24`.

## Use a local release candidate

Install the supplied tarball into the consumer project, not the repository's root package:

```bash
npm install --offline --ignore-scripts --no-audit --no-fund ./bla-readonly-0.1.0-rc.1.tgz
```

```bash
npx --offline bla-readonly audit ./dist
```

`audit` reports source text embedded in standalone/inline source maps and the presence of unverified map references in local JS/TS/CSS files. It reports counts, not source text, source names or URLs. It ignores unrelated file types. Reads are bounded (2 MiB per eligible file, 32 MiB total; at most 10,000 entries and 16 directory levels). Skips and malformed maps can make the report `partial`. A complete scan, even with zero findings, is **not a security certification**. Inspect stable local trees, not directories being concurrently modified by untrusted processes.

```bash
npx --offline bla-readonly verify ./bundle.js --sha256 "$EXPECTED_SHA256"
```

Digest mode compares the bytes to an independently obtained SHA-256. It does not authenticate who supplied the expected digest.

```bash
npx --offline bla-readonly verify ./bundle.js --manifest ./bundle.js.bla-manifest.json --public-key ./release-public.pem
```

Manifest mode accepts BLA's Ed25519 signatures (`sorted-keys-v1` and legacy insertion order). It requires **both** a matching trusted SPKI public key from outside the manifest and a matching `protectedSha256` for the explicitly named artifact. It never treats the embedded key alone as a trust anchor or uses a filename stored in the manifest. Inputs must be regular files, not final-component symlinks. Select trusted parent directories. Reads of manifests are limited to 1 MiB, public keys to 16 KiB; artifacts are hashed in chunks up to their initially observed length. Files that change detectably during a read are not certified.

Both commands print JSON; `--json` is optional. Exit `0` means a complete audit (findings are allowed) or a verified match; `1` means verification failed; `2` means partial audit, invalid arguments or input/read error. Audit coverage and authenticity are different claims.

## Build and check from the repository checkout

```bash
npm ci --prefix packages/bla-readonly --ignore-scripts
```

```bash
npm test --prefix packages/bla-readonly
```

```bash
npm run check:pack --prefix packages/bla-readonly
```

The last command packs **this subpackage**, checks the exact four archive members, installs the tarball with an empty offline npm cache, and re-runs the CLI tests against the installed binary. It saves the tested tarball and its SHA-256 under `artifacts/`. The archive contains only `dist/cli.mjs`, `package.json`, `README.md` and `LICENSE`. Nothing in this process publishes a package or creates a Git tag.
