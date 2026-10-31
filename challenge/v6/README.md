# BLA CrackMe v6 — Harden-Native Edition

The public target **is `bla harden` output**. No hand-written obfuscation, no
custom CTF crypto: a small multi-format app is hardened by `hardenProject()`
(the exact pipeline behind `bla harden <dir>`), and the result is published as-is.

| File | What it is | Hardened by |
|------|------------|-------------|
| [`hardened/vault.cjs`](./hardened/vault.cjs) | Node.js entitlement gate (entry point) | JS AST shield + exhaustion / deception suites + anti-strip interlock |
| [`hardened/panel.html`](./hardened/panel.html) | HTML panel whose inline script derives the stage-B token (the vault executes it) | HTML multi-script shield |
| [`hardened/core.wasm.gz`](./hardened/core.wasm.gz) | WebAssembly `mix` / `seal` core (gzipped; ~7 MB raw) | WASM shield (decoy exports / bloat) |
| [`SEAL.json`](./SEAL.json) | Public commitment: knobs, `keySha256`, `flagSha256`, artifact + template digests | — |

Harden knobs (pinned in `SEAL.json`, enforced by CI): `intensity=bankrupt`,
`llmDirectives=false` (risky LLM-directive layers OFF), `emitManifest=false`,
fixed seed → byte-for-byte reproducible.

## Run

```bash
npm run crackme:v6 -- '<16-char-key>'
# or: node challenge/v6/run.mjs '<16-char-key>'
```

`run.mjs` copies the bundle to a temp dir, gunzips `core.wasm`, clears
`NODE_OPTIONS`, and runs `vault.cjs`. Success prints `FLAG{...}`; anything else
prints a single uniform `[vault] DENIED` (no per-stage oracle).

## Rules of the game

The cleartext **template is public** ([`src/`](./src/)) — reading it tells you the
*shape* of the gate, not the answer. Every build fills in fresh constants (16 WASM
lane targets, the panel token, the encrypted flag) from maintainer secrets, then
hardens. To win you must recover those constants and the real logic from the
hardened output, i.e. defeat BLA:

- **Stage A** — each key byte goes through `seal(mix(byte, tweak_i))` in the hardened
  `core.wasm` and must hit a hidden 32-bit lane target.
- **Stage B** — the vault executes the hardened `panel.html` script; its token must match.
- **Stage C** — the key decrypts the flag; `SHA-256(flag)` must equal `flagSha256`.
- Retired keys (v4.1 / v5.2) are honeypots that print decoy flags.

## Prove a solve

```bash
node -e 'console.log(require("crypto").createHash("sha256").update(process.argv[1]).digest("hex"))' 'FLAG{...}'
```

It must equal `flagSha256` in [`SEAL.json`](./SEAL.json). Open an issue with the
**CrackMe v6 solve** template (hash + method notes). A *general* bypass of BLA's
hardening is worth more than a one-off patch of this fixture — say so in the issue.

## Honest scope

BLA raises the cost for **automated** AI reverse-engineering agents and plants
decoys. It does not claim immunity to patient interactive reversing (debuggers,
Frida, manual analysis). Known gap surfaced by this challenge: numeric literals
are not de-literalized by the JS shield, so the template keeps constants in
strings (which BLA does split / decoy).

## Reproducible build (maintainers)

```bash
npm run build
npm run crackme:build -- --fixture          # public demo secret → challenge/v6/.fixture (gitignored)
CRACKME_V6_KEY='<16 chars>' CRACKME_V6_FLAG='FLAG{…}' npm run crackme:build   # release → hardened/ + SEAL.json
npm run crackme:seal                        # CI gate: digests, deny/honeypot, fixture re-harden + reproducibility,
                                            # and (if secrets match SEAL) release unlock + byte-for-byte rebuild
```

Equivalent CLI recipe: materialize the template into `app/` (see
`scripts/crackme/lib.mjs#materializeVault`), copy `src/panel.html` and
`src/core.wasm`, then `bla harden app --intensity bankrupt --seed <SEAL.seed>`.

## History

- [`../archive/v6-tiered-protect/`](../archive/v6-tiered-protect/) — first v6 draft (PR #38): single-file L1/L2/L3 `protect` tiers.
- [`../archive/v5/`](../archive/v5/) — v5.2 hand-crafted Cognitive-Armor sponge.
