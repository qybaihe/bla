# CrackMe v8 — Aegis Design

> Status: **successor to CrackMe v7 Meridian**. Built with **bla-agents 2.0**
> after red/blue rounds 1–12; the published tree **is** `hardenProject()` output.

## Product framing

Aegis is a small entitlement unlock:

| Command | Behavior |
|---|---|
| `node license.cjs <16-char-key>` | Unlock certificate / FLAG on success; uniform `DENIED` otherwise |

There is no in-browser panel derive. `panel.html` is operator UI only.

## Why not re-harden Meridian v7

Meridian cleartext + `gen.mjs` live in a **maintainer-private store** (only
hardened + SEAL are in git). Round-1 already recorded that an honest 2.0
re-harden of v7 is impossible without that store. Aegis is the public
graduation of the standing red/blue entitlement design instead.

## Recipes absorbed from R1–R12

| Round | Lesson | Aegis response |
|---|---|---|
| R1 | Stable WASM ABI + independent 1-byte lanes | No `wasmPreserveExports` / no lane tables; bankrupt rename default |
| R2–R4 | Reversible seals, JS AES unwrap, panel oracles, soft self-seal | One-way SHA-256 seal; no AES unwrap; no panel derive; **`--self-seal`** |
| R5–R6 | Hydrate dump / XOR-mask sidecar | Unlock stays in WASM; no mask sidecar |
| R7–R9 | Seal.revision XOR-KP + weak mask KDF + structure KP | **SHA-256(key) mask KDF**; commitment **outside** XOR; seed-derived rounds+pad3 |
| v8 red | Public SEAL `seed` → schedule KP; public `keySha256` → offline key oracle | Harden/schedule seed **private** (derived from release secrets), SEAL v2 publishes only `label` + `flagSha256`; `bla_lint` warns `public-materialization-seed` / `public-key-digest-oracle` |
| R10–R12 | Arity-2 alias stack / export-order / body idx 0 | Prefer arity-2 aliases; export-order shuffle; unlock body-index scatter |
| P2 | Full WASM RE + SMT | **Honest residual** — not refused as a packaging lint |

## Architecture

```
challenge/v8/hardened/
  license.cjs      ← hardened host gate (arity + FLAG + certificateSha256)
  panel.html       ← hardened operator UI (no token derive)
  core.wasm.gz     ← unlock-in-WASM (gzipped; ~7 MB raw)
  seal.json        ← runtime one-way seal (revision + certificateSha256)
challenge/v8/SEAL.json  ← public digests / knobs only
```

### Unlock (happy path)

1. Host loads hardened `core.wasm`, finds **arity-2** exports (order/name-independent).
2. Invokes candidates; accepts UTF-8 matching `FLAG{…}`.
3. Requires `SHA-256(result) === seal.certificateSha256`.
4. Inside WASM: `mask = SHA-256(key[16])`, unmask pack
   `salt||rounds||pad3||entropyPad[32]||clen||cipher`, compare clear commitment
   segment to `SHA-256(ARX_state)`, decrypt certificate.

Wrong key / honeypot canary / missing sibling → uniform deny (honeypots never
call WASM unlock).

## Honest scope

Solvable by a determined reverse engineer who recovers the in-WASM unlock
(SHA-256 KDF + ARX + commitment layout) and searches the key space — **not**
by packaging footguns that R1–R12 closed. Gates do **not** claim white-box
secrecy against full WASM RE / online SMT.

## Maintainer recipe

```bash
npm run build
CRACKME_V8_KEY='…' CRACKME_V8_FLAG='FLAG{…}' npm run crackme:v8:build
npm run crackme:v8:seal
# fixture-only CI path (no release secrets):
npm run crackme:v8:build -- --fixture
```
