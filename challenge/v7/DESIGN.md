# CrackMe v7 — Meridian Design

> Status: **successor to CrackMe v6**. v6 (harden-native vault) shipped in
> bla-agents 1.6.1 as an interim snapshot and is retained under
> `challenge/v6/` for history; it is **not** the product challenge anymore.

## Product framing

Meridian is a small offline engineering calculator:

| Command | Behavior |
|---|---|
| `calc <expr>` | recursive-descent expression engine (`+ - * / % ^ !`, functions, constants) |
| `convert <v> <from> <to>` | unit conversion via `data/catalog.json` |
| `stats <n…>` | descriptive statistics |
| `units` / `version` | catalog / version |
| `license activate <KEY>` | Meridian Pro activation |

The public prize is the **activation certificate** printed on success. The
challenge never uses the word "flag" in product copy, so AI reverse agents
are not steered by CTF vocabulary. Secrets are product mechanisms
(revision digest + sealed certificate in the unit catalog), not an obvious
`FLAG{…}` gate.

## Why v6 failed (requirements this design answers)

Owner writeup against v6, mapped to design constraints:

| Critique | v7 response |
|---|---|
| 16 independent 1-byte lanes → ~95^1 search | **Chained 24–32 round ARX over the whole 20-symbol key.** Four 32-bit words packed from Crockford-base32; each round mixes all words with a seed-derived schedule. No per-lane oracle. |
| `LANE_SALT` / numeric literals survive harden | **No compile-time challenge constants in JS.** Expected digest lives in `catalog.json` as data; schedule/pad come from a SHA-256 stream keyed by `(integrity ‖ fingerprint ‖ env)`. Literals that remain are BLA's own injected numerics, not the secret. |
| WASM `mix`/`seal` kept export names, bit-identical to public ref | **No custom WASM crypto.** Crypto is ordinary `node:crypto` + ARX in JS, so BLA's JS shields (rename, string split, opaque predicates, decoys, anti-strip corpus) are the surface. |
| Opaque `hrtime` predicates / poisoned lanes | Documented as a **BLA product gap** (see issue). Challenge still runs through real `hardenProject()`; we avoid `class` constructors that BLA currently renames inconsistently (see below). |
| Static `solve.mjs` never executes the target | Activation **requires executing the hardened modules**: self-integrity hashes the five `.cjs` files at runtime; schedule seed binds that hash + a live feature fingerprint + an environment note. Pure static dumps of constants are insufficient. |
| No self-integrity / anti-debug | `measure()` SHA-256s all five modules; `environmentNote()` records inspector / `--inspect` / `NODE_OPTIONS` / `Function#toString` native-code checks. Tamper or attach → different seed → reject. |
| Decorative bankrupt score | Five real modules + catalog, all passed through `hardenProject({intensity:"bankrupt", llmDirectives:false})`. `SEAL.json` records per-file `defenseScore` from the live report. |

## Architecture

```
challenge/v7/dist/
  cli/meridian.cjs      ← hardened CLI
  core/expr.cjs         ← hardened expression engine
  core/units.cjs        ← hardened unit converter (reads catalog.json)
  core/stats.cjs        ← hardened stats
  core/license.cjs      ← hardened activation (ARX + integrity + env)
  data/catalog.json     ← units + revision (expected digest) + signature (sealed cert)
challenge/v7/SEAL.json  ← public digests / knobs only
```

Cleartext sources and the release generator live **outside git** (maintainer
store). Only hardened output + SEAL are public. That matches the product
story: customers receive BLA-hardened builds, not the preimage.

### Activation (happy path)

1. Normalize key → 20 Crockford-base32 symbols → pack into four integers.
2. `integrity = SHA256(pathᵢ ‖ bytesᵢ)` over the five hardened modules.
3. `fingerprint =` deterministic transcript of six `calc` cases, six
   `convert` cases, and one `stats` case (forces the other modules to run).
4. `env = environmentNote()` (empty string when clean).
5. `seed = SHA256("meridian/activation/v7" ‖ integrity ‖ fingerprint ‖ env)`.
6. Expand `seed` into `{rounds ∈ [24,32], pad[4], plan[rounds]}` via a
   counter-mode SHA-256 stream.
7. 4-word ARX permute; hex-encode → must equal `catalog.revision`.
8. Certificate keystream = SHA-256 stream over
   `("meridian/certificate/v7" ‖ symbols ‖ seed)`; XOR with
   `catalog.signature` → UTF-8 certificate.

Wrong key, tampered module, missing sibling file, or debugger attach all
collapse to the same `License rejected.` (exit 1). Bad format → usage
(exit 2). No per-stage oracle.

### Why multi-file + catalog

- BLA's discovery prefers `bin/` as a build-output name and skips `lib/` on
  supplemental walks. Layout uses `cli/` + `core/` so every module is
  discovered and hardened (enforced by the private generator).
- `data/catalog.json` is **not** JS, so BLA leaves it intact — the natural
  place to publish the expected digest and sealed certificate without
  embedding them as JS numeric/string literals that survive harden.

### Known BLA gaps exercised (filed as product issues)

1. **Numeric literals are not de-literalized** — still visible after
   bankrupt harden (confirmed with a probe `0x9e3779b9`).
2. **Class declaration vs. `new` sites can receive different renames**,
   producing `ReferenceError` at runtime. Meridian uses factory functions
   instead of `class` for that reason.
3. **Export / local names** that cross `require()` boundaries are only
   partially renamed; decoy injection can reference undefined constructors
   on dead branches.
4. A pure-static solver against harden output remains too strong if the
   app puts recoverable constants in one file — hence integrity + live
   fingerprint + env binding.

These are product findings, not challenge decorations.

## Honest scope

Solvable by a determined reverse engineer who:

1. Recovers the ARX / schedule logic from hardened `license.cjs`
   (rename + string-split + opaque predicates; no lane independence).
2. Runs (or faithfully rehosts) the integrity + fingerprint path so the
   seed matches.
3. Searches the 32^20 key space with the chained ARX — infeasible brute
   force; requires algebraic / differential insight or a bug in the
   binding, not 16 independent byte probes.

Out of scope: attacking npm, GitHub, or unrelated software; enabling
`--llm-directives`; extracting the maintainer store.

## Maintainer recipe (private)

```bash
# in the private store tree (not in git):
set -a; . secrets/crackme-v7-release.env; set +a
BLA_ROOT=/path/to/bla node gen.mjs /path/to/bla/challenge/v7/dist
# then fold build-info → SEAL.json (scripts/crackme/v7-seal.mjs --write-seal)
```

Fixture mode uses a public demo key for CI reproducibility without
publishing the release secret.
