# CrackMe v9 — Sovereign Design (BLA 3.0 Showcase)

> Status: **successor to CrackMe v8 Aegis**. Built with **bla-agents 3.0.0**
> through the **4-Stage Agent-Driven Hardening Playbook** (`bla_lint` →
> `bla_weave_plan` → `bla_verify_weave` → `bla_harden --weave-decoys --self-seal --sidecar-entangle`).

## Product framing

Sovereign is a polyglot (JS + WASM + HTML + Python) entitlement unlock:

| Command | Behavior |
|---|---|
| `node license.cjs <16-char-key>` | Unlock certificate / FLAG on success; uniform `DENIED` otherwise; hard-fails on any file/sidecar tamper |

## What CrackMe v9 (Sovereign) advances over v8 (Aegis)

| Dimension | CrackMe v8 (Aegis — 2.0) | CrackMe v9 (Sovereign — 3.0) |
|---|---|---|
| Pipeline | Single-step `bla harden --self-seal` | Full **4-Stage BLA 3.0 Playbook** (`bla_lint` → `bla_weave_plan` → `bla_verify_weave` → `bla_harden`) |
| `seal.json` sidecar coverage | Uncovered data sidecar (v8 residual) | **Closed**: `license.cjs` pins `EXPECTED_SEAL_SHA256` at runtime; tampering with `seal.json` hard-fails |
| Cross-format entanglement | `selfSeal: true` only | `selfSeal: true` + **`sidecarEntangle: true`** + **`weaveDecoys: true`** across JS, WASM, HTML, and Python (`policy.py`) |
| Structural weave verification | None | Enforced **100/100 (`weaveScore: 100`)** via `bla_verify_weave` both pre-harden and post-harden |
| Entry self-digest verification | Soft / post-hoc | Enforced `integrityCoverageSelfVerified: true` in `SEAL.json` |
| WASM + JS Deception Anchors | Strip-prone export roots | All injected JS exhaustion/deception roots + Python canary honeypots anchored to module init |

## Architecture

```
challenge/v9/hardened/
  license.cjs      ← hardened host gate (pinned EXPECTED_SEAL_SHA256 + self-seal + sidecar-entangle + woven state)
  panel.html       ← hardened operator UI (no token derive)
  policy.py        ← hardened Python quota ledger (woven customer defs + warm-init + sidecar-bound)
  core.wasm.gz     ← unlock-in-WASM (gzipped; ~7 MB raw)
  seal.json        ← runtime one-way seal (revision + certificateSha256, SHA-256 pinned in license.cjs)
challenge/v9/SEAL.json  ← public digests / 3.0 verification telemetry only
```

## Honest scope

Solvable by a determined reverse engineer who recovers the in-WASM unlock
(SHA-256 KDF + ARX + commitment layout) and searches the key space — **not**
by packaging footguns, sidecar stripping, `seal.json` tampering, or dead-code
decoy peeling. Gates do **not** claim white-box secrecy against full WASM RE /
online SMT.

## Maintainer recipe

```bash
npm run build
CRACKME_V9_KEY='…' CRACKME_V9_FLAG='FLAG{…}' npm run crackme:v9:build
npm run crackme:v9:seal
# fixture-only CI path (no release secrets):
npm run crackme:v9:build -- --fixture
```
