# Aegis (CrackMe v8)

Offline product entitlement gate shipped as a **real `bla harden` output**
(bankrupt + `--self-seal`, **no** `--allow-*`). Absorbs the red/blue R1–R12
recipes that held under BLA 2.0 packaging gates.

```bash
npm run crackme:v8 -- '<16-char-key>'
```

Rules, commitment digests, and design rationale live in
[`DESIGN.md`](./DESIGN.md) and [`SEAL.json`](./SEAL.json).

> **Scope note:** The in-WASM unlock derives its keystream from `SHA-256(key)` over a 16-character secret, so recovering the key by brute-forcing $94^{16}$ candidates is intentionally infeasible. Aegis is a **packaging-gate regression target** verifying that R1–R12 bypasses (lane independence, reversible seals, JS unwrap, panel oracles, stable ABI hooks, sidecar stripping) are closed — not a brute-forceable keygen.

This supersedes CrackMe v7 Meridian (still under `../v7/` for history).
