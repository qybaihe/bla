# CrackMe v9 — Sovereign (BLA 3.0)

Polyglot entitlement challenge built with the **BLA 3.0 4-Stage Agent-Driven Hardening Playbook** (`--intensity bankrupt --weave-decoys --self-seal --sidecar-entangle`, `weaveScore: 100`, `integrityCoverageSelfVerified: true`, and covered `seal.json`).

## Run

```bash
npm run crackme:v9 -- '<16-char-key>'
```

See [`DESIGN.md`](./DESIGN.md) and [`SEAL.json`](./SEAL.json).

> **Scope note:** Like v8, Sovereign derives its WASM keystream from `SHA-256(key)` over a 16-character secret; $94^{16}$ brute-force key search is intentionally infeasible. Sovereign is a **BLA 3.0 packaging & integrity regression showcase** verifying that packaging footguns, sidecar stripping, `seal.json` tampering, and dead-code decoy peeling are closed — not a brute-forceable keygen.
