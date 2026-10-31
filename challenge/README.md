# 🛡️ BLA CrackMe — Public Counter-REA Challenge

## Current: v6 (BLA-generated, tiered)

**Start here → [`v6/README.md`](./v6/README.md)**

v6 is the challenge that matches the project intent: a small clean license gate hardened by the **real BLA pipeline** (`bla protect` / `bla harden` engine) at three public tiers (L1 balanced → L2 maximum → L3 bankrupt + LLM directive layers).

```bash
env -u NODE_OPTIONS node challenge/v6/artifacts/L1.cjs '<authorization-key>'
```

Public flag commitment: see [`v6/commitment.json`](./v6/commitment.json) (`flagSha256` only — no plaintext flag in git).

## Legacy: v5.2 (archived)

[`v5/`](./v5/) keeps the older hand-crafted Cognitive-Armor sponge challenge for history. It is **not** the recommended target and does not represent a stock `bla harden` output.

## Rebuild / CI

```bash
npm run crackme:build -- --fixture   # demo secret, local pipeline check
npm run crackme:seal                 # digest + deny-wrong-key + fixture rebuild
# maintainers with repo secrets:
CRACKME_V6_KEY=… CRACKME_V6_FLAG=… npm run crackme:build
```
