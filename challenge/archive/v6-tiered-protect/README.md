> **Archived (superseded).** This was the first CrackMe v6 draft (PR #38): single-file
> `protect` tiers L1/L2/L3. It was replaced by the harden-native edition in
> [`../../v6/`](../../v6/), which hardens a multi-format app with the real `bla harden`
> pipeline and keeps risky LLM directive layers OFF. The build scripts that produced
> these artifacts were removed; see git history (`1e485fd`). Not exercised by CI.

# BLA CrackMe v6 — BLA-generated tiered challenge

This is the public Counter-REA challenge for **bla-agents**.
Unlike v5.x (hand-written crypto sponge), **v6 artifacts are produced by running the real BLA protector** (`bla protect` / the same engine as `bla harden`) on a small clean Node.js license gate.

## Tiers

| Tier | Profile | What it adds |
|------|---------|--------------|
| **L1** | `balanced` | AST opaque ternaries, tarpit/budget breakers, exhaustion suite, deception suite (llmDirectives OFF), honey source maps |
| **L2** | `maximum` | Same families at higher decoy / alias / obligation budgets |
| **L3** | `bankrupt` + `--llm-directives` | Strongest JS profile BLA ships, including opt-in LLM-facing cognitive-armor layers |

Artifacts: [`artifacts/L1.cjs`](./artifacts/L1.cjs), [`L2.cjs`](./artifacts/L2.cjs), [`L3.cjs`](./artifacts/L3.cjs).

Public commitment (hashes only): [`commitment.json`](./commitment.json).

## Run

```bash
env -u NODE_OPTIONS node challenge/v6/artifacts/L1.cjs '<authorization-key>'
# try L2 / L3 the same way
```

On success the program prints `FLAG{...}`.

## Prove a solve

1. Compute `SHA-256(FLAG{...})` (UTF-8, exact bytes):

```bash
node -e 'console.log(require("crypto").createHash("sha256").update(process.argv[1]).digest("hex"))' 'FLAG{...}'
```

2. It must equal `flagSha256` in [`commitment.json`](./commitment.json).
3. Open a GitHub issue with the **CrackMe v6 solve** template (paste the hash, tier broken, and a short method note). **Do not** paste the raw FLAG in public if you want coordinated disclosure — the hash is the proof.

## What counts as a break

- Recovering a key/flag that unlocks a published tier and matches `flagSha256`.
- Showing a **general** bypass of BLA's JS hardening (not a one-off patch of this fixture) is even more valuable — describe it in the issue.

## What BLA claims (honest)

- BLA raises cost for **automated** AI reverse-engineering agents (e.g. REA-style obligation / semantic budgets) and plants decoys.
- BLA is **not** a magic anti-RE seal against patient interactive reversing (Ghidra / Frida / LLDB / manual debugging).
- v6 showcases **BLA-generated** defenses. It is not a custom CTF crypto construction.

## Reproducible rebuild (maintainers)

```bash
npm run build
CRACKME_V6_KEY='…' CRACKME_V6_FLAG='FLAG{…}' npm run crackme:build
npm run crackme:seal
```

Clean template (no secrets): [`clean/target.template.cjs`](./clean/target.template.cjs).  
Profiles: [`profiles.json`](./profiles.json).

## Legacy

v5.2 is archived under [`../v5/`](../v5/) for history. New attempts should target **v6**.
