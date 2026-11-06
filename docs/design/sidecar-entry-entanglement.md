# DESIGN: Sidecar / entry entanglement (issue #40 / STATE)

Status: **JS + Python strip⇒fail** — binding digest + JS/Python preambles + protect/harden opt-in landed; WASM custom-section still TBD.

## Goal

Decoy / chaff sidecars must not be dismissible as an "independent protection layer".
If an attacker strips a sidecar or decoy file, the **entry** (main module / primary
artifact) must fail closed (integrity mismatch), not keep running happily.

This is the same honesty principle as weave-decoy: shared state + entry-reachable
checks beat orphan honeypot files.

## Non-goals

- No crack / RE playbooks.
- No claim that entanglement equals cryptographic unbreakability.
- No mandatory sidecar for every format in 1.6.x.

## Design (v1)

1. **Binding digest** — at protect time, compute `H = SHA-256(entryBytes || sidecarBytes || seedTag)`.
2. **Entry hook** — inject a tiny preamble (JS/Python) or custom-section note (WASM) that
   re-measures sibling sidecar path(s) and compares to `H` (or folds `H` into the opaque seed /
   self-seal digest — see `#40.5`).
3. **Strip ⇒ fail** — missing or altered sidecar changes the digest → opaque happy-path /
   activation gate fails.
4. **Opt-in** — `sidecarEntangle: true` in `.blarc` / CLI / MCP (not enabled by default until
   format coverage is broader).

## First slice (this batch)

- This DESIGN note (normative intent).
- Stub helper `planSidecarEntanglement()` returning a `bla-sidecar-entangle/v1` plan
  object (paths, digest algorithm, entry hook kind) **without** rewriting binaries yet.
- Unit tests for the planner.

## Follow-ups

- ~~Entry self-coverage~~ — landed 2026-11-05: self-seal embeds a canonical entry self-digest finalized at write time; harden reports `integrityCoverageSelfVerified` and drops paper self edges when it does not verify.
- ~~Wire planner into `protectTarget` for JS + Python when `sidecarEntangle` is set.~~ — JS 2026-11-05; Python 2026-11-06 nightly.
- Extend to ASAR / Bun snapshot / native companion files.
- Honesty: when entanglement is off, defenseScore gap annotation (like self-seal).
