# BLA state of the project

**Version:** 2.1.0 (`package.json` ↔ `src/identity.ts`, verified by build; see `CHANGELOG.md`)  
**Status:** CI matrix runs typecheck, build, tests and the benchmark on ubuntu / macos / windows with Node 24. Windows checkouts keep `challenge/**` LF via `.gitattributes` so the CrackMe seals verify.  
**Publishing:** tagged releases (`git tag bla-agents-<version>`) plus GitHub Releases. The release workflow can also publish the packed tarball to npm with provenance when `NPM_TOKEN`/OIDC is configured; a release cut may intentionally skip the npm step (see `CHANGELOG.md`).

## One-sentence usage

```bash
npx bla-agents setup -y    # register MCP + skill (default verb: bla_harden)
bla harden .               # or tell your agent: "Harden my software against REA"
```

Also: `bla_harden` MCP tool with `{ "directory": "." }`.

## What BLA covers

| Format | Canary + diagnostic + exhaustion | Empirical vs real REA | Notes |
|--------|----------------------------------|------------------------|-------|
| JavaScript / TypeScript | ✓ | **verified** — real REA `resourceLimits` (alias/getter/primitive) + anti-strip | AST + semantic budgets |
| Electron ASAR | ✓ | **verified** — `DEFAULT_ASAR_MAX_HEADER_BYTES` | |
| WebAssembly | ✓ export decoys | **verified** — Wabt `WASM_INTERFACE_REPRESENTATION_BYTES` / partial | needs Wabt for REA path |
| Python `.py` / `.pyc` | ✓ | designed-for | `.py` AST weave + `.pyc` remmarshal `co_consts` CODE weave when `weave_decoys` |
| Native ELF (Go/Flutter/Electron fuses) | ✓ | **verified** — `MAX_BUILD_INFO_BYTES`, pool URIs/tokens, fuse sentinels | |
| SQLite | ✓ honey + trap columns | **verified** on Node 24 — `SqliteColumnEvaluationFailure`; Node 22 soft `capability_gated` | |
| Safetensors | ✓ nesting breaker | **verified** — `MODEL_JSON_NESTING` (HF-loadable) | |
| GGUF | ✓ | **verified** — `MODEL_METADATA_NESTING` | |
| Erlang BEAM | ✓ | **verified** — `max_chunks` | |
| EVM bytecode | ✓ | **verified** — `EVM_INTERFACE_LIMITS.inputBytes` | |
| PCAP | ✓ | **verified** — `TSHARK_JSON_MAX_BYTES` (needs tshark) | |
| GPU PTX | ✓ canary/exhaustion | soft — REA still `after=ok` | densifies but no hard budget trip |
| DEX / IL2CPP / bplist / .NET / JVM / ZIP / **Android R8+JNI** | ✓ | designed-for (R8/JNI new in 1.4.6) | signed APK refused (by design); unsigned APK gets mapping.txt + decoy JNI .so |
| Firmware UF2 | ✓ canary/exhaustion | designed-for — counters REA #8230 (not-main-flash / file-container decoys) | added in 1.6.2 |
| SPIR-V / CUDA / AMD GPU objects | — | **skipped** | no stable REA analyzer / not in scope yet |

**Designed-for but not empirically verified here** (need native tooling on the REA side): Ghidra, Frida, LLDB, Rizin, JADX.

## Empirical red-team headlines (`npm run redteam:rea`)

Commodity hardware, sibling REA, Node 24.22.1 + Wabt 1.0.42 + tshark:

| Format | Before → after | REA budget / error |
|--------|----------------|--------------------|
| Go buildinfo | 51 339 → 1 214 706 B | `MAX_BUILD_INFO_BYTES` |
| Flutter pool | same ELF plant | `MAX_POOL_URIS` / `MAX_POOL_TOKENS` |
| BEAM | 84 → 267 876 B | `max_chunks` |
| EVM | 16 → 4 190 208 B | `EVM_INTERFACE_LIMITS.inputBytes` |
| PCAP | 24 → 1 348 012 B | `TSHARK_JSON_MAX_BYTES` |
| Safetensors | 128 → 10 328 B | `MODEL_JSON_NESTING` |
| GGUF | 24 → 7 840 B | `MODEL_METADATA_NESTING` |
| ASAR | 607 → 17 752 989 B | `DEFAULT_ASAR_MAX_HEADER_BYTES` |
| WASM | 54 → 6 878 763 B | `WASM_INTERFACE_REPRESENTATION_BYTES` |
| SQLite (N24) | 12 288 → 57 344 B | `SqliteColumnEvaluationFailure` |
| Electron fuses | same ELF plant | `maximumSentinelsPerSlice` |
| JavaScript | 761 → 116 210 B | `alias-selections`+`getter-expansion`+`primitive-bytes`+`primitive-candidates` |
| GPU PTX | 91 → 26 424 B | still soft (`after=ok`) |

`npm run verify:rea` — catalog **drift harness only** (42 checks). Not protection proof.
`npm run redteam:rea` — **only** authoritative evidence (real in-process REA exceptions).

## Benchmark (internal estimates)

14-target Counter-REA showcase: **~612.5×** token amplification, **~292.2×** cost, **100%** runtime-equivalent. Numbers are **internal model estimates**, not empirical REA process measurements. Do not cite as red-team proof.

## Dogfood (local user journey)

Outside the repo, `npm pack` → install tarball → isolated `HOME`:

1. `npx bla-agents setup -y --client cursor` → APPLIED; skill default verb `bla_harden`
2. `bla harden .` → discovered **10** artifacts (dist/* + root `tools.py` / `local.sqlite`), hardened **10/10**, doctor **HEALTHY**
3. Hardened JS/WASM/SQLite/Safetensors/ELF/ASAR/Python remain valid and runtime-equivalent
4. MCP `tools/list` includes `bla_harden`; `tools/call bla_harden` succeeds

## Done this critique pass

- Anti-strip / realistic identifiers + CF entanglement (JS AST)
- Orders-of-magnitude tarpit scaling (not keyed to exact REA consts)
- `redteam:rea` as sole authoritative evidence; `verify:rea` demoted
- Honest docs separation verified / designed-for / skipped

## Nightly progress (2026-10-28 Asia/Shanghai)

- Pulled both repos. REA delta since last local tip: **325 commits** on `main`
  (dd7a2da5b → 0cd7ef456). Headline new analyzers: Android R8/ProGuard mapping
  (#7456), JNI native-declaration ↔ `.so` export linking (#7472), manifest
  component declarations (#7379). Most other delta is evidence/contract refactors.
- Shipped **v1.4.6** counter: `android-r8.ts` + unsigned-APK wiring + identity
  constants + `verify:rea` drift entries.

## Red-blue packaging gates (R1–R12 → 2.0)

Unified `bla lint` / MCP `bla_lint` (`bla-packaging-gates/v1`) aggregates every bankrupt refuse lint from red-blue rounds 1–7; R8–R12 SHA-256 KDF / commitment-outside-XOR / arity+export hygiene live as Skill recipes + WASM protect defaults. Honesty residual: full WASM RE + online/SMT — **not** a new refuse lint. Skill **v2.0.0**. Shipped as **bla-agents 2.0.0** (PR #77).

## Post-2.0 continuous hardening (2026-11-05)

CrackMe v8 red team (round-20261105): **NO PRIZE** — key/FLAG not recovered; `redteam:rea` **unverified** (REA dist absent). Last round's public-seed KP and `keySha256` oracle verified closed by harness. New exposure (empirical tamper matrix, not REA): entry `license.cjs` self-tamper was undetected although the coverage matrix claimed `license.cjs#siteN → license.cjs` (paper coverage). Fixed by canonical entry self-digest + `integrityCoverageSelfVerified` honesty downgrade. Residual: unhardened `seal.json` data sidecar not covered (not a prize — public `flagSha256` is the proof); bankrupt `plaintext-secret` lint flags BLA's own decoy literals (false positive, not exploitable). Shipped `challenge/v8` artifacts predate PRs #84–86 + this fix (rebuild needs release secrets).

## Nightly roadmap remaining

1. ~~**Self-seal / defenseScore honesty (#40)**~~ — landed soft-caps + opt-in `--self-seal` / MCP `self_seal` / `.blarc selfSeal` (batch 2026-11-02). Remaining: deeper onefile/peel score model.
2. **Sidecar entry entanglement** — DESIGN + `planSidecarEntanglement()` stub landed; self-seal entry self-digest (edit⇒fail on the entry itself) landed 2026-11-05; full strip⇒fail rewrite still open.
3. **Deception shields → more formats** — WASM export rename + `wasmPreserveExports` landed; DEX/SQLite/model densify and broader numeric template hygiene still open.
4. **Empirical JADX / Android red-team** — real REA mapping+JNI vs BLA-hardened unsigned APK.
5. **ESP flash / esp-image (#8228)** — if REA moved there; UF2 empirical red-team otherwise.
6. **Dependabot majors #29–#35** — still held pending review.
7. Polish doctor subsystem list (SQLite / models / BEAM / EVM / Android R8) for parity with shields.
8. **Lane-independence lint (#40.1)** — `bla lint-lanes` heuristic shipped; optional CI gate / doctor hook TBD.

## Publish checklist (once a GitHub token exists)

1. Confirm `package.json` version === `src/identity.ts` === `CHANGELOG` / `docs/releases/v1.4.0.md` (already 1.4.0)  
2. Final gate matrix on Node 22.23.4 **and** Node 24.22.1 (+ Wabt for redteam):  
   `npm run build && npm test && npm run benchmark && npm run verify:rea && npm run redteam:rea`  
3. Prefer Node **22.23.4** / **24.x** for REA (avoid `~/node22` 22.13.0 — lacks `zstdDecompressSync`)  
4. `git push origin main` (local commits are ahead; remotes currently untouched)  
5. `git tag v1.4.0 && git push origin v1.4.0`  
6. `npm publish` for `bla-agents` (and alias/`bla-shield` dual-pack flow if still used)  
7. GitHub Release from `docs/releases/v1.4.0.md`  
8. Smoke: `npx bla-agents@latest setup -y` + `bla harden .` on a fresh machine  

## Honesty red line

BLA is a **defensive** tool for protecting **your own** software. See [DISCLAIMER.md](DISCLAIMER.md). Do not overclaim: separate empirically verified commodity hits from designed-for / unverified native-tool paths and skipped formats.
