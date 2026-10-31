<div align="center">

**English** · [简体中文](docs/readme/README_zh.md) · [繁體中文](docs/readme/README_zh-TW.md) · [日本語](docs/readme/README_ja.md) · [한국어](docs/readme/README_ko.md) · [Türkçe](docs/readme/README_tr.md) · [Русский](docs/readme/README_ru.md) · [Tiếng Việt](docs/readme/README_vi.md) · [ไทย](docs/readme/README_th.md) · [Deutsch](docs/readme/README_de.md) · [Español](docs/readme/README_es.md) · [Français](docs/readme/README_fr.md) · [Українська](docs/readme/README_uk.md) · [Polski](docs/readme/README_pl.md) · [Português (Brasil)](docs/readme/README_pt-BR.md) · [العربية](docs/readme/README_ar.md) · [فارسی](docs/readme/README_fa.md) · [Bahasa Indonesia](docs/readme/README_id.md) · [Italiano](docs/readme/README_it.md) · [Ελληνικά](docs/readme/README_el.md) · [മലയാളം](docs/readme/README_ml.md) · [Roman Urdu](docs/readme/README_ur-Latn.md) · [Română](docs/readme/README_ro.md)

# <img src="docs/assets/logo.png" alt="BLA Shield" width="42" align="absmiddle" /> BLA: Blind LLM Agents

### Make reverse engineering bankrupt again.

**Point BLA at the build you ship. When an AI reverse-engineering agent (REA) opens it, the analyzer hits resource budgets, follows decoys, and burns tokens — while your users still get the same runtime behavior.**

[![npm version](https://img.shields.io/badge/npm-bla--agents-2563eb?style=flat-square&logo=npm)](https://www.npmjs.com/package/bla-agents)
[![GitHub Trending](https://img.shields.io/badge/GitHub_Trending-%2315_Daily-0ea5e9?style=flat-square&logo=github&logoColor=white)](https://trendshift.io/repositories/323569)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-3b82f6?style=flat-square)](docs/cli-and-mcp.md)
[![Node.js](https://img.shields.io/badge/Node.js-%5E22.23.4_%7C%7C_24.x-0284c7?style=flat-square&logo=nodedotjs&logoColor=white)](#format-coverage)
[![Counter-REA](https://img.shields.io/badge/Counter--REA-empirically_measured-1d4ed8?style=flat-square)](#empirical-results-vs-real-rea)
[![MIT license](https://img.shields.io/badge/license-MIT-38bdf8?style=flat-square)](LICENSE)

**[Website](https://bla.tools/) · [Guides](https://bla.tools/guides/) · [Showcases](https://bla.tools/showcase/) · [Disclaimer](DISCLAIMER.md)**

[Quick start](#quick-start) · [Empirical results](#empirical-results-vs-real-rea) · [Format coverage](#format-coverage) · [Benchmark](#benchmark-14-targets-internal-estimates) · [FAQ](#faq)

```bash
bla harden .
# or tell your agent: "Harden my software against REA"
```

</div>

> [!IMPORTANT]
> BLA is a **defensive** tool for protecting **your own** software. See [DISCLAIMER.md](DISCLAIMER.md).
> Get BLA from [qybaihe/bla](https://github.com/qybaihe/bla) or [npm `bla-agents`](https://www.npmjs.com/package/bla-agents).

<div align="center">
<img src="docs/assets/bla-vs-rea-showcase.svg" alt="Side-by-side: REA on an unprotected artifact vs BLA-protected output" width="1200" />
</div>

---

## What BLA does

REA reverse-engineers release artifacts in one command. BLA is the Counter-REA half of that story:

| Layer | What happens |
| --- | --- |
| **Poison** | Plant format-valid canaries, honey metadata, and decoy control flow that look like real evidence. |
| **Exhaust** | Push the artifact past REA's documented resource budgets (headers, nesting, interface inventories, PCAP JSON, fuse sentinels, …). |
| **Hallucinate** | Leave the analyzer with truncated inventories, redaction failures, and ambiguous rabbit holes — while **runtime stays equivalent**. |

One sentence covers the common case (auto-discovers `dist/` / `build/` / `.asar` / `.wasm` / `.sqlite` / models / … and runs audit → protect → verify):

```bash
npx bla-agents harden .
# MCP / agent: bla_harden   ·   "Harden my software against REA"
```

Same pipeline as `bla defend` / `bla_defend` when you already know the path; `harden` is the default one-command UX.

## Quick start

```bash
# Node.js ^22.23.4 or 24.x recommended (REA red-team needs zlib.zstd on 22.23+)
npx bla-agents setup          # register MCP + skill with your coding agent
npx bla-agents harden .       # one-command Counter-REA pass on the current project
npx bla-agents benchmark      # 14-target showcase (local estimates + runtime checks)
```

Ask your agent after setup:

```text
Harden my software against REA
```

Or run stages explicitly: `audit` · `protect` · `verify` · `defend` — see [CLI and MCP](docs/cli-and-mcp.md).

---

## Empirical results vs real REA

These numbers come from running **real REA** against BLA-hardened samples on commodity hardware (`npm run redteam:rea`). Full machine-readable report: [`docs/redteam/empirical-rea-validation.md`](docs/redteam/empirical-rea-validation.md) / [`.json`](docs/redteam/empirical-rea-validation.json).

**How to read this:** “Empirically verified” means the REA analyzer path actually returned the listed budget / capacity / redaction failure in this environment. It is **not** a claim about Ghidra/Frida/LLDB/Rizin/JADX sessions we did not run here.

### Empirically verified on commodity hardware

Recorded under **Node v24.22.1** with optional **Wabt 1.0.42** + **tshark 4.4** when noted. Soft-skips keep Node 22 / CI green when tooling is absent.

| Format | Before → after | REA outcome after BLA | Budget / error |
| --- | ---: | --- | --- |
| **Go buildinfo** | 50 KiB → 1.16 MiB | capacity error | `MAX_BUILD_INFO_BYTES` (1 MiB) — *Go build-info string length exceeds the 1 MiB limit* |
| **Erlang BEAM** | 84 B → 262 KiB | capacity error | `max_chunks` — *BEAM form exceeds the 64-chunk budget* |
| **EVM bytecode** | 16 B → **4.00 MiB** | approaches full input cap | `EVM_INTERFACE_LIMITS.inputBytes` (4 MiB) |
| **PCAP** | 24 B → 1.29 MiB | budget rejected | `TSHARK_JSON_MAX_BYTES` (>8 MiB) → `AnalysisResourceConstraintError` (tshark present) |
| **Electron ASAR** | 607 B → **16.9 MiB** | capacity error | `DEFAULT_ASAR_MAX_HEADER_BYTES` (16 MiB) |
| **WASM + Wabt** | 54 B → **6.56 MiB** · 251 exports | `ifaceState=partial` | `WASM_INTERFACE_REPRESENTATION_BYTES` — *Typed WASM interface decoding exceeds the WABT output representation budget* |
| **SQLite** (Node 24) | 12 KiB → 56 KiB | redaction / column eval | `SqliteColumnEvaluationFailure` — unknown `enclave_unseal_payload()` on honey trap columns |
| **JavaScript** | 761 B → 116 KiB | budget rejected | `alias-selections` + `getter-expansion` + `primitive-bytes` + `primitive-candidates` (real REA `resourceLimits`) |
| **Safetensors** | 128 B → 10.1 KiB | capacity error | `MODEL_JSON_NESTING` — *Safetensors JSON nesting exceeds 32 levels* (HF-loadable; tensor bytes unchanged) |
| **GGUF** | 24 B → 7.7 KiB | capacity error | `MODEL_METADATA_NESTING` — *GGUF metadata nesting exceeds 32 array frames* |
| **Electron fuses** | 50 KiB → 1.16 MiB | budget rejected | `ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice` (>32) |
| **Flutter pool** | 50 KiB → 1.16 MiB | projected cap | `MAX_POOL_URIS` / `MAX_POOL_TOKENS` (REA would truncate with “at least N”) |

Reproduce:

```bash
# Prefer Node 22.23.4+ or 24.x; set Wabt/tshark for full coverage
export REA_WABT_BIN_DIRECTORY=$HOME/opt/wabt-1.0.42/bin   # optional
npm run build && npm run redteam:rea
```

### Designed-for but **not** empirically verified here

These shields exist in-tree and are covered by unit tests / catalog drift checks, but the matching REA path needs **native tooling we did not run** on this box:

| Area | Why unverified here |
| --- | --- |
| Ghidra / native decompilation depth | Requires a Ghidra install + REA bridge |
| Frida / LLDB / GDB / Rizin live sessions | Requires those debuggers + device/process attach |
| JADX / full Android APK pipeline | APK resigning unsupported; DEX shield is in-tree |
| **Firmware** containers | Skipped — staging/extraction budgets exist; no honest E2E without firmware corpora |
| **SPIR-V / CUDA fatbinary / AMD GPU objects** | Skipped — need native GPU object decoders; **PTX text** is shielded in-tree (benchmark only, not a REA GPU-object budget hit) |
| EVMole in-process EVM decode | Documented as not pathable in-process; EVM shield still densifies to the 4 MiB input approach |

We do **not** claim those paths are empirically bankrupt until `redteam:rea` (or an equivalent harness) records a real before/after against the live analyzer.

---

## Format coverage

| Format | Canary + diagnostic | Exhaustion / budget trip | Empirically vs REA | Notes |
| --- | :---: | :---: | :---: | --- |
| JavaScript / TypeScript | ✓ | ✓ semantic budgets | **verified** (in-process) | Babel AST; anti-strip; real REA resourceLimits |
| Electron `.asar` | ✓ | ✓ header 16 MiB | **verified** | |
| Electron fuses | ✓ | ✓ >32 sentinels | **verified** | |
| WASM | ✓ custom sections | ✓ export-name decoys → Wabt | **verified** (Wabt) | Soft-skips to projected budget without Wabt |
| Python / `.pyc` | ✓ | ✓ | designed-for | |
| SQLite | ✓ honey + trap cols | ✓ column eval | **verified** (Node 24) | Soft `capability_gated` on Node 22 |
| Safetensors | ✓ string metadata | ✓ JSON nesting >32 | **verified** | HF-loadable; tensor bytes preserved |
| GGUF | ✓ | ✓ ARRAY nesting >32 | **verified** | |
| Go buildinfo | ✓ | ✓ >1 MiB | **verified** | Mapped ELF section |
| Flutter / Dart pool | ✓ | ✓ URI/token caps | **verified** (projected) | |
| Erlang BEAM | ✓ | ✓ chunks / atoms | **verified** | |
| EVM + Solidity meta | ✓ | ✓ → 4 MiB input | **verified** (approach) | |
| PCAP | ✓ | ✓ tshark JSON >8 MiB | **verified** (tshark) | Soft-skip without tshark |
| NVIDIA PTX (text) | ✓ | entry flood | benchmark only | Not a REA GPU-object budget |
| DEX / IL2CPP / bplist / .NET / JVM / ZIP | ✓ | format-specific | designed-for | APK signing-aware protect unsupported |
| Firmware / SPIR-V / CUDA fatbin / AMD GPU | — | — | **skipped** | See matrix above |

---

## Benchmark (14 targets, internal estimates)

`npx bla-agents benchmark` runs a **local Counter-REA showcase**: exposure scores, **estimated** token/cost multipliers, and **measured** runtime equivalence. Token/$ columns are **internal estimates** derived from BLA's catalog of REA limits — they are **not** the same as the empirical REA process measurements above (those are byte-level analyzer failures with real error strings). `npm run verify:rea` is a **constant-drift harness only** and must never be cited as protection evidence; the only authoritative gate is `npm run redteam:rea`.

Latest local run (bla-agents **v1.4.0**): aggregate **~612.5×** tokens · **~292.2×** cost · **14/14** runtime-exact.

| Target | Unprotected (est.) | Protected (est.) | Token mult (est.) | Runtime |
| --- | --- | --- | ---: | :---: |
| DX-Ball sound-pan (`.js`) | 84/100 · 4,800 tok · $0.20 | 2/100 · 13.5M tok · $212.82 · LIMITED | **2822.7×** | 100% |
| Notion Electron clipboard (`.asar`) | 98/100 · 9,132 tok · $0.34 | 2/100 · 23.1M tok · $358.28 · LIMITED | **2532.3×** | 100% |
| Enterprise license validator | 84/100 · 4,800 tok · $0.20 | 2/100 · 13.5M tok · $212.82 · LIMITED | **2822.7×** | 100% |
| WASM crypto kernel | 81/100 · 4,800 tok · $0.20 | 6/100 · 1.83M tok · $30.23 · LIMITED | **381.5×** | 100% |
| Native ELF64 (Rust/Go/Fuse/Dart) | 81/100 · 35,222 tok · $0.73 | 2/100 · 3.72M tok · $60.03 · LIMITED | **105.6×** | 100% |
| SQLite entitlement DB | 81/100 · 10,568 tok · $0.29 | 7/100 · 1.71M tok · $28.39 · LIMITED | **162.1×** | 100% |
| Edge AI Safetensors | 81/100 · 4,800 tok · $0.20 | 6/100 · 1.81M tok · $29.90 · LIMITED | **376.8×** | 100% |
| Android DEX | 81/100 · 8,900 tok · $0.34 | 7/100 · 2.79M tok · $45.11 · LIMITED | **313.2×** | 100% |
| Apple bplist | 81/100 · 6,440 tok · $0.26 | 9/100 · 1.36M tok · $22.96 · LIMITED | **211.8×** | 100% |
| .NET managed DLL | 81/100 · 8,900 tok · $0.34 | 6/100 · 2.45M tok · $39.96 · LIMITED | **274.8×** | 100% |
| Erlang BEAM | 81/100 · 8,900 tok · $0.34 | 5/100 · 3.86M tok · $62.08 · LIMITED | **433.2×** | 100% |
| EVM Solidity metadata | 81/100 · 6,440 tok · $0.26 | 6/100 · 1.78M tok · $29.40 · LIMITED | **276.3×** | 100% |
| libpcap capture | 81/100 · 4,800 tok · $0.20 | 8/100 · 1.60M tok · $26.58 · LIMITED | **333.2×** | 100% |
| NVIDIA PTX text | 81/100 · 4,800 tok · $0.20 | 6/100 · 2.40M tok · $39.29 · LIMITED | **500.2×** | 100% |

---

## How BLA works

1. **Exhaustion** — trip documented REA caps (`primitive-candidates`, ASAR header bytes, WASM interface representation, SQLite column evaluation, model JSON/ARRAY nesting, Go buildinfo, BEAM chunks, PCAP tshark JSON, fuse sentinels, …).
2. **Deception** — canary credentials + system-diagnostic rabbit holes across Python/WASM/SQLite/models/DEX/IL2CPP/bplist/.NET/JVM/ZIP; decoy IPC / enclave manifests / VLQ maps.
3. **Runtime guard** — Electron V1 fuse hardening; CDP/Frida/inspector detection returns synthetic telemetry during inspection sessions.

Protections are format-native (no commercial packer / external LLVM required). Red line: **never break protected program behavior, export surface, binary/section integrity, or format validity.**

---

## FAQ

<details>
<summary><strong>Which agents can use BLA?</strong></summary>

Any coding agent with local MCP or `SKILL.md` workflows. `npx bla-agents setup` configures Claude Code, Cursor, Codex, Gemini CLI, Windsurf, Google Antigravity, OpenCode, VS Code, and GitHub Copilot CLI.
</details>

<details>
<summary><strong>Does BLA change runtime output?</strong></summary>

No on the hot path. Budget guards sit behind $O(1)$ opaque predicates. Every benchmark target checks 100% input/output equivalence against the unprotected build.
</details>

<details>
<summary><strong>Do I need Ghidra, Hopper, IDA, or Wabt to protect files?</strong></summary>

No. Shields are built into `bla-agents`. Wabt/tshark/Node 24 are optional — they unlock **empirical** red-team probes (`npm run redteam:rea`), not protection itself.
</details>

<details>
<summary><strong>Is BLA for attacking other people's software?</strong></summary>

No. See [DISCLAIMER.md](DISCLAIMER.md). Protective payloads activate under reverse-engineering inspection of artifacts **you** hardened.
</details>

## Documentation

- [DISCLAIMER.md](DISCLAIMER.md) — defensive use, own-software only
- [Installation and agent setup](docs/installation.md)
- [CLI and MCP contracts](docs/cli-and-mcp.md)
- [Empirical REA validation](docs/redteam/empirical-rea-validation.md)
- [Counter-REA matrix](.agents/skills/blind-llm-agents/references/counter-rea-matrix.md)
- [v1.4.0 release notes (staged)](docs/releases/v1.4.0.md)
- [CHANGELOG](CHANGELOG.md)

Report security issues through [SECURITY.md](SECURITY.md).

## Contributing

Issues and PRs welcome at [qybaihe/bla](https://github.com/qybaihe/bla). Before submitting:

```bash
export PATH=$HOME/node22.23.4/bin:$PATH   # or node24
npm run build && npm test && node dist/cli.js benchmark
npm run redteam:rea                        # authoritative (real REA)
# npm run verify:rea                       # drift harness only — NOT protection proof
```

## Community / 友情社区

- 🎯 **[Public BLA CrackMe Challenge (`challenge/`)](challenge/README.md)** — Can your AI reverse-engineering agent beat a `bankrupt`-hardened BLA binary without falling into our Honeypot Flags?
- [LINUX DO (`linux.do`)](https://linux.do/) — 新的理想型社区

## License

[MIT](LICENSE)
