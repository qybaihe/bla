<div align="center">

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · **മലയാളം** · [Roman Urdu](README_ur-Latn.md) · [Română](README_ro.md)

# BLA: Blind LLM Agents

### AI റിവേഴ്സ് എഞ്ചിനീയറിംഗിൽ നിന്ന് ബൈനറികളെയും ആപ്ലിക്കേഷനുകളെയും സംരക്ഷിക്കുന്നതിനുള്ള ഏക MCP ഷീൽഡ്.

**നിങ്ങൾ നിർമ്മിച്ച ഫീച്ചർ സുരക്ഷിതമാക്കുക. അത് പകർത്താൻ ശ്രമിക്കുന്ന AI ഏജന്റുകളെ ബൈനറി തലത്തിൽ തടയുക.**

[![npm version](https://img.shields.io/badge/npm-bla--agents-2563eb?style=flat-square&logo=npm)](https://www.npmjs.com/package/bla-agents)
[![GitHub Trending](https://img.shields.io/badge/GitHub_Trending-%2315_Daily-0ea5e9?style=flat-square&logo=github&logoColor=white)](https://trendshift.io/repositories/323569)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-3b82f6?style=flat-square)](../cli-and-mcp.md)
[![Node.js requirements](https://img.shields.io/badge/Node.js-%5E22.13_%7C%7C_%3E%3D24-0284c7?style=flat-square&logo=nodedotjs&logoColor=white)](#what-you-can-protect)
[![Counter-REA Verified](https://img.shields.io/badge/Counter--REA-BLUE_SHIELD-1d4ed8?style=flat-square)](#showcases)
[![MIT license](https://img.shields.io/badge/license-MIT-38bdf8?style=flat-square)](../../LICENSE)

[വേഗത്തിൽ തുടങ്ങാം](#quick-start) · [BLA എങ്ങനെ പ്രവർത്തിക്കുന്നു](#how-bla-works) · [എന്തൊക്കെ സംരക്ഷിക്കാം](#what-you-can-protect) · [ഷോകേസുകളും ബെഞ്ച്മാർക്കുകളും](#showcases) · [പതിവ് ചോദ്യങ്ങൾ (FAQ)](#faq) · [ഡോക്യുമെന്റേഷൻ](#documentation)

<code>npx bla-agents setup</code> · <code>npx bla-agents defend ./dist --manifest</code>

</div>

> [!IMPORTANT]
> Get BLA from [qybaihe/bla](https://github.com/qybaihe/bla) or the [bla-agents npm package](https://www.npmjs.com/package/bla-agents).

<div align="center">

<br />

<img src="../assets/bla-vs-rea-showcase.svg" alt="Before BLA vs After npx bla-agents protect" width="1200" />

<br />

</div>

---

REA ഉപയോഗിച്ച് നിങ്ങളുടെ ആപ്പ് നിമിഷങ്ങൾക്കുള്ളിൽ ക്ലോൺ ചെയ്യപ്പെടുമെന്ന് ആശങ്കയുണ്ടോ? BLA (`Poison → Exhaust → Hallucinate`) ഉപയോഗിച്ച് ബിൽഡ് സുരക്ഷിതമാക്കാൻ നിങ്ങളുടെ ഏജന്റിനോട് ആവശ്യപ്പെടുക.

നേറ്റീവ് ബൈനറികൾ, JavaScript/Electron ആപ്പുകൾ, WebAssembly, Python ബൈറ്റ്കോഡ്, SQLite ഡാറ്റാബേസുകൾ, AI മോഡലുകൾ എന്നിവ 100% റൺടൈം കൃത്യതയോടെ പ്രാദേശികമായി സംരക്ഷിക്കാൻ BLA സഹായിക്കുന്നു.

<a id="quick-start"></a>

## വേഗത്തിൽ തുടങ്ങാം

### ഏജന്റ് സജ്ജമാക്കുക

```bash
npx bla-agents setup
```

### ഏജന്റിനോട് ആവശ്യപ്പെടുക

- **1. Audit (`Pre-flight REA Audit`):**
  ```text
  Audit my ./dist directory against REA, show me every exposed module and IPC channel, and estimate how much it would cost Claude to reconstruct it.
  ```
- **2. Protect (`Poison + Exhaust + Hallucinate`):**
  ```text
  Protect ./dist/app.asar with BLA at bankrupt intensity, inject enclave chaff and algorithmic tarpits, and output to ./dist/app.shielded.asar.
  ```
- **3. Verify (`Verify Defense & Token Burn`):**
  ```text
  Verify ./dist/app.shielded.asar against the original ./dist/app.asar and confirm that REA's examination degrades to limited status.
  ```

### ടെർമിനൽ ഉപയോഗിക്കുക

```bash
# 1. Audit exposure
npx -y bla-agents@latest audit /absolute/path/to/app --json

# 2. Protect artifact
npx -y bla-agents@latest protect /absolute/path/to/app -o /absolute/path/to/app.shielded --intensity bankrupt

# 3. Verify Counter-REA resistance
npx -y bla-agents@latest verify /absolute/path/to/app.shielded /absolute/path/to/app

# 4. Run 8-target Counter-REA benchmark
npx -y bla-agents@latest benchmark

# 5. Emit compile-time C/C++, Rust, or Go defense headers
npx -y bla-agents@latest emit-headers --lang c -o ./include/bla_shield.h

# Install globally
npm install --global bla-agents
bla --help
```

### ബണ്ട്ലറിൽ ഉപയോഗിക്കുക

```typescript
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-agents/bundler";

export default defineConfig({
  plugins: [blaVitePlugin({ intensity: "bankrupt", enableHoneySourceMaps: true })],
});
```

### BLA അപ്ഡേറ്റ് ചെയ്യുക

```bash
bla update
npx bla-agents@latest setup
```

<a id="how-bla-works"></a>

## BLA എങ്ങനെ പ്രവർത്തിക്കുന്നു

1. **Poison (`Architectural Chaff & Honey Assets`):** Embeds hardware enclave delegation manifests (`SGX` / `TPM2` / `Secure Enclave`), VLQ v3 Honey Source Maps (`enclave://tee-runtime/`), honey WASM `"name"` sections, and honey SQLite tables.
2. **Exhaust (`Semantic Budget Breakers & Algorithmic Tarpits`):** Trips `REA`'s internal analyzer limits (`primitive-candidates > 256`, `alias-selections > 512`, `getter-expansion > 512`, `primitive-bytes > 1 MiB`, `maximum_rustc_hashes > 64`, `maximumSentinelsPerSlice > 32`) and weaves 14–36 Fake XRef state machines.
3. **Hallucinate (`Anti-CDP Runtime Deception & Fuse Hardening`):** Hardens Electron V1 fuse wires (`RunAsNode=0`, `EnableNodeCliInspectArguments=0`) and serves synthetic enclave telemetry to CDP/Inspector/Frida probes.

<a id="what-you-can-protect"></a>

## എന്തൊക്കെ സംരക്ഷിക്കാം

| Target                  | What BLA injects & how REA fails                                                                  | Command / prompt & requirements                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| JavaScript / TypeScript | Trips `primitive-candidates > 256`, `alias-selections > 512`, `getter-expansion > 512` + 36 tarpits | `bla protect app.js` · Built-in Babel AST engine                                                    |
| Electron `.asar` apps   | De-literalizes IPC channels (`channel: null`), adds duplicate decoy IPC handlers & shadow module  | `bla protect app.asar` · Built-in Chromium Pickle `.asar` unpacker & SHA-256 repacker               |
| Electron binary fuses   | Hardens real V1 fuses (`RunAsNode=0`, `Inspect=0`) + injects `34 > 32` decoy fuse sentinels       | `bla protect ElectronApp` · Trips `ElectronFuseResourceFailure (maximumSentinelsPerSlice = 32)`       |
| Native / Rust / Go      | Injects `68 > 64` `/rustc/<40-hex>/` paths, decoy `.dep-v0` crate graph & Go `dep\t` lines        | `bla protect daemon.elf` · Built-in ELF64, Mach-O, and PE/COFF shield                               |
| Flutter / Dart AOT      | Injects `66 > 64` Dart snapshot headers (`0xf5f5dcdc`) + `6 > 4` LLVM toolchain lines             | `bla protect libapp.so` · Trips `SnapshotHashScanner (capped: true)`                                |
| WASM artifacts          | Strips debug sections; injects honey `"name"` section (`tee_hardware_enclave_stub`) + custom chaff | `bla protect core.wasm` · Built-in LEB128 binary parser; 100% `WebAssembly.validate`                |
| Python & `.pyc`         | Injects Python tarpit state machines into `.py` & `TYPE_ASCII` marshal chaff into `.pyc` pools    | `bla protect module.pyc` · Built-in CPython 3.7–3.14 `.pyc` marshal shield                         |
| SQLite databases        | Injects 3 enclave honey tables with `GENERATED ALWAYS AS (bla_enclave_unseal(...)) VIRTUAL` traps | `bla protect data.sqlite` · Trips `SqliteColumnEvaluationFailure` on REA preview                    |
| Model artifacts         | Injects `35 > 32` nested JSON/ARRAY headers into `.safetensors` and `.gguf` model headers         | `bla protect weights.safetensors` · Trips `ModelFormatFailure (json-nesting / metadata-nesting > 32)` |
| Android DEX & IL2CPP    | Injects `Lcom/enclave/sgx/...` decoy classes into `classes.dex` (valid SHA-1/Adler32) & `Il2Cpp` | `bla protect classes.dex` or `global-metadata.dat` · Pollutes JADX/JEB & IL2CPP recovery           |

<a id="showcases"></a>

## ഷോകേസുകളും ബെഞ്ച്മാർക്കുകളും

| Showcase Target | Before BLA (REA Alone) | After `npx bla-agents protect` | Token Burn | Runtime Check |
| :--- | :--- | :--- | :---: | :---: |
| **1. DX-Ball Sound-Pan Calculation** (`.js`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,068` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% Exact |
| **2. Notion Electron Clipboard Bridge** (`.asar`) | `98/100` · `9,132` tok · **`$0.34`** (`COMPLETE`) | `2/100` · `23,125,000` tok · **`$358.28`** (`LIMITED`) | **2,532.3x** | ✅ 100% Exact |
| **3. Enterprise Offline License Validator** (`.ts`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,169` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% Exact |
| **4. WebAssembly Crypto Kernel** (`.wasm`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,067` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% Exact |
| **5. Native ELF64 Binary** (Rust / Go / Fuse / Dart) | `81/100` · `9,278` tok · **`$0.35`** (`COMPLETE`) | `2/100` · `3,698,135` tok · **`$59.72`** (`LIMITED`) | **398.6x** | ✅ 100% Exact |
| **6. Local SQLite Entitlement Database** (`.sqlite`) | `81/100` · `10,568` tok · **`$0.29`** (`COMPLETE`) | `7/100` · `1,711,235` tok · **`$28.36`** (`LIMITED`) | **161.9x** | ✅ 100% Exact |
| **7. Proprietary Edge AI Weights** (`.safetensors`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,073` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% Exact |
| **8. Android Dalvik Bytecode** (`classes.dex`) | `81/100` · `8,900` tok · **`$0.34`** (`COMPLETE`) | `7/100` · `2,786,285` tok · **`$45.09`** (`LIMITED`) | **313.1x** | ✅ 100% Exact |

<a id="faq"></a>

## പതിവ് ചോദ്യങ്ങൾ (FAQ)

<details>
<summary><strong>Which agents can use BLA?</strong></summary>

Any agent that supports local MCP servers or `SKILL.md` workflows (Claude Code, Cursor, Codex, Gemini CLI, Windsurf, Google Antigravity, OpenCode, VS Code, and GitHub Copilot CLI). Run `npx bla-agents setup`.

</details>

<details>
<summary><strong>Does BLA slow down my app or change its runtime output?</strong></summary>

No. All semantic budget breakers and tarpits are guarded by $O(1)$ number-theoretic opaque predicates ($7x^2 - 1 \neq y^2 \pmod 7$) and preserve 100% input/output equivalence.

</details>

<details>
<summary><strong>Do I need Hopper, Ghidra, IDA, or WABT installed?</strong></summary>

No. All 19 format shields are built directly into `bla-agents` with zero external dependencies.

</details>

<details>
<summary><strong>Does BLA upload my source code or binaries anywhere?</strong></summary>

Never. All operations run 100% locally on your machine.

</details>

<a id="documentation"></a>

## ഡോക്യുമെന്റേഷൻ

- [Installation and agent setup](../installation.md)
- [CLI and MCP contracts](../cli-and-mcp.md)
- [Counter-REA technical defense matrix](../../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md)
- [Disclaimer](../../DISCLAIMER.md) · [MIT License](../../LICENSE)
