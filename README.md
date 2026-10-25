> **Evidence limits:** This is a research prototype. Audit/verify use local heuristics, not REA execution. Token, cost, and timing numbers are hypothetical estimates with fixed assumptions, not measurements. No LLM is run. Runtime checks cover only the explicitly listed synthetic samples; they do not establish general equivalence, zero overhead, or reconstruction resistance. Test copies with your own application before deployment.

<div align="center">

**English** · [简体中文](docs/readme/README_zh.md) · [繁體中文](docs/readme/README_zh-TW.md) · [日本語](docs/readme/README_ja.md) · [한국어](docs/readme/README_ko.md) · [Türkçe](docs/readme/README_tr.md) · [Русский](docs/readme/README_ru.md) · [Tiếng Việt](docs/readme/README_vi.md) · [ไทย](docs/readme/README_th.md) · [Deutsch](docs/readme/README_de.md) · [Español](docs/readme/README_es.md) · [Français](docs/readme/README_fr.md) · [Українська](docs/readme/README_uk.md) · [Polski](docs/readme/README_pl.md) · [Português (Brasil)](docs/readme/README_pt-BR.md) · [العربية](docs/readme/README_ar.md) · [فارسی](docs/readme/README_fa.md) · [Bahasa Indonesia](docs/readme/README_id.md) · [Italiano](docs/readme/README_it.md) · [Ελληνικά](docs/readme/README_el.md) · [മലയാളം](docs/readme/README_ml.md) · [Roman Urdu](docs/readme/README_ur-Latn.md) · [Română](docs/readme/README_ro.md)

# BLA: Blind LLM Agents

### One MCP for defending binaries, applications, and runtime behavior against AI reverse engineering.

**Ship a feature you built. Blind the agents trying to clone it, down to the binary level.**

[![npm version](https://img.shields.io/badge/npm-bla--shield-cb3837?style=flat-square&logo=npm)](https://www.npmjs.com/package/bla-shield)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/cli-and-mcp.md)
[![Node.js requirements](https://img.shields.io/badge/Node.js-22.13%2B%20%7C%2024%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#what-you-can-protect)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

[Quick start](#quick-start) · [How BLA works](#how-bla-works) · [What you can protect](#what-you-can-protect) · [Showcases](#showcases) · [FAQ](#faq) · [Documentation](#documentation)

<code>npx bla-shield setup</code>

</div>

> [!IMPORTANT]
> Get BLA from [qybaihe/bla](https://github.com/qybaihe/bla) or the [bla-shield npm package](https://www.npmjs.com/package/bla-shield).
> Follow the installation and release links from these official sources.

<div align="center">

<br />



<br />

</div>

---

Worried that someone will point [REA](https://github.com/morluto/rea) or a coding agent at your shipped product and clone your core logic in seconds? Ask your agent to harden it with BLA (`Poison → Exhaust → Hallucinate`). It audits your build without requiring source-code rewrites, shows what an attacking agent would recover, injects adversarial chaff and algorithmic tarpits, and reports local heuristic indicators for further evaluation.

BLA connects your agent to tools for protecting native binaries, JavaScript and Electron apps, WebAssembly modules, Python bytecode, SQLite databases, AI model files, and mobile packages. You can also run the same tools from your terminal or build bundler. Protection runs locally; runtime compatibility must be independently tested.

Setup registers BLA with your agent and installs matching workflow instructions. Every static, bytecode, and binary shield is built in—no commercial packer, external LLVM toolchain, or third-party obfuscator is required.

## Quick start

### Set up your agent

With Node.js and npm installed, run:

```bash
npx bla-shield setup
```

Choose your agents (or pass `--all-detected --yes`), review the proposed changes, and approve them. Setup registers BLA's MCP server and installs the `blind-llm-agents` skill, with backups of existing configuration. Restart your agent afterward.

Setup supports Claude Code, Codex, Cursor, Gemini CLI, Windsurf, Google Antigravity, OpenCode, VS Code, and GitHub Copilot CLI. See [installation and setup](docs/installation.md) for manual MCP registration.

### Ask your agent

Every defense stage can be triggered directly in natural language:

- **1. Audit exposure before shipping (`Pre-flight REA Audit`):**
  ```text
  Audit my ./dist directory against REA, show me every exposed module and IPC channel, and estimate how much it would cost Claude to reconstruct it.
  ```
- **2. Inject Counter-REA protection (`Poison + Exhaust + Hallucinate`):**
  ```text
  Protect ./dist/app.asar with BLA at bankrupt intensity, inject enclave chaff and algorithmic tarpits, and output to ./dist/app.shielded.asar.
  ```
- **3. Verify defense gates & token amplification (`Verify`):**
  ```text
  Verify ./dist/app.shielded.asar against the original ./dist/app.asar and report local indicators separately from unverified REA behavior.
  ```

### Use the terminal

Every workflow is available directly from your terminal with `npx bla-shield` (or `bla` when installed globally):

- **1. Audit a target (`audit`)** — inspect exposure score (`0–100`), exposed symbols, and estimated attacker clone cost:
  ```bash
  npx -y bla-shield@latest audit /absolute/path/to/app --json
  ```
- **2. Protect a target (`protect`)** — inject semantic budget breakers, tarpit state machines, enclave chaff, and runtime shields:
  ```bash
  npx -y bla-shield@latest protect /absolute/path/to/app -o /absolute/path/to/app.shielded --intensity bankrupt
  ```
- **3. Verify Counter-REA resistance (`verify`)** — inspect heuristic indicators and projected amplification; not an empirical pass:
  ```bash
  npx -y bla-shield@latest verify /absolute/path/to/app.shielded /absolute/path/to/app
  ```
- **4. Run the 8-target Counter-REA benchmark (`benchmark`)**:
  ```bash
  npx -y bla-shield@latest benchmark
  ```
- **5. Emit compile-time native headers (`emit-headers`)** for C/C++, Rust, or Go builds:
  ```bash
  npx -y bla-shield@latest emit-headers --lang c -o ./include/bla_shield.h
  ```

To install the `bla` command for regular use:

```bash
npm install --global bla-shield
bla --help
```

### Output path safety

Directory protection requires a **new output path outside the input tree**. Existing
output directories and in-place directory protection are rejected without deleting
or merging files. Symlink aliases in existing path components are resolved before
checking containment. File outputs that refer to the input (including symlinks or
hard links) require explicit `--in-place` / `inPlace: true`. These admission checks
assume no other process changes filesystem paths during protection; they are not a
filesystem sandbox.

### Use in your build bundler

Import `bla-shield/bundler` in Vite, Rollup, Webpack, or esbuild to automatically shield emitted JavaScript chunks, Honey Source Maps, and `.wasm` assets at build time:

```typescript
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-shield/bundler";

export default defineConfig({
  plugins: [blaVitePlugin({ intensity: "bankrupt", enableHoneySourceMaps: true })],
});
```

### Update BLA

For a CLI installed with `npm install --global` or `bun add --global`:

```bash
bla update
```

`bla --update` is an alias for this workflow. If you use `npx`, refresh your agent registrations and skill with:

```bash
npx bla-shield@latest setup
```

Review the setup changes and restart your agent. For one-off CLI commands, use `npx bla-shield@latest` (or `bunx bla-shield@latest`) followed by the command.

## How BLA works

Your agent calls BLA through MCP to inspect and transform artifacts. The following mechanisms describe intended effects, not verified outcomes against a pinned REA version or an actual agent:

1. **Poison (`Architectural Chaff & Honey Assets`):** Embeds benign hardware enclave delegation manifests (`SGX` / `TPM2` / `Secure Enclave`), VLQ v3 **Honey Source Maps** (`enclave://tee-runtime/`), honey WASM `"name"` sections, and honey SQLite tables across dead branches and constant pools.
2. **Exhaust (`Semantic Budget Breakers & Algorithmic Tarpits`):** Trips `morluto/rea`'s hardcoded analyzer caps (`primitive-candidates > 256`, `alias-selections > 512`, `getter-expansion > 512`, `primitive-bytes > 1 MiB`, `maximum_rustc_hashes > 64`, `maximumSentinelsPerSlice > 32`) at zero runtime cost, while weaving 14–36 interconnected Fake XRef state machines into the call graph.
3. **Hallucinate (`Anti-CDP Runtime Deception & Fuse Hardening`):** Hardens Electron V1 fuse wires in-place (`RunAsNode=0`, `EnableNodeCliInspectArguments=0`) and injects the "Truman Show" runtime guard that serves synthetic enclave attestation telemetry whenever CDP, Node Inspector, Frida, or WebDriver probes attach.

## What you can protect

BLA requires Node.js 22.x (22.13.0 or newer) or Node.js 24+ and npm. All shields run self-contained with zero external tool dependencies:

| Target                  | Transforms and intended effects (not measured REA outcomes)                                                                  | Command / prompt & requirements                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| JavaScript / TypeScript | Trips `primitive-candidates > 256`, `alias-selections > 512`, `getter-expansion > 512` + 36 tarpits | `bla protect app.js` · Built-in Babel AST engine; [Counter-REA matrix](.agents/skills/blind-llm-agents/references/counter-rea-matrix.md) |
| Electron `.asar` apps   | De-literalizes IPC channels (`channel: null`), adds duplicate decoy IPC handlers & shadow module  | `bla protect app.asar` · Built-in Chromium Pickle `.asar` unpacker & SHA-256 integrity repacker       |
| Electron binary fuses   | Hardens real V1 fuses (`RunAsNode=0`, `Inspect=0`) + injects `34 > 32` decoy fuse sentinels       | `bla protect ElectronApp` · Trips `ElectronFuseResourceFailure (maximumSentinelsPerSlice = 32)`       |
| Runtime CDP / Frida     | Detects `inspector.url()`, `--inspect`, `__frida` and returns synthetic enclave telemetry         | Automatically injected into JS/TS/Electron bundles via [`runtime-shield.ts`](src/shields/runtime/runtime-shield.ts) |
| Source maps & HTML      | Strips real maps; injects valid VLQ v3 Honey Source Maps (`enclave://tee-runtime/...`)            | `bla protect index.html` · Redirects REA `recover_javascript_sources` & `trace_web_source_location`   |
| Native binaries         | Appends `.bla.rodata` enclave chaff, decoy symbol table entries, and multi-scanner overflow traps | `bla protect daemon.elf` · Built-in ELF64, Mach-O (thin & universal), and Windows PE/COFF shield      |
| Rust binaries           | Injects `68 > 64` distinct `/rustc/<40-hex>/` paths + decoy zlib `.dep-v0` crate dependency graph | `bla protect rust-bin` · Trips `RustBinaryProvider` (`MAX_RUSTC_HASHES = 64` capacity failure)        |
| Go binaries             | Injects decoy Go `go1.23.4` buildinfo & `dep\tgithub.com/enclave-tees/sgx-bridge` module lines    | `bla protect go-bin` · Pollutes REA `inspect_go_binary` module inventory                              |
| Flutter / Dart AOT      | Injects `66 > 64` Dart snapshot magic headers (`0xf5f5dcdc`) + `6 > 4` LLVM toolchain lines       | `bla protect libapp.so` · Trips `SnapshotHashScanner (capped: true)` & `conflicting-dart-version`     |
| WASM artifacts          | Strips debug sections; injects honey `"name"` section (`tee_hardware_enclave_stub`) + custom chaff | `bla protect core.wasm` · Built-in LEB128 binary parser; validate your output independently        |
| Python & `.pyc`         | Injects Python tarpit state machines into `.py` & `TYPE_ASCII` marshal chaff into `.pyc` pools    | `bla protect module.pyc` · Built-in CPython 3.7–3.14 `.pyc` header & marshal framing shield           |
| SQLite databases        | Injects 3 enclave honey tables with `GENERATED ALWAYS AS (bla_enclave_unseal(...)) VIRTUAL` traps | `bla protect data.sqlite` · application compatibility must be tested independently |
| Model artifacts         | Safetensors metadata transformation; GGUF protection is disabled to prevent tensor data loss | `bla protect weights.gguf` fails without writing output; GGUF inspection remains available |
| Android DEX & APKs      | Injects `Lcom/enclave/sgx/...` decoy classes into `classes.dex` and recomputes SHA-1 & Adler32    | `bla protect classes.dex` or `app.apk` · Valid Dalvik/ART verification; pollutes JADX/JEB class trees |
| Unity IL2CPP metadata   | Appends enclave bridge metadata and method-topology tarpits to `global-metadata.dat` (`0xFAB11BAF`) | `bla protect global-metadata.dat` · Pollutes REA `inspect_il2cpp_metadata` type/method recovery       |
| C / C++ / Rust / Go src | Generates compile-time `bla_shield.h`, `bla_shield.rs`, or `bla_shield.go` with `used, noinline` tarpits | `bla emit-headers --lang c\|rust\|go` ·Compiles directly into Ghidra/Hopper/IDA decompiler views      |

## Showcases

`npx bla-shield benchmark` runs eight synthetic fixtures, not the real DX-Ball/Notion products or REA. All exposure, token, cost and time values are local heuristic projections. Fixed price assumptions are not current provider quotes.

| Fixture | Actual runtime check in this benchmark |
| :--- | :--- |
| DX-Ball-inspired JavaScript | Two `calculateSoundPan` input/output comparisons in a VM |
| Notion-inspired Electron ASAR | Not run |
| License validator | One successful license input; `valid` and `tier` compared |
| WebAssembly | V8 validation/instantiation and one `computeDigest` input/output comparison |
| ELF / SQLite / Safetensors / DEX | Not run; markers are not runtime checks |

Passing these samples does not prove equivalence for other inputs or production applications. The benchmark does not measure runtime overhead, invoke REA, or call an LLM. Unknown agent outcomes and overflow probabilities are reported as `NOT_MEASURED` and `null`.

`verify` reports `verificationStatus: "unverified"`, `functionalIntegrityStatus: "not-run"`, and `overallPassed: false` (CLI exit code 2). Local indicators remain available as `heuristicMatched` and `heuristicChecksPassed`; they are not empirical passes. Without an original artifact, amplification uses an explicitly labeled assumed baseline.

## FAQ

<details>
<summary><strong>Which agents can use BLA?</strong></summary>

Any coding agent that supports local MCP servers or `SKILL.md` workflows. `npx bla-shield setup` auto-configures Claude Code, Cursor, Codex, Gemini CLI, Windsurf, Google Antigravity, OpenCode, VS Code, and GitHub Copilot CLI. See [supported agents](docs/installation.md).

</details>

<details>
<summary><strong>Does BLA slow down my app or change its runtime output?</strong></summary>

Runtime compatibility and overhead are not generally verified. Three benchmark fixtures have bounded runtime checks; the other five have none. Validate your own application and performance on copies.

</details>

<details>
<summary><strong>How is BLA different from traditional obfuscators like javascript-obfuscator or O-LLVM?</strong></summary>

BLA explores format-specific transforms aimed at AI-assisted analysis. Its local estimates do not establish actual agent cost, failure, or superiority over other tools.

</details>

<details>
<summary><strong>Do I need Hopper, Ghidra, IDA, or WABT installed to protect my files?</strong></summary>

No. Implemented format shields (Babel AST, Chromium `.asar`, LEB128 `.wasm`, CPython `.pyc`, ELF/Mach-O/PE, SQLite3, `.safetensors`, and `.dex`/`Il2Cpp`) are built directly into `bla-shield` with zero external binary dependencies. GGUF protection is unsupported until tensor-preserving rewriting is implemented: the buffer API throws `UnsupportedGgufProtectionError`, the CLI exits with status 1, and MCP returns `isError: true`. No protected GGUF output is produced, and existing input/output files are left unchanged.

</details>

<details>
<summary><strong>What happens when someone runs REA against a BLA-protected app?</strong></summary>

Actual outcomes depend on the artifact, REA version, tools and agent strategy. This repository’s benchmark does not run REA or an LLM, so it cannot answer that empirically.

</details>

<details>
<summary><strong>What does installing the skill do?</strong></summary>

The [`blind-llm-agents` skill](.agents/skills/blind-llm-agents/SKILL.md) teaches your coding agent how to run pre-release Counter-REA audits, select the right protection intensity (`stealth`, `balanced`, `maximum`, `bankrupt`), integrate bundler plugins, and verify defense gates automatically.

</details>

<details>
<summary><strong>Does BLA upload my source code or binaries anywhere?</strong></summary>

Never. BLA audits, protects, and verifies all files 100% locally on your machine with deterministic seeded PRNG transforms (`--seed`) and zero network calls.

</details>

<details>
<summary><strong>What should I do if I hit a bug?</strong></summary>

Update first and run `bla doctor` to check engine readiness:

```bash
npx bla-shield@latest doctor
npx bla-shield@latest setup
```

If the issue persists, [open an issue](https://github.com/qybaihe/bla/issues) with your BLA version (`bla --version`), target format, and steps to reproduce.

</details>

## Documentation

- [Installation and agent setup](docs/installation.md): agent registration, bundler plugins, updates, and uninstall.
- [CLI and MCP contracts](docs/cli-and-mcp.md): commands, options, exit codes, and JSON-RPC 2.0 MCP tool schemas.
- [Counter-REA technical defense matrix](.agents/skills/blind-llm-agents/references/counter-rea-matrix.md): exact `morluto/rea` source limits and how BLA exploits them.

Report security issues through [SECURITY.md](SECURITY.md).

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use guidance.

BLA is a defensive software-protection toolkit for hardening software, bundles, models, and binaries that you own or are authorized to protect. All injected chaff payloads are strictly benign architectural metadata and synthetic decoy functions whose runtime compatibility requires independent testing.

## Contributing

Issues and pull requests are welcome at [qybaihe/bla](https://github.com/qybaihe/bla). Run `npm run build && npm test && node dist/cli.js benchmark` before submitting changes.

## License

[MIT](LICENSE)
