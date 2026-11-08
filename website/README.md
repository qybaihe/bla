# `bla-site` — Official Website for BLA (`bla.tools`)

Official website and interactive Counter-REA defense labs for **[BLA: Blind LLM Agents (`bla-agents`)](https://github.com/qybaihe/bla)**.

## Pages & Interactive Labs

- `/` ([`index.html`](./index.html)):
  - **Tactical HUD & Instant Setup Card** (One-click copy prompts for Claude Code, Cursor, Codex, and Antigravity + `npx bla-agents@latest setup`).
  - **Interactive 3-Step REA Analyzer Tripwire Inspector** (`01 · JS/Electron Semantic & IPC Breaker`, `02 · Rust/Fuse/Dart Binary Trap`, `03 · SQLite Virtual Column & AI Model Bomb`).
  - **Interactive Lab 01 — Playable 60 FPS Dinosaur Shield Lab**: Direct counterpart to `rea.tools`'s Chrome Dinosaur demo. Toggle **BLA Shield ON / OFF** in real time to see the game run at 60 FPS (`0ms` overhead) while the attacking REA agent terminal drowns in 10.1M tokens of enclave chaff.
  - **Interactive Lab 02 — Token Bankruptcy Calculator**: Select any of the 8 target formats, BLA intensity (`stealth`, `balanced`, `maximum`, `bankrupt`), and attacker LLM (`Claude Opus 4`, `OpenAI o3`, `Claude Sonnet 4`).
  - **Instant Bilingual Switcher (`English` / `简体中文`)** & **Dark / Light Theme Switcher**.
- `/get-started/` ([`get-started/index.html`](./get-started/index.html)): Step-by-step agent registration, stage-by-stage natural-language prompts, CLI reference, and Vite/Webpack/Rollup/esbuild bundler integration.
- `/showcase/` ([`showcase/index.html`](./showcase/index.html)): 8-target Counter-REA benchmark suite and deep-dive case studies (Notion Electron IPC, DX-Ball Sound-Pan, Native ELF64 / SQLite3 / Safetensors).
- `/guides/` ([`guides/index.html`](./guides/index.html)): Format-by-format defense workflows across all 19 supported artifact types.
- `/faq/` ([`faq/index.html`](./faq/index.html)): Frequently asked questions and troubleshooting (`bla doctor`, `bla update`).
- `/enterprise/` ([`enterprise/index.html`](./enterprise/index.html)): Enterprise hardening engagement — assess, custom harden, verify; public contact `qybaihe@gmail.com`; pricing confirmed by email.

## Binding Custom Domain (`bla.tools`)

1. In your DNS provider for `bla.tools`, add:
   - `CNAME` record for `www` $\rightarrow$ `qybaihe.github.io`
   - `A` records for `@` (`bla.tools`) $\rightarrow$ `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
2. In **GitHub $\rightarrow$ `qybaihe/bla-site` $\rightarrow$ Settings $\rightarrow$ Pages $\rightarrow$ Custom domain**, enter `bla.tools` and check **Enforce HTTPS**.
   (Or run: `gh api -X PUT repos/qybaihe/bla-site/pages -f cname="bla.tools"`)
