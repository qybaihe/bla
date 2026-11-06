# AGENTS.md — Repository Guide for Coding Agents

This repository contains **BLA (`bla-agents` — Blind LLM Agents)**, an open-source adversarial Blue Defense toolkit engineered to protect software artifacts against AI reverse-engineering agents (specifically `morluto/rea`).

## Project Layout

- `src/identity.ts`: Product metadata (`bla-agents`) and exact `REA_INTERNAL_LIMITS` constants.
- `src/core/`:
  - `types.ts`: Domain interfaces (`AuditReport`, `ProtectionResult`, `VerificationReport`, `BenchmarkReport`).
  - `detector.ts`: Magic-byte and file-extension format detection across 19 artifact types (including JS/TS, `.asar`, `.wasm`, `.py`/`.pyc`, ELF/Mach-O/PE, `.sqlite`, `.safetensors`, `.gguf`, `.dex`, and `Il2Cpp` metadata).
  - `sqlite-runtime.ts`: Lazy `node:sqlite` `DatabaseSync` loader validating Node `^22.23.4 || >=24.0.0`.
  - `output-path.ts`: Safe output path admission checks (`assertSafeOutputPath`).
  - `release-exposure.ts`: Bounded read-only source-map & symbol exposure scanner (`inspectReleaseExposure`).
  - `prng.ts`: Deterministic xorshift/mulberry32 PRNG (`SeededPrng`).
  - `token-estimator.ts`: Models REA MCP tool turns and token cost across Claude Opus 4, Sonnet 4, and o3.
- `src/shields/`:
  - `exhaustion/`: Surgical Resource-Exhaustion Engine (`rea-budget-matrix.ts`, `obligation-flooder.ts`, `callgraph-labyrinth.ts`, `bpe-token-amplifier.ts`, `wasm-interface-exhaustion.ts`, `cdp-shape-budget-breaker.ts`, `frida-capture-saturation.ts`, `regex-worker-tarpit.ts`, `asar-header-amplifier.ts`).
  - `deception/`: Surgical Model-Misjudgment Induction & Cognitive-Armor Engine (`shadow-business-logic.ts`, `evidence-contract-poison.ts`, `architecture-mirage.ts`, `semantic-honeypot.ts`, `decompiler-illusion.ts`, `prompt-completion-poison.ts`, `diff-noise-injector.ts`, `crash-trace-decoy.ts`, `canary-honeypot.ts`, `system-diagnostic-decoy.ts`, `cognitive-armor-trigger.ts`, `format-payloads.ts`).
  - `chaff/chaff-generator.ts`: Generates benign hardware-enclave delegation manifests and decoy offset contracts.
  - `tarpit/opaque-predicates.ts` & `tarpit-generator.ts`: Number-theoretic opaque predicates ($O(1)$ runtime invariants) and REA Semantic Budget Breakers.
  - `runtime/runtime-shield.ts` & `runtime/memory-diff-shield.ts`: "Truman Show" Anti-CDP / Anti-Inspector / Anti-Frida dynamic runtime deception shield, plus Synchronized Shadow Heap Churn and Split-Share Rolling XOR memory masking against $M_0 \to M_1$ runtime memory diffing.
  - `javascript/ast-shield.ts`: Babel AST shield combining opaque ternaries, Electron IPC de-literalization, exhaustion suite, and deception suite.
  - `formats/`: Format-specific shields for `sourcemap.ts`, `asar.ts`, `electron-fuses.ts`, `wasm.ts`, `python.ts`, `native.ts`, `sqlite.ts`, `model.ts`, `mobile-game.ts`, `apple-plist.ts`, `dotnet-managed.ts`, `headers.ts`, and `archive.ts`.
- `src/bundler/index.ts`: Vite, Rollup, Webpack, and esbuild bundler plugins (`bla-agents/bundler`).
- `src/engine/`: `defender.ts` (One-Click 5-Stage `defendTarget`), `auditor.ts`, `protector.ts`, `verifier.ts`, and `benchmark.ts` (8-target showcase benchmark).
- `src/mcp/server.ts`: JSON-RPC 2.0 MCP stdio server (`bla_defend`, `bla_audit`, `bla_protect`, `bla_verify`, `bla_benchmark`, `bla_emit_headers`, `bla_doctor`).
- `src/setup/`: Auto-registration for Claude Code, Cursor, Codex, Windsurf, Gemini CLI, and Antigravity.

## Build & Test Commands

```bash
npm run build
npm test
node dist/cli.js benchmark
node dist/cli.js defend ./dist --manifest
```
