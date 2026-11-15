# AGENTS.md — Repository Guide for Coding Agents

This repository contains **BLA (`bla-agents` — Blind LLM Agents)**, an open-source adversarial Blue Defense toolkit engineered to protect software artifacts against AI reverse-engineering agents (specifically `morluto/rea`).

## Project Layout

- `src/identity.ts`: Product metadata (`bla-agents`) and exact `REA_INTERNAL_LIMITS` constants.
- `src/core/`:
  - `types.ts`: Domain interfaces (`AuditReport`, `ProtectionResult`, `VerificationReport`, `BenchmarkReport`).
  - `detector.ts`: Magic-byte and file-extension format detection across 26 artifact formats (`ArtifactFormat` in `types.ts`, plus the `directory` and `unknown` sentinels).
  - `sqlite-runtime.ts`: Lazy `node:sqlite` `DatabaseSync` loader validating Node `^22.23.4 || >=24.0.0`.
  - `output-path.ts`: Safe output path admission checks (`assertSafeOutputPath`).
  - `release-exposure.ts`: Bounded read-only source-map & symbol exposure scanner (`inspectReleaseExposure`).
  - `prng.ts`: Deterministic xorshift/mulberry32 PRNG (`SeededPrng`).
  - `token-estimator.ts`: Models REA MCP tool turns and token cost across Claude Opus 4, Sonnet 4, and o3.
- `src/shields/`:
  - `exhaustion/`: Surgical Resource-Exhaustion Engine (`rea-budget-matrix.ts`, `obligation-flooder.ts`, `callgraph-labyrinth.ts`, `bpe-token-amplifier.ts`, `wasm-interface-exhaustion.ts`, `cdp-shape-budget-breaker.ts`, `frida-capture-saturation.ts`, `regex-worker-tarpit.ts`, `asar-header-amplifier.ts`).
  - `deception/`: Surgical Model-Misjudgment Induction & Cognitive-Armor Engine (`shadow-business-logic.ts`, `evidence-contract-poison.ts`, `architecture-mirage.ts`, `semantic-honeypot.ts`, `decompiler-illusion.ts`, `prompt-completion-poison.ts`, `diff-noise-injector.ts`, `crash-trace-decoy.ts`, `canary-honeypot.ts`, `system-diagnostic-decoy.ts`, `cognitive-armor-trigger.ts`, `hypothesis-revision-decoy.ts`, `format-payloads.ts`).
  - `chaff/chaff-generator.ts`: Generates benign hardware-enclave delegation manifests and decoy offset contracts.
  - `tarpit/opaque-predicates.ts` & `tarpit-generator.ts`: Number-theoretic opaque predicates ($O(1)$ runtime invariants) and REA Semantic Budget Breakers.
  - `runtime/runtime-shield.ts` & `runtime/memory-diff-shield.ts`: "Truman Show" Anti-CDP / Anti-Inspector / Anti-Frida dynamic runtime deception shield, plus Synchronized Shadow Heap Churn and Split-Share Rolling XOR memory masking against $M_0 \to M_1$ runtime memory diffing. Also `runtime/self-seal.ts` (opt-in self-integrity preamble) and `runtime/sidecar-entangle.ts` (interleaved strip⇒fail sibling binding).
  - `javascript/ast-shield.ts` & `javascript/node-runtime-carrier.ts`: Babel AST shield combining opaque ternaries, Electron IPC de-literalization, exhaustion suite, and deception suite; the runtime carrier binds the shield into the emitted entry.
  - `weave/weave-decoy.ts`: AST-level surgical weave workorder + structural weave verifier (`bla-weave-plan/v1`, `bla-weave-verify/v1`).
  - `formats/`: Format-specific shields — `sourcemap.ts`, `asar.ts`, `electron-fuses.ts`, `wasm.ts`, `python.ts`, `python-ast-weave.ts`, `python-pyc-weave.ts`, `native.ts`, `sqlite.ts`, `model.ts`, `gguf-layout.ts`, `mobile-game.ts`, `apple-plist.ts`, `dotnet-managed.ts`, `headers.ts`, `archive.ts`, `android-dex-xref.ts`, `dex-layout.ts`, `android-manifest.ts`, `android-r8.ts`, `bun-standalone.ts`, `erlang-beam.ts`, `evm-bytecode.ts`, `firmware-uf2.ts`, `go-flutter-exhaustion.ts`, `gpu-ptx.ts`, `jvm-bytecode.ts`, and `pcap-capture.ts`.
- `src/bundler/index.ts`: Vite, Rollup, Webpack, and esbuild bundler plugins (`bla-agents/bundler`).
- `src/engine/`: `defender.ts` (One-Click 5-Stage `defendTarget`), `auditor.ts`, `protector.ts`, `verifier.ts`, and `benchmark.ts` (14-target showcase benchmark); plus `harden.ts`, `bind-scope.ts`, `encrypt-strings.ts`, `packaging-gates.ts`, `integrity-coverage.ts`, `run-evidence.ts`, `polymorph-report.ts`, `rea-observability.ts`, `defense-score-honesty.ts`, and the `*-lint.ts` packaging / red-blue gates.
- `src/mcp/server.ts`: JSON-RPC 2.0 MCP stdio server exposing 31 tools (full catalogue in `docs/cli-and-mcp.md`), including `bla_harden`, `bla_defend`, `bla_audit`, `bla_protect`, `bla_verify`, `bla_benchmark`, `bla_lint`, `bla_weave_plan`, `bla_verify_weave`, `bla_emit_headers`, and `bla_doctor`.
- `src/setup/`: Auto-registration for Claude Code, Cursor, Codex, Windsurf, Gemini CLI, and Antigravity.

## Build & Test Commands

```bash
npm run build
npm test
node dist/cli.js benchmark
node dist/cli.js defend ./dist --manifest
```
