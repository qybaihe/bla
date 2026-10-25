---
name: blind-llm-agents
description: Audit, protect, and verify software artifacts (JavaScript/TypeScript, Electron ASAR, WebAssembly, Python .py/.pyc, and Native ELF/Mach-O/PE Binaries) against AI reverse-engineering agents like REA using BLA (Blind LLM Agents / Block Anything).
metadata:
  version: "1.0.0"
---

# BLA: Blind LLM Agents (Block Anything)

Use BLA when the user wants to evaluate how exposed a software build artifact is to automated AI reverse-engineering tools (such as REA — Reverse Engineer Anything), inject adversarial software protection shields before shipping, verify defense effectiveness, or generate compile-time native C/C++, Rust, or Go defense headers.

> **Evidence limits:** This is a research prototype. Audit/verify use local heuristics, not REA execution. Token, cost, and timing numbers are hypothetical estimates with fixed assumptions, not measurements. No LLM is run. Runtime checks cover only the explicitly listed synthetic samples; they do not establish general equivalence, zero overhead, or reconstruction resistance. Test copies with your own application before deployment.

## Core Workflow: Audit -> Protect -> Verify

1. **Audit (`bla_audit` or `npx bla-shield audit <target>`)**:
   - Inspects the target artifact (`javascript`, `typescript`, `electron-asar`, `sourcemap`, `html-bundle`, `wasm`, `python-source`, `python-pyc`, `native-elf`, `native-macho`, `native-pe`, `archive-zip`, `android-apk`, or `directory`).
   - Reports the **REA Exposure Score (0–100)**, exposed functions/classes/IPC channels/routes, and estimated attacker token and dollar costs across Claude Opus 4, Claude Sonnet 4, and OpenAI o3.
2. **Protect (`bla_protect` or `npx bla-shield protect <target> -o <output>`)**:
   - Injects BLA's 4-layer Counter-REA shield:
     - **Layer 1 (REA Semantic Budget Breakers)**: Triggers `alias-selections` (>512 states), `primitive-candidates` (>256 alternatives), `primitive-bytes` (>1 MiB), `getter-expansion` (>512 states), `returned-reference-widening`, and `electron_call_paths_limited` in REA's static/semantic analyzer with zero runtime overhead.
     - **Layer 2 (Algorithmic Tarpit & Fake XRefs)**: Weaves interconnected decoy state machines and number-theoretic opaque predicates into the call graph, multiplying REA's `trace_application_feature` and `build_reconstruction_obligation_ledger` by 15x–50x.
     - **Layer 3 (Electron IPC Ambiguity & Route/SourceMap Mirage)**: De-literalizes IPC channels, registers duplicate decoy IPC handlers to defeat REA's unique-literal pairing rule, plants decoy routes, and replaces source maps with valid VLQ Honey Source Maps.
     - **Layer 4 (Binary Container & Section Shields)**: Protects `.asar`, `.wasm` (custom `"name"` & attestation sections), `.py`/`.pyc` (marshal constant pool & tarpit), and Native ELF/Mach-O/PE binaries (exceeding REA's `MAX_RUSTC_HASHES = 64` capacity limit and injecting decoy `.dep-v0` / Go buildinfo metadata).
3. **Verify (`bla_verify` or `npx bla-shield verify <protected> [original]`)**:
   - Reports local heuristic indicators and hypothetical amplification only. Empirical verification is unverified (CLI exits 2); never treat parsing or marker matches as functional equivalence.

## CLI Fallback Commands

If the BLA MCP server is not connected in the current session, run the CLI directly:

```bash
npx -y bla-shield@latest audit /absolute/path/to/target --json
npx -y bla-shield@latest protect /absolute/path/to/target -o /absolute/path/to/protected --intensity bankrupt --json
npx -y bla-shield@latest verify /absolute/path/to/protected /absolute/path/to/target --json
```

See [references/counter-rea-matrix.md](references/counter-rea-matrix.md) for the complete mapping between REA's internal analyzers and BLA's countermeasures.
