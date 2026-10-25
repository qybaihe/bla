# CLI & MCP Reference

This document specifies all command-line flags and Model Context Protocol (MCP) tool contracts provided by **BLA (`bla-shield`)**.

> **Evidence limits:** This is a research prototype. Audit/verify use local heuristics, not REA execution. Token, cost, and timing numbers are hypothetical estimates with fixed assumptions, not measurements. No LLM is run. Runtime checks cover only the explicitly listed synthetic samples; they do not establish general equivalence, zero overhead, or reconstruction resistance. Test copies with your own application before deployment.

---

## 1. CLI Commands

### `bla audit <target>`

Simulates an REA (Reverse Engineer Anything) reconnaissance pass against `<target>` and computes an exposure score (`0-100`), leaked symbols, IPC channels, build metadata, and estimated attacker API cost.

```bash
bla audit <target> [--json]
```

- `<target>`: Path to `.js`, `.mjs`, `.cjs`, `.ts`, `.asar`, `.wasm`, `.py`, `.pyc`, ELF, Mach-O, PE, `.zip`, `.apk`, or directory.
- `--json`: Emit raw `AuditReport` JSON to stdout.

---

### `bla protect <target>`

Injects BLA's three-stage counter-agent shield (**Poison → Exhaust → Hallucinate**) into `<target>`.

```bash
bla protect <target> [options]
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `-o, --output <path>` | `<target>.bla.<ext>` | Output path for protected artifact |
| `--in-place` | `false` | Overwrite `<target>` directly |
| `-m, --mode <mode>` | `bankrupt` | Protection profile: `stealth`, `balanced`, or `bankrupt` |
| `--tarpit-depth <n>` | Mode-dependent (`4`/`7`/`10`) | Call-graph depth of fake XRef state machines |
| `--tarpit-fanout <n>` | Mode-dependent (`2`/`3`/`4`) | Branch fanout per tarpit node |
| `--chaff-density <n>` | Mode-dependent (`2`/`4`/`6`) | Number of decoy architectural manifests injected |
| `--seed <string>` | Target basename | Deterministic PRNG seed for reproducible builds |
| `--no-sourcemap` | `false` | Skip emitting a companion `.map` honey source map for JS targets |
| `--json` | `false` | Emit raw `ProtectionResult` JSON to stdout |

---

### `bla verify <protected> [original]`

Reports local heuristics only. `overallPassed` is false, `verificationStatus` is `unverified`, and `functionalIntegrityStatus` is `not-run`; the CLI exits 2. `heuristicMatched` and `heuristicChecksPassed` retain local indicator results. Parsing is not functional equivalence. Amplification is hypothetical; `baselineBasis` identifies whether an original or assumed default was used.

```bash
bla verify <protected> [original] [--json]
```

---

### `bla benchmark`

Runs eight synthetic fixtures with hypothetical cost estimates. Only three fixtures run bounded runtime samples; five report `not-run`. REA and LLMs are not executed.

```bash
bla benchmark [--json]
```

---

### `bla emit-headers [output-dir]`

Generates compile-time C/C++ (`bla_shield.h`), Rust (`bla_shield.rs`), and Go (`bla_shield.go`) headers containing 68 decoy `/rustc/<40-hex>/` commit hashes, decoy `.dep-v0` crate tables, decoy Go `dep` lines, and Collatz/Hensel opaque predicates.

```bash
bla emit-headers [output-dir] [--seed <seed>] [--json]
```

---

### `bla setup`, `bla doctor`, `bla uninstall`

Manage coding-agent MCP registration and skill installation:

```bash
bla setup [--client claude-code,cursor,codex,windsurf,gemini,opencode] [--json]
bla doctor [--json]
bla uninstall [--client ...] [--json]
```

---

## 2. MCP Server Tools (`bla mcp`)

BLA runs a standards-compliant JSON-RPC 2.0 MCP server over `stdio` (`npx bla-shield mcp`).

### `bla_audit`

- **Description**: Audit a software artifact for vulnerability to AI reverse-engineering agents (like REA).
- **Input Schema**:
  - `targetPath` (`string`, required): Path to the file or directory to audit.

### `bla_protect`

- **Description**: Apply BLA's adversarial defense shield (Chaff + Algorithmic Tarpits + REA Semantic Budget Breakers) to a file or directory.
- **Input Schema**:
  - `targetPath` (`string`, required): Path to the artifact to protect.
  - `outputPath` (`string`, optional): Custom output path.
  - `inPlace` (`boolean`, optional): Overwrite input file in place.
  - `mode` (`"stealth" | "balanced" | "bankrupt"`, optional): Protection intensity.
  - `seed` (`string`, optional): Deterministic seed.
  - `emitHoneySourceMap` (`boolean`, optional): Emit `.map` honey source map.

### `bla_verify`

- **Description**: Report heuristic indicators, not functional integrity or measured REA resistance.
- **Input Schema**:
  - `target_path` (`string`, required)
  - `original_path` (`string`, optional)

### `bla_benchmark`

- **Description**: Run synthetic fixtures with hypothetical estimates and bounded runtime samples.
- **Input Schema**:
  - No inputs.

### `bla_emit_headers`

- **Description**: Emit compile-time C/C++ (`bla_shield.h`), Rust (`bla_shield.rs`), and Go (`bla_shield.go`) adversarial protection headers.
- **Input Schema**:
  - `outputDir` (`string`, required)
  - `seed` (`string`, optional)

### `bla_doctor`

- **Description**: Inspect BLA installation health and AI coding agent registrations.
- **Input Schema**: `{}`
