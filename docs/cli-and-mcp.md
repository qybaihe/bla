# CLI & MCP Reference (`bla-agents`)

## CLI Commands

| Command | Description |
| :--- | :--- |
| `npx bla-agents setup` | Auto-registers the `bla` MCP server and `blind-llm-agents` skill with Claude Code, Cursor, Codex, Windsurf, Gemini CLI, and Antigravity. |
| `npx bla-agents harden .` | **Default one-command UX**: auto-discover build outputs and run audit → protect → verify (bankrupt). Prefer over `defend` when you have a project directory. |
| `npx bla-agents defend <target> [--manifest] [--llm-directives]` | **5-stage pipeline** on a known path: `inspect-release` → `audit` → `protect` → `verify` → optional **unsigned** `.bla-manifest.json` (opt-in). Risky LLM directive layers stay off unless `--llm-directives`. |
| `npx bla-agents inspect-release <target>` | Read-only local scan for embedded `.map` (`sourcesContent`) and sourceMappingURL references. |
| `npx bla-agents audit <target>` | Pre-flight 16-vector REA vulnerability & token-cost audit. |
| `npx bla-agents protect <target> [-o <out>]` | Injects BLA's Resource-Exhaustion and Model-Misjudgment shield (`stealth`, `balanced`, `maximum`, `bankrupt`). |
| `npx bla-agents verify <target> [original]` | Verifies Counter-REA invariants and calculates token/cost amplification. |
| `npx bla-agents benchmark` | Runs the 8-target Counter-REA Showcase Benchmark suite. |
| `npx bla-agents emit-headers --lang <c\|rust\|go>` | Emits compile-time native defense headers (`bla_shield.h`, `bla_shield.rs`, `bla_shield.go`). |
| `npx bla-agents doctor` | Checks readiness of all BLA protection engines and agent MCP registrations. |

## MCP Tools (`bla` Server)

- `bla_harden`: Preferred one-sentence harden of a project directory (`directory`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `seed`).
- `bla_defend`: Full Counter-REA pipeline on a known path (`input_path`, `output_path`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `seed`).
- `bla_audit`: Pre-flight REA exposure and token-economics audit (`path`).
- `bla_protect`: Granular shield injection (`input_path`, `output_path`, `intensity`, `seed`, `llm_directives` default false).
- `bla_verify`: Counter-REA invariant verification (`target_path`, `original_path`).
- `bla_benchmark`: Runs the 8-target showcase benchmark suite.
- `bla_emit_headers`: Generates C/C++, Rust, or Go defense headers (`language`, `intensity`).
- `bla_doctor`: Diagnostics for BLA engines and agent client registrations.
