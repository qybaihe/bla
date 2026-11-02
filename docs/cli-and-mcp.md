# CLI & MCP Reference (`bla-agents`)

For coding agents, the **[`blind-llm-agents` skill](../.agents/skills/blind-llm-agents/SKILL.md)** is the primary one-click harden guide; this page indexes the CLI/MCP execution surface.

## CLI Commands

| Command | Description |
| :--- | :--- |
| `npx bla-agents setup` | Auto-registers the `bla` MCP server and `blind-llm-agents` skill with Claude Code, Cursor, Codex, Windsurf, Gemini CLI, and Antigravity. |
| `npx bla-agents harden .` | **Default one-command UX**: auto-discover build outputs and run audit → protect → verify (bankrupt). Prefer over `defend` when you have a project directory. Agent guide: [`blind-llm-agents` skill](../.agents/skills/blind-llm-agents/SKILL.md). |
| `npx bla-agents defend <target> [--manifest] [--llm-directives] [--weave-decoys]` | **5-stage pipeline** on a known path: `inspect-release` → `audit` → `protect` → `verify` → optional **unsigned** `.bla-manifest.json` (opt-in). Risky LLM directive layers stay off unless `--llm-directives`. Structural weave decoys stay off unless `--weave-decoys`. |
| `npx bla-agents harden . [--weave-decoys]` | Same as `harden` with opt-in structural weave (`weave_decoys`). |
| `npx bla-agents inspect-release <target>` | Read-only local scan for embedded `.map` (`sourcesContent`) and sourceMappingURL references. |
| `npx bla-agents audit <target>` | Pre-flight 16-vector REA vulnerability & token-cost audit. |
| `npx bla-agents protect <target> [-o <out>] [--weave-decoys]` | Injects BLA's Resource-Exhaustion and Model-Misjudgment shield (`stealth`, `balanced`, `maximum`, `bankrupt`). Opt-in `--weave-decoys` for structural Python customer-def weave. |
| `npx bla-agents verify <target> [original]` | Verifies Counter-REA invariants and calculates token/cost amplification. |
| `npx bla-agents benchmark` | Runs the 8-target Counter-REA Showcase Benchmark suite. |
| `npx bla-agents emit-headers --lang <c\|rust\|go>` | Emits compile-time native defense headers (`bla_shield.h`, `bla_shield.rs`, `bla_shield.go`). |
| `npx bla-agents doctor` | Checks readiness of all BLA protection engines and agent MCP registrations. |

## MCP Tools (`bla` Server)

- `bla_harden`: Preferred one-sentence harden of a project directory (`directory`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `weave_decoys` default false, `seed`).
- `bla_defend`: Full Counter-REA pipeline on a known path (`input_path`, `output_path`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `weave_decoys` default false, `seed`).
- `bla_audit`: Pre-flight REA exposure and token-economics audit (`path`).
- `bla_protect`: Granular shield injection (`input_path`, `output_path`, `intensity`, `seed`, `llm_directives` default false, `weave_decoys` default false).
- `bla_verify`: Counter-REA invariant verification (`target_path`, `original_path`).
- `bla_benchmark`: Runs the 8-target showcase benchmark suite.
- `bla_emit_headers`: Generates C/C++, Rust, or Go defense headers (`language`, `intensity`).
- `bla_doctor`: Diagnostics for BLA engines and agent client registrations.
- `bla_weave_plan`: Read-only weave-decoy planner (`path`, optional `max_targets`) → `bla-weave-plan/v1` JSON (defensive theory checklist; no crack/RE).

`weave_decoys: true` activates structural Python customer-def weave (shared-slot touch + opaque-false decoy calls) after the #51 tarpit; when false, Python stays warm-init-only. JS AST weave remains always-on.

Project config parity: set `"weaveDecoys": true` in `.blarc` / `bla.config.json` (schema `bla.config.v1.json`) to enable the same flag without repeating `--weave-decoys` / MCP `weave_decoys` on every invoke. CLI/MCP flags still OR with the config value.

Opt-in **self-seal** (issue #40.5): CLI `--self-seal`, MCP `self_seal`, `.blarc` `"selfSeal": true`. Injects a Node self-integrity preamble (module + optional sibling paths + env fingerprint) and folds the digest into the opaque-predicate seed for JS/Node targets.
WASM public ABI preserve list (issue #40.3): CLI `--wasm-preserve-exports a,b`, MCP `wasm_preserve_exports`, `.blarc` `"wasmPreserveExports": ["a","b"]`. Kept names stay; internal-looking exports may still rename at maximum/bankrupt.

Heuristic **lane-independence lint** (issue #40.1): `bla lint-lanes <file>` warns when gate code looks like independent per-lane checks. Defensive guidance only — prefer whole-key chained mixing.

### MCP Resources

- `bla://directives/weave-decoy` — weave-decoy theory + executor checklist (Markdown).
- `bla://docs/weave-decoy-mcp` — same directives payload (doc pointer URI).

See [`weave-decoy-mcp.md`](./weave-decoy-mcp.md).
