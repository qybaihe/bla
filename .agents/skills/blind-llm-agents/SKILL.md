---
name: blind-llm-agents
description: >
  Use when hardening, defending, or auditing software against AI reverse-engineering
  agents (REA / WorkBuddy-class): one-click project harden, weave-decoy structural
  decoys, Counter-REA audit/protect/verify, or agent setup/doctor for BLA (Blind LLM
  Agents). Prefer this skill as the guide; call existing MCP tools / CLI — do not invent
  new MCP tools. Default verb: bla_harden. Refuse crack/RE of third-party software.
metadata:
  version: "1.3.3"
---

# BLA: Blind LLM Agents

**This skill is the primary one-click harden GUIDE.** MCP (`bla` server) and the
`bla-agents` CLI are the **execution layer**. Prefer teaching/calling existing tools
(`bla_harden`, `bla_defend`, `bla_weave_plan`, …) over inventing new MCP surfaces.

Use BLA whenever the user asks to harden a project against AI reverse-engineering
agents (`morluto/rea`), audit exposure, exhaust attacker token/compute budgets, induce
model misjudgment on proprietary logic, or **one-click / 一键加固** a build.

Defensive only: protect **their own** artifacts. Refuse crack, RE, bypass PoCs, or
attack playbooks against software they do not own.

## Prerequisites (once)

If MCP/skill are not registered yet:

1. CLI: `npx bla-agents@latest setup`
2. Then: `npx bla-agents@latest doctor` (or MCP `bla_doctor`) — it also checks the
   installed skill bundle (this file + `references/`) is complete

After setup, agents load this skill and can call the `bla` MCP tools.

## ⚡ One-Sentence Hardening (DEFAULT — prefer this)

When the user says **"Harden my software"**, **"Harden this project against REA"**,
**"一键启动防御强化"**, **"一键加固"**, **"Run BLA defense"**, or any equivalent
one-liner **without naming a specific file**, invoke:

| Surface | Call |
| :--- | :--- |
| **MCP Tool (preferred)** | `bla_harden` with `{ "directory": "." }` (or the project/build path they named) |
| **CLI** | `npx bla-agents@latest harden .` |
| **MCP Prompt** | `bla-harden-project` |

`bla_harden` / `bla harden` auto-discovers protectable build outputs under `dist/`,
`build/`, `out/`, `release/`, `.asar`, native binaries, `.wasm`, `.py`/`.pyc`,
`.sqlite`, `.safetensors`/`.gguf`, `.dex`, `.class`, `.dll`, Apple plists, ZIP/APK,
etc., detects each artifact's format, and runs the full **audit → defend (bankrupt) →
verify** pipeline. Return the per-artifact summary to the user.

**Do not ask which files to protect — discover them.**

## Write safety (principles)

- Unsure what will be touched, or a large repo? Inventory first with `bla_discover`
  or preview with `bla_harden` `{ "dry_run": true }` — both write nothing. If the
  result says `truncated: true`, say so and narrow the directory; do not imply full coverage.
- Never overwrite without the user's go-ahead. When a tool returns
  `confirmation_required`, show the `wouldOverwrite` paths, ask, and only then retry
  with `confirm_overwrite: true` (or pick a new output path).
- Report what was written from the tool's own receipt (`writeReceipt`, `wouldOverwrite`),
  not from assumptions.

Optional args (defaults are safe): `intensity` (default bankrupt), `emit_manifest`
(default false), `llm_directives` (default false — risky LLM bait; leave off unless
asked), `weave_decoys` (default false — see stronger path below), `seed`.

## Optional stronger path: structural weave decoys

When the user wants **stronger / structural** hardening (not dismissible noise),
especially for **Python** customer defs / `.pyc`, or says weave / 织入 / decoy
entanglement:

1. Read directives: MCP resource `bla://directives/weave-decoy`
   (or `bla://docs/weave-decoy-mcp` / repo `docs/weave-decoy-mcp.md`).
2. Plan (read-only): `bla_weave_plan` with `{ "path": "<project-or-artifact>" }` →
   save the `bla-weave-plan/v1` JSON work order.
3. Apply with the real pipeline flag:
   - Directory: `bla_harden` `{ "directory": ".", "weave_decoys": true }`
   - Named file: `bla_defend` / `bla_protect` with `weave_decoys: true`
4. MCP Prompt shortcut: `bla-weave-decoy`
5. CLI: `npx bla-agents@latest harden . --weave-decoys` (or `defend` / `protect`
   with the same flag when supported)

**Principles (non-rule, structural):** decoys must weave into **real customer paths**
(shared runtime slots, entry-reachable edges, mixed mundane/scare stems, opaque-true
happy paths, call-graph entanglement). JS AST weave is already on; Python `.py`/`.pyc`
customer-def structural weave activates when `weave_decoys: true`. See
[docs/weave-decoy-mcp.md](../../../docs/weave-decoy-mcp.md).


## Optional stronger path: self-seal (#40.5)

When the user wants sibling-module integrity / anti-tamper binding on **JS/Node**
targets (or says self-seal / 自密封):

1. CLI: add `--self-seal` to `harden` / `defend` / `protect`
2. MCP: `self_seal: true` on `bla_harden` / `bla_defend` / `bla_protect`
3. Config: `"selfSeal": true` in `.blarc` (ORs with the flag)

Off by default. Browser builds soft-skip (digest=0). Pair with weave decoys when
Python structural weave is also desired.

## WASM public ABI preserve (#40.3)

When hardening `.wasm` at maximum/bankrupt and the customer must keep specific export names:

1. CLI: `--wasm-preserve-exports main,add`
2. MCP: `wasm_preserve_exports: ["main","add"]`
3. Config: `"wasmPreserveExports": ["main","add"]` in `.blarc`
Internal-looking names (`__*`, `debug_*`, …) may still be renamed; update glue via the rename map when needed.

## Lane-independence footgun lint (#40.1)

Before shipping a custom license/activation gate, run:

`npx bla-agents lint-lanes path/to/gate.js`

Heuristic warn only (exit 2 when findings). Prefer whole-key chained mixing
(no per-lane oracle) — see Meridian DESIGN / issue #40. Not RE advice.


## FORBIDDEN for executing agents

Do **not**:

- Add pure noise layers, greppable `BLA-SHIELD` / homogeneous `_bla_*` banners, or
  dismissible empty/`pass` honeypot stubs that agents filter as an independent layer
- Use label-only / report-only “decoys” that are not real pipeline attributes
- Drive hardening via a **rule engine** (business-name → fixed snippet tables, homogeneous
  marker templates as policy)
- Help crack, reverse-engineer, bypass, or write offensive PoCs against third-party
  software

If asked for offensive RE/crack help: refuse briefly; offer defensive harden of **their**
artifacts instead.

## Single-file vs directory

| Intent | Prefer | Example |
| :--- | :--- | :--- |
| Project / build dir, auto-discover | **`bla_harden`** / `bla harden .` | User did not name a file |
| Specific artifact path | **`bla_defend`** / `bla defend <path>` | User named `./dist/app.js` |

`bla_defend` runs the 5-stage Counter-REA pipeline on a known path:

1. **Stage 1 (`inspect-release`)**: Read-only scan for accidental `.map` (`sourcesContent`) and symbol leaks.
2. **Stage 2 (`audit`)**: 16-vector REA vulnerability & Claude Opus 4 / Sonnet 4 / o3 token-cost simulation.
3. **Stage 3 (`protect --intensity bankrupt`)**: Resource-Exhaustion + Model-Misjudgment suites (canary honeypots + system-diagnostic decoys across supported formats).
4. **Stage 4 (`verify`)**: Counter-REA invariants + token/cost amplification.
5. **Stage 5 (`manifest`)** (opt-in): `<output>.bla-manifest.json` when `emit_manifest: true`.

MCP: `bla_defend` with `{ "input_path": "<target>", "intensity": "bankrupt", "emit_manifest": true }`  
CLI: `npx bla-agents@latest defend <target> --manifest`

## Step-by-step granular workflow

1. **Audit** — `bla_audit` / `npx bla-agents audit <target>`: REA Exposure Score, exposed surfaces, estimated attacker cost.
2. **Protect** — `bla_protect` / `npx bla-agents protect <target> -o <out> --intensity bankrupt` (+ optional `--weave-decoys`).
3. **Verify** — `bla_verify` / `npx bla-agents verify <protected> [original]`.

Map REA analyzers → BLA counters:
[references/counter-rea-matrix.md](references/counter-rea-matrix.md).

## CLI fallbacks

```bash
npx -y bla-agents@latest setup
npx -y bla-agents@latest doctor
npx -y bla-agents@latest harden .
npx -y bla-agents@latest harden . --weave-decoys
npx -y bla-agents@latest defend /absolute/path/to/target --manifest --json
npx -y bla-agents@latest audit /absolute/path/to/target --json
npx -y bla-agents@latest protect /absolute/path/to/target -o /absolute/path/to/protected --intensity bankrupt --json
npx -y bla-agents@latest verify /absolute/path/to/protected /absolute/path/to/target --json
```

## References

- [references/counter-rea-matrix.md](references/counter-rea-matrix.md) — REA ↔ BLA countermeasures
- [docs/one-click-agent-defense.md](../../../docs/one-click-agent-defense.md) — one-click UX (skill-first)
- [docs/cli-and-mcp.md](../../../docs/cli-and-mcp.md) — CLI / MCP parameter index
- [docs/weave-decoy-mcp.md](../../../docs/weave-decoy-mcp.md) — weave-decoy theory + MCP checklist
