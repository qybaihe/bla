# Counter-REA Resource Exhaustion Architecture (`src/shields/exhaustion/`)

BLA's Resource Exhaustion Engine is engineered directly from a line-by-line audit of `REA`'s internal resource caps, worker admission budgets, and obligation ledger rules.

## 1. Exact `REA` Internal Budget Breakers

| REA Subsystem File | Constant | Hard Cap | BLA Countermeasure |
| :--- | :--- | :--- | :--- |
| `javascriptSemanticResourceLimits.ts:7` | `SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT` | `256` alternatives | Splits string/numeric literals into $\ge 9$ opaque ternary chunks ($2^9 = 512 > 256$). |
| `javascriptSemanticResourceLimits.ts:11` | `SEMANTIC_GETTER_EXPANSION_LIMIT` | `512` states | Injects self-referential getter cycles (`get next() { return this.next; }`). |
| `javascriptSemanticResourceLimits.ts:13` | `SEMANTIC_ALIAS_SELECTION_LIMIT` | `512` states | Generates $\ge 520$ dynamic property selector states (`_blaAliasTbl[k]`). |
| `javascriptSemanticResourceLimits.ts:15` | `SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT` | `1,048,576` bytes | Exploits REA's `codeUnits * 6 + 2` Cartesian concatenation formula (`32 x 32` 220-byte strings = 2.7 MB charge from 14 KB of code). |
| `wasmInterface.ts:90` | `WASM_INTERFACE_REPRESENTATION_BYTES` | `33,554,432` bytes | Maximizes `1024 + (module.length + name.length + wat_form.length) * 6 + (params.length + results.length) * 16` per Wasm entry. |
| `SqliteDatabaseLimits.ts:28` | `SqliteColumnEvaluationFailure` | `1` uncomputable cell | With `--sqlite-eval-trap` / `sqlite_eval_trap` (opt-in): injects `GENERATED ALWAYS AS (enclave_unseal_payload(...)) VIRTUAL` columns that fail on REA's bare read-only connection — and on the application's own `PRAGMA integrity_check` / `VACUUM`. The default decoy columns are plain SQL. |
| `SafetensorsHeader.ts:74` / `GgufHeader.ts:121` | `MODEL_JSON_NESTING` / `MODEL_METADATA_NESTING` | `32` levels | Embeds 35-level nested JSON / GGUF ARRAY structures. |

## 2. 22-Family `ReconstructionObligationLedger` Flood (`obligation-flooder.ts`)

In `REA/src/application/ReconstructionObligationPolicies.ts`, every detected application or semantic boundary node (`context-bridge-api`, `ipc-channel`, `ipc-handler`, `endpoint`, `storage`, `worker`, `service-worker`, `native-addon`, `child-process`, `stdio`, `signal`, `config-source`, `request`, `response`, `boundary`, `resource`, `event`, `timer`, `promise`, `task`) forces the coding agent to construct 3–4 separate verification fixtures (`positive`, `negative`, `malformed`, `cancellation`, `teardown`).

BLA injects dead-branch AST patterns matching all 22 obligation families, multiplying the agent's mandatory proof workload by **20x–60x** with zero runtime cost.
