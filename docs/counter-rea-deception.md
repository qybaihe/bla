# Counter-REA Model-Misjudgment Induction (`src/shields/deception/`)

While traditional obfuscators only try to hide code, BLA actively **induces LLM reverse-engineering agents to reconstruct the wrong algorithm** by exploiting REA's Evidence Contract.

## Exploiting REA's `COMMON_DISCIPLINE` (`promptContracts.ts:52-57`)

REA instructs coding agents:
1. *"Report Observations only from cited Evidence returned by tools. Label reasoning as Inference with confidence and competing explanations."*
2. *"Keep incomplete coverage, unsupported capabilities, and conflicting evidence explicit as Unknowns."*

BLA exploits this discipline through a two-pronged pincer movement:
- **Prong A (Demote Real Logic to `Unknown`)**: Wrap the real business logic in REA Semantic Budget Breakers (`primitive-candidates > 256`, `alias-selections > 512`) so REA's static analyzer tags the real logic as `status: "unknown"`.
- **Prong B (Promote Shadow Logic to High-Confidence `Observation`)**: Inject crystal-clear, syntactically pristine **Shadow Business Logic** (`shadow-business-logic.ts`), **Semantic Honeypots** (`semantic-honeypot.ts`), **Evidence Contract Competing-Explanation Lures** (`evidence-contract-poison.ts`), and **Multi-Tier gRPC/vsock Architecture Mirages** (`architecture-mirage.ts`).

When the LLM agent queries REA's `search_procedures`, `search_strings`, and `analyze_function`, the Shadow Business Logic returns 100% complete `observed` Evidence—causing the LLM to faithfully rebuild the decoy algorithm!


## Python / PyInstaller honesty

BLA's Python shield densifies `.py` / `.pyc` artifacts (interconnected tarpit,
opaque predicates, diversified chaff). It does **not** rewrite a packed
PyInstaller onefile CArchive in place: `detectNativeEofAppendHazard` only
refuses EOF trailers that would break the MEI cookie.

**Expected attacker move:** peel onefile → extract entry `pyc` / scripts.
**Defense that still helps:** run `bla harden` on sources *before*
`pyinstaller`, so the peeled archive still contains dense decoys rather than
clean customer logic. Opt-in self-seal / anti-debug helpers that bind the
customer entry to intact bytes remain a separate product gap (issue #40).

## Weave decoys (not dismissible noise)

Empty / homogeneous scare decoys are filtered as a separate layer by
WorkBuddy-class agents. Prefer **weaving** decoys into real customer paths
(shared state, entry reachability, mixed vocabulary, opaque-true happy path).
JS AST already weaves; Python `.py` with `weave_decoys:true` structurally weaves decoys into customer defs (warm-init-only when the flag is false).
Executable theory + MCP: [`weave-decoy-mcp.md`](./weave-decoy-mcp.md),
resource `bla://directives/weave-decoy`, tool `bla_weave_plan`, flag
`weave_decoys`.


## WASM export rename (#40.3)

`protectWasmBinary` renames exports not listed in `preserveExports`. At `maximum`/`bankrupt`, **all** non-preserved names rename by default (red-blue round-1). Keeping a stable public ABI requires an explicit preserve list. Optional `renameInternalOnly: true` restores the weaker internal-only pass. Returns `exportsRenamed` for glue updates. Project / CLI / MCP parity: `.blarc` `wasmPreserveExports`, `--wasm-preserve-exports`, MCP `wasm_preserve_exports`.
