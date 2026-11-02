# MCP / skill completion roadmap

Goal: turn bla's MCP and skill from an executable one-click command into a
defensive workbench that is reviewable, drift-aware, and backed by
reproducible redteam evidence. This document is the plan only; it changes
no tool, skill text, intensity default, or shield logic.

Baseline (bla-agents 1.6.4): MCP is stdio-only with 11 tools and no
session/run ledger, paging, progress, or cancel. The only skill is
`.agents/skills/blind-llm-agents/SKILL.md` (1.3.2), which is a thick guide
over a strong execution layer, but setup only copies `SKILL.md` and
doctor only hashes it, so the referenced counter-REA matrix and docs
links do not exist in the installed client skill directory.

## Completion definition

1. A bare agent using only MCP prompts + skill, without reading repo
   source, follows "audit first, then protect, bankrupt by default,
   llm_directives off", and prompt defaults match skill defaults
   (checked by automated tests).
2. After a fresh install, every relative link inside the skill opens;
   matrix rows align with the key constants in `REA_INTERNAL_LIMITS`
   and carry an REA version field; without an REA checkout, drift
   checks report "unverified", not a silent pass.
3. Every protect/defend/harden run has a `run_id` whose per-artifact
   evidence can be retrieved afterwards (paging, field filtering),
   and verify honesty caps are no longer miscalculated from missing
   protection metadata.
4. Redteam evidence is reported in cohorts: default budget, relaxed
   budget, and swapped engine, each with token/time/whether key
   conclusions were reached. A shield that only wins at default
   budgets must not be reported as "protected".
5. Volume and startup cost have limits: bankrupt must not inflate
   without bound, and P95 startup/load time belongs in benchmark.

## Segments (each independently reviewable and revertible)

- **PR1 — prompt reconstruction (done, PR #69).** Distinct prompt
  texts for `shield-against-rea`, `bla-hardening-workflow`, and
  `bla-counter-rea`, with decision steps, safe defaults, and
  acceptance criteria; omitted optional arguments are allowed.
- **PR2 — skill bundle completeness and matrix alignment
  (issue #70).** Install `references/counter-rea-matrix.md` with
  `SKILL.md`, verify references in doctor, align the matrix with
  `REA_INTERNAL_LIMITS` (R8/JNI/UF2/BEAM/EVM rows), add an REA
  version field, and make matrix changes bump the skill version.
- **PR3 — read-only discover, dry-run, and confirmation
  (issue #71).** Add `bla_discover` (reusing
  `discoverHardenableArtifacts`, zero writes), a dry-run preview,
  and a confirmation receipt for writes. No in-place overwrite
  without confirmation.
- **PR4 — evidence ledger and verify honesty passthrough
  (issue #72).** Issue a `run_id` per run, add `bla_run_get`, and
  let `bla_verify` receive protection metadata (`selfSeal`,
  `wasmExportRenameApplied`).
- **PR5 — REA drift query and relaxed-budget redteam reporting
  (issue #73).** Add `bla_rea_drift` (reusing the named assertions
  in `scripts/verify-rea-constants.mjs`) and `bla_redteam_report`
  (default / relaxed / swapped-engine cohorts, measured results
  separated from estimates).
- **PR6 — CLI-MCP parity and format-specific skill slices
  (issue #74).** Add `bla_lint_lanes`, outputDirectory/maxArtifacts/
  inPlace (with confirmation)/honeySourceMaps, min_defense_score,
  and sarif output to MCP; split the skill into generic decisions
  plus JS/WASM/Python/Android appendices.
- **PR7 — transport and interaction upgrade, optional
  (issue #75).** Streamable HTTP, progress, cancel, paging, a CI
  skill, and a defensive-evaluator skill. Do this after PR2-PR6,
  and only split tool families or compact schemas when the tool
  surface exceeds 20 tools or must enter a gateway/small-schema
  client.

## Order principles

1. Fix misleading guides first (PR1, PR2), then add tools
   (PR3-PR5); otherwise new tools are refused or bypassed by the
   old skill.
2. Read-only and confirmation first (PR3), then ledgers (PR4),
   then public effectiveness claims (PR5).
3. Every segment ships its tests with its code; do not merge code
   first and tests later.
4. Out of scope for this roadmap: REA-style analysis/reconstruction
   tools; intensity default changes; `llm_directives` as a default;
   presenting benchmark estimates as measured results; silently
   overwriting a user-modified `SKILL.md`.

## References

- REA MCP/skill reference analysis: skill as router, MCP as
  execution layer, Evidence as audit ledger; default to summaries
  and gate conclusions, keep full decoy lists in local files only,
  and keep relaxed-budget / engine-swapped work in a clearly
  marked redteam mode, never in the default protection surface.
