import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";
import { runCli } from "../src/cli.js";
import type {
  WeavePlan,
  WeaveVerificationReport,
} from "../src/shields/weave/weave-decoy.js";
import type { PackagingGatesReport } from "../src/engine/packaging-gates.js";
import type { VerificationReport } from "../src/core/types.js";

const temps: string[] = [];
afterEach(() => {
  for (const d of temps.splice(0)) {
    rmSync(d, { recursive: true, force: true });
  }
});

describe("BLA 3.0 End-to-End Agent-Driven Hardening Loop (MCP + CLI)", () => {
  it("guides a host Agent through Stage 1 (Recon/Lint/WeavePlan) -> Stage 2 (Source Surgery & VerifyWeave) -> Stage 3 (Harden) -> Stage 4 (Equivalence & Verify)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-v3-agent-loop-"));
    temps.push(dir);

    const licensePath = join(dir, "license.cjs");
    const servicePyPath = join(dir, "service.py");

    // Initial fragile source:
    // 1) Lane-independent byte-by-byte gate (triggers bla_lint refuse)
    // 2) Unreferenced empty `_bla_decoy` stub (triggers bla_verify_weave failure)
    writeFileSync(
      licensePath,
      `
function _bla_decoy() {}

const target = [0x42, 0x4c, 0x41, 0x33, 0x5f, 0x50, 0x52, 0x4f];

function verifyLicenseKey(key) {
  if (typeof key !== "string" || key.length !== 8) return false;
  for (let i = 0; i < 8; i++) {
    if (key[i] === target[i]) {
      continue;
    }
  }
  return "DENIED";
}

module.exports = { verifyLicenseKey };
`.trim() + "\n",
      "utf8",
    );

    writeFileSync(
      servicePyPath,
      `
_session_ledger_state = {"epoch": 1, "cursor": 0}

def reconcile_quota_checkpoint(amount):
    _session_ledger_state["cursor"] = (_session_ledger_state["cursor"] + amount) & 0xFFFF
    return _session_ledger_state["cursor"]

def compute_invoice_total(units, price):
    if _session_ledger_state["epoch"] >= 1:
        reconcile_quota_checkpoint(units)
    return units * price
`.trim() + "\n",
      "utf8",
    );

    // =========================================================================
    // STAGE 1: Recon, Packaging Gates & Surgical Workorder
    // =========================================================================
    const lintRes1 = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: {
        name: "bla_lint",
        arguments: { directory: dir },
      },
    });
    expect((lintRes1?.result as { isError: boolean }).isError).toBe(true);
    const lintReport1 = (
      lintRes1?.result as { structuredContent: PackagingGatesReport }
    ).structuredContent;
    expect(lintReport1.shouldRefuseBankrupt).toBe(true);
    expect(lintReport1.remediationPlan.length).toBeGreaterThanOrEqual(1);
    const laneRemediation = lintReport1.remediationPlan.find(
      (r) => r.gate === "lane-independence",
    );
    expect(laneRemediation).toBeDefined();
    expect(laneRemediation!.owner).toBe("agent-source-refactor");
    expect(laneRemediation!.sourceRefactorRecipe).toContain("whole-key chained");

    // Call bla_weave_plan to get the AST surgicalWorkorder
    const planRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: {
        name: "bla_weave_plan",
        arguments: { path: dir },
      },
    });
    expect((planRes?.result as { isError: boolean }).isError).toBe(false);
    const weavePlan = (
      planRes?.result as { structuredContent: WeavePlan }
    ).structuredContent;
    expect(weavePlan.surgicalTargetsCount).toBe(2);
    expect(weavePlan.agentPlaybook).toHaveLength(4);
    expect(weavePlan.siblingEntanglementCandidates.length).toBeGreaterThanOrEqual(1);

    const jsTargetPlan = weavePlan.targets.find((t) =>
      t.relativePath.endsWith("license.cjs"),
    );
    expect(jsTargetPlan?.surgicalWorkorder).toBeDefined();
    expect(
      jsTargetPlan!.surgicalWorkorder!.entryFunctions.some(
        (fn) => fn.name === "verifyLicenseKey" && fn.role === "gate-or-auth",
      ),
    ).toBe(true);
    expect(
      jsTargetPlan!.surgicalWorkorder!.agentRewriteRecipe.length,
    ).toBeGreaterThanOrEqual(3);

    // =========================================================================
    // STAGE 2: Verify Weave (initial failure -> Agent source surgery -> pass)
    // =========================================================================
    const verifyWeaveRes1 = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 12,
      method: "tools/call",
      params: {
        name: "bla_verify_weave",
        arguments: { path: licensePath },
      },
    });
    expect((verifyWeaveRes1?.result as { isError: boolean }).isError).toBe(true);
    const verifyWeave1 = (
      verifyWeaveRes1?.result as { structuredContent: WeaveVerificationReport }
    ).structuredContent;
    expect(verifyWeave1.overallPassed).toBe(false);
    expect(
      verifyWeave1.agentActions.some((a) => a.checkId === "no-forbidden-markers"),
    ).toBe(true);
    expect(
      verifyWeave1.agentActions.some((a) => a.checkId === "customer-entry-edges"),
    ).toBe(true);
    expect(
      verifyWeave1.agentActions.some((a) => a.checkId === "shared-state-mutation"),
    ).toBe(true);

    // Host Agent applies remediationPlan + surgicalWorkorder:
    // 1. Replaces per-byte lane check with whole-key chained FNV-1a mix
    // 2. Introduces shared state carrier `sessionLedgerState`
    // 3. Replaces `_bla_decoy` with domain-plausible helpers called from `verifyLicenseKey`
    writeFileSync(
      licensePath,
      `
const sessionLedgerState = { epoch: 1, cursor: 0, digest: 0x811c9dc5 };

function reconcileSessionQuota(inputLen) {
  sessionLedgerState.cursor = (sessionLedgerState.cursor + inputLen) & 0xffff;
  sessionLedgerState.epoch = (sessionLedgerState.epoch ^ (inputLen & 3)) | 1;
  return sessionLedgerState.cursor;
}

function attestCommitmentDigest(seedDigest) {
  sessionLedgerState.digest = ((sessionLedgerState.digest ^ seedDigest) >>> 0);
  return sessionLedgerState.digest;
}

function verifyLicenseKey(key) {
  if (typeof key !== "string" || key.length !== 8) return "DENIED";
  if ((sessionLedgerState.epoch & 1) !== 0) {
    reconcileSessionQuota(key.length);
  }
  let acc = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    acc ^= key.charCodeAt(i);
    acc = Math.imul(acc, 0x01000193) >>> 0;
  }
  attestCommitmentDigest(acc);
  // Chained FNV-1a digest of "BLA3_PRO" is 0x3b8e8580
  return acc === 0x3b8e8580 ? "ENTITLED:PRO" : "DENIED";
}

module.exports = { verifyLicenseKey };
`.trim() + "\n",
      "utf8",
    );

    // Adjust expected FNV-1a digest dynamically so our test key "BLA3_PRO" is exact
    const req = createRequire(import.meta.url);
    let expectedAcc = 0x811c9dc5;
    for (let i = 0; i < "BLA3_PRO".length; i++) {
      expectedAcc ^= "BLA3_PRO".charCodeAt(i);
      expectedAcc = Math.imul(expectedAcc, 0x01000193) >>> 0;
    }
    writeFileSync(
      licensePath,
      readFileSync(licensePath, "utf8").replaceAll(
        "0x3b8e8580",
        `0x${expectedAcc.toString(16)}`,
      ),
      "utf8",
    );

    // Re-run bla_lint: should now pass with 0 blocking gates
    const lintRes2 = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 13,
      method: "tools/call",
      params: {
        name: "bla_lint",
        arguments: { directory: dir },
      },
    });
    expect((lintRes2?.result as { isError: boolean }).isError).toBe(false);
    const lintReport2 = (
      lintRes2?.result as { structuredContent: PackagingGatesReport }
    ).structuredContent;
    expect(lintReport2.shouldRefuseBankrupt).toBe(false);
    expect(lintReport2.blocking).toHaveLength(0);

    // Re-run bla_verify_weave on the directory: both JS and Python pass 100%
    const verifyWeaveRes2 = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 14,
      method: "tools/call",
      params: {
        name: "bla_verify_weave",
        arguments: { path: dir },
      },
    });
    expect((verifyWeaveRes2?.result as { isError: boolean }).isError).toBe(false);
    const verifyWeave2 = (
      verifyWeaveRes2?.result as { structuredContent: WeaveVerificationReport }
    ).structuredContent;
    expect(verifyWeave2.overallPassed).toBe(true);
    expect(verifyWeave2.weaveScore).toBe(100);
    expect(verifyWeave2.agentActions).toHaveLength(0);

    // =========================================================================
    // STAGE 3: Post-Build Counter-REA Exhaustion Harden
    // =========================================================================
    const hardenRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 15,
      method: "tools/call",
      params: {
        name: "bla_harden",
        arguments: {
          directory: dir,
          weave_decoys: true,
          self_seal: true,
          sidecar_entangle: true,
        },
      },
    });
    expect((hardenRes?.result as { isError: boolean }).isError).toBe(false);
    const hardenReport = (
      hardenRes?.result as {
        structuredContent: {
          overallSuccess: boolean;
          artifacts: Array<{
            relativePath: string;
            outputPath: string;
            success: boolean;
          }>;
        };
      }
    ).structuredContent;
    expect(hardenReport.overallSuccess).toBe(true);
    expect(hardenReport.artifacts.length).toBe(2);

    // =========================================================================
    // STAGE 4: Equivalence & Verification
    // =========================================================================
    const hardenedJs = hardenReport.artifacts.find((a) =>
      a.relativePath.endsWith("license.cjs"),
    )!;
    expect(hardenedJs.success).toBe(true);

    const mod = req(hardenedJs.outputPath) as {
      verifyLicenseKey: (k: string) => string;
    };
    expect(mod.verifyLicenseKey("BLA3_PRO")).toBe("ENTITLED:PRO");
    expect(mod.verifyLicenseKey("WRONGKEY")).toBe("DENIED");

    // Verify without self_seal_enabled surfaces agentActions to pass self_seal_enabled
    const verifyGapRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 16,
      method: "tools/call",
      params: {
        name: "bla_verify",
        arguments: {
          target_path: hardenedJs.outputPath,
          original_path: licensePath,
        },
      },
    });
    const verifyGapReport = (
      verifyGapRes?.result as { structuredContent: VerificationReport }
    ).structuredContent;
    expect(
      verifyGapReport.agentActions?.some((a) => a.id === "enable-self-seal"),
    ).toBe(true);

    // Verify with self_seal_enabled: true has 0 gap actions and high score
    const verifyFullRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 17,
      method: "tools/call",
      params: {
        name: "bla_verify",
        arguments: {
          target_path: hardenedJs.outputPath,
          original_path: licensePath,
          self_seal_enabled: true,
        },
      },
    });
    const verifyFullReport = (
      verifyFullRes?.result as { structuredContent: VerificationReport }
    ).structuredContent;
    expect(verifyFullReport.overallPassed).toBe(true);
    expect(verifyFullReport.defenseScore).toBeGreaterThanOrEqual(90);
    expect(verifyFullReport.agentActions).toHaveLength(0);

    // CLI parity for weave-plan and verify-weave
    expect(await runCli(["weave-plan", dir])).toBe(0);
    expect(await runCli(["verify-weave", dir, "--json"])).toBe(0);
  });
});
