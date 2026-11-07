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
      jsTargetPlan!.surgicalWorkorder!.crownJewelCandidates.some(
        (c) =>
          c.functionName === "verifyLicenseKey" &&
          (c.vulnerabilityKind === "single-point-boolean-gate" ||
            c.vulnerabilityKind === "isolated-verify-oracle"),
      ),
    ).toBe(true);
    expect(
      jsTargetPlan!.surgicalWorkorder!.dataFlowEntanglementPlan.stateCarrierName,
    ).toBe("target");
    expect(
      jsTargetPlan!.surgicalWorkorder!.agentRewriteRecipe.length,
    ).toBeGreaterThanOrEqual(3);

    // Calling bla_harden with require_agent_weave: true BEFORE Stage 2 source
    // surgery is refused by the Agent-First gate and returns surgicalWorkorders + agentActions
    const prematureHardenRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 115,
      method: "tools/call",
      params: {
        name: "bla_harden",
        arguments: {
          directory: dir,
          require_agent_weave: true,
          weave_decoys: true,
        },
      },
    });
    expect((prematureHardenRes?.result as { isError: boolean }).isError).toBe(
      true,
    );
    const prematureReport = (
      prematureHardenRes?.result as {
        structuredContent: {
          overallSuccess: boolean;
          agentWeaveGateBlocked?: boolean;
          agentWeaveAssessment?: {
            weaveVerified: boolean;
            unwovenSourceFiles: string[];
            agentActions: unknown[];
            surgicalWorkorders: Record<string, unknown>;
          };
        };
      }
    ).structuredContent;
    expect(prematureReport.overallSuccess).toBe(false);
    expect(prematureReport.agentWeaveGateBlocked).toBe(true);
    expect(prematureReport.agentWeaveAssessment?.weaveVerified).toBe(false);
    expect(prematureReport.agentWeaveAssessment?.unwovenSourceFiles).toContain(
      "license.cjs",
    );
    expect(
      prematureReport.agentWeaveAssessment?.agentActions.length,
    ).toBeGreaterThanOrEqual(1);
    expect(
      prematureReport.agentWeaveAssessment?.surgicalWorkorders["license.cjs"],
    ).toBeDefined();

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
    // STAGE 3: Post-Build Counter-REA Exhaustion Harden (with require_agent_weave: true)
    // =========================================================================
    const hardenRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 15,
      method: "tools/call",
      params: {
        name: "bla_harden",
        arguments: {
          directory: dir,
          require_agent_weave: true,
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
          agentWeaveGateBlocked?: boolean;
          agentWeaveAssessment?: {
            weaveVerified: boolean;
            weaveScore: number;
          };
          artifacts: Array<{
            relativePath: string;
            outputPath: string;
            success: boolean;
          }>;
        };
      }
    ).structuredContent;
    expect(hardenReport.overallSuccess).toBe(true);
    expect(hardenReport.agentWeaveGateBlocked).toBeUndefined();
    expect(hardenReport.agentWeaveAssessment?.weaveVerified).toBe(true);
    expect(hardenReport.agentWeaveAssessment?.weaveScore).toBe(100);
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

  it("extracts crownJewelCandidates and native surgicalWorkorders for C/Rust/Go sources", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-v3-native-workorder-"));
    temps.push(dir);

    writeFileSync(
      join(dir, "auth.rs"),
      `
pub fn verify_license_token(token: &str) -> bool {
    token.len() == 16
}
`.trim() + "\n",
      "utf8",
    );
    writeFileSync(
      join(dir, "gate.js"),
      `
export function checkSubscriptionTier(secret) {
  if (secret === "PRO_ENTERPRISE_2026") return true;
  return false;
}
`.trim() + "\n",
      "utf8",
    );

    const planRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 20,
      method: "tools/call",
      params: {
        name: "bla_weave_plan",
        arguments: { path: dir },
      },
    });
    const plan = (planRes?.result as { structuredContent: WeavePlan })
      .structuredContent;
    const rustTarget = plan.targets.find((t) =>
      t.relativePath.endsWith("auth.rs"),
    );
    expect(rustTarget?.surgicalWorkorder?.language).toBe("native-source");
    expect(
      rustTarget?.surgicalWorkorder?.crownJewelCandidates.some(
        (c) => c.functionName === "verify_license_token",
      ),
    ).toBe(true);

    const jsTarget = plan.targets.find((t) =>
      t.relativePath.endsWith("gate.js"),
    );
    expect(
      jsTarget?.surgicalWorkorder?.crownJewelCandidates.some(
        (c) => c.vulnerabilityKind === "single-point-boolean-gate",
      ),
    ).toBe(true);
    expect(
      jsTarget?.surgicalWorkorder?.crownJewelCandidates.some(
        (c) => c.vulnerabilityKind === "cleartext-comparison",
      ),
    ).toBe(true);
  });

  it("rejects cosmetic side-effect-only weaves, raw boolean gates, and syntax errors via Check 7 (crown-jewel-entanglement)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-v3-cosmetic-weave-"));
    temps.push(dir);
    const gatePath = join(dir, "gate.mjs");

    // 1. Cosmetic weave: passes checks 1-6 (mundane stems, shared state read/write across 2 fns,
    // reachable helper edges, opaque-true if guard, non-empty bodies), but leaves a cleartext
    // secret compare, raw boolean returns, and side-effect-only helper calls in the gate entry.
    writeFileSync(
      gatePath,
      `
const sessionLedgerState = { epoch: 1, digest: 0x5f3759df };

function reconcileSessionQuota(step) {
  sessionLedgerState.epoch = (sessionLedgerState.epoch + step) | 1;
  return sessionLedgerState.epoch;
}

function auditLedgerEpoch() {
  sessionLedgerState.digest = (sessionLedgerState.digest ^ sessionLedgerState.epoch) >>> 0;
  return sessionLedgerState.digest;
}

export function verifyLicense(key) {
  if ((sessionLedgerState.epoch & 1) !== 0) {
    reconcileSessionQuota(1);
    auditLedgerEpoch();
  }
  if (key === "SUPER-SECRET-2026") return true;
  return false;
}
`.trim() + "\n",
      "utf8",
    );

    const cosmeticRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 30,
      method: "tools/call",
      params: {
        name: "bla_verify_weave",
        arguments: { path: gatePath },
      },
    });
    expect((cosmeticRes?.result as { isError: boolean }).isError).toBe(true);
    const cosmeticReport = (
      cosmeticRes?.result as { structuredContent: WeaveVerificationReport }
    ).structuredContent;
    expect(cosmeticReport.overallPassed).toBe(false);
    const crownCheck = cosmeticReport.files[0]?.checks.find(
      (c) => c.id === "crown-jewel-entanglement",
    );
    expect(crownCheck?.passed).toBe(false);
    expect(crownCheck?.evidence).toContain("raw boolean return");
    expect(crownCheck?.evidence).toContain("cleartext secret comparison");
    expect(crownCheck?.evidence).toContain("cosmetic/unentangled gate");

    // 2. Broken syntax introduced during source surgery is caught with syntaxValid: false
    writeFileSync(
      gatePath,
      `export function verifyLicense(key { return key; }\n`,
      "utf8",
    );
    const syntaxRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 31,
      method: "tools/call",
      params: {
        name: "bla_verify_weave",
        arguments: { path: gatePath },
      },
    });
    expect((syntaxRes?.result as { isError: boolean }).isError).toBe(true);
    const syntaxReport = (
      syntaxRes?.result as { structuredContent: WeaveVerificationReport }
    ).structuredContent;
    expect(syntaxReport.overallPassed).toBe(false);
    expect(syntaxReport.files[0]?.syntaxValid).toBe(false);
  });

  it("verifies native C/Rust source weave and enforces require_agent_weave on bla_defend", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-v3-native-verify-defend-"));
    temps.push(dir);
    const cPath = join(dir, "auth.c");
    const jsPath = join(dir, "token.cjs");

    writeFileSync(
      cPath,
      `
int verify_token(const char *input) {
  if (strcmp(input, "PLAIN_C_SECRET") == 0) {
    return true;
  }
  return false;
}
`.trim() + "\n",
      "utf8",
    );

    const cVerify1 = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 40,
      method: "tools/call",
      params: {
        name: "bla_verify_weave",
        arguments: { path: cPath },
      },
    });
    expect((cVerify1?.result as { isError: boolean }).isError).toBe(true);
    const cReport1 = (
      cVerify1?.result as { structuredContent: WeaveVerificationReport }
    ).structuredContent;
    expect(cReport1.overallPassed).toBe(false);
    expect(cReport1.files[0]?.format).toBe("native-source");

    // Weave shared state + mundane helpers + bitwise mixing into auth.c
    writeFileSync(
      cPath,
      `
static unsigned int g_session_ledger_epoch = 1u;

static unsigned int reconcile_session_quota(unsigned int step) {
  g_session_ledger_epoch = (g_session_ledger_epoch ^ step) | 1u;
  return g_session_ledger_epoch;
}

static unsigned int audit_quota_digest(const char *buf, unsigned int seed) {
  unsigned int acc = seed ^ g_session_ledger_epoch;
  for (int i = 0; buf[i] != 0; i++) {
    acc = (acc ^ (unsigned int)buf[i]) * 16777619u;
  }
  return acc;
}

int verify_token(const char *input) {
  if ((g_session_ledger_epoch & 1u) != 0u) {
    reconcile_session_quota(3u);
  }
  unsigned int digest = audit_quota_digest(input, 2166136261u);
  return (digest ^ (g_session_ledger_epoch & 1u)) == 0x1a2b3c4du ? 200 : 403;
}
`.trim() + "\n",
      "utf8",
    );

    const cVerify2 = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 41,
      method: "tools/call",
      params: {
        name: "bla_verify_weave",
        arguments: { path: cPath },
      },
    });
    expect((cVerify2?.result as { isError: boolean }).isError).toBe(false);
    const cReport2 = (
      cVerify2?.result as { structuredContent: WeaveVerificationReport }
    ).structuredContent;
    expect(cReport2.overallPassed).toBe(true);
    expect(cReport2.weaveScore).toBe(100);

    // Verify bla_defend with require_agent_weave: true refuses unwoven JS and succeeds after weave
    writeFileSync(
      jsPath,
      `
function verifyApiKey(k) {
  return k === "RAW_KEY_1234";
}
module.exports = { verifyApiKey };
`.trim() + "\n",
      "utf8",
    );

    const defendBlocked = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 42,
      method: "tools/call",
      params: {
        name: "bla_defend",
        arguments: {
          input_path: jsPath,
          output_path: join(dir, "token.defended.cjs"),
          require_agent_weave: true,
          weave_decoys: true,
        },
      },
    });
    expect((defendBlocked?.result as { isError: boolean }).isError).toBe(true);
    expect(
      (defendBlocked?.result as { content: Array<{ text: string }> }).content[0]
        ?.text,
    ).toContain("refused by require_agent_weave");
  });
});
