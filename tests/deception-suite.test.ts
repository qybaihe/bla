import { describe, expect, it } from "vitest";
import { withLlmDirectives } from "../src/core/llm-directives.js";
import { SeededPrng } from "../src/core/prng.js";
import {
  generateArchitectureMirage,
  generateCanaryHoneypot,
  generateCounterReaDeceptionSuite,
  generateDecompilerPseudocodeIllusion,
  generateEvidenceContractPoison,
  generateSemanticHoneypot,
  generateShadowBusinessLogic,
  generateSystemDiagnosticDecoy,
} from "../src/shields/deception/index.js";

describe("Counter-REA Model-Misjudgment Induction Suite", () => {
  it("generates crystal-clear Shadow Business Logic across all 4 archetypes", () => {
    const prng = new SeededPrng("shadow-test");
    const res = generateShadowBusinessLogic(prng, "bankrupt");
    expect(res.archetypesInjected).toHaveLength(4);
    expect(res.shadowProceduresCreated).toHaveLength(4);
    expect(res.code).toContain("RFC8032-Ed25519-Shamir-3-of-5");
    expect(res.code).toContain("bla.enterprise.billing.v4");
    expect(res.code).toContain("TPM2.0-Quote-PCR0-PCR7");
  });

  it("embeds Evidence Contract competing-explanation lures targeting REA COMMON_DISCIPLINE", () => {
    const prng = new SeededPrng("evidence-poison");
    const res = generateEvidenceContractPoison(prng, "bankrupt");
    expect(res.lures).toHaveLength(4);
    expect(res.lures[0]!.decoyConfidenceScore).toBeGreaterThan(0.9);
    expect(res.code).toContain("vsock://16:9443");
  });

  it("generates gRPC/Protobuf architecture mirages and high-salience semantic honeypot functions", () => {
    const prng = new SeededPrng("mirage-honeypot");
    const mirage = generateArchitectureMirage(prng, "bankrupt");
    expect(mirage.decoyRpcMethods).toHaveLength(8);
    expect(mirage.code).toContain("AttestationAuthority/VerifyEnclaveQuote");

    const honeypot = generateSemanticHoneypot(prng, "bankrupt");
    expect(honeypot.baitSymbols).toHaveLength(8);
    expect(honeypot.baitSymbols[0]).toMatch(/^verifyEnterpriseMasterLicense_/);
  });

  it("creates shared-ArrayBuffer decompiler aliasing illusions and orchestrates the full deception suite", () => {
    const prng = new SeededPrng("illusion-suite");
    const illusion = generateDecompilerPseudocodeIllusion(prng, "maximum");
    expect(illusion.illusionPatternsInjected).toBe(3);
    expect(illusion.code).toContain("Int32Array(_rawBuf)");

    const suite = generateCounterReaDeceptionSuite(
      new SeededPrng("full-deception"),
      "bankrupt",
    );
    expect(suite.totalDeceptionNodesInjected).toBeGreaterThanOrEqual(44);
    expect(suite.combinedJsCode).toMatch(/grpcServiceMirage_[a-f0-9]+/);
  });

  it("generates Canary Credential Honeypots triggering REA recordedTransportUrl ambiguous redaction and System-Diagnostic Rabbit Holes", () => {
    const prng = new SeededPrng("canary-diag");
    const canary = withLlmDirectives(true, () => generateCanaryHoneypot(prng, "bankrupt"));
    expect(canary.syntheticCanaryTokens).toHaveLength(8);
    expect(canary.complianceBoundaryNotices).toHaveLength(3);
    expect(canary.code).toContain("COPPA_16_CFR_312");
    expect(canary.code).toContain("IEC_62304_CLASS_C");
    expect(canary.triggersReaTransportRedaction).toBe(true);
    expect(canary.triggersReaQueryConflictUnknown).toBe(true);

    // Verify exact REA recordedTransportUrl.ts:25-46 condition:
    // WHATWG URL.parse sees username/password, while REA's two-slash prefix regex returns null!
    const sampleUrl = canary.ambiguousCredentialUrls[0]!;
    const parsedUrl = new URL(sampleUrl);
    expect(parsedUrl.username.length).toBeGreaterThan(0);
    expect(parsedUrl.password.length).toBeGreaterThan(0);
    const reaTwoSlashPrefix = /^[\x00-\x20]*(?:([A-Za-z][A-Za-z0-9+.-]*):)?\/\//u;
    expect(reaTwoSlashPrefix.exec(sampleUrl)).toBeNull();

    const diag = generateSystemDiagnosticDecoy(prng, "bankrupt");
    expect(diag.diagnosticsInjected).toHaveLength(8);
    expect(diag.estimatedTroubleshootingTokensInduced).toBeGreaterThanOrEqual(12_000);
    expect(diag.code).toContain("DarwinProcessOwnershipInspectionError");
    expect(diag.code).toContain("GhidraSnapshotCacheMismatchError");
  });
});
