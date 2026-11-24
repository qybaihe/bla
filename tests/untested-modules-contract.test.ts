import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { sanitizeTerminalText } from "../src/core/terminal-text.js";
import type { ProtectionIntensity } from "../src/core/types.js";
import {
  discoverAndLintReleaseHygiene,
  intensityEnforcesReleaseHygieneRefusal,
  lintReleaseHygieneFile,
  releaseHygieneRefuseMessage,
} from "../src/engine/release-hygiene-lint.js";
import { generateArchitectureMirage } from "../src/shields/deception/architecture-mirage.js";
import { generateDecompilerPseudocodeIllusion } from "../src/shields/deception/decompiler-illusion.js";
import { generateEvidenceContractPoison } from "../src/shields/deception/evidence-contract-poison.js";
import { generateSemanticHoneypot } from "../src/shields/deception/semantic-honeypot.js";
import { generateShadowBusinessLogic } from "../src/shields/deception/shadow-business-logic.js";
import { generateSystemDiagnosticDecoy } from "../src/shields/deception/system-diagnostic-decoy.js";
import { generateCallGraphLabyrinth } from "../src/shields/exhaustion/callgraph-labyrinth.js";
import { generateObligationLedgerFlood } from "../src/shields/exhaustion/obligation-flooder.js";

const intensities: readonly ProtectionIntensity[] = [
  "stealth",
  "balanced",
  "maximum",
  "bankrupt",
];
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-untested-"));
  tempDirs.push(dir);
  return dir;
}

describe("terminal text sanitization", () => {
  it("replaces C0/C1 control characters but keeps newline and tab", () => {
    const raw = "a\u001b]8;;https://evil\u0007b\u0000c\nnext\tcol\u009f";
    const safe = sanitizeTerminalText(raw);
    expect(safe).not.toContain("\u001b");
    expect(safe).not.toContain("\u0000");
    expect(safe).not.toContain("\u009f");
    expect(safe).toContain("\nnext\tcol");
    expect(safe).toBe("a?]8;;https://evil?b?c\nnext\tcol?");
  });

  it("leaves ordinary paths untouched", () => {
    expect(sanitizeTerminalText("dist/../app.js")).toBe("dist/../app.js");
  });
});

describe("release hygiene lint", () => {
  it("flags solution notes, dotenv secrets, private keys and debug symbols", () => {
    const dir = scratch();
    writeFileSync(join(dir, "SOLUTION.md"), "# answer\n", "utf8");
    writeFileSync(join(dir, ".env"), "API_KEY=super-secret-value\n", "utf8");
    writeFileSync(join(dir, "id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\n", "utf8");
    writeFileSync(join(dir, "release.pdb"), "symbols", "utf8");
    writeFileSync(join(dir, "app.js"), "export const x = 1;\n", "utf8");

    const solution = lintReleaseHygieneFile(join(dir, "SOLUTION.md"));
    const dotenv = lintReleaseHygieneFile(join(dir, ".env"));
    const key = lintReleaseHygieneFile(join(dir, "id_ed25519"));
    const pdb = lintReleaseHygieneFile(join(dir, "release.pdb"));
    const benign = lintReleaseHygieneFile(join(dir, "app.js"));

    expect(solution.findings.map((f) => f.kind)).toContain("leaked-solution-or-writeup");
    expect(dotenv.findings.map((f) => f.kind)).toContain("leaked-dotenv-secrets");
    expect(key.findings.map((f) => f.kind)).toContain("leaked-private-key");
    expect(pdb.findings.map((f) => f.kind)).toContain("leaked-debug-symbols");
    expect(benign.findings).toEqual([]);
    expect(benign.shouldRefuseBankrupt).toBe(false);
    expect(solution.shouldRefuseBankrupt).toBe(true);
    expect(releaseHygieneRefuseMessage(solution)).toMatch(/Refusing bankrupt\/maximum harden/);

    const discovered = discoverAndLintReleaseHygiene(dir).map((r) => r.path);
    expect(discovered.length).toBeGreaterThanOrEqual(4);
    expect(intensityEnforcesReleaseHygieneRefusal("bankrupt")).toBe(true);
    expect(intensityEnforcesReleaseHygieneRefusal("maximum")).toBe(true);
    expect(intensityEnforcesReleaseHygieneRefusal("balanced")).toBe(false);
  });
});

describe("deception generators emit runnable, deterministic code", () => {
  const generators = [
    { name: "architecture-mirage", run: (p: SeededPrng, i: ProtectionIntensity) => generateArchitectureMirage(p, i) },
    { name: "decompiler-illusion", run: (p: SeededPrng, i: ProtectionIntensity) => generateDecompilerPseudocodeIllusion(p, i) },
    { name: "evidence-contract-poison", run: (p: SeededPrng, i: ProtectionIntensity) => generateEvidenceContractPoison(p, i) },
    { name: "semantic-honeypot", run: (p: SeededPrng, i: ProtectionIntensity) => generateSemanticHoneypot(p, i) },
    { name: "shadow-business-logic", run: (p: SeededPrng, i: ProtectionIntensity) => generateShadowBusinessLogic(p, i) },
    { name: "system-diagnostic-decoy", run: (p: SeededPrng, i: ProtectionIntensity) => generateSystemDiagnosticDecoy(p, i) },
  ] as const;

  for (const generator of generators) {
    for (const intensity of intensities) {
      it(`${generator.name} (${intensity}) compiles and is seed-stable`, () => {
        const first = generator.run(new SeededPrng(`untested-${generator.name}`), intensity);
        const again = generator.run(new SeededPrng(`untested-${generator.name}`), intensity);
        const other = generator.run(new SeededPrng(`other-${generator.name}`), intensity);
        expect(first.code.length).toBeGreaterThan(0);
        expect(again.code).toBe(first.code);
        expect(other.code).not.toBe(first.code);
        expect(() => new Function(first.code)).not.toThrow();
      });
    }
  }

  it("reports the per-intensity counts the generators actually emit", () => {
    const mirage = generateArchitectureMirage(new SeededPrng("counts"), "stealth");
    expect(mirage.decoyRpcMethods.length).toBe(2);
    expect(mirage.decoyServicesCount).toBeGreaterThan(0);

    expect(
      generateDecompilerPseudocodeIllusion(new SeededPrng("counts"), "stealth")
        .illusionPatternsInjected,
    ).toBe(1);
    expect(
      generateDecompilerPseudocodeIllusion(new SeededPrng("counts"), "bankrupt")
        .illusionPatternsInjected,
    ).toBe(4);

    const evidence = generateEvidenceContractPoison(new SeededPrng("counts"), "bankrupt");
    expect(evidence.lures.length).toBeGreaterThan(0);
    expect(evidence.code).toContain(evidence.lures[0]!.evidenceAnchorId);

    const honeypot = generateSemanticHoneypot(new SeededPrng("counts"), "balanced");
    expect(honeypot.baitSymbols.length).toBeGreaterThan(0);
    for (const symbol of honeypot.baitSymbols) expect(honeypot.code).toContain(symbol);

    const shadow = generateShadowBusinessLogic(new SeededPrng("counts"), "maximum");
    expect(shadow.archetypesInjected.length).toBeGreaterThan(0);
    expect(shadow.shadowProceduresCreated.length).toBeGreaterThan(0);
    expect(shadow.decoyConstantsCount).toBeGreaterThan(0);

    const diagnostics = generateSystemDiagnosticDecoy(new SeededPrng("counts"), "balanced", {
      platform: "windows",
    });
    expect(diagnostics.diagnosticsInjected.length).toBeGreaterThan(0);
    expect(diagnostics.estimatedTroubleshootingTokensInduced).toBe(
      diagnostics.diagnosticsInjected.length * 1650,
    );
  });
});

describe("exhaustion generators emit runnable, bounded code", () => {
  for (const intensity of intensities) {
    it(`callgraph-labyrinth (${intensity}) compiles and reports its nodes`, () => {
      const result = generateCallGraphLabyrinth(new SeededPrng("untested-callgraph"), intensity);
      expect(result.sccClusterCount).toBeGreaterThan(0);
      expect(result.totalLabyrinthNodes).toBe(result.sccClusterCount * 5);
      expect(result.crossReferenceEdgesCreated).toBeGreaterThan(0);
      expect(result.code).toContain(result.entrySymbol);
      expect(() => new Function(result.code)).not.toThrow();
    });

    it(`obligation-flooder (${intensity}) compiles and reports its families`, () => {
      const result = generateObligationLedgerFlood(new SeededPrng("untested-obligation"), intensity);
      expect(result.obligationFamiliesInjected.length).toBeGreaterThan(0);
      expect(result.totalDecoyObligations).toBeGreaterThan(0);
      expect(result.mandatoryVerificationCasesInduced).toBeGreaterThan(0);
      expect(result.obligationFamiliesInjected).toContain("package");
      expect(result.code).toContain("_never");
      expect(() => new Function(result.code)).not.toThrow();
    });
  }
});