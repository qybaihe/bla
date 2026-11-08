import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { protectTarget } from "../src/engine/protector.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-coverage-contract-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("coverage contract surfaced on audit and verify reports", () => {
  it("audit output states the client-artifact-only scope", () => {
    const dir = makeTempDir();
    const target = join(dir, "app.js");
    writeFileSync(target, "export const answer = 42;\n", "utf8");

    const contract = auditTarget(target).coverageContract;
    expect(contract).toBeDefined();
    expect(contract!.clientArtifact.status).toBe("not-protected");
    expect(contract!.clientArtifact.guaranteesConfidentialityOfShippedData).toBe(false);
    expect(contract!.clientArtifact.enforcesAccessControl).toBe(false);
    expect(contract!.serverAuthorization.status).toBe(
      "not-assessed/external-control-required",
    );
    expect(contract!.threatPremises.length).toBeGreaterThan(0);
    expect(
      contract!.threatPremises.every((p) => p.coveredByClientArtifactShield === false),
    ).toBe(true);
  });

  it("verify output carries the same contract and marks a protected client artifact", () => {
    const dir = makeTempDir();
    const input = join(dir, "app.js");
    const output = join(dir, "app.shielded.js");
    writeFileSync(input, "export const answer = 42;\n", "utf8");
    protectTarget({ inputPath: input, outputPath: output, intensity: "balanced" });

    const contract = verifyTarget(output, input).coverageContract;
    expect(contract).toBeDefined();
    expect(contract!.clientArtifact.guaranteesConfidentialityOfShippedData).toBe(false);
    expect(contract!.clientArtifact.enforcesAccessControl).toBe(false);
  });
});