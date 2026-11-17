import { describe, expect, it } from "vitest";
import {
  formatHardenProjectReport,
  type HardenProjectReport,
} from "../src/engine/harden.js";

/** Minimal valid report with hostile (OSC-bearing) artifact-derived strings. */
function hostileReport(): HardenProjectReport {
  const osc = "\u001b]0;pwned\u0007";
  return {
    blaVersion: "test",
    directory: `${osc}/project`,
    intensity: "bankrupt",
    overallSuccess: false,
    discoveredCount: 1,
    hardenedCount: 0,
    failedCount: 1,
    outputDirectory: `${osc}/project/.bla-hardened`,
    artifacts: [
      {
        inputPath: `${osc}/project/app.js`,
        relativePath: `app${osc}.js`,
        format: "javascript",
        outputPath: `${osc}/project/.bla-hardened/app.js`,
        success: false,
        defenseScore: 0,
        tokenAmplificationFactor: 1,
        costAmplificationFactor: 1,
        outputExisted: false,
        error: `refused: hostile name ${osc}`,
      },
    ],
    oneSentenceUsage: `run bla harden ${osc} to finish`,
    weaveDecoys: false,
    selfSeal: false,
    sidecarEntangle: false,
    selfSealRecommended: false,
    dryRun: false,
    truncated: false,
    maxArtifacts: 100,
    wouldOverwrite: [],
    discoveryReadErrors: [`unreadable${osc}:EACCES`],
    runId: "run-0000",
    cancelled: true,
    written: [`${osc}/project/.bla-hardened/other.js`],
    sidecarEntangleError: `bind failed for ${osc}`,
  };
}

describe("harden report terminal hygiene", () => {
  it("does not forward control characters from artifact-derived strings", () => {
    const text = formatHardenProjectReport(hostileReport());
    expect(text).not.toContain("\u001b]0;");
    expect(text).not.toContain("\u0007");
    expect(text).not.toContain("\u001b");
    // The readable residue stays so operators still see the path shape.
    expect(text).toContain("pwned");
    expect(text).toContain("app");
    expect(text).toContain(".js");
    expect(text).toContain("Output:");
  });
});
