import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { generatePromptCompletionPoison } from "../src/shields/deception/prompt-completion-poison.js";
import { generateVersionDiffNoise } from "../src/shields/deception/diff-noise-injector.js";
import { generateCrashTraceDecoy } from "../src/shields/deception/crash-trace-decoy.js";
import { generateRegexWorkerTarpit } from "../src/shields/exhaustion/regex-worker-tarpit.js";
import { generateAsarHeaderDecoyFiles } from "../src/shields/exhaustion/asar-header-amplifier.js";

describe("Prompt Completion, Version Diff, Crash Trace & Regex/ASAR Shields", () => {
  it("sorts $-prefixed early-sort symbols ahead of standard identifiers without a shared greppable literal", () => {
    const res = generatePromptCompletionPoison(
      new SeededPrng("sort-seed"),
      "bankrupt",
    );
    expect(res.prioritySortedSymbols).toHaveLength(8);
    for (const sym of res.prioritySortedSymbols) {
      expect(sym.startsWith("$")).toBe(true);
      expect(sym).not.toMatch(/\$00_AAA/);
    }
    // No shared greppable prefix longer than "$" across the set
    const tails = res.prioritySortedSymbols.map((s) => s.slice(1, 3));
    expect(new Set(tails).size).toBeGreaterThan(1);
    const earliest = [...res.prioritySortedSymbols].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))[0]!;
    const combined = ["verifyLicense", "authenticate", ...res.prioritySortedSymbols];
    combined.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(combined[0]).toBe(earliest);
    expect(earliest < "authenticate").toBe(true);
    expect(earliest < "verifyLicense").toBe(true);
  });

  it("generates version-diff structural permutations and crash-trace decoy signals", () => {
    const prng = new SeededPrng("diff-crash");
    const diff = generateVersionDiffNoise(prng, "maximum");
    expect(diff.permutedBlocksCount).toBe(6);
    expect(diff.syntheticDiffFrontiersCreated).toBe(24);

    const crash = generateCrashTraceDecoy(prng, "bankrupt");
    expect(crash.decoyCrashSignalsEmbedded).toHaveLength(4);
    expect(crash.code).toContain("SIGSEGV_ENCLAVE_EPC_PAGE_FAULT");
  });

  it("generates regex worker search magnets and ASAR header decoy shard files", () => {
    const prng = new SeededPrng("regex-asar");
    const regex = generateRegexWorkerTarpit(prng, "bankrupt");
    expect(regex.nearMissCandidatesGenerated).toBe(64);

    const asarFiles = generateAsarHeaderDecoyFiles(prng, "bankrupt");
    expect(asarFiles.length).toBeGreaterThan(1000);
    expect(asarFiles[0]!.relativePath).toContain("enclave/shards/");
  });
});
