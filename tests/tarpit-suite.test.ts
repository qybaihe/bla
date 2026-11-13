import { spawnSync } from "node:child_process";
import { Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import {
  generateJsTarpitAndBudgetBreaker,
  generatePythonTarpit,
} from "../src/shields/tarpit/tarpit-generator.js";
import type { ProtectionIntensity } from "../src/core/types.js";

const chaff = generateChaffPayloads(new SeededPrng("tarpit-chaff"), "bankrupt");

const JS_DECOY_COUNTS: ReadonlyArray<readonly [ProtectionIntensity, number]> = [
  ["stealth", 6],
  ["balanced", 14],
  ["maximum", 24],
  ["bankrupt", 36],
];

const PYTHON_DECOY_COUNTS: ReadonlyArray<readonly [ProtectionIntensity, number]> = [
  ["stealth", 5],
  ["balanced", 10],
  ["maximum", 18],
  ["bankrupt", 18],
];

describe("tarpit generator suite (JS)", () => {
  it("scales decoy function counts with intensity (plus alias/budget/anchor)", () => {
    for (const [intensity, decoys] of JS_DECOY_COUNTS) {
      const result = generateJsTarpitAndBudgetBreaker(
        new SeededPrng(`js-tarpit-${intensity}`),
        intensity,
        chaff,
      );
      expect(result.decoyFunctionNames, `intensity ${intensity}`).toHaveLength(
        decoys + 3,
      );
      expect(new Set(result.decoyFunctionNames).size).toBe(decoys + 3);
      expect(result.crossReferenceEdges).toBeGreaterThanOrEqual(4 * decoys);
    }
  });

  it("emits syntactically valid JavaScript (compiles without executing)", () => {
    for (const intensity of ["stealth", "bankrupt"] as const) {
      const result = generateJsTarpitAndBudgetBreaker(
        new SeededPrng(`js-parse-${intensity}`),
        intensity,
        chaff,
      );
      expect(() => new Script(result.code), intensity).not.toThrow();
    }
  });

  it("reports the five documented semantic budget triggers", () => {
    const result = generateJsTarpitAndBudgetBreaker(
      new SeededPrng("js-triggers"),
      "balanced",
      chaff,
    );
    expect(result.semanticBudgetTriggers).toEqual([
      "alias-selections",
      "primitive-candidates",
      "primitive-bytes",
      "getter-expansion",
      "returned-reference-widening",
    ]);
  });

  it("embeds chaff raw texts and stays deterministic per seed", () => {
    const a = generateJsTarpitAndBudgetBreaker(new SeededPrng("js-det"), "balanced", chaff);
    const b = generateJsTarpitAndBudgetBreaker(new SeededPrng("js-det"), "balanced", chaff);
    expect(a.code).toBe(b.code);
    expect(a.code).toContain(chaff[0]!.rawText);
    expect(a.code).not.toMatch(/\$00_AAA|BLA-SHIELD/i);
  });
});

describe("tarpit generator suite (Python)", () => {
  it("emits warm-init, shared slot, and state var names without BLA markers", () => {
    for (const [intensity, decoys] of PYTHON_DECOY_COUNTS) {
      const result = generatePythonTarpit(
        new SeededPrng(`py-tarpit-${intensity}`),
        intensity,
        chaff,
      );
      expect(result.decoyFunctionNames, `intensity ${intensity}`).toHaveLength(
        decoys + 1,
      );
      expect(result.sharedSlotName).toBeTruthy();
      expect(result.stateVarName).toBeTruthy();
      expect(result.warmInitName).toBeTruthy();
      expect(result.code).toContain(`def ${result.warmInitName}(`);
      expect(result.code).toContain(`${result.warmInitName}(`);
      expect(result.code).not.toMatch(/_bla|\$00_AAA|BLA-SHIELD/i);
      expect(result.semanticBudgetTriggers).toEqual([
        "python-marshal-code-graph-tarpit",
      ]);
    }
  });

  it("emits syntactically valid Python when an interpreter is available", () => {
    const python =
      spawnSync("python3", ["--version"], { encoding: "utf8" }).status === 0
        ? "python3"
        : spawnSync("python", ["--version"], { encoding: "utf8" }).status === 0
          ? "python"
          : null;
    if (python === null) return; // No interpreter in this environment — compile check skipped.
    const result = generatePythonTarpit(
      new SeededPrng("py-parse"),
      "balanced",
      chaff,
    );
    const probe = spawnSync(
      python,
      ["-c", `import sys; compile(sys.stdin.read(), "tarpit.py", "exec")`],
      { encoding: "utf8", input: result.code },
    );
    expect(probe.status, probe.stderr).toBe(0);
  });
});
