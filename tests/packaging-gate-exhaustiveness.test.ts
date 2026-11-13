import { describe, expect, it } from "vitest";
import {
  filterBlockingFindings,
  type PackagingGateFinding,
} from "../src/engine/packaging-gates.js";

function finding(gate: string, shouldRefuseBankrupt = true): PackagingGateFinding {
  return {
    gate: gate as PackagingGateFinding["gate"],
    path: `/repo/${gate}.js`,
    relativePath: `${gate}.js`,
    shouldRefuseBankrupt,
    oneLineAdvice: "advice",
    findingCount: 1,
  };
}

describe("packaging gate refuse matrix exhaustiveness", () => {
  it("refuses a known blocking gate at bankrupt", () => {
    expect(filterBlockingFindings([finding("seal-commitment")], "bankrupt", {})).toHaveLength(1);
  });

  it("still honours the per-gate allow escape at bankrupt", () => {
    expect(
      filterBlockingFindings([finding("seal-commitment")], "bankrupt", {
        allowPlaintextSeal: true,
      }),
    ).toHaveLength(0);
  });

  it("still lets a low intensity downgrade a known gate to advisory", () => {
    expect(filterBlockingFindings([finding("seal-commitment")], "balanced", {})).toHaveLength(0);
  });

  it("fails closed instead of silently allowing an unhandled gate id", () => {
    expect(() => filterBlockingFindings([finding("future-gate")], "bankrupt", {})).toThrow(
      /Unhandled packaging gate: future-gate/,
    );
  });
});