import { describe, expect, it } from "vitest";
import {
  planSidecarEntanglement,
  SIDECAR_ENTANGLE_SCHEMA,
} from "../src/shields/runtime/sidecar-entangle.js";
import { evaluateCoverageMatrix } from "../src/engine/integrity-coverage.js";

describe("sidecar entry entanglement planner (Direction-3)", () => {
  it("returns a bla-sidecar-entangle/v1 plan with stable planId + coverage matrix", () => {
    const fileBytes = {
      "dist/main.js": Buffer.from("entry-body-v1"),
      "dist/main.js.bla-sidecar": Buffer.from("sidecar-a"),
      "dist/assets.chaff": Buffer.from("chaff"),
    };
    const a = planSidecarEntanglement({
      entryPath: "dist/main.js",
      sidecarPaths: ["dist/main.js.bla-sidecar", "dist/assets.chaff"],
      seedTag: "test-seed",
      fileBytes,
    });
    const b = planSidecarEntanglement({
      entryPath: "dist/main.js",
      sidecarPaths: ["dist/main.js.bla-sidecar", "dist/assets.chaff"],
      seedTag: "test-seed",
      fileBytes,
    });
    expect(a.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(a.status).toBe("ready");
    expect(a.entryHookKind).toBe("js-preamble");
    expect(a.planId).toBe(b.planId);
    expect(a.digestAlgorithm).toBe("sha256");
    expect(a.sidecarPaths).toHaveLength(2);
    expect(a.coverageMatrix.schema).toBe("bla-integrity-coverage/v1");
    expect(evaluateCoverageMatrix(a.coverageMatrix).ok).toBe(true);
  });

  it("marks incomplete when hashes are missing", () => {
    const plan = planSidecarEntanglement({
      entryPath: "dist/main.js",
      sidecarPaths: ["dist/sib.wasm"],
      seedTag: "no-bytes",
    });
    expect(plan.status).toBe("incomplete");
    expect(plan.coverageEvaluation.shouldRefuseBankrupt).toBe(true);
  });

  it("guesses python / wasm hook kinds", () => {
    expect(
      planSidecarEntanglement({ entryPath: "app.py", sidecarPaths: ["app.pyc"] })
        .entryHookKind,
    ).toBe("python-preamble");
    expect(
      planSidecarEntanglement({ entryPath: "core.wasm", sidecarPaths: ["core.name"] })
        .entryHookKind,
    ).toBe("wasm-custom-section");
  });
});
