import { describe, expect, it } from "vitest";
import {
  planSidecarEntanglement,
  SIDECAR_ENTANGLE_SCHEMA,
} from "../src/shields/runtime/sidecar-entangle.js";

describe("sidecar entry entanglement planner stub", () => {
  it("returns a bla-sidecar-entangle/v1 plan with stable planId", () => {
    const a = planSidecarEntanglement({
      entryPath: "dist/main.js",
      sidecarPaths: ["dist/main.js.bla-sidecar", "dist/assets.chaff"],
      seedTag: "test-seed",
    });
    const b = planSidecarEntanglement({
      entryPath: "dist/main.js",
      sidecarPaths: ["dist/main.js.bla-sidecar", "dist/assets.chaff"],
      seedTag: "test-seed",
    });
    expect(a.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(a.status).toBe("planned-stub");
    expect(a.entryHookKind).toBe("js-preamble");
    expect(a.planId).toBe(b.planId);
    expect(a.digestAlgorithm).toBe("sha256");
    expect(a.sidecarPaths).toHaveLength(2);
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
