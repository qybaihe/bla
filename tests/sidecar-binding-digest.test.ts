import { describe, expect, it } from "vitest";
import {
  computeSidecarBindingDigest,
} from "../src/shields/runtime/sidecar-entangle.js";

describe("computeSidecarBindingDigest", () => {
  it("is deterministic for identical entry + sidecars + seedTag", () => {
    const entry = {
      pathLabel: "main.js",
      bytes: new TextEncoder().encode("module.exports = 1;\n"),
    };
    const sidecars = [
      {
        pathLabel: "main.js.bla-sidecar",
        bytes: new TextEncoder().encode("chaff-a"),
      },
      {
        pathLabel: "assets.chaff",
        bytes: new TextEncoder().encode("chaff-b"),
      },
    ];
    const a = computeSidecarBindingDigest(entry, sidecars, "test-seed");
    const b = computeSidecarBindingDigest(entry, sidecars, "test-seed");
    expect(a.hex).toBe(b.hex);
    expect(a.hex).toMatch(/^[0-9a-f]{64}$/);
    expect(a.u32).toBe(parseInt(a.hex.slice(0, 8), 16) >>> 0);
    expect(a.u32).toBeGreaterThan(0);
  });

  it("sidecars mode ignores entry body changes (preamble-safe)", () => {
    const sib = {
      pathLabel: "sib.js",
      bytes: new TextEncoder().encode("sidecar-bytes"),
    };
    const a = computeSidecarBindingDigest(
      { pathLabel: "main.js", bytes: new TextEncoder().encode("v1") },
      [sib],
      "v1",
      "sidecars",
    );
    const b = computeSidecarBindingDigest(
      { pathLabel: "main.js", bytes: new TextEncoder().encode("v1-WITH-PREAMBLE") },
      [sib],
      "v1",
      "sidecars",
    );
    expect(a.hex).toBe(b.hex);
  });

  it("full mode includes entry body", () => {
    const sib = {
      pathLabel: "sib.js",
      bytes: new TextEncoder().encode("sidecar-bytes"),
    };
    const a = computeSidecarBindingDigest(
      { pathLabel: "main.js", bytes: new TextEncoder().encode("v1") },
      [sib],
      "v1",
      "full",
    );
    const b = computeSidecarBindingDigest(
      { pathLabel: "main.js", bytes: new TextEncoder().encode("v2") },
      [sib],
      "v1",
      "full",
    );
    expect(a.hex).not.toBe(b.hex);
  });

  it("changes when a sidecar is stripped or altered (strip⇒fail contract)", () => {
    const entry = {
      pathLabel: "main.js",
      bytes: new TextEncoder().encode("ok"),
    };
    const sidecar = {
      pathLabel: "sib.js",
      bytes: new TextEncoder().encode("sidecar-bytes"),
    };
    const base = computeSidecarBindingDigest(entry, [sidecar], "v1");
    const stripped = computeSidecarBindingDigest(entry, [], "v1");
    const altered = computeSidecarBindingDigest(
      entry,
      [{ ...sidecar, bytes: new TextEncoder().encode("TAMPERED") }],
      "v1",
    );
    expect(stripped.hex).not.toBe(base.hex);
    expect(altered.hex).not.toBe(base.hex);
    expect(stripped.u32).not.toBe(base.u32);
    expect(altered.u32).not.toBe(base.u32);
  });

  it("changes when seedTag differs", () => {
    const entry = {
      pathLabel: "e.js",
      bytes: new Uint8Array([1, 2, 3]),
    };
    const a = computeSidecarBindingDigest(entry, [], "tag-a");
    const b = computeSidecarBindingDigest(entry, [], "tag-b");
    expect(a.hex).not.toBe(b.hex);
  });
});
