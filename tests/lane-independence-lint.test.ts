import { describe, expect, it } from "vitest";
import { lintLaneIndependence } from "../src/engine/lane-independence-lint.js";

describe("lane-independence footgun lint (#40.1)", () => {
  it("stays quiet on chained whole-key mixing (Meridian-like)", () => {
    const src = `
      function activate(key) {
        let a = pack(key.slice(0,5)), b = pack(key.slice(5,10));
        let c = pack(key.slice(10,15)), d = pack(key.slice(15,20));
        for (let r = 0; r < 24; r++) {
          a = (a + b) | 0; b = rotl(b ^ a, 7);
          c = (c + d) | 0; d = rotl(d ^ c, 9);
          a ^= c; b ^= d;
        }
        return hex(a,b,c,d) === catalog.revision;
      }
    `;
    const report = lintLaneIndependence(src);
    expect(report.looksLaneIndependent).toBe(false);
    expect(report.findings).toHaveLength(0);
  });

  it("warns on per-lane byte compare table + key identifiers", () => {
    const src = `
      const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];
      function check(key) {
        return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]);
      }
    `;
    const report = lintLaneIndependence(src);
    expect(report.looksLaneIndependent).toBe(true);
    expect(report.findings.some((f) => f.id === "per-lane-byte-compare-array")).toBe(true);
    expect(report.findings.some((f) => f.id === "independent-lane-and-reduce")).toBe(true);
    expect(report.oneLineAdvice).toMatch(/whole-key chained mixing/i);

    const explicit = lintLaneIndependence(`
      const lanes = [1,2,3,4];
      const ok = lanes.every((b) => b > 0);
    `);
    expect(explicit.findings.some((f) => f.id === "independent-lane-and-reduce")).toBe(true);
  });

  it("warns on indexed lane oracle loops", () => {
    const src = `
      for (let i = 0; i < 16; i++) {
        if (key[i] === target[i]) ok++;
      }
    `;
    const report = lintLaneIndependence(src);
    expect(report.findings.some((f) => f.id === "indexed-lane-oracle-loop")).toBe(true);
  });
});
