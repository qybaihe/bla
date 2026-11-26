import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  lintLaneIndependence,
  formatSupportsLaneIndependenceLint,
  laneIndependenceRefuseMessage,
  MAX_SCAN_CHARS,
} from "../src/engine/lane-independence-lint.js";

describe("lane-independence footgun lint (#40.1 / red-blue round-1)", () => {
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

  it("errors on per-lane byte compare table + key identifiers", () => {
    const src = `
      const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];
      function check(key) {
        return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]);
      }
    `;
    const report = lintLaneIndependence(src);
    expect(report.looksLaneIndependent).toBe(true);
    expect(report.findings.every((f) => f.severity === "error")).toBe(true);
    expect(report.findings.some((f) => f.id === "per-lane-byte-compare-array")).toBe(true);
    expect(report.findings.some((f) => f.id === "independent-lane-and-reduce")).toBe(true);
    expect(report.oneLineAdvice).toMatch(/whole-key chained mixing/i);
    expect(report.oneLineAdvice).toMatch(/ERROR/i);

    const explicit = lintLaneIndependence(`
      const lanes = [1,2,3,4];
      const ok = lanes.every((b) => b > 0);
    `);
    expect(explicit.findings.some((f) => f.id === "independent-lane-and-reduce")).toBe(true);
  });

  it("errors on indexed lane oracle loops", () => {
    const src = `
      for (let i = 0; i < 16; i++) {
        if (key[i] === target[i]) ok++;
      }
    `;
    const report = lintLaneIndependence(src);
    expect(report.findings.some((f) => f.id === "indexed-lane-oracle-loop")).toBe(true);
    expect(report.findings[0]!.severity).toBe("error");
  });

  it("ignores all-zero init arrays used for whole-key packing (round-2 blue)", () => {
    const src = `
      function packWord(key, start) {
        let w = 0;
        for (let i = 0; i < 4; i++) w = (w << 8) | key.charCodeAt(start + i);
        return w | 0;
      }
      function activate(key) {
        let a = packWord(key, 0), b = packWord(key, 4), c = packWord(key, 8), d = packWord(key, 12);
        // legacy-looking zero buffer that is NOT a compare table:
        const scratch = [0, 0, 0, 0];
        void scratch;
        for (let r = 0; r < 24; r++) {
          a = (a + b) | 0; b = (b ^ a) | 0; c = (c + d) | 0; d = (d ^ c) | 0;
          a ^= c; b ^= d;
        }
        return (a ^ b ^ c ^ d) === 0x12345678;
      }
    `;
    const report = lintLaneIndependence(src);
    expect(report.findings.some((f) => f.id === "per-lane-byte-compare-array")).toBe(false);
    expect(report.looksLaneIndependent).toBe(false);
  });

  it("errors on CrackMe v6-style per-byte WASM lane oracles", () => {
    const tpl = readFileSync(
      resolve(process.cwd(), "challenge/v6/src/vault.template.cjs"),
      "utf8",
    );
    const report = lintLaneIndependence(tpl);
    expect(report.looksLaneIndependent).toBe(true);
    expect(report.findings.some((f) => f.id === "per-byte-wasm-lane-oracle")).toBe(true);
    expect(report.findings.every((f) => f.severity === "error")).toBe(true);
    expect(laneIndependenceRefuseMessage(report, "/tmp/vault.cjs")).toMatch(
      /allowLaneIndependentGates|allow-lane-independent/i,
    );
  });

  it("formatSupportsLaneIndependenceLint covers JS/TS only", () => {
    expect(formatSupportsLaneIndependenceLint("javascript")).toBe(true);
    expect(formatSupportsLaneIndependenceLint("typescript")).toBe(true);
    expect(formatSupportsLaneIndependenceLint("wasm")).toBe(false);
    expect(formatSupportsLaneIndependenceLint("html-bundle")).toBe(false);
  });

  it("names the scan window instead of hiding a truncated scan", () => {
    // The lint is a refuse gate, so a gate past the window would otherwise look
    // like a clean file. The report has to say the tail was not inspected.
    const gate = 'const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];\n'
      + 'function check(key) { return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]); }\n';
    const padded = `// ${"x".repeat(MAX_SCAN_CHARS)}\n${gate}`;
    const report = lintLaneIndependence(padded);

    expect(report.truncated).toBe(true);
    expect(report.scannedChars).toBe(MAX_SCAN_CHARS);
    expect(report.sourceChars).toBe(padded.length);

    const truncatedFinding = report.findings.find((f) => f.id === "lane-scan-truncated");
    expect(truncatedFinding).toBeDefined();
    expect(truncatedFinding!.severity).toBe("warning");
    expect(truncatedFinding!.summary).toMatch(/tail was not inspected/i);

    // The real gate sits past the window, so it was not seen and must not be
    // claimed; a warning alone must not refuse a harden run.
    expect(report.looksLaneIndependent).toBe(false);
    expect(report.findings.filter((f) => f.severity === "error")).toHaveLength(0);
    expect(report.oneLineAdvice).toMatch(/tail was not inspected/i);
  });

  it("keeps the refuse message about the errors when a scan was also truncated", () => {
    const gate = 'const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];\n'
      + 'function check(key) { return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]); }\n';
    const padded = gate + `// ${"x".repeat(MAX_SCAN_CHARS)}\n`;
    const report = lintLaneIndependence(padded);

    expect(report.truncated).toBe(true);
    expect(report.looksLaneIndependent).toBe(true);
    const message = laneIndependenceRefuseMessage(report, "/tmp/gate.cjs");
    expect(message).toMatch(/per-lane-byte-compare-array/);
    expect(message).not.toMatch(/lane-scan-truncated/);
  });

  it("scans a full window of minified text in linear time", () => {
    // A long run of word characters used to drive the split-segment rule into
    // quadratic backtracking (23 s per 80k characters, minutes at the window).
    const startedAt = performance.now();
    const report = lintLaneIndependence("x".repeat(MAX_SCAN_CHARS));
    const elapsed = performance.now() - startedAt;

    expect(report.truncated).toBe(false);
    expect(report.findings).toHaveLength(0);
    expect(elapsed).toBeLessThan(3000);
  }, 15000);
});
