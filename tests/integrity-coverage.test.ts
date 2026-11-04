import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { SeededPrng } from "../src/core/prng.js";
import {
  INTEGRITY_COVERAGE_SCHEMA,
  buildInterleavedCoverageMatrix,
  evaluateCoverageMatrix,
  finalizeCoverageMatrixHashes,
} from "../src/engine/integrity-coverage.js";
import { generateSelfSealSnippet } from "../src/shields/runtime/self-seal.js";

function sha(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

describe("integrity coverage matrix (Direction-3)", () => {
  it("ring of 2 JS hosts + payload satisfies all refuse predicates", () => {
    const files = {
      "license.cjs": "entry",
      "peer.cjs": "peer",
      "panel.html": "<html/>",
      "core.wasm": "wasm",
    };
    const expectedSha256 = Object.fromEntries(
      Object.entries(files).map(([k, v]) => [k, sha(v)]),
    );
    const matrix = buildInterleavedCoverageMatrix({
      fileNodes: Object.keys(files),
      checkerHosts: ["license.cjs", "peer.cjs"],
      expectedSha256,
    });
    expect(matrix.schema).toBe(INTEGRITY_COVERAGE_SCHEMA);
    const ev = evaluateCoverageMatrix(matrix);
    expect(ev.ok).toBe(true);
    expect(ev.shouldRefuseBankrupt).toBe(false);
    expect(ev.checkerCount).toBe(2);
  });

  it("colocated sites on one host pass anti-single-point after finalize", () => {
    const host = "license.cjs";
    const files: Record<string, string> = {
      [host]: "module.exports=1",
      "panel.html": "<p/>",
      "core.wasm": "\0wasm",
    };
    let matrix = buildInterleavedCoverageMatrix({
      fileNodes: Object.keys(files),
      checkerHosts: [host],
      expectedSha256: {},
      colocatedSites: 2,
    });
    matrix = finalizeCoverageMatrixHashes(
      matrix,
      Object.fromEntries(Object.entries(files).map(([k, v]) => [k, Buffer.from(v)])),
    );
    const ev = evaluateCoverageMatrix(matrix);
    expect(ev.ok).toBe(true);
    expect(ev.uncoveredCheckers).toEqual([]);
  });

  it("refuses single-checker topology (anti-single-point)", () => {
    const matrix = {
      schema: INTEGRITY_COVERAGE_SCHEMA,
      nodes: ["a.js", "b.wasm"],
      edges: { "a.js": ["b.wasm"] },
      expectedSha256: { "a.js": sha("a"), "b.wasm": sha("b") },
    };
    const ev = evaluateCoverageMatrix(matrix);
    expect(ev.ok).toBe(false);
    expect(ev.reasons).toContain("checker-not-covered");
    expect(ev.shouldRefuseBankrupt).toBe(true);
  });

  it("refuses missing hashes", () => {
    const matrix = buildInterleavedCoverageMatrix({
      fileNodes: ["a.js", "b.js", "c.wasm"],
      checkerHosts: ["a.js", "b.js"],
      expectedSha256: { "a.js": sha("a") },
    });
    const ev = evaluateCoverageMatrix(matrix);
    expect(ev.reasons).toContain("missing-hash");
    expect(ev.shouldRefuseBankrupt).toBe(true);
  });

  it("interleaved self-seal hard-fails when a sibling is tampered", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-intcov-"));
    const sib = join(dir, "asset.bin");
    writeFileSync(sib, "clean-asset");
    const hex = createHash("sha256").update("clean-asset").digest("hex");
    const snip = generateSelfSealSnippet(new SeededPrng("intcov-runtime"), {
      siblingPaths: ["./asset.bin"],
      expectedSiblingSha256: { "./asset.bin": hex },
      hardFailOnSiblingMismatch: true,
      interleavedSites: 2,
      bindingName: "integrityDigestTest",
      checkerHostPath: "main.cjs",
      coverageFileNodes: ["main.cjs", "./asset.bin"],
      envFingerprint: false,
    });
    expect(snip.interleavedSites).toBe(2);
    expect(snip.code.match(/function /g)?.length).toBeGreaterThanOrEqual(2);

    const main = join(dir, "main.cjs");
    writeFileSync(
      main,
      `"use strict";\n${snip.code}\nconsole.log("ok", integrityDigestTest);\n`,
    );
    const ok = spawnSync(process.execPath, [main], { encoding: "utf8" });
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain("ok");

    writeFileSync(sib, "TAMPERED");
    const bad = spawnSync(process.execPath, [main], { encoding: "utf8" });
    expect(bad.status).not.toBe(0);
    expect(String(bad.stderr) + String(bad.stdout)).toMatch(/integrity check failed/);
  });

  it("deleting one colocated checker site from matrix fails anti-single-point lint", () => {
    const files = {
      "license.cjs": "x",
      "panel.html": "y",
    };
    let matrix = buildInterleavedCoverageMatrix({
      fileNodes: Object.keys(files),
      checkerHosts: ["license.cjs"],
      expectedSha256: {},
      colocatedSites: 2,
    });
    matrix = finalizeCoverageMatrixHashes(
      matrix,
      Object.fromEntries(Object.entries(files).map(([k, v]) => [k, Buffer.from(v)])),
    );
    expect(evaluateCoverageMatrix(matrix).ok).toBe(true);

    // Simulate deleting site1: drop its edge and node.
    const broken = {
      ...matrix,
      nodes: matrix.nodes.filter((n) => n !== "license.cjs#site1"),
      edges: Object.fromEntries(
        Object.entries(matrix.edges).filter(([k]) => k !== "license.cjs#site1"),
      ),
    };
    // site0 still targets site1 which is gone from nodes — also strip that target
    broken.edges = {
      "license.cjs#site0": (matrix.edges["license.cjs#site0"] ?? []).filter(
        (t) => t !== "license.cjs#site1",
      ),
    };
    const ev = evaluateCoverageMatrix(broken);
    expect(ev.ok).toBe(false);
    expect(ev.reasons.length).toBeGreaterThan(0);
  });
});
