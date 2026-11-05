/**
 * Coverage-matrix honesty for entry self-coverage (CrackMe v8 red team 2026-11-05).
 *
 * The matrix may only claim `host#siteN → host` edges when the host's runtime
 * self check can actually hard-fail (canonical self-digest verifies on disk).
 */
import { describe, expect, it } from "vitest";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  buildInterleavedCoverageMatrix,
  evaluateCoverageMatrix,
  finalizeCoverageMatrixHashes,
  withoutHostSelfCoverage,
} from "../src/engine/integrity-coverage.js";
import { hardenProject } from "../src/engine/harden.js";

function run(path: string) {
  return spawnSync(process.execPath, [path], { encoding: "utf8" });
}

describe("integrity coverage honesty for host self-coverage", () => {
  it("withoutHostSelfCoverage makes a single-host matrix refuse", () => {
    const files = { "license.cjs": "x", "panel.html": "y" };
    const matrix = finalizeCoverageMatrixHashes(
      buildInterleavedCoverageMatrix({
        fileNodes: Object.keys(files),
        checkerHosts: ["license.cjs"],
        expectedSha256: {},
        colocatedSites: 2,
      }),
      Object.fromEntries(Object.entries(files).map(([k, v]) => [k, Buffer.from(v)])),
    );
    expect(evaluateCoverageMatrix(matrix).ok).toBe(true);
    const honest = withoutHostSelfCoverage(matrix, "license.cjs");
    for (const targets of Object.values(honest.edges)) {
      expect(targets).not.toContain("license.cjs");
      expect(targets.some((t) => t.startsWith("license.cjs#site"))).toBe(false);
      expect(targets).toContain("panel.html");
    }
    const ev = evaluateCoverageMatrix(honest);
    expect(ev.ok).toBe(false);
    expect(ev.shouldRefuseBankrupt).toBe(true);
  });

  it("harden --self-seal reports a verified entry self-digest and the entry hard-fails on edit", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-selfdig-harden-"));
    try {
      const src = join(root, "app");
      mkdirSync(src);
      writeFileSync(
        join(src, "license.cjs"),
        ['"use strict";', "const helper = require('./helper.js');",
          "if (require.main === module) console.log('sum', helper.add(2, 3));", ""].join("\n"),
      );
      writeFileSync(
        join(src, "helper.js"),
        ['"use strict";', "function add(a, b) { return a + b; }", "module.exports = { add };", ""].join("\n"),
      );
      const out = join(root, "out");
      const report = hardenProject({
        directory: src,
        intensity: "bankrupt",
        seed: "selfdig-harden",
        outputDirectory: out,
        selfSeal: true,
      });
      expect(report.overallSuccess).toBe(true);
      expect(report.integrityCoverageSelfVerified).toBe(true);
      const matrix = JSON.parse(readFileSync(report.integrityCoveragePath!, "utf8"));
      expect(evaluateCoverageMatrix(matrix).ok).toBe(true);

      const lic = join(out, "license.cjs");
      const intact = run(lic);
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout).toContain("sum 5");
      appendFileSync(lic, "\n// patched\n");
      const tampered = run(lic);
      expect(tampered.status).not.toBe(0);
      expect(`${tampered.stderr}${tampered.stdout}`).toMatch(/integrity check failed/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
