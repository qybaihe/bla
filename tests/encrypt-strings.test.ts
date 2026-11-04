import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ENCRYPT_STRINGS_SCHEMA,
  buildKeystream,
  encryptStrings,
  xorDecodeBytes,
  xorEncodeToBytes,
} from "../src/engine/encrypt-strings.js";
import { SeededPrng } from "../src/core/prng.js";
import { lintPlaintextSecretsSource } from "../src/engine/plaintext-secret-lint.js";

describe("encrypt-strings (Direction-2)", () => {
  it("XOR round-trip preserves UTF-8", () => {
    const prng = new SeededPrng("test-seed").derive("string.encrypt");
    const ks = buildKeystream(prng, 64);
    const plain = "FLAG{round_trip_demo_value}";
    const enc = xorEncodeToBytes(plain, ks);
    expect(xorDecodeBytes(enc, ks)).toBe(plain);
  });

  it("encrypts FLAG + high-entropy in license.cjs and clears refuse lint", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-"));
    const src = `
function unlock(key) {
  const flag = "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}";
  const token = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c";
  return key === "DemoV8-AegisKey!" ? flag : token;
}
module.exports = { unlock };
`;
    writeFileSync(join(dir, "license.cjs"), src);
    const before = lintPlaintextSecretsSource(src, { path: "license.cjs" });
    expect(before.shouldRefuseBankrupt).toBe(true);

    const report = encryptStrings({
      path: dir,
      seed: "unit-test-seed-v1",
      outDir: join(dir, "out"),
    });
    expect(report.schema).toBe(ENCRYPT_STRINGS_SCHEMA);
    expect(report.status).toBe("ok");
    expect(report.totalEncrypted).toBeGreaterThanOrEqual(2);
    expect(report.postLintClean).toBe(true);

    const out = readFileSync(join(dir, "out", "license.cjs"), "utf8");
    expect(out).toContain("_blaS");
    expect(out).not.toContain("FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}");
    expect(out).not.toContain("7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c");

    const after = lintPlaintextSecretsSource(out, { path: "license.cjs" });
    expect(after.shouldRefuseBankrupt).toBe(false);

    // Functional equivalence: require the rewritten module and call unlock.
    const mod = require(join(dir, "out", "license.cjs"));
    expect(mod.unlock("DemoV8-AegisKey!")).toBe(
      "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}",
    );
  });

  it("same seed is reproducible; different seed differs", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-repro-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `module.exports.flag = "FLAG{repro_check_value_xx}";\n`,
    );
    const a = encryptStrings({
      path: dir,
      seed: "seed-A",
      outDir: join(dir, "a"),
    });
    const b = encryptStrings({
      path: dir,
      seed: "seed-A",
      outDir: join(dir, "b"),
    });
    const c = encryptStrings({
      path: dir,
      seed: "seed-B",
      outDir: join(dir, "c"),
    });
    expect(a.status).toBe("ok");
    const outA = readFileSync(join(dir, "a", "license.cjs"), "utf8");
    const outB = readFileSync(join(dir, "b", "license.cjs"), "utf8");
    const outC = readFileSync(join(dir, "c", "license.cjs"), "utf8");
    expect(outA).toBe(outB);
    expect(outA).not.toBe(outC);
  });


  it("encrypted stub does not trip lane-independence byte-compare lint", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-lane-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `function unlock(key){return key==="x"?"FLAG{lane_lint_safe_value_xx}":"no";}\nmodule.exports={unlock};\n`,
    );
    const report = encryptStrings({ path: dir, seed: "lane-seed", outDir: join(dir, "out") });
    expect(report.status).toBe("ok");
    const out = readFileSync(join(dir, "out", "license.cjs"), "utf8");
    expect(out).not.toMatch(/\[\s*\d+\s*(?:,\s*\d+\s*){3,}\]/);
    const { lintLaneIndependence } = await import("../src/engine/lane-independence-lint.js");
    const lane = lintLaneIndependence(out);
    expect(lane.looksLaneIndependent).toBe(false);
  });

  it("leaves UI-only license alone (noop)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-ui-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `module.exports = { title: "Enter license", hint: "16-char key" };\n`,
    );
    const report = encryptStrings({ path: dir, seed: "seed-ui" });
    expect(report.status).toBe("noop");
    expect(report.totalEncrypted).toBe(0);
  });
});
