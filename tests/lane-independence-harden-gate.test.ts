import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const INDEPENDENT_GATE = `
  const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];
  export function check(key) {
    return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]);
  }
`;

const WHOLE_KEY_GATE = `
  export function activate(key) {
    let a = 0, b = 1;
    for (let i = 0; i < key.length; i++) {
      a = (a + key.charCodeAt(i) * (i + 3)) | 0;
      b = Math.imul(b ^ a, 0x01000193) | 0;
    }
    return (a ^ b) === 0x12345678;
  }
`;

describe("harden/protect lane-independence gate (red-blue round-1 P0)", () => {
  it("refuses independent 1-byte lane JS by default", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-lane-refuse-"));
    dirs.push(root);
    const src = join(root, "gate.js");
    writeFileSync(src, INDEPENDENT_GATE, "utf8");
    expect(() =>
      protectTarget({
        inputPath: src,
        outputPath: join(root, "out.js"),
        intensity: "balanced",
        seed: "lane-refuse",
      }),
    ).toThrow(/allowLaneIndependentGates|lane-independent/i);

    const app = join(root, "app");
    mkdirSync(app);
    writeFileSync(join(app, "gate.js"), INDEPENDENT_GATE, "utf8");
    const report = hardenProject({
      directory: app,
      intensity: "stealth",
      seed: "lane-refuse-harden",
      outputDirectory: join(root, "hardened"),
    });
    expect(report.overallSuccess).toBe(false);
    expect(report.artifacts.some((a) => a.error && /lane-independent|allowLaneIndependent/i.test(a.error))).toBe(
      true,
    );
  });

  it("passes whole-key mixing without allow flag", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-lane-ok-"));
    dirs.push(root);
    const src = join(root, "gate.js");
    writeFileSync(src, WHOLE_KEY_GATE, "utf8");
    const res = protectTarget({
      inputPath: src,
      outputPath: join(root, "out.js"),
      intensity: "balanced",
      seed: "lane-ok",
    });
    expect(res.outputPath).toBe(join(root, "out.js"));
  });

  it("allows independent lanes only with allowLaneIndependentGates", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-lane-allow-"));
    dirs.push(root);
    const src = join(root, "gate.js");
    writeFileSync(src, INDEPENDENT_GATE, "utf8");
    const res = protectTarget({
      inputPath: src,
      outputPath: join(root, "out.js"),
      intensity: "balanced",
      seed: "lane-allow",
      allowLaneIndependentGates: true,
    });
    expect(res.outputPath).toBe(join(root, "out.js"));
  });
});
