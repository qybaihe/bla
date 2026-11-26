import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { protectTarget } from "../src/engine/protector.js";

function withScratch(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-skipped-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("sidecar entangle reports requested paths it could not bind", () => {
  it("names a missing requested sidecar while still binding the present one", () => {
    withScratch((dir) => {
      const entry = join(dir, "main.js");
      writeFileSync(entry, "module.exports = { v: 1 };\n", "utf8");
      writeFileSync(join(dir, "present.js"), "present-sidecar\n", "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: join(dir, "main.out.js"),
        intensity: "balanced",
        seed: "skipped-mixed",
        honeySourceMaps: false,
        sidecarEntangle: true,
        sidecarEntanglePaths: ["present.js", "absent.js"],
      });

      expect(res.sidecarEntangle).toBe(true);
      expect(res.sidecarEntangleSkipped).toEqual(["absent.js"]);
    });
  });

  it("reports every requested path and leaves the binding off when none resolve", () => {
    withScratch((dir) => {
      const entry = join(dir, "main.js");
      writeFileSync(entry, "module.exports = { v: 2 };\n", "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: join(dir, "main.out.js"),
        intensity: "balanced",
        seed: "skipped-none",
        honeySourceMaps: false,
        sidecarEntangle: true,
        sidecarEntanglePaths: ["ghost-a.js", "ghost-b.js"],
      });

      expect(res.sidecarEntangle).toBeUndefined();
      expect(res.sidecarEntangleSkipped).toEqual(["ghost-a.js", "ghost-b.js"]);
    });
  });

  it("omits the field when every requested sidecar was bound", () => {
    withScratch((dir) => {
      const entry = join(dir, "main.js");
      writeFileSync(entry, "module.exports = { v: 3 };\n", "utf8");
      writeFileSync(join(dir, "sib.js"), "sibling\n", "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: join(dir, "main.out.js"),
        intensity: "balanced",
        seed: "skipped-all-bound",
        honeySourceMaps: false,
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.js"],
      });

      expect(res.sidecarEntangle).toBe(true);
      expect(res.sidecarEntangleSkipped).toBeUndefined();
    });
  });
});
