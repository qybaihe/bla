import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { defendTarget } from "../src/engine/defender.js";

describe("defendTarget stage-1 honesty", () => {
  it("reports warn instead of passed when the release-exposure scan cannot run", () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "bla-defend-stage-"));
    const real = path.join(base, "real");
    fs.mkdirSync(real);
    fs.writeFileSync(path.join(real, "app.js"), "export const value = 42;\n", "utf8");
    const link = path.join(base, "link");
    try {
      fs.symlinkSync(real, link, process.platform === "win32" ? "junction" : "dir");
    } catch {
      return; // symlink/junction creation unavailable on this host
    }
    try {
      const report = defendTarget({
        inputPath: link,
        outputPath: path.join(base, "out"),
        intensity: "balanced",
        seed: "stage-honesty-test",
      });
      expect(report.releaseExposure).toBeNull();
      expect(report.stages[0]).toMatchObject({
        stage: "1-release-exposure-scan",
        status: "warn",
      });
      expect(report.stages[0]!.headline).toMatch(/could not run/);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});