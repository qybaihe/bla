import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];

function createLintTarget(options: { readonly configIntensity?: string } = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-lint-intensity-"));
  tempDirs.push(dir);
  fs.writeFileSync(
    path.join(dir, "seal.json"),
    JSON.stringify({ schema: "bla-seal/v1", certificateCipherHex: "aabbccdd" }),
    "utf8",
  );
  if (options.configIntensity !== undefined) {
    fs.writeFileSync(
      path.join(dir, "bla.config.json"),
      JSON.stringify({ intensity: options.configIntensity }),
      "utf8",
    );
  }
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("bla lint intensity contract", () => {
  it("refuses plaintext seal sidecars by default, like bla harden and bla_lint", async () => {
    const dir = createLintTarget();
    expect(await runCli(["lint", dir])).toBe(2);
  });

  it("honors an explicit --intensity balanced opt-out", async () => {
    const dir = createLintTarget();
    expect(await runCli(["lint", dir, "--intensity", "balanced"])).toBe(0);
  });

  it("honors .blarc intensity instead of hardcoding a parser default", async () => {
    const dir = createLintTarget({ configIntensity: "bankrupt" });
    expect(await runCli(["lint", dir, "--config", path.join(dir, "bla.config.json")])).toBe(2);
  });

  it("honors an explicit --config that downgrades the gate", async () => {
    const dir = createLintTarget({ configIntensity: "balanced" });
    expect(await runCli(["lint", dir, "--config", path.join(dir, "bla.config.json")])).toBe(0);
  });
});
