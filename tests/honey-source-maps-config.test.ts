import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-honey-config-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

const JS = "export const add = (a, b) => a + b;\nexport const twice = (a) => add(a, a);\n";

describe(".blarc honeySourceMaps wiring", () => {
  async function protectWithConfig(
    dir: string,
    honeySourceMaps: boolean,
    suffix: string,
  ): Promise<string> {
    const input = join(dir, "app.mjs");
    writeFileSync(input, JS, "utf8");
    const config = join(dir, `cfg-${suffix}.json`);
    writeFileSync(
      config,
      JSON.stringify({ honeySourceMaps, seed: "bla-honey-config-test" }, null, 2),
      "utf8",
    );
    const output = join(dir, `out-${suffix}.mjs`);
    await runCli(["protect", input, "--output", output, "--config", config]);
    return readFileSync(output, "utf8");
  }

  it("honours honeySourceMaps:false instead of ignoring the config field", async () => {
    const dir = createTempDir();
    const off = await protectWithConfig(dir, false, "off");
    const on = await protectWithConfig(dir, true, "on");

    // The engine already gates on the option; the CLI used to forward only the
    // --no-honey-maps flag, so both runs produced byte-identical output.
    expect(off).not.toContain("sourceMappingURL");
    expect(on).toContain("sourceMappingURL");
    expect(off).not.toBe(on);
  });
});