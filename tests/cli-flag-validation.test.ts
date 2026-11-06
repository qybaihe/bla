import { describe, expect, it } from "vitest";
import { parseCliArgs, runCli } from "../src/cli.js";

describe("CLI flag validation", () => {
  it("rejects out-of-range --fail-under values", () => {
    expect(parseCliArgs(["--fail-under", "-1"]).argErrors.join(" ")).toMatch(/between 0 and 100/);
    expect(parseCliArgs(["--fail-under", "101"]).argErrors.join(" ")).toMatch(/between 0 and 100/);
    expect(parseCliArgs(["--fail-under", "nope"]).argErrors.join(" ")).toMatch(/between 0 and 100/);
    expect(parseCliArgs(["--fail-under"]).argErrors.join(" ")).toMatch(/requires a value/);
  });

  it("accepts a valid --fail-under value", () => {
    const parsed = parseCliArgs(["--fail-under", "75"]);
    expect(parsed.argErrors).toEqual([]);
    expect(parsed.failUnder).toBe(75);
  });

  it("rejects unknown --intensity and --lang values instead of silently defaulting", () => {
    const intensity = parseCliArgs(["--intensity", "nope"]);
    expect(intensity.argErrors.join(" ")).toMatch(/--intensity must be one of/);
    expect(intensity.intensity).toBe("balanced");

    const lang = parseCliArgs(["--lang", "nope"]);
    expect(lang.argErrors.join(" ")).toMatch(/--lang must be one of/);
    expect(lang.lang).toBe("c");

    expect(parseCliArgs(["--intensity", "maximum"]).argErrors).toEqual([]);
    expect(parseCliArgs(["--lang", "rust"]).argErrors).toEqual([]);
  });

  it("rejects an empty --seed value", () => {
    expect(parseCliArgs(["--seed", ""]).argErrors.join(" ")).toMatch(/non-empty/);
    expect(parseCliArgs(["--seed", "abc"]).argErrors).toEqual([]);
  });

  it("returns exit code 1 for invalid flags and 0 for --help", async () => {
    await expect(runCli(["--fail-under", "-1", "protect", "x"])).resolves.toBe(1);
    await expect(runCli(["--help", "--fail-under", "-1"])).resolves.toBe(0);
  });
});