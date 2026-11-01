import { describe, expect, it } from "vitest";
import { blaRollupPlugin } from "../src/bundler/index.js";

describe("bundler plugin resilience", () => {
  it("passes the chunk through unshielded when the transform fails and failBuildOnError is false (default)", () => {
    const plugin = blaRollupPlugin({ seed: "resilience" });
    const warnings: string[] = [];
    const origWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(" "));
    };
    let result: unknown;
    try {
      result = plugin.renderChunk(
        "function ( {", // Unparseable: the transform throws.
        { fileName: "broken.js" },
        { format: "es" },
      );
    } finally {
      console.warn = origWarn;
    }
    // null means Rollup treats it as "no change"; the original code passes through.
    expect(result).toBeNull();
    expect(warnings.some((w) => w.includes("[bla-shield] skipped protection for broken.js"))).toBe(true);
  });

  it("throws and fails the build when failBuildOnError is true", () => {
    const plugin = blaRollupPlugin({ seed: "resilience", failBuildOnError: true });
    expect(() =>
      plugin.renderChunk(
        "function ( {",
        { fileName: "broken.js" },
        { format: "es" },
      ),
    ).toThrow(/Failed to parse JavaScript\/TypeScript input/);
  });

  it("still shields valid input normally when failBuildOnError is false", () => {
    const plugin = blaRollupPlugin({ seed: "resilience-valid", honeySourceMap: false });
    const input = "export function unlock(token) { return token === 'LIVE-KEY'; }\n";
    const result = plugin.renderChunk(
      input,
      { fileName: "app.js" },
      { format: "es" },
    ) as { code: string } | null;
    // Non-null means the transform ran and produced shielded code (not a pass-through).
    expect(result).not.toBeNull();
    expect(result!.code).toContain("unlock");
    expect(result!.code).not.toBe(input);
  });
});
