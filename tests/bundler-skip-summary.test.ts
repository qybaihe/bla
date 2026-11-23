import { describe, expect, it } from "vitest";
import { blaRollupPlugin, blaVitePlugin } from "../src/bundler/index.js";

function captureWarnings<T>(fn: () => T): { result: T; warnings: string[] } {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };
  try {
    return { result: fn(), warnings };
  } finally {
    console.warn = original;
  }
}

describe("bundler skip summary", () => {
  it("summarises unshielded chunks at bundle generation", () => {
    const plugin = blaRollupPlugin({ seed: "summary" });
    const output = { format: "es" };
    const { warnings } = captureWarnings(() => {
      plugin.renderChunk("function ( {", { fileName: "broken-a.js" }, output);
      plugin.renderChunk("function ( {", { fileName: "broken-b.js" }, output);
      plugin.generateBundle.call({ emitFile: () => "map" }, output, {});
      return null;
    });

    const summary = warnings.find((w) => w.includes("UNPROTECTED"));
    expect(summary).toBeDefined();
    expect(summary).toContain("2 chunk(s)");
    expect(summary).toContain("broken-a.js");
    expect(summary).toContain("broken-b.js");
  });

  it("stays quiet when every chunk was shielded", () => {
    const plugin = blaRollupPlugin({ seed: "quiet", honeySourceMap: false });
    const output = { format: "es" };
    const { warnings } = captureWarnings(() => {
      plugin.renderChunk("export const a = 1;\n", { fileName: "ok.js" }, output);
      plugin.generateBundle.call({ emitFile: () => "map" }, output, {});
      return null;
    });

    expect(warnings.some((w) => w.includes("UNPROTECTED"))).toBe(false);
  });

  it("exposes the same summary on the Vite alias", () => {
    const plugin = blaVitePlugin({ seed: "vite-summary" });
    const output = { format: "es" };
    const { warnings } = captureWarnings(() => {
      plugin.renderChunk("function ( {", { fileName: "broken-vite.js" }, output);
      plugin.generateBundle.call({ emitFile: () => "map" }, output, {});
      return null;
    });

    expect(warnings.some((w) => w.includes("UNPROTECTED") && w.includes("broken-vite.js"))).toBe(true);
  });
});