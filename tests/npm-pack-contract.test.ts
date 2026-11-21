import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as {
  files: string[];
  main: string;
  bin: Record<string, string>;
};

/**
 * BLA's own build emits `.js.map` / `.d.ts.map` for every module (`tsconfig.json`
 * sets `sourceMap` and `declarationMap`), and the published package is an
 * allowlist of `["dist", ...]`. A root `.npmignore` does NOT filter inside an
 * allowlisted directory — verified with `npm pack --dry-run`, which still listed
 * 240 maps — so the negation below is the only thing keeping a source-protection
 * tool from shipping a full map of its own source layout.
 */
describe("published package contents", () => {
  it("keeps dist but negates source maps out of the allowlist", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("!dist/**/*.map");
  });

  it("still declares the runtime entry points the package needs", () => {
    expect(pkg.main).toBe("./dist/index.js");
    expect(Object.values(pkg.bin)).toContain("./dist/cli.js");
  });
});
