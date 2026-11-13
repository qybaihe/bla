import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { expandSiblingGlobs, globToRegExp } from "../src/core/sibling-globs.js";
import { parseCliArgs, resolveSelfSealSiblingPaths } from "../src/cli.js";

const tempDirs: string[] = [];

function makeTree(): string {
  const root = mkdtempSync(join(tmpdir(), "bla-globs-"));
  tempDirs.push(root);
  mkdirSync(join(root, "dist", "nested"), { recursive: true });
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "dist", "core.wasm"), "wasm\n");
  writeFileSync(join(root, "dist", "nested", "extra.wasm"), "wasm\n");
  writeFileSync(join(root, "dist", "app.js"), "js\n");
  writeFileSync(join(root, "src", "index.ts"), "ts\n");
  return root;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("globToRegExp", () => {
  it("matches single-segment stars without crossing separators", () => {
    const re = globToRegExp("dist/*.wasm");
    expect(re.test("dist/core.wasm")).toBe(true);
    expect(re.test("dist/nested/extra.wasm")).toBe(false);
  });

  it("supports ** across segments, including zero segments", () => {
    const re = globToRegExp("**/*.wasm");
    expect(re.test("core.wasm")).toBe(true);
    expect(re.test("dist/core.wasm")).toBe(true);
    expect(re.test("dist/nested/extra.wasm")).toBe(true);
    expect(re.test("dist/app.js")).toBe(false);
  });

  it("escapes regex metacharacters in literal segments", () => {
    const re = globToRegExp("a+b(c).js");
    expect(re.test("a+b(c).js")).toBe(true);
    expect(re.test("aab(c).js")).toBe(false);
  });
});

describe("expandSiblingGlobs", () => {
  it("returns absolute matches for a scoped pattern", () => {
    const root = makeTree();
    const matches = expandSiblingGlobs(root, ["dist/*.wasm"]);
    expect(matches).toEqual([resolve(root, "dist", "core.wasm")]);
  });

  it("returns all recursive matches for a ** pattern", () => {
    const root = makeTree();
    const matches = expandSiblingGlobs(root, ["**/*.wasm"]);
    expect(matches).toEqual([
      resolve(root, "dist", "core.wasm"),
      resolve(root, "dist", "nested", "extra.wasm"),
    ]);
  });

  it("returns [] for no patterns and for no matches", () => {
    const root = makeTree();
    expect(expandSiblingGlobs(root, [])).toEqual([]);
    expect(expandSiblingGlobs(root, ["does/not/*"])).toEqual([]);
  });

  it("combines multiple patterns without duplicate paths", () => {
    const root = makeTree();
    const matches = expandSiblingGlobs(root, ["dist/*.wasm", "**/*.wasm"]);
    expect(new Set(matches).size).toBe(matches.length);
    expect(matches).toHaveLength(2);
  });

  it("emits POSIX-style relative matching regardless of platform separators", () => {
    const root = makeTree();
    const matches = expandSiblingGlobs(root, [`dist${sep}*.wasm`.split(sep).join("/")]);
    expect(matches).toHaveLength(1);
  });
});

describe("resolveSelfSealSiblingPaths", () => {
  it("returns paths relative to the output directory and skips entry/output", () => {
    const root = makeTree();
    const target = join(root, "dist", "app.js");
    const resolved = resolveSelfSealSiblingPaths({
      root,
      globs: ["dist/*.wasm"],
      targetPath: target,
      outputPath: join(root, "dist", "app.shielded.js"),
    });
    expect(resolved).toEqual(["core.wasm"]);
  });

  it("returns [] when globs are empty", () => {
    const root = makeTree();
    expect(
      resolveSelfSealSiblingPaths({
        root,
        globs: [],
        targetPath: join(root, "dist", "app.js"),
      }),
    ).toEqual([]);
  });

  it("excludes the target itself from matches", () => {
    const root = makeTree();
    const resolved = resolveSelfSealSiblingPaths({
      root,
      globs: ["dist/*.js"],
      targetPath: join(root, "dist", "app.js"),
      outputPath: join(root, "out", "app.shielded.js"),
    });
    expect(resolved).not.toContain("app.js");
    expect(resolved).toEqual([]);
  });
});

describe("CLI --self-seal-sibling-glob parsing", () => {
  it("accepts comma-separated patterns with --self-seal on protect", () => {
    const parsed = parseCliArgs([
      "protect",
      "dist/app.js",
      "--self-seal",
      "--self-seal-sibling-glob",
      "dist/*.wasm,dist/*.pyc",
    ]);
    expect(parsed.argErrors).toEqual([]);
    expect(parsed.selfSealSiblingGlobs).toEqual(["dist/*.wasm", "dist/*.pyc"]);
  });

  it("supports the --flag=value spelling", () => {
    const parsed = parseCliArgs([
      "protect",
      "dist/app.js",
      "--self-seal",
      "--self-seal-sibling-glob=dist/*.wasm",
    ]);
    expect(parsed.argErrors).toEqual([]);
    expect(parsed.selfSealSiblingGlobs).toEqual(["dist/*.wasm"]);
  });

  it("rejects globs without --self-seal", () => {
    const parsed = parseCliArgs([
      "protect",
      "dist/app.js",
      "--self-seal-sibling-glob",
      "dist/*.wasm",
    ]);
    expect(parsed.argErrors.join(" ")).toContain("--self-seal");
  });

  it("rejects globs on commands other than protect", () => {
    const parsed = parseCliArgs([
      "defend",
      "dist",
      "--self-seal",
      "--self-seal-sibling-glob",
      "dist/*.wasm",
    ]);
    expect(parsed.argErrors.join(" ")).toContain("only supported for the protect");
  });

  it("rejects a missing or empty value", () => {
    expect(
      parseCliArgs(["protect", "x.js", "--self-seal", "--self-seal-sibling-glob"])
        .argErrors.join(" "),
    ).toContain("requires a value");
    expect(
      parseCliArgs([
        "protect",
        "x.js",
        "--self-seal",
        "--self-seal-sibling-glob",
        " , ",
      ]).argErrors.join(" "),
    ).toContain("at least one pattern");
  });
});
