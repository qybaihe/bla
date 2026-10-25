import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { protectTarget } from "../src/engine/protector.js";

let root: string;
let input: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bla-output-safety-"));
  input = join(root, "input");
  mkdirSync(input);
  writeFileSync(join(input, "data.txt"), "original");
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function protect(outputPath: string, inPlace = false) {
  return protectTarget({ inputPath: input, outputPath, inPlace });
}
function expectSourceIntact() {
  expect(readdirSync(input)).toEqual(["data.txt"]);
  expect(readFileSync(join(input, "data.txt"), "utf8")).toBe("original");
}

describe("directory output admission", () => {
  it.each(["child", "missing/child", ".", "../input/child"])("rejects contained output %s before writing", (path) => {
    expect(() => protect(join(input, path))).toThrow(/outside the input/);
    expectSourceIntact();
  });
  it("rejects directory in-place mode", () => {
    expect(() => protectTarget({ inputPath: input, inPlace: true })).toThrow(/in-place directory/);
    expectSourceIntact();
  });
  it("resolves symlinked destination ancestors before containment checks", () => {
    const alias = join(root, "alias");
    symlinkSync(input, alias, "dir");
    expect(() => protect(join(alias, "missing", "child"))).toThrow(/outside the input/);
    expectSourceIntact();
  });
  it("resolves a symlinked input directory", () => {
    const alias = join(root, "alias");
    symlinkSync(input, alias, "dir");
    expect(() => protectTarget({ inputPath: alias, outputPath: join(input, "child") })).toThrow(/outside the input/);
    expectSourceIntact();
  });
  it("leaves existing output and nested symlinks untouched", () => {
    const output = join(root, "output");
    mkdirSync(output);
    symlinkSync(join(input, "data.txt"), join(output, "data.txt"));
    writeFileSync(join(output, "keep.txt"), "keep");
    expect(() => protect(output)).toThrow(/existing outputs/);
    expect(readFileSync(join(output, "keep.txt"), "utf8")).toBe("keep");
    expectSourceIntact();
  });
  it("fails closed for dangling destination ancestors", () => {
    const missing = join(root, "missing");
    const alias = join(root, "alias");
    symlinkSync(missing, alias, "dir");
    expect(() => protect(join(alias, "output"))).toThrow();
    expect(existsSync(missing)).toBe(false);
    expectSourceIntact();
  });
  it("allows a new sibling whose name shares the input prefix", () => {
    const output = join(root, "input-shielded");
    protect(output);
    expect(readFileSync(join(output, "data.txt"), "utf8")).toBe("original");
    expectSourceIntact();
  });
});

describe("file overwrite admission", () => {
  it.each(["same", "symlink", "hardlink"])("requires explicit permission for %s aliases", (kind) => {
    const source = join(root, "page.html");
    const output = kind === "same" ? source : join(root, "alias.html");
    writeFileSync(source, "<p>original</p>");
    if (kind === "symlink") symlinkSync(source, output);
    if (kind === "hardlink") linkSync(source, output);
    expect(() => protectTarget({ inputPath: source, outputPath: output })).toThrow(/explicitly enable inPlace/);
    expect(readFileSync(source, "utf8")).toBe("<p>original</p>");
  });
  it("preserves explicit file in-place support", () => {
    const source = join(root, "page.html");
    writeFileSync(source, "<p>original</p>");
    protectTarget({ inputPath: source, inPlace: true });
    expect(readFileSync(source, "utf8")).toBe("<p>original</p>");
  });
});
