import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-output-safety-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("protectTarget output path safety", () => {
  it("rejects directory outputs inside the input directory, in-place directories, and existing directories", () => {
    const root = makeTempDir();
    const inputDir = join(root, "app");
    const existingDir = join(root, "existing");
    mkdirSync(inputDir);
    mkdirSync(existingDir);
    writeFileSync(join(inputDir, "index.js"), "export const answer = 42;\n");
    writeFileSync(join(existingDir, "keep.txt"), "keep\n");

    expect(() =>
      protectTarget({
        inputPath: inputDir,
        outputPath: join(inputDir, "nested", "out"),
      }),
    ).toThrow(/outside the input directory/);
    expect(() =>
      protectTarget({ inputPath: inputDir, inPlace: true }),
    ).toThrow(/in-place directory protection is not supported/);
    expect(() =>
      protectTarget({ inputPath: inputDir, outputPath: existingDir }),
    ).toThrow(/existing outputs are not overwritten/);
    expect(readFileSync(join(existingDir, "keep.txt"), "utf8")).toBe("keep\n");
  });

  it("rejects symlinked directory outputs that resolve inside the input directory", () => {
    const root = makeTempDir();
    const inputDir = join(root, "app");
    const insideDir = join(inputDir, "inside");
    const aliasParent = join(root, "alias");
    mkdirSync(insideDir, { recursive: true });
    writeFileSync(join(inputDir, "index.js"), "export const answer = 42;\n");
    try {
      symlinkSync(insideDir, aliasParent, process.platform === "win32" ? "junction" : "dir");
    } catch (err) {
      if (process.platform === "win32" && (err as NodeJS.ErrnoException).code === "EPERM") return;
      throw err;
    }

    expect(() =>
      protectTarget({
        inputPath: inputDir,
        outputPath: join(aliasParent, "out"),
      }),
    ).toThrow(/outside the input directory/);
  });

  it("rejects overwriting the input file through direct, symlink, or hardlink aliases unless inPlace is true", () => {
    const root = makeTempDir();
    const inputFile = join(root, "bundle.js");
    const symlinkFile = join(root, "bundle.symlink.js");
    const hardlinkFile = join(root, "bundle.hardlink.js");
    const original = "export function calc(x) { return x + 1; }\n";
    writeFileSync(inputFile, original);
    linkSync(inputFile, hardlinkFile);
    let hasFileSymlink = true;
    try {
      symlinkSync(inputFile, symlinkFile);
    } catch (err) {
      if (process.platform === "win32" && (err as NodeJS.ErrnoException).code === "EPERM") {
        hasFileSymlink = false;
      } else {
        throw err;
      }
    }

    const candidates = hasFileSymlink
      ? [inputFile, symlinkFile, hardlinkFile]
      : [inputFile, hardlinkFile];
    for (const outputPath of candidates) {
      expect(() => protectTarget({ inputPath: inputFile, outputPath })).toThrow(
        /explicitly enable inPlace/,
      );
      expect(readFileSync(inputFile, "utf8")).toBe(original);
    }

    protectTarget({
      inputPath: inputFile,
      outputPath: hasFileSymlink ? symlinkFile : hardlinkFile,
      inPlace: true,
    });
    expect(readFileSync(inputFile, "utf8")).not.toBe(original);
  });
});
