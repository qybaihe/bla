import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-dir-fail-open-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("directory protection reports child failures instead of copying unprotected bytes", () => {
  it("fails loudly when a detected child artifact cannot be protected", () => {
    const dir = createTempDir();
    const input = join(dir, "in");
    mkdirSync(input, { recursive: true });
    writeFileSync(join(input, "app.js"), "const x = 1;\n", "utf8");
    // Invalid WASM magic bytes: format detection routes this to the WASM shield,
    // which must refuse instead of silently emitting the original file.
    const brokenWasm = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    writeFileSync(join(input, "broken.wasm"), brokenWasm);

    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: join(dir, "out"),
        intensity: "balanced",
      }),
    ).toThrow(/Directory protection failed for 'broken\.wasm'/);
  });

  it("still copies non-protectable file types as a documented pass-through", () => {
    const dir = createTempDir();
    const input = join(dir, "in");
    const output = join(dir, "out");
    mkdirSync(input, { recursive: true });
    writeFileSync(join(input, "app.js"), "const x = 1;\n", "utf8");
    writeFileSync(join(input, "notes.txt"), "plain text asset", "utf8");

    const result = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "balanced",
    });

    expect(result.detectedFormat).toBe("directory");
    expect(readFileSync(join(output, "notes.txt"), "utf8")).toBe("plain text asset");
  });
});
