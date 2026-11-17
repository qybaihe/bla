import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { formatCliError, runCli } from "../src/cli.js";

const tempDirs: string[] = [];

function createTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("CLI error output", () => {
  it("strips control characters from an error message", () => {
    const text = formatCliError(new Error("\u001b]0;pwned\u0007"));
    expect(text.startsWith("Error: ")).toBe(true);
    expect(text).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/);
  });

  it.skipIf(process.platform === "win32")(
    "does not print artifact-derived control characters",
    async () => {
      const dir = createTempDir("bla-cli-err-");
      const output = `${dir}-out`;
      tempDirs.push(output);
      const poisoned = join(dir, "\u001b]0;pwned\u0007.gguf");
      const header = Buffer.alloc(24);
      header.write("GGUF", 0, "ascii");
      header.writeUInt32LE(3, 4);
      header.writeBigUInt64LE(1n, 8); // tensorCount > 0, kvCount = 0
      writeFileSync(poisoned, header);

      const errors: string[] = [];
      const originalError = console.error;
      console.error = (...args: unknown[]) => {
        errors.push(args.map(String).join(" "));
      };
      let code: number;
      try {
        code = await runCli(["protect", dir, "--output", output, "--intensity", "stealth"]);
      } finally {
        console.error = originalError;
      }

      const text = errors.join("\n");
      expect(code).not.toBe(0);
      expect(text).toContain("Directory protection failed");
      expect(text).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/);
    },
  );
});