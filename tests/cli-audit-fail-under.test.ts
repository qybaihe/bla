import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

describe("bla audit --fail-under", () => {
  it("exits 2 when audit exposure exceeds the threshold and 0 when within", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-audit-fail-under-"));
    const target = path.join(dir, "app.js");
    fs.writeFileSync(target, "export const value = 42;\n", "utf8");
    try {
      // Unprotected artifact: exit code stays 0 without an explicit gate.
      expect(await runCli(["audit", target])).toBe(0);
      // A threshold of 100 accepts any exposure score (0..100 inclusive).
      expect(await runCli(["audit", target, "--fail-under", "100"])).toBe(0);
      // A threshold of 0 fails any target that still exposes attack surface.
      expect(await runCli(["audit", target, "--fail-under", "0"])).toBe(2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
