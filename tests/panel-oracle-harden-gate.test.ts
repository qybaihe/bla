import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { rewriteStablePanelDeriveSymbols } from "../src/engine/panel-derive-abi-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("red-blue round-4 panel oracle gate", () => {
  it("bankrupt protect refuses deriveLocal + panelTokenSha256 unless allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-panel-oracle-"));
    dirs.push(dir);
    const input = join(dir, "panel.js");
    const output = join(dir, "panel.out.js");
    writeFileSync(
      input,
      [
        "function deriveLocal(key) { return String(key).length.toString(16); }",
        "function check(seal, key) {",
        "  return deriveLocal(key) === seal.panelTokenSha256;",
        "}",
        "module.exports = { deriveLocal, check };",
        "",
      ].join("\n"),
      "utf8",
    );
    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "bankrupt",
        seed: "r4-oracle",
        honeySourceMaps: false,
      }),
    ).toThrow(/allowPanelOfflineOracle|panel offline oracle/);
    const ok = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r4-oracle",
      honeySourceMaps: false,
      allowPanelOfflineOracle: true,
    });
    expect(ok.detectedFormat).toBe("javascript");
    const out = require("node:fs").readFileSync(ok.outputPath, "utf8");
    expect(out).not.toMatch(/\bfunction\s+deriveLocal\b/);
    const expected = rewriteStablePanelDeriveSymbols(
      "function deriveLocal(key) { return key; }",
      "r4-oracle",
    ).renames.find((r) => r.from === "deriveLocal")!.to;
    expect(out).toContain(expected);
  });
});
