import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverAndLintWasmSealXorKnownPlaintext } from "../src/engine/wasm-seal-xor-known-plaintext-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const WASM_BYTES = Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);

describe("wasm-seal known-plaintext discovery walk safety", () => {
  it("does not descend symlinked directories or follow symlinked wasm files", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-seal-walk-"));
    dirs.push(dir);
    writeFileSync(join(dir, "root.wasm"), WASM_BYTES);
    const outside = mkdtempSync(join(tmpdir(), "bla-seal-outside-"));
    dirs.push(outside);
    writeFileSync(join(outside, "linked.wasm"), WASM_BYTES);
    try {
      symlinkSync(outside, join(dir, "link-dir"), "dir");
    } catch (err) {
      if (process.platform === "win32" && (err as NodeJS.ErrnoException).code === "EPERM") {
        return;
      }
      throw err;
    }
    const reports = discoverAndLintWasmSealXorKnownPlaintext(dir);
    const paths = reports.map((r) => r.path).sort();
    expect(paths).toEqual([join(dir, "root.wasm")]);
  });

  it("skips hidden directories like the sibling wasm lints", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-seal-hidden-"));
    dirs.push(dir);
    writeFileSync(join(dir, "root.wasm"), WASM_BYTES);
    mkdirSync(join(dir, ".hidden"));
    writeFileSync(join(dir, ".hidden", "secret.wasm"), WASM_BYTES);
    const reports = discoverAndLintWasmSealXorKnownPlaintext(dir);
    expect(reports.map((r) => r.path)).toEqual([join(dir, "root.wasm")]);
  });
});
