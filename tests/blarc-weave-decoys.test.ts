import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_BLA_CONFIG,
  initBlaConfig,
  loadBlaConfig,
} from "../src/core/config.js";
import { parseCliArgs } from "../src/cli.js";

describe(".blarc weaveDecoys parity with CLI --weave-decoys / MCP weave_decoys", () => {
  it("DEFAULT_BLA_CONFIG exposes weaveDecoys:false (opt-in)", () => {
    expect(DEFAULT_BLA_CONFIG.weaveDecoys).toBe(false);
  });

  it("initBlaConfig writes weaveDecoys:false into starter config", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-weave-cfg-"));
    try {
      const res = initBlaConfig(dir);
      expect(res.config.weaveDecoys).toBe(false);
      const loaded = loadBlaConfig(dir);
      expect(loaded.config.weaveDecoys).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadBlaConfig honors weaveDecoys:true from .blarc", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-weave-blarc-"));
    try {
      writeFileSync(
        join(dir, ".blarc"),
        JSON.stringify({
          intensity: "bankrupt",
          weaveDecoys: true,
          seed: "bla-test-weave-decoys-seed-01",
        }),
        "utf8",
      );
      const loaded = loadBlaConfig(dir);
      expect(loaded.config.weaveDecoys).toBe(true);
      expect(loaded.sourcePath).toBe(join(dir, ".blarc"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("parseCliArgs sets weaveDecoys from --weave-decoys", () => {
    const off = parseCliArgs(["harden", "."]);
    expect(off.weaveDecoys).toBe(false);
    const on = parseCliArgs(["harden", ".", "--weave-decoys"]);
    expect(on.weaveDecoys).toBe(true);
  });
});
