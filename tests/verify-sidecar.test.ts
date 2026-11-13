import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { verifySidecarTarget } from "../src/engine/verify-sidecar.js";
import {
  BUN_SIDECAR_COMPANION_SUFFIX,
  bindBunSidecarEntanglement,
  bindWasmSidecarEntanglement,
} from "../src/shields/runtime/sidecar-entangle.js";

/** Minimal WASM exporting compute_score(i32)->i32 = x*42+7 */
function fixtureComputeScore(): Buffer {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x11, 0x01, 0x0d, 0x63, 0x6f, 0x6d, 0x70,
    0x75, 0x74, 0x65, 0x5f, 0x73, 0x63, 0x6f, 0x72,
    0x65, 0x00, 0x00,
    0x0a, 0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x41,
    0x2a, 0x6c, 0x41, 0x07, 0x6a, 0x0b,
  ]);
}

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-verify-sidecar-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("verifySidecarTarget", () => {
  it("reports an intact wasm binding as valid", () => {
    const dir = makeTempDir();
    const entry = fixtureComputeScore();
    const sibSrc = "sidecar-payload\n";
    const bound = bindWasmSidecarEntanglement({
      entryPath: "core.wasm",
      sidecarPaths: ["sib.bin"],
      seedTag: "verify-cli-wasm",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode(sibSrc)],
    });
    writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
    writeFileSync(join(dir, "core.wasm"), bound.bytes);

    const result = verifySidecarTarget(join(dir, "core.wasm"));
    expect(result.ok, result.reason).toBe(true);
    expect(result.verifier).toBe("wasm-custom-section");
    expect(result.format).toBe("wasm");
    expect(result.measuredHex).toBe(bound.digest.hex);
  });

  it("fails closed when the wasm sidecar section is absent", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "plain.wasm"), fixtureComputeScore());
    const result = verifySidecarTarget(join(dir, "plain.wasm"));
    expect(result.ok).toBe(false);
    expect(result.verifier).toBe("wasm-custom-section");
    expect(result.reason).toMatch(/missing|unreadable/);
  });

  it("verifies a bun companion note beside the entry", () => {
    const dir = makeTempDir();
    const entryBytes = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
      Buffer.alloc(120, 0),
      Buffer.alloc(64, 0x41),
    ]);
    const snapBytes = Buffer.from("bun-decoy-graph\n");
    writeFileSync(join(dir, "app.bunfs-snapshot"), snapBytes);
    const bound = bindBunSidecarEntanglement({
      entryPath: "app",
      sidecarPaths: ["app.bunfs-snapshot"],
      seedTag: "verify-cli-bun",
      entryBytes,
      sidecarBytes: [snapBytes],
    });
    writeFileSync(join(dir, "app"), entryBytes);
    writeFileSync(join(dir, `app${BUN_SIDECAR_COMPANION_SUFFIX}`), bound.noteBytes);

    const result = verifySidecarTarget(join(dir, "app"));
    expect(result.ok, result.reason).toBe(true);
    expect(result.verifier).toBe("bun-companion-note");

    writeFileSync(join(dir, "app.bunfs-snapshot"), Buffer.from("tampered\n"));
    const bad = verifySidecarTarget(join(dir, "app"));
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/mismatch/);
  });

  it("labels formats without an offline verifier as runtime-only", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "app.js"), "module.exports = {};\n", "utf8");
    const result = verifySidecarTarget(join(dir, "app.js"));
    expect(result.ok).toBe(false);
    expect(result.verifier).toBe("runtime-only");
    expect(result.reason).toContain("runtime");
  });

  it("reports a missing entry path", () => {
    const result = verifySidecarTarget(join(tmpdir(), "definitely-missing.wasm"));
    expect(result.ok).toBe(false);
    expect(result.verifier).toBe("entry-missing");
  });
});

describe("bla verify-sidecar CLI", () => {
  it("exits 1 without a target", async () => {
    await expect(runCli(["verify-sidecar"])).resolves.toBe(1);
  });

  it("exits 0 for an intact binding and 2 when strip-fail check fails", async () => {
    const dir = makeTempDir();
    const entry = fixtureComputeScore();
    const sibSrc = "sidecar-payload\n";
    const bound = bindWasmSidecarEntanglement({
      entryPath: "core.wasm",
      sidecarPaths: ["sib.bin"],
      seedTag: "verify-cli-exit",
      entryBytes: entry,
      sidecarBytes: [new TextEncoder().encode(sibSrc)],
    });
    const wasmPath = join(dir, "core.wasm");
    writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");
    writeFileSync(wasmPath, bound.bytes);

    await expect(runCli(["verify-sidecar", wasmPath])).resolves.toBe(0);
    rmSync(join(dir, "sib.bin"));
    await expect(runCli(["verify-sidecar", wasmPath])).resolves.toBe(2);
    // json flag keeps working alongside the exit contract
    await expect(runCli(["verify-sidecar", wasmPath, "--json"])).resolves.toBe(2);
    expect(readFileSync(wasmPath).length).toBeGreaterThan(0);
  });
});
