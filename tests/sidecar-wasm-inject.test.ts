import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  bindWasmSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarWasmCustomSection,
  SIDECAR_ENTANGLE_SCHEMA,
  stripWasmSidecarCustomSection,
  verifyWasmSidecarCustomSection,
  WASM_SIDECAR_SECTION_NAME,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  inspectWasmBinary,
  protectWasmBinary,
} from "../src/shields/formats/wasm.js";
import { protectTarget } from "../src/engine/protector.js";

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

describe("sidecar WASM custom-section strip⇒fail", () => {
  it("generateSidecarWasmCustomSection rejects non-hex expected digests", () => {
    expect(() =>
      generateSidecarWasmCustomSection({
        entryPath: "core.wasm",
        sidecarPaths: ["sib.bin"],
        expectedHex: "deadbeef",
      }),
    ).toThrow(/64-char/);
  });

  it("bindWasmSidecarEntanglement plants bla.sidecar.v1; magic+exports intact", () => {
    const entry = fixtureComputeScore();
    const before = inspectWasmBinary(entry);
    expect(before.validMagic).toBe(true);
    expect(before.exportNames).toContain("compute_score");

    const sibBytes = new TextEncoder().encode("sidecar-payload\n");
    const bound = bindWasmSidecarEntanglement({
      entryPath: "core.wasm",
      sidecarPaths: ["sib.bin"],
      seedTag: "wasm-inject-v1",
      entryBytes: entry,
      sidecarBytes: [sibBytes],
    });

    expect(bound.plan.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("wasm-custom-section");
    expect(bound.inject.sectionName).toBe(WASM_SIDECAR_SECTION_NAME);
    expect(bound.inject.expectedHex).toBe(bound.digest.hex);

    const after = inspectWasmBinary(bound.bytes);
    expect(after.validMagic).toBe(true);
    expect(after.customSectionNames).toContain(WASM_SIDECAR_SECTION_NAME);
    expect(after.exportNames).toEqual(before.exportNames);
  });

  it("digest matches computeSidecarBindingDigest sidecars-mode", () => {
    const entry = fixtureComputeScore();
    const sibSrc = "sidecar-payload\n";
    const digest = computeSidecarBindingDigest(
      { pathLabel: "core.wasm", bytes: entry },
      [{ pathLabel: "sib.bin", bytes: new TextEncoder().encode(sibSrc) }],
      "parity-wasm-v1",
    );
    const inject = generateSidecarWasmCustomSection({
      entryPath: "core.wasm",
      sidecarPaths: ["sib.bin"],
      seedTag: "parity-wasm-v1",
      expectedHex: digest.hex,
    });
    expect(inject.expectedHex).toBe(digest.hex);
    expect(inject.expectedU32).toBe(digest.u32);
    expect(inject.note.digest).toBe(digest.hex);
  });

  it("verify: intact sidecars pass; strip section or mutate sidecar fails", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-wasm-inject-"));
    try {
      const entry = fixtureComputeScore();
      const sibName = "sib.bin";
      const sibSrc = "sidecar-payload\n";
      writeFileSync(join(dir, sibName), sibSrc, "utf8");

      const bound = bindWasmSidecarEntanglement({
        entryPath: "core.wasm",
        sidecarPaths: [sibName],
        seedTag: "rt-wasm-v1",
        entryBytes: entry,
        sidecarBytes: [new TextEncoder().encode(sibSrc)],
      });
      writeFileSync(join(dir, "core.wasm"), bound.bytes);

      const intact = verifyWasmSidecarCustomSection({
        wasmBytes: readFileSync(join(dir, "core.wasm")),
        baseDir: dir,
      });
      expect(intact.ok, intact.reason).toBe(true);
      expect(intact.measuredHex).toBe(bound.digest.hex);

      // Mutate sidecar bytes → fail closed
      writeFileSync(join(dir, sibName), "tampered\n", "utf8");
      const mutated = verifyWasmSidecarCustomSection({
        wasmBytes: readFileSync(join(dir, "core.wasm")),
        baseDir: dir,
      });
      expect(mutated.ok).toBe(false);
      expect(mutated.reason).toMatch(/integrity binding mismatch/);

      // Restore sidecar, strip custom section → fail closed
      writeFileSync(join(dir, sibName), sibSrc, "utf8");
      const strippedBytes = stripWasmSidecarCustomSection(
        readFileSync(join(dir, "core.wasm")),
      );
      const strippedInspect = inspectWasmBinary(strippedBytes);
      expect(strippedInspect.validMagic).toBe(true);
      expect(strippedInspect.customSectionNames).not.toContain(
        WASM_SIDECAR_SECTION_NAME,
      );
      expect(strippedInspect.exportNames).toContain("compute_score");

      const stripped = verifyWasmSidecarCustomSection({
        wasmBytes: strippedBytes,
        baseDir: dir,
      });
      expect(stripped.ok).toBe(false);
      expect(stripped.reason).toMatch(/missing|unreadable/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("append after protectWasmBinary keeps magic + section; verify still works", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-wasm-protect-"));
    try {
      const entry = fixtureComputeScore();
      const protectedRes = protectWasmBinary(entry, {
        intensity: "balanced",
        seed: "wasm-protect-sidecar",
        preserveExports: ["compute_score"],
      });
      const sibName = "sib.bin";
      const sibSrc = "after-protect-sib\n";
      writeFileSync(join(dir, sibName), sibSrc, "utf8");

      const bound = bindWasmSidecarEntanglement({
        entryPath: "core.wasm",
        sidecarPaths: [sibName],
        seedTag: "after-protect-v1",
        entryBytes: protectedRes.buffer,
        sidecarBytes: [new TextEncoder().encode(sibSrc)],
      });
      const inspected = inspectWasmBinary(bound.bytes);
      expect(inspected.validMagic).toBe(true);
      expect(inspected.customSectionNames).toContain(WASM_SIDECAR_SECTION_NAME);
      expect(inspected.exportNames).toContain("compute_score");

      writeFileSync(join(dir, "core.wasm"), bound.bytes);
      const ok = verifyWasmSidecarCustomSection({
        wasmBytes: bound.bytes,
        baseDir: dir,
      });
      expect(ok.ok, ok.reason).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protectTarget with sidecarEntangle plants section on .wasm", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sidecar-wasm-pt-"));
    try {
      const entry = join(dir, "core.wasm");
      const out = join(dir, "core.out.wasm");
      const sibSrc = "protect-target-sib\n";
      writeFileSync(entry, fixtureComputeScore());
      writeFileSync(join(dir, "sib.bin"), sibSrc, "utf8");

      const res = protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "pt-wasm-sidecar",
        wasmPreserveExports: ["compute_score"],
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
      });
      expect(res.sidecarEntangle).toBe(true);

      const outBytes = readFileSync(out);
      const inspected = inspectWasmBinary(outBytes);
      expect(inspected.validMagic).toBe(true);
      expect(inspected.customSectionNames).toContain(WASM_SIDECAR_SECTION_NAME);
      expect(inspected.exportNames).toContain("compute_score");

      const verified = verifyWasmSidecarCustomSection({
        wasmBytes: outBytes,
        baseDir: dir,
      });
      expect(verified.ok, verified.reason).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
