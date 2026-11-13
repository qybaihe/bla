import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { SeededPrng } from "../src/core/prng.js";
import { generateAndroidDexXrefCounter } from "../src/shields/formats/android-dex-xref.js";
import {
  DEX_SIDECAR_METADATA_KEY,
  DEX_SIDECAR_METADATA_KIND,
  SIDECAR_ENTANGLE_SCHEMA,
  bindDexSidecarEntanglement,
  computeSidecarBindingDigest,
  entangleDexEntryWithSidecars,
  extractDexSidecarStringPoolNote,
  generateSidecarDexStringPoolNote,
  planSidecarEntanglement,
  stripDexSidecarStringPoolNote,
  verifyDexSidecarStringPoolNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  dexChecksumsValid,
  parseDexLayout,
  readDexStringPool,
} from "../src/shields/formats/dex-layout.js";
import { protectTarget } from "../src/engine/protector.js";
import { protectAndroidDexBuffer } from "../src/shields/formats/mobile-game.js";
import { verifySidecarTarget } from "../src/engine/verify-sidecar.js";

function insnDigests(bytes: Buffer): string[] {
  const layout = parseDexLayout(bytes)!;
  return layout.codeItems.map((item) =>
    createHash("sha256").update(item.raw.subarray(16)).digest("hex"),
  );
}

function sampleDex(): Buffer {
  return generateAndroidDexXrefCounter(new SeededPrng("sidecar-dex-fx"), "stealth").dexBuffer;
}

describe("sidecar DEX string-pool note", () => {
  it("planSidecarEntanglement guesses dex-string-pool-note for .dex", () => {
    const plan = planSidecarEntanglement({
      entryPath: "classes.dex",
      sidecarPaths: ["assets.bin"],
    });
    expect(plan.entryHookKind).toBe("dex-string-pool-note");
  });

  it("generateSidecarDexStringPoolNote emits the binding note body", () => {
    const digest = computeSidecarBindingDigest(
      { pathLabel: "classes.dex", bytes: Buffer.from("entry") },
      [{ pathLabel: "sib.bin", bytes: Buffer.from("sib") }],
      "seed-a",
      "sidecars",
    );
    const inject = generateSidecarDexStringPoolNote({
      entryPath: "classes.dex",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-a",
      expectedHex: digest.hex,
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.kind).toBe(DEX_SIDECAR_METADATA_KIND);
    expect(inject.key).toBe(DEX_SIDECAR_METADATA_KEY);
    expect(inject.note.digest).toBe(digest.hex);
    expect(inject.stringBody).toContain(digest.hex);
  });

  it("bind + verify round-trips; strip fails closed; indices and insns stay stable", () => {
    const entry = sampleDex();
    const pool0 = readDexStringPool(entry)!;
    const insn0 = insnDigests(entry);
    const layout0 = parseDexLayout(entry)!;
    const types0 = layout0.typeIds.slice();
    const methods0 = layout0.methodIds.map((m) => ({ ...m }));

    const sib = Buffer.from("sidecar-payload-v1");
    const bound = bindDexSidecarEntanglement({
      entryPath: "classes.dex",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-dex",
      entryBytes: entry,
      sidecarBytes: [sib],
    });
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("dex-string-pool-note");
    expect(dexChecksumsValid(bound.bytes)).toBe(true);
    expect(insnDigests(bound.bytes)).toEqual(insn0);

    const after = parseDexLayout(bound.bytes)!;
    expect(after.strings.slice(0, pool0.length).map((s) => s.text)).toEqual(pool0);
    expect(after.typeIds).toEqual(types0);
    expect(after.methodIds).toEqual(methods0);

    const note = extractDexSidecarStringPoolNote(bound.bytes);
    expect(note).not.toBeNull();
    expect(note!.digest).toBe(bound.digest.hex);
    expect(note!.sidecarPaths).toEqual(["sib.bin"]);

    const ok = verifyDexSidecarStringPoolNote({
      entryBytes: bound.bytes,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(ok.ok).toBe(true);
    expect(ok.measuredHex).toBe(bound.digest.hex);

    const bad = verifyDexSidecarStringPoolNote({
      entryBytes: bound.bytes,
      sidecarBytes: { "sib.bin": Buffer.from("tampered") },
    });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/mismatch/);

    const stripped = stripDexSidecarStringPoolNote(bound.bytes);
    expect(extractDexSidecarStringPoolNote(stripped)).toBeNull();
    expect(readDexStringPool(stripped)).toEqual(pool0);
    expect(insnDigests(stripped)).toEqual(insn0);
    const missing = verifyDexSidecarStringPoolNote({
      entryBytes: stripped,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(missing.ok).toBe(false);

    const rebound = bindDexSidecarEntanglement({
      entryPath: "classes.dex",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-dex",
      entryBytes: bound.bytes,
      sidecarBytes: [sib],
    });
    const notes = parseDexLayout(rebound.bytes)!.strings.filter(
      (s) => extractDexSidecarStringPoolNote(Buffer.concat([rebound.bytes.subarray(0, 0), rebound.bytes])) &&
        s.text.includes(DEX_SIDECAR_METADATA_KEY),
    );
    // Simpler: only one sidecar note in the pool
    const noteCount = parseDexLayout(rebound.bytes)!.strings.filter((s) =>
      s.text.includes('"kind":"dex-string-pool-note"'),
    ).length;
    expect(noteCount).toBe(1);
    expect(insnDigests(rebound.bytes)).toEqual(insn0);
    void notes;
  });

  it("entangleDexEntryWithSidecars returns null when no sidecars or on a stub", () => {
    expect(
      entangleDexEntryWithSidecars({
        entryPath: "classes.dex",
        entryBytes: sampleDex(),
        sidecars: [],
      }),
    ).toBeNull();
    const stub = Buffer.alloc(112, 0);
    stub.write("dex\n035\0", 0, "ascii");
    stub.writeUInt32LE(112, 32);
    stub.writeUInt32LE(112, 36);
    stub.writeUInt32LE(0x12345678, 40);
    expect(
      entangleDexEntryWithSidecars({
        entryPath: "classes.dex",
        entryBytes: stub,
        sidecars: [{ pathLabel: "sib.bin", bytes: Buffer.from("x") }],
      }),
    ).toBeNull();
  });

  it("protectTarget with sidecarEntangle plants the note (host-verify only)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-dex-prot-"));
    try {
      const entry = sampleDex();
      const protected_ = protectAndroidDexBuffer(entry, {
        intensity: "stealth",
        seed: "dex-sidecar-protect",
      });
      const inPath = join(dir, "classes.dex");
      const sibPath = join(dir, "sib.bin");
      const outPath = join(dir, "out.dex");
      writeFileSync(inPath, protected_.buffer);
      writeFileSync(sibPath, Buffer.from("sibling-bytes"));
      const report = protectTarget({
        inputPath: inPath,
        outputPath: outPath,
        intensity: "stealth",
        seed: "dex-sidecar-protect",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
      });
      expect(report.sidecarEntangle).toBe(true);
      expect(existsSync(outPath)).toBe(true);
      const out = readFileSync(outPath);
      expect(dexChecksumsValid(out)).toBe(true);
      const note = extractDexSidecarStringPoolNote(out);
      expect(note).not.toBeNull();
      expect(note!.key).toBe(DEX_SIDECAR_METADATA_KEY);
      const verified = verifyDexSidecarStringPoolNote({
        entryBytes: out,
        sidecarBytes: { "sib.bin": readFileSync(sibPath) },
      });
      expect(verified.ok).toBe(true);
      expect(report.counteredReaVectors).not.toContain("dex-sidecar-entangle");
      const cli = verifySidecarTarget(outPath);
      expect(cli.ok, cli.reason).toBe(true);
      expect(cli.verifier).toBe("dex-string-pool-note");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("default OFF: protectTarget without the flag does not plant a note", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-dex-off-"));
    try {
      const inPath = join(dir, "classes.dex");
      const outPath = join(dir, "out.dex");
      writeFileSync(inPath, sampleDex());
      const report = protectTarget({
        inputPath: inPath,
        outputPath: outPath,
        intensity: "stealth",
        seed: "dex-sidecar-off",
      });
      expect(report.sidecarEntangle).not.toBe(true);
      expect(extractDexSidecarStringPoolNote(readFileSync(outPath))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
