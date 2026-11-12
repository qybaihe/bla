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
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  GGUF_SIDECAR_METADATA_KEY,
  GGUF_SIDECAR_METADATA_KIND,
  SIDECAR_ENTANGLE_SCHEMA,
  bindGgufSidecarEntanglement,
  computeSidecarBindingDigest,
  entangleGgufEntryWithSidecars,
  extractGgufSidecarMetadataNote,
  generateSidecarGgufMetadataNote,
  planSidecarEntanglement,
  stripGgufSidecarMetadataNote,
  verifyGgufSidecarMetadataNote,
} from "../src/shields/runtime/sidecar-entangle.js";
import {
  encodeGgufString,
  encodeGgufStringKv,
  parseGgufLayout,
  rebuildGguf,
} from "../src/shields/formats/gguf-layout.js";
import { protectTarget } from "../src/engine/protector.js";
import { protectGgufBuffer } from "../src/shields/formats/model.js";

const VENV_PY = "/tmp/ggufvenv/bin/python";
const HAS_GGUF_READER = (() => {
  const r = spawnSync(VENV_PY, ["-c", "import gguf"], { encoding: "utf8" });
  return r.status === 0;
})();

/**
 * Minimal GGUF v3 with one STRING KV and one UINT32 tensor-info + 4 data bytes.
 * Built in-process so the suite does not require the gguf Python package.
 * Alignment pad is computed so dataStart % 32 == 0.
 */
function buildMinimalGguf(): Buffer {
  const kv = encodeGgufStringKv("general.architecture", "llama");
  // Tensor info: name "w" (u64len+bytes) + n_dims=1 + dim0=1 + ggml_type=0 + offset=0
  const name = encodeGgufString("w");
  const rest = Buffer.alloc(4 + 8 + 4 + 8);
  rest.writeUInt32LE(1, 0); // n_dims
  rest.writeBigUInt64LE(1n, 4); // dim0
  rest.writeUInt32LE(0, 12); // ggml_type F32-ish placeholder
  rest.writeBigUInt64LE(0n, 16); // relative offset
  const header = Buffer.alloc(24);
  header.write("GGUF", 0, "ascii");
  header.writeUInt32LE(3, 4);
  header.writeBigUInt64LE(1n, 8); // tensorCount
  header.writeBigUInt64LE(1n, 16); // kvCount
  const metaAndInfos = Buffer.concat([header, kv, name, rest]);
  const align = 32;
  const rem = metaAndInfos.length % align;
  const pad = rem === 0 ? Buffer.alloc(0) : Buffer.alloc(align - rem, 0);
  const data = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  return Buffer.concat([metaAndInfos, pad, data]);
}

function tensorDataDigest(bytes: Buffer): string {
  const layout = parseGgufLayout(bytes)!;
  return createHash("sha256")
    .update(bytes.subarray(layout.dataStart))
    .digest("hex");
}

describe("sidecar GGUF metadata note", () => {
  it("planSidecarEntanglement guesses gguf-metadata-note for .gguf", () => {
    const plan = planSidecarEntanglement({
      entryPath: "model.gguf",
      sidecarPaths: ["weights.bin"],
    });
    expect(plan.entryHookKind).toBe("gguf-metadata-note");
  });

  it("generateSidecarGgufMetadataNote emits a STRING KV with the binding note", () => {
    const digest = computeSidecarBindingDigest(
      { pathLabel: "model.gguf", bytes: Buffer.from("entry") },
      [{ pathLabel: "sib.bin", bytes: Buffer.from("sib") }],
      "seed-a",
      "sidecars",
    );
    const inject = generateSidecarGgufMetadataNote({
      entryPath: "model.gguf",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-a",
      expectedHex: digest.hex,
    });
    expect(inject.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(inject.kind).toBe(GGUF_SIDECAR_METADATA_KIND);
    expect(inject.key).toBe(GGUF_SIDECAR_METADATA_KEY);
    expect(inject.note.digest).toBe(digest.hex);
    expect(inject.kvRecord.length).toBeGreaterThan(32);
    // KV must start with the key length of "bla.sidecar.v1"
    expect(inject.kvRecord.readBigUInt64LE(0)).toBe(
      BigInt(Buffer.from(GGUF_SIDECAR_METADATA_KEY, "utf8").length),
    );
  });

  it("bind + verify round-trips; strip fails closed; tensors stay bit-exact", () => {
    const entry = buildMinimalGguf();
    const layout0 = parseGgufLayout(entry);
    expect(layout0).not.toBeNull();
    const dataDigest0 = tensorDataDigest(entry);

    const sib = Buffer.from("sidecar-payload-v1");
    const bound = bindGgufSidecarEntanglement({
      entryPath: "model.gguf",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-gguf",
      entryBytes: entry,
      sidecarBytes: [sib],
    });
    expect(bound.plan.status).toBe("bound");
    expect(bound.plan.entryHookKind).toBe("gguf-metadata-note");
    expect(tensorDataDigest(bound.bytes)).toBe(dataDigest0);

    const note = extractGgufSidecarMetadataNote(bound.bytes);
    expect(note).not.toBeNull();
    expect(note!.digest).toBe(bound.digest.hex);
    expect(note!.sidecarPaths).toEqual(["sib.bin"]);

    const ok = verifyGgufSidecarMetadataNote({
      entryBytes: bound.bytes,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(ok.ok).toBe(true);
    expect(ok.measuredHex).toBe(bound.digest.hex);

    // Altered sibling ⇒ fail closed
    const bad = verifyGgufSidecarMetadataNote({
      entryBytes: bound.bytes,
      sidecarBytes: { "sib.bin": Buffer.from("tampered") },
    });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/mismatch/);

    // Missing note ⇒ fail closed
    const stripped = stripGgufSidecarMetadataNote(bound.bytes);
    expect(extractGgufSidecarMetadataNote(stripped)).toBeNull();
    expect(tensorDataDigest(stripped)).toBe(dataDigest0);
    const missing = verifyGgufSidecarMetadataNote({
      entryBytes: stripped,
      sidecarBytes: { "sib.bin": sib },
    });
    expect(missing.ok).toBe(false);

    // Re-bind is idempotent (single note)
    const rebound = bindGgufSidecarEntanglement({
      entryPath: "model.gguf",
      sidecarPaths: ["sib.bin"],
      seedTag: "seed-gguf",
      entryBytes: bound.bytes,
      sidecarBytes: [sib],
    });
    const layout1 = parseGgufLayout(rebound.bytes)!;
    const noteKeys = layout1.kvs.filter((k) => k.key === GGUF_SIDECAR_METADATA_KEY);
    expect(noteKeys.length).toBe(1);
    expect(tensorDataDigest(rebound.bytes)).toBe(dataDigest0);
  });

  it("entangleGgufEntryWithSidecars returns null when no sidecars", () => {
    expect(
      entangleGgufEntryWithSidecars({
        entryPath: "model.gguf",
        entryBytes: buildMinimalGguf(),
        sidecars: [],
      }),
    ).toBeNull();
  });

  it("protectTarget with sidecarEntangle plants the note (host-verify only)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-prot-"));
    try {
      const entry = buildMinimalGguf();
      // Pre-protect so we have decoys, then entangle via protectTarget.
      const protected_ = protectGgufBuffer(entry, {
        intensity: "balanced",
        seed: "gguf-sidecar-protect",
      });
      const inPath = join(dir, "model.gguf");
      const sibPath = join(dir, "sib.bin");
      const outPath = join(dir, "out.gguf");
      writeFileSync(inPath, protected_.buffer);
      writeFileSync(sibPath, Buffer.from("sibling-bytes"));
      const report = protectTarget({
        inputPath: inPath,
        outputPath: outPath,
        intensity: "balanced",
        seed: "gguf-sidecar-protect",
        sidecarEntangle: true,
        sidecarEntanglePaths: ["sib.bin"],
      });
      expect(report.sidecarEntangle).toBe(true);
      expect(existsSync(outPath)).toBe(true);
      const out = readFileSync(outPath);
      const note = extractGgufSidecarMetadataNote(out);
      expect(note).not.toBeNull();
      expect(note!.key).toBe(GGUF_SIDECAR_METADATA_KEY);
      const verified = verifyGgufSidecarMetadataNote({
        entryBytes: out,
        sidecarBytes: { "sib.bin": readFileSync(sibPath) },
      });
      expect(verified.ok).toBe(true);
      // Honesty: do NOT claim the process-start strip⇒fail vector yet
      // (host-verify only; load-time hook TBD).
      expect(report.counteredReaVectors).not.toContain("gguf-sidecar-entangle");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("real gguf writer round-trip keeps tensors after bind (when reader available)", () => {
    if (!HAS_GGUF_READER) return;
    const dir = mkdtempSync(join(tmpdir(), "bla-gguf-real-"));
    try {
      const out = join(dir, "real.gguf");
      const script = `
import gguf, numpy as np, sys
w = gguf.GGUFWriter(sys.argv[1], "llama")
w.add_name("tiny")
w.add_tensor("a", np.arange(11, dtype=np.float32))
w.add_tensor("b", np.ones((2, 3), dtype=np.float32))
w.write_header_to_file(); w.write_kv_data_to_file(); w.write_tensors_to_file(); w.close()
`;
      writeFileSync(join(dir, "make.py"), script);
      const r = spawnSync(VENV_PY, [join(dir, "make.py"), out], { encoding: "utf8" });
      expect(r.status).toBe(0);
      const entry = readFileSync(out);
      const sib = Buffer.from("real-sib");
      const bound = bindGgufSidecarEntanglement({
        entryPath: "real.gguf",
        sidecarPaths: ["sib.bin"],
        seedTag: "seed-real",
        entryBytes: entry,
        sidecarBytes: [sib],
      });
      writeFileSync(join(dir, "bound.gguf"), bound.bytes);
      const readScript = `
import gguf, hashlib, json, sys
r = gguf.GGUFReader(sys.argv[1])
print(json.dumps({t.name: hashlib.sha256(bytes(t.data.tobytes())).hexdigest() for t in r.tensors}))
`;
      writeFileSync(join(dir, "read.py"), readScript);
      const before = spawnSync(
        VENV_PY,
        [join(dir, "read.py"), out],
        { encoding: "utf8" },
      );
      const after = spawnSync(
        VENV_PY,
        [join(dir, "read.py"), join(dir, "bound.gguf")],
        { encoding: "utf8" },
      );
      expect(before.status).toBe(0);
      expect(after.status).toBe(0);
      expect(JSON.parse(after.stdout)).toEqual(JSON.parse(before.stdout));
      expect(
        verifyGgufSidecarMetadataNote({
          entryBytes: bound.bytes,
          sidecarBytes: { "sib.bin": sib },
        }).ok,
      ).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
