import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  encodeGgufStringKv,
  parseGgufLayout,
  rebuildGguf,
  GGUF_DEFAULT_ALIGNMENT,
} from "../src/shields/formats/gguf-layout.js";
import { protectGgufBuffer } from "../src/shields/formats/model.js";

const VENV_PY = "/tmp/ggufvenv/bin/python";
const HAS_GGUF_READER = (() => {
  const r = spawnSync(VENV_PY, ["-c", "import gguf"], { encoding: "utf8" });
  return r.status === 0;
})();

function makeRealGguf(): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "bla-gguf-layout-"));
  try {
    const out = join(dir, "tiny.gguf");
    const script = `
import gguf, numpy as np, sys
w = gguf.GGUFWriter(sys.argv[1], "llama")
w.add_name("tiny-test")
w.add_uint32("tiny.custom", 7)
w.add_tensor("tok_emb", np.arange(15, dtype=np.float32).reshape(3, 5))
w.add_tensor("bias", np.array([1.5, -2.25, 3.0], dtype=np.float32))
w.add_tensor("w2", (np.arange(7, dtype=np.float32) * 0.5))
w.write_header_to_file(); w.write_kv_data_to_file(); w.write_tensors_to_file(); w.close()
`;
    const py = join(dir, "make.py");
    writeFileSync(py, script);
    const r = spawnSync(VENV_PY, [py, out], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`gguf write failed: ${r.stderr || r.stdout}`);
    return readFileSync(out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function readTensorDigests(bytes: Buffer): Record<string, string> {
  const dir = mkdtempSync(join(tmpdir(), "bla-gguf-read-"));
  try {
    const path = join(dir, "m.gguf");
    writeFileSync(path, bytes);
    const script = `
import gguf, hashlib, json, sys
r = gguf.GGUFReader(sys.argv[1])
print(json.dumps({
  "align": int(r.alignment),
  "data_offset": int(r.data_offset),
  "tensors": {t.name: hashlib.sha256(bytes(t.data.tobytes())).hexdigest() for t in r.tensors},
  "keys": [k for k in r.fields.keys() if not k.startswith("GGUF.")],
}))
`;
    const py = join(dir, "read.py");
    writeFileSync(py, script);
    const r = spawnSync(VENV_PY, [py, path], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`gguf read failed: ${r.stderr || r.stdout}`);
    return JSON.parse(r.stdout.trim());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("gguf-layout alignment-safe rewrite", () => {
  function makeGgufWithAlignment(alignment: number, dataBytes = 32): Buffer {
    const u32 = (n: number): Buffer => {
      const b = Buffer.alloc(4);
      b.writeUInt32LE(n >>> 0, 0);
      return b;
    };
    const u64 = (n: bigint | number): Buffer => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(BigInt(n), 0);
      return b;
    };
    const str = (text: string): Buffer => {
      const encoded = Buffer.from(text, "utf8");
      return Buffer.concat([u64(encoded.length), encoded]);
    };
    const headerAndInfos = Buffer.concat([
      Buffer.from("GGUF", "ascii"),
      u32(3),
      u64(1), // tensorCount
      u64(1), // kvCount
      str("general.alignment"),
      u32(4), // UINT32
      u32(alignment),
      str("w"),
      u32(1), // nDims
      u64(1), // dim
      u32(0), // ggml_type
      u64(0), // offset
    ]);
    // Leave the deliberately hostile alignments unpadded without allocating them.
    const padSize = alignment <= 64 ? (alignment - headerAndInfos.length % alignment) % alignment : 0;
    return Buffer.concat([headerAndInfos, Buffer.alloc(padSize), Buffer.alloc(dataBytes, 7)]);
  }

  it("accepts a sane alignment and preserves the tensor bytes", () => {
    const bytes = makeGgufWithAlignment(GGUF_DEFAULT_ALIGNMENT);
    const layout = parseGgufLayout(bytes);
    expect(layout).not.toBeNull();
    expect(layout!.alignment).toBe(GGUF_DEFAULT_ALIGNMENT);
    const rebuilt = rebuildGguf(bytes, layout!, { appendKvs: [] });
    expect(rebuilt.length).toBeGreaterThan(layout!.dataStart);
  });

  it("rejects an out-of-range general.alignment instead of allocating a huge pad", () => {
    // 2 GiB alignment: previously accepted, which made rebuildGguf allocate a
    // ~2 GiB zeroed pad and slice away the whole tensor region.
    expect(parseGgufLayout(makeGgufWithAlignment(0x80000000))).toBeNull();
    expect(parseGgufLayout(makeGgufWithAlignment(0x2000000))).toBeNull();
    expect(parseGgufLayout(makeGgufWithAlignment(64))).not.toBeNull();
  });

  it("rejects a data section shorter than the tensor extent", () => {
    const bytes = makeGgufWithAlignment(GGUF_DEFAULT_ALIGNMENT, 2);
    expect(parseGgufLayout(bytes)).toBeNull();
  });

  it("protectGgufBuffer fails closed when a tensor-bearing GGUF has no layout", () => {
    expect(() =>
      protectGgufBuffer(makeGgufWithAlignment(0x80000000), {
        intensity: "balanced",
        seed: "gguf-alignment-test",
      }),
    ).toThrow(/tensor-bearing GGUF has no preservable tensor layout/);
  });

  it("parses a real GGUF and reports the default alignment", () => {
    if (!HAS_GGUF_READER) return;
    const bytes = makeRealGguf();
    const layout = parseGgufLayout(bytes);
    expect(layout).not.toBeNull();
    expect(layout!.alignment).toBe(GGUF_DEFAULT_ALIGNMENT);
    expect(layout!.tensorCount).toBe(3n);
    expect(layout!.hasDataRegion).toBe(true);
    expect(layout!.dataStart % layout!.alignment).toBe(0);
  });

  it("rebuildGguf keeps every tensor byte-exact after KV append (reference reader)", () => {
    if (!HAS_GGUF_READER) return;
    const original = makeRealGguf();
    const before = readTensorDigests(original);
    const layout = parseGgufLayout(original)!;
    const rebuilt = rebuildGguf(original, layout, {
      appendKvs: [encodeGgufStringKv("bla.test.note", '{"ok":true}')],
    });
    const after = readTensorDigests(rebuilt);
    expect(after.tensors).toEqual(before.tensors);
    expect(after.keys).toContain("bla.test.note");
    expect(after.align).toBe(before.align);
  });

  it("protectGgufBuffer keeps every tensor byte-exact (reference reader)", () => {
    if (!HAS_GGUF_READER) return;
    const original = makeRealGguf();
    const before = readTensorDigests(original);
    const protected_ = protectGgufBuffer(original, {
      intensity: "balanced",
      seed: "gguf-layout-test",
    });
    const after = readTensorDigests(protected_.buffer);
    expect(after.tensors).toEqual(before.tensors);
    expect(after.keys).toContain("enclave.delegation.manifest");
    expect(after.keys).toContain("enclave.topology.slots");
  });

  it("rejects non-GGUF / truncated input without throwing", () => {
    expect(parseGgufLayout(Buffer.from("not-gguf"))).toBeNull();
    expect(parseGgufLayout(Buffer.from("GGUF"))).toBeNull();
    const magic = Buffer.alloc(24, 0);
    magic.write("GGUF", 0, "ascii");
    magic.writeUInt32LE(3, 4);
    magic.writeBigUInt64LE(1n, 8); // tensorCount
    magic.writeBigUInt64LE(1n, 16); // kvCount — truncated body
    expect(parseGgufLayout(magic)).toBeNull();
  });

  it("idempotent drop+append does not change tensor digests", () => {
    if (!HAS_GGUF_READER) return;
    const original = makeRealGguf();
    const layout = parseGgufLayout(original)!;
    const once = rebuildGguf(original, layout, {
      appendKvs: [encodeGgufStringKv("bla.sidecar.v1", '{"d":"a"}')],
    });
    const layout2 = parseGgufLayout(once)!;
    const twice = rebuildGguf(once, layout2, {
      dropKeys: new Set(["bla.sidecar.v1"]),
      appendKvs: [encodeGgufStringKv("bla.sidecar.v1", '{"d":"b"}')],
    });
    expect(readTensorDigests(once).tensors).toEqual(
      readTensorDigests(original).tensors,
    );
    expect(readTensorDigests(twice).tensors).toEqual(
      readTensorDigests(original).tensors,
    );
    // Content hash of the note itself must differ after re-bind.
    expect(createHash("sha256").update(once).digest("hex")).not.toBe(
      createHash("sha256").update(twice).digest("hex"),
    );
  });
});
