import { describe, expect, it } from "vitest";
import { protectGgufBuffer } from "../src/shields/formats/model.js";

const ALIGNMENT = 32;

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}

function u64(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

/**
 * GGUF v3 with one F32 tensor named "t" (4 values). Layout follows the spec:
 * header, tensor-info records, padding to `general.alignment`, tensor data.
 */
function ggufWithTensor(): { buffer: Buffer; tensorDataOffset: number; tensorValues: number[] } {
  const tensorValues = [1.25, 2.5, 3.75, 5];
  const header = Buffer.alloc(24);
  header.write("GGUF", 0, "ascii");
  header.writeUInt32LE(3, 4);
  header.writeBigUInt64LE(1n, 8); // tensor_count
  header.writeBigUInt64LE(0n, 16); // metadata_kv_count

  const name = Buffer.from("t", "utf8");
  const tensorInfo = Buffer.concat([
    u64(name.length),
    name,
    u32(1), // n_dims
    u64(tensorValues.length), // shape[0]
    u32(0), // ggml_type F32
    u64(0), // offset within the tensor-data region
  ]);

  const beforePad = 24 + tensorInfo.length;
  const pad = (ALIGNMENT - (beforePad % ALIGNMENT)) % ALIGNMENT;
  const tensorData = Buffer.alloc(tensorValues.length * 4);
  tensorValues.forEach((v, i) => tensorData.writeFloatLE(v, i * 4));

  return {
    buffer: Buffer.concat([header, tensorInfo, Buffer.alloc(pad), tensorData]),
    tensorDataOffset: beforePad + pad,
    tensorValues,
  };
}

function findTensorDataOffset(out: Buffer, values: number[]): number {
  const probe = Buffer.alloc(4);
  probe.writeFloatLE(values[0]!, 0);
  return out.indexOf(probe);
}

describe("GGUF protection keeps tensor data aligned", () => {
  for (const intensity of ["balanced", "bankrupt"] as const) {
    it(`keeps the tensor-data offset on a ${ALIGNMENT}-byte boundary (${intensity})`, () => {
      const input = ggufWithTensor();
      expect(input.tensorDataOffset % ALIGNMENT).toBe(0);

      const res = protectGgufBuffer(input.buffer, { intensity, seed: `gguf-align-${intensity}` });
      const out = res.buffer;

      // Everything the protection adds lands before the tensor region, so the
      // whole tail shifts by a constant. That shift must stay a multiple of the
      // alignment or every conformant loader reads the wrong bytes.
      expect((out.length - input.buffer.length) % ALIGNMENT).toBe(0);

      const dataOffset = findTensorDataOffset(out, input.tensorValues);
      expect(dataOffset).toBeGreaterThan(0);
      expect(dataOffset % ALIGNMENT).toBe(0);
      // Tensor bytes themselves are untouched.
      expect([...out.subarray(dataOffset, dataOffset + 16)]).toEqual([
        ...input.buffer.subarray(input.tensorDataOffset, input.tensorDataOffset + 16),
      ]);
    });
  }

  it("still protects a header-only GGUF (no tensors) without inventing one", () => {
    const res = protectGgufBuffer(Buffer.alloc(0), { intensity: "balanced", seed: "gguf-empty" });
    expect(res.triggeredMetadataNestingBreaker).toBe(true);
    expect(res.buffer.toString("latin1")).toContain("enclave.nesting.breaker");
  });
});