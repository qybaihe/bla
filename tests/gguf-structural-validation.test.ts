import { describe, expect, it } from "vitest";
import { protectGgufBuffer, inspectModelBuffer } from "../src/shields/formats/model.js";
import { parseGgufLayout } from "../src/shields/formats/gguf-layout.js";

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

function gguf(options: { withTensor?: boolean; pad?: boolean; truncateTensorInfo?: boolean } = {}) {
  const withTensor = options.withTensor ?? true;
  const pad = options.pad ?? true;
  const header = Buffer.alloc(24);
  header.write("GGUF", 0, "ascii");
  header.writeUInt32LE(3, 4);
  header.writeBigUInt64LE(withTensor ? 1n : 0n, 8);
  header.writeBigUInt64LE(0n, 16);
  if (!withTensor) return header;

  const name = Buffer.from("t", "utf8");
  const tensorInfo = Buffer.concat([
    u64(name.length),
    name,
    u32(1),
    u64(4),
    u32(0), // F32
    u64(0),
  ]);
  const info = options.truncateTensorInfo ? tensorInfo.subarray(0, 12) : tensorInfo;
  if (options.truncateTensorInfo) {
    // File really ends inside the tensor-info record.
    return Buffer.concat([header, info]);
  }
  const beforePad = 24 + info.length;
  const padLen = pad ? (ALIGNMENT - (beforePad % ALIGNMENT)) % ALIGNMENT : 0;
  const data = Buffer.alloc(16);
  [1.25, 2.5, 3.75, 5].forEach((v, i) => data.writeFloatLE(v, i * 4));
  return Buffer.concat([header, info, Buffer.alloc(padLen), data]);
}

describe("GGUF inspection does not trust the magic alone", () => {
  it("reports the parsed counts for a structurally complete, aligned file", () => {
    const inspection = inspectModelBuffer(gguf());
    expect(inspection.validModel).toBe(true);
    expect(inspection.format).toBe("gguf");
    expect(inspection.tensorCount).toBe(1);
    expect(inspection.tensorDataAligned).toBe(true);
  });

  it("accepts a header-only GGUF with no tensor table", () => {
    const inspection = inspectModelBuffer(gguf({ withTensor: false }));
    expect(inspection.validModel).toBe(true);
    expect(inspection.tensorCount).toBe(0);
    expect(inspection.tensorDataAligned).toBe(true);
  });

  it("rejects a truncated tensor-info record instead of trusting the magic", () => {
    const broken = gguf({ truncateTensorInfo: true });
    expect(parseGgufLayout(new Uint8Array(broken))).toBeNull();
    const inspection = inspectModelBuffer(broken);
    expect(inspection.validModel).toBe(false);
    expect(inspection.format).toBe("gguf");
    expect(inspection.tensorCount).toBe(0);
  });

  it("flags a tensor region that is not padded to the alignment", () => {
    const inspection = inspectModelBuffer(gguf({ pad: false }));
    expect(inspection.validModel).toBe(true);
    expect(inspection.tensorDataAligned).toBe(false);
  });

  it("rejects a buffer that is not GGUF at all", () => {
    const inspection = inspectModelBuffer(Buffer.from("not a model"));
    expect(inspection.validModel).toBe(false);
  });

  it("keeps reporting a protected GGUF as protected even when it does not parse", () => {
    const broken = gguf({ truncateTensorInfo: true });
    const tagged = Buffer.concat([broken, Buffer.from(" BLA-MODEL-SHIELD")]);
    const inspection = inspectModelBuffer(tagged);
    expect(inspection.validModel).toBe(false);
    expect(inspection.blaProtected).toBe(true);
  });

  it("refuses to replace a non-GGUF file with synthetic metadata", () => {
    // A `.gguf` extension alone routes a file here, so the protection entry
    // point must fail closed instead of emitting a container with no weights.
    expect(() =>
      protectGgufBuffer(Buffer.from("not a model at all"), {
        intensity: "balanced",
        seed: "gguf-fail-closed",
      }),
    ).toThrow(/not a parseable GGUF/);
    expect(() =>
      protectGgufBuffer(Buffer.alloc(0), {
        intensity: "balanced",
        seed: "gguf-fail-closed",
      }),
    ).toThrow(/not a parseable GGUF/);
  });

  it("still protects a well-formed GGUF with no tensors", () => {
    const protectedModel = protectGgufBuffer(gguf({ withTensor: false }), {
      intensity: "balanced",
      seed: "gguf-fail-closed",
    });
    expect(protectedModel.buffer.subarray(0, 4).toString("ascii")).toBe("GGUF");
    expect(protectedModel.buffer.length).toBeGreaterThan(24);
  });
});