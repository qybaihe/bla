import { describe, expect, it } from "vitest";
import { inspectErlangBeam, protectErlangBeamBuffer } from "../src/shields/formats/erlang-beam.js";

function u32be(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value >>> 0);
  return b;
}

function buildAtU8Chunk(): Buffer {
  const payload = Buffer.from([0, 0, 0, 1, 4, 0x74, 0x65, 0x73, 0x74, 0, 0, 0]);
  return Buffer.concat([Buffer.from("AtU8", "latin1"), u32be(9), payload]);
}

function buildWellFormedBeam(): Buffer {
  const body = Buffer.concat([Buffer.from("BEAM", "latin1"), buildAtU8Chunk()]);
  const formSize = Buffer.alloc(4);
  formSize.writeUInt32BE(body.length, 0);
  return Buffer.concat([Buffer.from("FOR1", "latin1"), formSize, body]);
}

function buildTruncatedBeam(): Buffer {
  const badChunk = Buffer.concat([
    Buffer.from("Code", "latin1"),
    u32be(100),
    Buffer.from([0x01, 0x02]),
  ]);
  const body = Buffer.concat([Buffer.from("BEAM", "latin1"), buildAtU8Chunk(), badChunk]);
  const formSize = Buffer.alloc(4);
  formSize.writeUInt32BE(body.length, 0);
  return Buffer.concat([Buffer.from("FOR1", "latin1"), formSize, body]);
}

describe("Erlang BEAM chunk-table truncation fail-closed protection", () => {
  it("refuses to protect a BEAM whose chunk declares a payload past EOF instead of silently dropping it", () => {
    const truncated = buildTruncatedBeam();
    expect(() => protectErlangBeamBuffer(truncated)).toThrow(/Truncated BEAM chunk/);
  });

  it("keeps inspectErlangBeam non-throwing on a truncated BEAM chunk table", () => {
    const truncated = buildTruncatedBeam();
    const inspection = inspectErlangBeam(truncated);
    expect(inspection.validMagic).toBe(true);
    expect(inspection.chunkCount).toBe(1);
    expect(inspection.chunkNames).toEqual(["AtU8"]);
  });

  it("protects a well-formed BEAM while preserving its original chunks", () => {
    const wellFormed = buildWellFormedBeam();
    const result = protectErlangBeamBuffer(wellFormed);
    const inspection = inspectErlangBeam(result.buffer);
    expect(inspection.validMagic).toBe(true);
    expect(inspection.chunkNames).toContain("AtU8");
  });
});
