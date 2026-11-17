import { describe, expect, it } from "vitest";
import { protectApplePlistBuffer } from "../src/shields/formats/apple-plist.js";

const BPLIST_TRAILER_BYTES = 32;

function shapedBinaryPlist(body: Buffer = Buffer.alloc(0)): Buffer {
  return Buffer.concat([
    Buffer.from("bplist00", "latin1"),
    body,
    Buffer.alloc(BPLIST_TRAILER_BYTES, 0),
  ]);
}

describe("binary Apple plist protection", () => {
  it("keeps the binary plist trailer at EOF while inserting decoys", () => {
    const raw = shapedBinaryPlist(Buffer.from([1, 2, 3, 4]));
    const out = protectApplePlistBuffer(raw, {
      intensity: "balanced",
      seed: "bplist-trailer",
    });

    expect(out.buffer.length).toBeGreaterThan(raw.length);
    expect(
      out.buffer.subarray(out.buffer.length - BPLIST_TRAILER_BYTES),
    ).toEqual(raw.subarray(raw.length - BPLIST_TRAILER_BYTES));
    expect(
      out.buffer.subarray(0, raw.length - BPLIST_TRAILER_BYTES),
    ).toEqual(raw.subarray(0, raw.length - BPLIST_TRAILER_BYTES));
    expect(out.buffer.toString("latin1")).toContain(
      "BLA_BPLIST_DEPTH_GUARD_132",
    );
    expect(out.buffer.toString("latin1")).toContain(
      "PROTECTED_CANARY_CREDENTIAL=",
    );
  });

  it("refuses a binary plist without room for a header and trailer", () => {
    expect(() =>
      protectApplePlistBuffer(Buffer.from("bplist00", "latin1")),
    ).toThrow(/binary Apple property list/i);
  });
});