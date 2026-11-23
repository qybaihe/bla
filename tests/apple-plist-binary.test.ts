import { describe, expect, it } from "vitest";
import { protectApplePlistBuffer } from "../src/shields/formats/apple-plist.js";

describe("binary Apple plist protection", () => {
  it("refuses a trailer claiming an absent offset table", () => {
    const raw = Buffer.concat([Buffer.from("bplist00"), Buffer.from([0xd0]), Buffer.alloc(32)]);
    expect(() => protectApplePlistBuffer(raw)).toThrow(/invalid offset table or trailer/i);
  });

  it("refuses a binary plist without room for a header and trailer", () => {
    expect(() =>
      protectApplePlistBuffer(Buffer.from("bplist00", "latin1")),
    ).toThrow(/binary Apple property list/i);
  });
});
