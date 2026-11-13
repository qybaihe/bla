import { describe, expect, it } from "vitest";
import {
  appendWasmCustomSection,
  inspectWasmBinary,
  readWasmCustomSectionContent,
  stripWasmCustomSectionByName,
} from "../src/shields/formats/wasm.js";

// Valid magic + version, then a lone section-id byte with no size LEB128 →
// the section-size header is truncated. The walk helpers must stay defensive.
const TRUNCATED = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x07]);

describe("WASM section walk is defensive on a truncated section header", () => {
  it("inspectWasmBinary returns a summary instead of throwing", () => {
    const info = inspectWasmBinary(TRUNCATED);
    expect(info.validMagic).toBe(true);
    expect(info.sectionCount).toBe(0);
    expect(info.exportNames).toEqual([]);
  });

  it("readWasmCustomSectionContent returns null instead of throwing", () => {
    expect(readWasmCustomSectionContent(TRUNCATED, "name")).toBeNull();
  });

  it("stripWasmCustomSectionByName preserves the bytes instead of throwing", () => {
    const out = stripWasmCustomSectionByName(TRUNCATED, "name");
    expect(out.equals(TRUNCATED)).toBe(true);
  });

  it("appendWasmCustomSection still appends instead of throwing", () => {
    const out = appendWasmCustomSection(TRUNCATED, "bla.sidecar.v1", Buffer.from("x"));
    expect(out.subarray(0, TRUNCATED.length).equals(TRUNCATED)).toBe(true);
    expect(out.toString("latin1")).toContain("bla.sidecar.v1");
  });
});
