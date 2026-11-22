import { describe, expect, it } from "vitest";
import {
  inspectPcapCapture,
  protectPcapCaptureBuffer,
} from "../src/shields/formats/pcap-capture.js";

const PCAP_MAGIC = 0xa1b2c3d4;

function globalHeader(linkType = 1): Buffer {
  const h = Buffer.alloc(24, 0);
  h.writeUInt32LE(PCAP_MAGIC, 0);
  h.writeUInt16LE(2, 4);
  h.writeUInt16LE(4, 6);
  h.writeUInt32LE(65535, 16);
  h.writeUInt32LE(linkType, 20);
  return h;
}

function record(payload: Buffer): Buffer {
  const h = Buffer.alloc(16, 0);
  h.writeUInt32LE(payload.length, 8);
  h.writeUInt32LE(payload.length, 12);
  return Buffer.concat([h, payload]);
}

describe("protect refuses a libpcap capture whose record table is incomplete", () => {
  it("rejects a record that declares more bytes than the file holds", () => {
    const truncated = Buffer.concat([
      globalHeader(),
      Buffer.alloc(16, 0), // record header claiming 0x0 bytes...
    ]);
    truncated.writeUInt32LE(4000, 24 + 8); // ...then a 4000-byte incl_len with nothing behind it
    truncated.writeUInt32LE(4000, 24 + 12);

    expect(() => protectPcapCaptureBuffer(truncated)).toThrow(/libpcap capture/i);
  });

  it("keeps inspectPcapCapture read-only on the same truncated input", () => {
    const truncated = Buffer.concat([globalHeader(), Buffer.alloc(16, 0)]);
    truncated.writeUInt32LE(4000, 24 + 8);

    const inspection = inspectPcapCapture(truncated);
    expect(inspection.validMagic).toBe(true);
    expect(inspection.exactFraming).toBe(false);
  });

  it("rejects trailing bytes that cannot form a record header", () => {
    const withFragment = Buffer.concat([
      globalHeader(),
      record(Buffer.from("12345678", "latin1")),
      Buffer.from([0x01, 0x02, 0x03]),
    ]);
    expect(() => protectPcapCaptureBuffer(withFragment)).toThrow(/libpcap capture/i);
  });

  it("still protects a well-formed capture", () => {
    const wellFormed = Buffer.concat([
      globalHeader(),
      record(Buffer.from("12345678", "latin1")),
      record(Buffer.from("abcdefgh", "latin1")),
    ]);
    const result = protectPcapCaptureBuffer(wellFormed, { intensity: "balanced", seed: "pcap-ok" });
    expect(result.buffer.length).toBeGreaterThan(wellFormed.length);
    expect(inspectPcapCapture(result.buffer).validMagic).toBe(true);
  });
});
