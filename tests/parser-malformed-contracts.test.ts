import { describe, expect, it } from "vitest";
import { inspectErlangBeam, protectErlangBeamBuffer } from "../src/shields/formats/erlang-beam.js";
import { inspectPcapCapture, protectPcapCaptureBuffer } from "../src/shields/formats/pcap-capture.js";
import { protectApplePlistBuffer } from "../src/shields/formats/apple-plist.js";
import { protectDotnetManagedBuffer } from "../src/shields/formats/dotnet-managed.js";
import { protectGpuPtxText } from "../src/shields/formats/gpu-ptx.js";

const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

const chunk = (name: string, payload: Buffer): Buffer =>
  Buffer.concat([Buffer.from(name, "latin1"), u32(payload.length), payload]);

function buildMinimalBeam(): Buffer {
  const atoms = ["demo_mod", "module_info"];
  const atomBody = Buffer.concat([
    u32(atoms.length),
    ...atoms.map((a) => Buffer.concat([Buffer.from([a.length]), Buffer.from(a, "utf8")])),
  ]);
  const code = Buffer.concat([u32(16), u32(0), u32(169), u32(4), u32(2), Buffer.from("code")]);
  const form = Buffer.concat([
    Buffer.from("BEAM", "latin1"),
    chunk("AtU8", atomBody),
    chunk("Code", code),
  ]);
  return Buffer.concat([Buffer.from("FOR1", "latin1"), u32(form.length), form]);
}

function buildMinimalPcapHeader(): Buffer {
  const hdr = Buffer.alloc(24);
  hdr.writeUInt32LE(0xa1b2c3d4, 0);
  hdr.writeUInt16LE(2, 4);
  hdr.writeUInt16LE(4, 6);
  hdr.writeUInt32LE(65535, 16);
  hdr.writeUInt32LE(1, 20);
  return hdr;
}

describe("parser shields fail closed on malformed input", () => {
  it("refuses to synthesize a replacement libpcap capture", () => {
    expect(() => protectPcapCaptureBuffer(Buffer.alloc(0), {})).toThrow(/libpcap capture/);
    expect(() =>
      protectPcapCaptureBuffer(Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]), {}),
    ).toThrow(/libpcap capture/);
  });

  it("preserves the original libpcap global header and existing bytes", () => {
    const header = buildMinimalPcapHeader();
    const out = protectPcapCaptureBuffer(header, { intensity: "balanced", seed: "pcap-contract" });
    expect(out.buffer.subarray(0, header.length).equals(header)).toBe(true);
    expect(out.buffer.length).toBeGreaterThan(header.length);
    expect(inspectPcapCapture(out.buffer).validMagic).toBe(true);
  });

  it("refuses to synthesize a replacement BEAM module", () => {
    expect(() => protectErlangBeamBuffer(Buffer.alloc(0), {})).toThrow(/BEAM module/);
    expect(() => protectErlangBeamBuffer(Buffer.from("FOR1xxxxNOPE"), {})).toThrow(/BEAM module/);
  });

  it("keeps original BEAM atoms and chunks when the container is valid", () => {
    const raw = buildMinimalBeam();
    expect(inspectErlangBeam(raw).validMagic).toBe(true);
    const out = protectErlangBeamBuffer(raw, { intensity: "balanced", seed: "beam-contract" });
    expect(inspectErlangBeam(out.buffer).validMagic).toBe(true);
    expect(out.buffer.toString("utf8")).toContain("demo_mod");
    expect(out.buffer.length).toBeGreaterThan(raw.length);
  });

  it("refuses to synthesize a replacement Apple plist", () => {
    expect(() => protectApplePlistBuffer(Buffer.alloc(0))).toThrow(/Apple property list/);
    expect(() => protectApplePlistBuffer(Buffer.from("not a plist at all"))).toThrow(
      /Apple property list/,
    );
  });

  it("appends to a binary plist without losing the original bytes", () => {
    const raw = Buffer.from("bplist00", "latin1");
    const out = protectApplePlistBuffer(raw, { intensity: "balanced", seed: "plist-contract" });
    expect(out.buffer.subarray(0, raw.length).equals(raw)).toBe(true);
  });

  it("never loses PTX or managed-assembly input bytes", () => {
    const ptx = "hello world";
    expect(protectGpuPtxText(ptx, { intensity: "balanced" }).text.startsWith(ptx)).toBe(true);

    const managed = Buffer.from([0x4d, 0x5a]);
    const out = protectDotnetManagedBuffer(managed, { intensity: "balanced" });
    expect(out.buffer.subarray(0, managed.length).equals(managed)).toBe(true);
  });
});