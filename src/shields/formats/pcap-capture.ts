import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

/** Classic libpcap global-header magic (microsecond, little-endian host). */
const PCAP_MAGIC_LE = 0xa1b2c3d4;

/**
 * Upper bound of what REA's tshark field pass prints for one injected packet.
 * REA does not dissect a capture in full: it asks tshark for a fixed list of
 * fields (`-T json -e frame.number -e ip.src … -e dns.qry.name …`), and only
 * that output is held to TSHARK_JSON_MAX_BYTES; a failed second pass over the
 * DNS packets only marks REA's result partial. Measured against REA `05be423`
 * with tshark 4.4: about 550 bytes per injected HTTP-like packet and 1,030 per
 * DNS packet (it carries the query name). HTTP headers are not among the
 * fields, so the header count does not change it.
 */
const REA_FIELD_PASS_BYTES_PER_PACKET = 1_536;

export interface PcapInspection {
  readonly validMagic: boolean;
  readonly exactFraming: boolean;
  readonly versionMajor: number;
  readonly versionMinor: number;
  readonly packetCount: number;
  readonly decoyPacketCount: number;
  readonly blaProtected: boolean;
}

function ipv4Checksum(ipHeader: Buffer): number {
  let sum = 0;
  for (let i = 0; i < 20; i += 2) {
    sum += ipHeader.readUInt16BE(i);
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

function recordWrap(frame: Buffer, tsSec: number, tsUsec: number): Buffer {
  const recHdr = Buffer.alloc(16);
  recHdr.writeUInt32LE(tsSec, 0);
  recHdr.writeUInt32LE(tsUsec, 4);
  recHdr.writeUInt32LE(frame.length, 8);
  recHdr.writeUInt32LE(frame.length, 12);
  return Buffer.concat([recHdr, frame]);
}

function buildUdpPacket(payload: Buffer, tsSec: number, tsUsec: number): Buffer {
  const eth = Buffer.alloc(14, 0);
  eth[12] = 0x08;
  eth[13] = 0x00;
  const ipLen = 20 + 8 + payload.length;
  const ip = Buffer.alloc(20, 0);
  ip[0] = 0x45;
  ip.writeUInt16BE(ipLen, 2);
  ip[8] = 64;
  ip[9] = 17;
  ip[12] = 10;
  ip[13] = 0;
  ip[14] = 0;
  ip[15] = 1;
  ip[16] = 10;
  ip[17] = 0;
  ip[18] = 0;
  ip[19] = 2;
  ip.writeUInt16BE(ipv4Checksum(ip), 10);
  const udp = Buffer.alloc(8, 0);
  udp.writeUInt16BE(1337, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  return recordWrap(Buffer.concat([eth, ip, udp, payload]), tsSec, tsUsec);
}

function buildTcpHttpPacket(
  payload: Buffer,
  tsSec: number,
  tsUsec: number,
  seq: number,
): Buffer {
  const eth = Buffer.alloc(14, 0);
  eth[12] = 0x08;
  eth[13] = 0x00;
  const tcpHdrLen = 20;
  const ipLen = 20 + tcpHdrLen + payload.length;
  const ip = Buffer.alloc(20, 0);
  ip[0] = 0x45;
  ip.writeUInt16BE(ipLen, 2);
  ip[8] = 64;
  ip[9] = 6;
  ip[12] = 10;
  ip[13] = 0;
  ip[14] = 0;
  ip[15] = 1;
  ip[16] = 10;
  ip[17] = 0;
  ip[18] = 0;
  ip[19] = 2;
  ip.writeUInt16BE(ipv4Checksum(ip), 10);
  const tcp = Buffer.alloc(tcpHdrLen, 0);
  tcp.writeUInt16BE(40_000 + (seq % 1000), 0);
  tcp.writeUInt16BE(80, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(1, 8);
  tcp[12] = 5 << 4;
  tcp[13] = 0x18; // PSH+ACK
  tcp.writeUInt16BE(65535, 14);
  return recordWrap(Buffer.concat([eth, ip, tcp, payload]), tsSec, tsUsec);
}

function buildDnsQueryPayload(depth: number, canary: string): Buffer {
  const hdr = Buffer.alloc(12, 0);
  hdr.writeUInt16BE(0xb1a0, 0);
  hdr.writeUInt16BE(0x0100, 2); // standard query
  hdr.writeUInt16BE(1, 4); // qdcount
  const labels: Buffer[] = [];
  for (let i = 0; i < depth; i++) {
    const lab = `l${i.toString(36)}${canary.slice(0, 4)}`;
    const b = Buffer.from(lab, "ascii");
    labels.push(Buffer.from([b.length]), b);
  }
  labels.push(Buffer.from([0])); // root
  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0); // A
  qtype.writeUInt16BE(1, 2); // IN
  return Buffer.concat([hdr, ...labels, qtype]);
}

function buildHttpLikePayload(prng: SeededPrng, headerCount: number): Buffer {
  const lines: string[] = [
    "GET /bla/tarpit/exhaust HTTP/1.1",
    "Host: enclave.internal",
    "User-Agent: BLA-PCAP-Shield/1.0",
    `[BLA-PCAP-SHIELD] canary=${prng.hex(16)}`,
  ];
  for (let i = 0; i < headerCount; i++) {
    lines.push(`X-BLA-Nested-${i}: ${prng.hex(48)}`);
  }
  lines.push("Connection: keep-alive", "", "");
  return Buffer.from(lines.join("\r\n"), "utf8");
}

export function inspectPcapCapture(bytes: Buffer): PcapInspection {
  const validMagic =
    bytes.length >= 24 &&
    (bytes.readUInt32LE(0) === PCAP_MAGIC_LE ||
      bytes.readUInt32BE(0) === PCAP_MAGIC_LE ||
      bytes.readUInt32LE(0) === 0xa1b23c4d);
  let versionMajor = 0;
  let versionMinor = 0;
  let packetCount = 0;
  let decoyPacketCount = 0;
  let exactFraming = false;
  const marker = Buffer.from("[BLA-PCAP-SHIELD]", "utf8");
  if (validMagic && bytes.length >= 24) {
    const le =
      bytes.readUInt32LE(0) === PCAP_MAGIC_LE ||
      bytes.readUInt32LE(0) === 0xa1b23c4d;
    versionMajor = le ? bytes.readUInt16LE(4) : bytes.readUInt16BE(4);
    versionMinor = le ? bytes.readUInt16LE(6) : bytes.readUInt16BE(6);
    let at = 24;
    let truncated = false;
    while (at + 16 <= bytes.length) {
      const incl = le ? bytes.readUInt32LE(at + 8) : bytes.readUInt32BE(at + 8);
      const dataStart = at + 16;
      const nextAt = dataStart + incl;
      if (nextAt > bytes.length) {
        truncated = true;
        break;
      }
      if (bytes.subarray(dataStart, nextAt).includes(marker)) {
        decoyPacketCount++;
      }
      at = nextAt;
      packetCount++;
      if (packetCount > 100_000) break;
    }
    exactFraming = !truncated && at === bytes.length;
  }
  return {
    validMagic,
    exactFraming,
    versionMajor,
    versionMinor,
    packetCount,
    decoyPacketCount,
    blaProtected: validMagic && exactFraming && decoyPacketCount >= 8,
  };
}

/**
 * Protects a classic libpcap capture by appending decoy packets (HTTP-like TCP
 * + deep DNS UDP) that carry canary values and diagnostic bait, preserving the
 * original global header and existing packets byte-for-byte.
 *
 * `estimatedTsharkJsonBytes` is an upper bound of REA's tshark field pass over
 * the injected packets. It stays far below `TSHARK_JSON_MAX_BYTES` (8 MiB) at
 * every intensity — measured against REA `05be423`: 116 KiB for the 160
 * bankrupt packets, whose full dissection would be 12 MiB — so REA reads the
 * decoys rather than refusing the capture, and `exceedsTsharkJsonBudget` says so.
 */
export function protectPcapCaptureBuffer(
  input: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string;
  } = {},
): {
  readonly buffer: Buffer;
  readonly packetsInjected: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly estimatedTsharkJsonBytes: number;
  readonly exceedsTsharkJsonBudget: boolean;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-pcap-shield");
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const hasGlobalHeader =
    input.length >= 24 &&
    (input.readUInt32LE(0) === PCAP_MAGIC_LE ||
      input.readUInt32BE(0) === PCAP_MAGIC_LE ||
      input.readUInt32LE(0) === 0xa1b23c4d);
  if (!hasGlobalHeader) {
    throw new Error(
      "Invalid or truncated libpcap capture: expected a 24-byte global header with the pcap magic; refusing to synthesize a replacement capture.",
    );
  }
  const base = input;

  const httpPackets =
    intensity === "bankrupt" ? 96 : intensity === "maximum" ? 24 : 4;
  const dnsPackets =
    intensity === "bankrupt" ? 64 : intensity === "maximum" ? 16 : 4;
  const headerCount =
    intensity === "bankrupt" ? 200 : intensity === "maximum" ? 48 : 12;
  const dnsDepth = intensity === "bankrupt" ? 32 : intensity === "maximum" ? 16 : 6;

  const injected: Buffer[] = [];

  for (let i = 0; i < httpPackets; i++) {
    const payload = buildHttpLikePayload(prng, headerCount);
    injected.push(
      buildTcpHttpPacket(payload, 1_700_000_000 + i, i * 1000, 1000 + i * 4096),
    );
  }
  for (let i = 0; i < dnsPackets; i++) {
    const payload = buildDnsQueryPayload(dnsDepth, prng.hex(8));
    // Append diagnostic bait as additional TXT-like trailing bytes (still UDP).
    const bait = Buffer.from(
      `\n[BLA-PCAP-SHIELD]\n${deception.textRecords[i % Math.max(1, deception.textRecords.length)] ?? ""}\n`,
      "utf8",
    );
    const full = Buffer.concat([payload, bait]);
    injected.push(buildUdpPacket(full, 1_700_100_000 + i, i * 2000));
  }

  // REA's field pass grows with the packet count, not the payload size.
  const estimatedTsharkJsonBytes =
    injected.length * REA_FIELD_PASS_BYTES_PER_PACKET;

  return {
    buffer: Buffer.concat([base, ...injected]),
    packetsInjected: injected.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    estimatedTsharkJsonBytes,
    exceedsTsharkJsonBudget:
      estimatedTsharkJsonBytes > REA_INTERNAL_LIMITS.PCAP_TSHARK_JSON_MAX_BYTES,
  };
}
