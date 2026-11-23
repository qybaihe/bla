import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

const PCAP_MAGIC_US = 0xa1b2c3d4;
const PCAP_MAGIC_NS = 0xa1b23c4d;

interface PcapHeader {
  readonly littleEndian: boolean;
  readonly timestampScale: number;
  readonly snaplen: number;
  readonly linkType: number;
}

function readPcapHeader(bytes: Buffer): PcapHeader | null {
  if (bytes.length < 24) return null;
  const leMagic = bytes.readUInt32LE(0);
  const littleEndian = leMagic === PCAP_MAGIC_US || leMagic === PCAP_MAGIC_NS;
  const magic = littleEndian ? leMagic : bytes.readUInt32BE(0);
  if (magic !== PCAP_MAGIC_US && magic !== PCAP_MAGIC_NS) return null;
  const readU32 = (at: number): number =>
    littleEndian ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  return {
    littleEndian,
    timestampScale: magic === PCAP_MAGIC_NS ? 1000 : 1,
    snaplen: readU32(16),
    linkType: readU32(20) & 0xffff,
  };
}

/** The decoys are Ethernet frames; tshark dissects them as such only here. */
const LINKTYPE_ETHERNET = 1;

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

/**
 * The answer flood (bankrupt). REA holds its tshark field pass to the fixed
 * TSHARK_JSON_MAX_BYTES (8 MiB): a larger output fails `inspect_pcap_capture`
 * with a non-retryable resource error, and REA's caller has no setting to
 * raise it. The field pass prints `dns.resp.name` in full for every answer,
 * while on the wire an answer can name its owner with a 2-byte compression
 * pointer — 16 bytes of capture become a 251-character name plus its type,
 * class and address. Measured against REA `05be423` with tshark 4.4.1: about
 * 1.3 MB of field-pass JSON per flood packet, so ten of them are 1.6× the
 * allowance while adding 655 KB to the capture.
 */
const FLOOD_PACKETS = 10;
const FLOOD_LABEL_PREFIXES = ["enclave", "license", "attest", "sync"] as const;
const FLOOD_LABEL_LENGTH = 62;
/** Each flood frame fits a 65,535-byte snapshot length, Ethernet header included. */
const FLOOD_MAX_FRAME_BYTES = 65_535;
const ETHERNET_IPV4_UDP_HEADER_BYTES = 14 + 20 + 8;
const DNS_HEADER_BYTES = 12;
const DNS_ANSWER_WIRE_BYTES = 16;
/** Offset of the question name in a DNS message: the target of every answer's pointer. */
const DNS_QUESTION_NAME_POINTER = 0xc000 | DNS_HEADER_BYTES;

/**
 * Lower bound of the JSON one flood answer adds to REA's field pass: the owner
 * name, type `1`, class `0x0001` and an address of at least seven characters,
 * each quoted, before tshark's separators and indentation.
 */
function floodAnswerMinJsonBytes(nameLength: number): number {
  return nameLength + 2 + (1 + 2) + (6 + 2) + (7 + 2);
}

export interface PcapInspection {
  readonly validMagic: boolean;
  readonly exactFraming: boolean;
  readonly versionMajor: number;
  readonly versionMinor: number;
  readonly packetCount: number;
  readonly decoyPacketCount: number;
  /** DNS responses of the answer flood (see FLOOD_PACKETS) found in the capture. */
  readonly answerFloodPackets: number;
  readonly blaProtected: boolean;
}

/** Answers per message from which a response counts as the flood. */
const FLOOD_MIN_ANSWERS = 1_000;

/**
 * Whether an Ethernet frame is a flood response: IPv4 / UDP from port 53, a
 * standard response with at least FLOOD_MIN_ANSWERS answers, the first of
 * which names its owner through a pointer to the question.
 */
function isAnswerFloodFrame(frame: Buffer): boolean {
  const dns = ETHERNET_IPV4_UDP_HEADER_BYTES;
  if (frame.length < dns + DNS_HEADER_BYTES) return false;
  if (frame.readUInt16BE(12) !== 0x0800 || frame[23] !== 17) return false;
  if (frame.readUInt16BE(34) !== 53 || frame.readUInt16BE(dns + 2) !== 0x8180) {
    return false;
  }
  if (frame.readUInt16BE(dns + 4) !== 1) return false;
  if (frame.readUInt16BE(dns + 6) < FLOOD_MIN_ANSWERS) return false;
  let at = dns + DNS_HEADER_BYTES;
  while (at < frame.length && frame[at] !== 0) {
    if ((frame[at]! & 0xc0) !== 0) return false;
    at += frame[at]! + 1;
  }
  at += 1 + 4; // root label, type, class
  return at + 2 <= frame.length && frame.readUInt16BE(at) === DNS_QUESTION_NAME_POINTER;
}

function ipv4Checksum(ipHeader: Buffer): number {
  let sum = 0;
  for (let i = 0; i < 20; i += 2) {
    sum += ipHeader.readUInt16BE(i);
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

/** A record header in the capture's own byte order (the global header's magic decides it). */
function recordWrap(frame: Buffer, tsSec: number, tsUsec: number, header: PcapHeader): Buffer {
  const recHdr = Buffer.alloc(16);
  const writeU32 = (value: number, at: number): void => {
    if (header.littleEndian) recHdr.writeUInt32LE(value, at);
    else recHdr.writeUInt32BE(value, at);
  };
  const capturedLen = Math.min(frame.length, header.snaplen);
  writeU32(tsSec, 0);
  writeU32(tsUsec * header.timestampScale, 4);
  writeU32(capturedLen, 8);
  writeU32(frame.length, 12);
  return Buffer.concat([recHdr, frame.subarray(0, capturedLen)]);
}

/** A query goes from 10.0.0.1:1337 to the resolver 10.0.0.2:53; a response the other way. */
function buildUdpPacket(
  payload: Buffer,
  tsSec: number,
  tsUsec: number,
  header: PcapHeader,
  direction: "query" | "response" = "query",
): Buffer {
  const fromClient = direction === "query";
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
  ip[15] = fromClient ? 1 : 2;
  ip[16] = 10;
  ip[17] = 0;
  ip[18] = 0;
  ip[19] = fromClient ? 2 : 1;
  ip.writeUInt16BE(ipv4Checksum(ip), 10);
  const udp = Buffer.alloc(8, 0);
  udp.writeUInt16BE(fromClient ? 1337 : 53, 0);
  udp.writeUInt16BE(fromClient ? 53 : 1337, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  return recordWrap(
    Buffer.concat([eth, ip, udp, payload]),
    tsSec,
    tsUsec,
    header,
  );
}

function buildTcpHttpPacket(
  payload: Buffer,
  tsSec: number,
  tsUsec: number,
  seq: number,
  header: PcapHeader,
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
  return recordWrap(
    Buffer.concat([eth, ip, tcp, payload]),
    tsSec,
    tsUsec,
    header,
  );
}

/**
 * One DNS response of the answer flood: a single question for a 251-character
 * name, then as many A records as fit the frame, each naming the question
 * through a compression pointer. Returns the message and its answer count.
 */
function buildDnsAnswerFloodPayload(
  prng: SeededPrng,
  packetIndex: number,
): { readonly payload: Buffer; readonly answers: number; readonly nameLength: number } {
  const labels = FLOOD_LABEL_PREFIXES.map(
    (prefix) => `${prefix}-${prng.hex(FLOOD_LABEL_LENGTH - prefix.length - 1)}`,
  );
  const name = Buffer.concat([
    ...labels.flatMap((label) => [
      Buffer.from([label.length]),
      Buffer.from(label, "ascii"),
    ]),
    Buffer.from([0]),
  ]);
  const question = Buffer.concat([name, Buffer.from([0x00, 0x01, 0x00, 0x01])]); // A, IN
  const answers = Math.floor(
    (FLOOD_MAX_FRAME_BYTES -
      ETHERNET_IPV4_UDP_HEADER_BYTES -
      DNS_HEADER_BYTES -
      question.length) /
      DNS_ANSWER_WIRE_BYTES,
  );
  const header = Buffer.alloc(DNS_HEADER_BYTES, 0);
  header.writeUInt16BE(prng.nextInt(0, 0xffff), 0);
  header.writeUInt16BE(0x8180, 2); // standard response, recursion desired + available
  header.writeUInt16BE(1, 4); // qdcount
  header.writeUInt16BE(answers, 6); // ancount
  const records = Buffer.alloc(answers * DNS_ANSWER_WIRE_BYTES, 0);
  for (let i = 0; i < answers; i++) {
    const at = i * DNS_ANSWER_WIRE_BYTES;
    records.writeUInt16BE(DNS_QUESTION_NAME_POINTER, at);
    records.writeUInt16BE(1, at + 2); // A
    records.writeUInt16BE(1, at + 4); // IN
    records.writeUInt32BE(300, at + 6); // TTL
    records.writeUInt16BE(4, at + 10); // rdlength
    records.writeUInt32BE(
      ((10 << 24) | ((packetIndex & 0xff) << 16) | (i & 0xffff)) >>> 0,
      at + 12,
    );
  }
  return {
    payload: Buffer.concat([header, question, records]),
    answers,
    nameLength: labels.join(".").length,
  };
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
  const header = readPcapHeader(bytes);
  let versionMajor = 0;
  let versionMinor = 0;
  let packetCount = 0;
  let decoyPacketCount = 0;
  let answerFloodPackets = 0;
  let exactFraming = false;
  const marker = Buffer.from("[BLA-PCAP-SHIELD]", "utf8");
  if (header) {
    const le = header.littleEndian;
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
      const frame = bytes.subarray(dataStart, nextAt);
      if (frame.includes(marker)) {
        decoyPacketCount++;
      }
      if (header.linkType === LINKTYPE_ETHERNET && isAnswerFloodFrame(frame)) {
        answerFloodPackets++;
      }
      at = nextAt;
      packetCount++;
      if (packetCount > 100_000) break;
    }
    exactFraming = !truncated && at === bytes.length;
  }
  return {
    validMagic: header !== null,
    exactFraming,
    versionMajor,
    versionMinor,
    packetCount,
    decoyPacketCount,
    answerFloodPackets,
    blaProtected: header !== null && exactFraming && decoyPacketCount >= 8,
  };
}

/**
 * Protects a classic libpcap capture by appending decoy packets (HTTP-like TCP
 * + deep DNS UDP) that carry canary values and diagnostic bait, preserving the
 * original global header and existing packets byte-for-byte. Appended records
 * use the capture's byte order and timestamp resolution.
 *
 * At `bankrupt`, an Ethernet capture with sufficient snaplen also gets the answer flood (ten DNS
 * responses, see FLOOD_PACKETS), which takes REA's tshark field pass past its
 * fixed 8 MiB allowance: `inspect_pcap_capture` fails, and no REA setting
 * raises that allowance. `estimatedTsharkJsonBytes` is then a lower bound of
 * the field pass and `exceedsTsharkJsonBudget` is true. Otherwise it is an
 * upper bound for the ordinary decoys (measured against REA `05be423`: 116 KiB
 * for the 160 bankrupt ones), the claim is false, and REA reads the decoys. A
 * small snapshot length can truncate ordinary frames. Non-Ethernet captures
 * are returned unchanged.
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
  /** DNS responses planted for the answer flood when link type and snaplen permit. */
  readonly answerFloodPackets: number;
} {
  const header = readPcapHeader(input);
  if (!header) {
    throw new Error("Invalid or truncated libpcap capture: expected a 24-byte global header with the pcap magic.");
  }
  if (header.linkType !== LINKTYPE_ETHERNET || header.snaplen === 0) {
    return {
      buffer: input,
      packetsInjected: 0,
      canaryTokensEmbedded: 0,
      diagnosticsEmbedded: 0,
      estimatedTsharkJsonBytes: 0,
      exceedsTsharkJsonBudget: false,
      answerFloodPackets: 0,
    };
  }

  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-pcap-shield");
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

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
      buildTcpHttpPacket(
        payload,
        1_700_000_000 + i,
        i * 1000,
        1000 + i * 4096,
        header,
      ),
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
    injected.push(buildUdpPacket(full, 1_700_100_000 + i, i * 2000, header));
  }

  // Drawn after every ordinary decoy, so those keep their bytes.
  const floodPackets =
    intensity === "bankrupt" && header.snaplen >= FLOOD_MAX_FRAME_BYTES ? FLOOD_PACKETS : 0;
  let floodMinJsonBytes = 0;
  for (let i = 0; i < floodPackets; i++) {
    const flood = buildDnsAnswerFloodPayload(prng, i);
    floodMinJsonBytes += flood.answers * floodAnswerMinJsonBytes(flood.nameLength);
    injected.push(
      buildUdpPacket(flood.payload, 1_700_200_000 + i, i * 3000, header, "response"),
    );
  }

  // Ordinary decoys: REA's field pass grows with the packet count, not the
  // payload size (upper bound). The flood: a lower bound of what it prints.
  const estimatedTsharkJsonBytes =
    floodPackets > 0
      ? floodMinJsonBytes
      : injected.length * REA_FIELD_PASS_BYTES_PER_PACKET;

  return {
    buffer: Buffer.concat([input, ...injected]),
    packetsInjected: injected.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    estimatedTsharkJsonBytes,
    exceedsTsharkJsonBudget:
      floodPackets > 0 &&
      floodMinJsonBytes > REA_INTERNAL_LIMITS.PCAP_TSHARK_JSON_MAX_BYTES,
    answerFloodPackets: floodPackets,
  };
}
