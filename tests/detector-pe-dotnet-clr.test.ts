import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectArtifactFormat } from "../src/core/detector.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-pe-clr-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * Builds a minimal PE32+ image with `.text` and `.rdata` sections plus a CLR
 * Runtime Header data-directory entry (index 14) at a controllable RVA/Size.
 * Layout mirrors `tests/issue-157-pe32-and-marker-spoof.test.ts`.
 */
function buildPe32PlusWithClrDir(opts: {
  readonly clrRva: number;
  readonly clrSize: number;
  readonly plantBsjb: boolean;
}): Buffer {
  const peOffset = 0x80;
  const optHeaderSize = 0xf0;
  const sizeOfHeaders = 0x400;
  const rdataRawOffset = 0x600;
  const rdataRawSize = 0x200;
  const totalBytes = rdataRawOffset + rdataRawSize;

  const buf = Buffer.alloc(totalBytes, 0);
  buf.write("MZ", 0, "ascii");
  buf.writeUInt32LE(peOffset, 0x3c);
  buf.write("PE\0\0", peOffset, "ascii");

  const coff = peOffset + 4;
  buf.writeUInt16LE(0xaa64, coff + 0); // Machine = ARM64
  buf.writeUInt16LE(2, coff + 2); // NumberOfSections = 2
  buf.writeUInt16LE(optHeaderSize, coff + 16); // SizeOfOptionalHeader = 0xf0

  const opt = coff + 20;
  buf.writeUInt16LE(0x20b, opt + 0); // Magic = PE32+
  buf.writeUInt32LE(0x2000, opt + 56); // SizeOfImage
  buf.writeUInt32LE(sizeOfHeaders, opt + 60); // SizeOfHeaders
  buf.writeUInt32LE(16, opt + 108); // NumberOfRvaAndSizes = 16

  // CLR Runtime Header data directory = index 14 -> opt + 112 + 14 * 8
  const clrDir = opt + 112 + 14 * 8;
  buf.writeUInt32LE(opts.clrRva, clrDir);
  buf.writeUInt32LE(opts.clrSize, clrDir + 4);

  const sec0 = opt + optHeaderSize;
  buf.write(".text", sec0, "ascii");
  buf.writeUInt32LE(0x2000, sec0 + 12);
  buf.writeUInt32LE(0x200, sec0 + 16);
  buf.writeUInt32LE(0x400, sec0 + 20);
  buf.writeUInt32LE(0x60000020, sec0 + 36);

  const sec1 = sec0 + 40;
  buf.write(".rdata", sec1, "ascii");
  buf.writeUInt32LE(0x100, sec1 + 8);
  buf.writeUInt32LE(0x2000, sec1 + 12);
  buf.writeUInt32LE(rdataRawSize, sec1 + 16);
  buf.writeUInt32LE(rdataRawOffset, sec1 + 20);
  buf.writeUInt32LE(0x40000040, sec1 + 36);

  if (opts.plantBsjb) {
    buf.write("BSJB", rdataRawOffset, "ascii");
  }
  return buf;
}

describe("S24: native PE with `BSJB` bytes must not be routed to dotnet-managed", () => {
  it("classifies a PE32+ with a zeroed CLR data directory and BSJB in .rdata as native-pe", () => {
    const dir = makeTempDir();
    const pe = buildPe32PlusWithClrDir({ clrRva: 0, clrSize: 0, plantBsjb: true });
    const path = join(dir, "native-bsjb.exe");
    writeFileSync(path, pe);

    const format = detectArtifactFormat(path);
    expect(format).toBe("native-pe");
    expect(pe.toString("latin1")).toContain("BSJB");
  });

  it("classifies a PE32+ with a real non-zero CLR data directory (index 14) as dotnet-managed", () => {
    const dir = makeTempDir();
    const pe = buildPe32PlusWithClrDir({ clrRva: 0x2000, clrSize: 0x40, plantBsjb: false });
    const path = join(dir, "real-dotnet.exe");
    writeFileSync(path, pe);

    const format = detectArtifactFormat(path);
    expect(format).toBe("dotnet-managed");
  });

  it("classifies a truncated MZ-only file as native-pe without throwing", () => {
    const dir = makeTempDir();
    const path = join(dir, "truncated.exe");
    writeFileSync(path, Buffer.from("MZ"));

    let thrown: unknown = undefined;
    let format: ReturnType<typeof detectArtifactFormat> | undefined;
    try {
      format = detectArtifactFormat(path);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeUndefined();
    expect(format).toBe("native-pe");
  });
});
