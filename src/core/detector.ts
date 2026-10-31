import { statSync, openSync, readSync, closeSync } from "node:fs";
import { extname } from "node:path";
import type { ArtifactFormat } from "./types.js";

/**
 * Format-aware detector that inspects both magic bytes and file extensions
 * to route targets accurately across all 19 REA-supported artifact formats.
 */
export function detectArtifactFormat(targetPath: string): ArtifactFormat {
  let stats;
  try {
    stats = statSync(targetPath);
  } catch {
    return "unknown";
  }

  if (stats.isDirectory()) {
    return "directory";
  }

  const ext = extname(targetPath).toLowerCase();

  // Read up to 4096 header bytes for binary magic & CLR metadata inspection
  const header = Buffer.alloc(Math.min(4096, stats.size));
  if (header.length > 0) {
    const fd = openSync(targetPath, "r");
    try {
      readSync(fd, header, 0, header.length, 0);
    } finally {
      closeSync(fd);
    }
  }

  // 0. Apple Binary PropertyList (`bplist00` / `bplist01`)
  if (
    header.length >= 8 &&
    header.subarray(0, 6).toString("latin1") === "bplist"
  ) {
    return "apple-plist";
  }

  // 1. SQLite 3 database: `SQLite format 3\0`
  if (
    header.length >= 16 &&
    header.subarray(0, 16).toString("latin1") === "SQLite format 3\0"
  ) {
    return "sqlite";
  }

  // 2. GGUF model artifact: `GGUF` (0x47 0x47 0x55 0x46)
  if (
    header.length >= 4 &&
    header[0] === 0x47 &&
    header[1] === 0x47 &&
    header[2] === 0x55 &&
    header[3] === 0x46
  ) {
    return "model-gguf";
  }

  // 3. Android Dalvik Executable (`.dex`): `dex\n` (0x64 0x65 0x78 0x0a)
  if (
    header.length >= 4 &&
    header[0] === 0x64 &&
    header[1] === 0x65 &&
    header[2] === 0x78 &&
    header[3] === 0x0a
  ) {
    return "android-dex";
  }

  // 4. Unity IL2CPP `global-metadata.dat`: magic 0xFAB11BAF (little-endian: AF 1B B1 FA)
  if (header.length >= 4 && header.readUInt32LE(0) === 0xfab11baf) {
    return "il2cpp-metadata";
  }

  // 5. WebAssembly binary: `\0asm` (0x00 0x61 0x73 0x6d)
  if (
    header.length >= 4 &&
    header[0] === 0x00 &&
    header[1] === 0x61 &&
    header[2] === 0x73 &&
    header[3] === 0x6d
  ) {
    return "wasm";
  }

  // 6. ELF binary: `\x7fELF`
  if (
    header.length >= 4 &&
    header[0] === 0x7f &&
    header[1] === 0x45 &&
    header[2] === 0x4c &&
    header[3] === 0x46
  ) {
    return "native-elf";
  }

  // 7. JVM `.class` vs Mach-O binary (thin 32/64 BE/LE or fat universal)
  if (header.length >= 4) {
    const magicBE = header.readUInt32BE(0);
    if (magicBE === 0xcafebabe) {
      if (ext === ".class") return "jvm-class";
      // In Mach-O universal fat binaries, uint32BE(4) is nfat_arch (1..20).
      // In JVM .class files, uint16BE(4) is minor_version and uint16BE(6) is major_version (>= 45).
      if (header.length >= 8) {
        const nfatOrVersion = header.readUInt32BE(4);
        const majorVersion = header.readUInt16BE(6);
        if (nfatOrVersion > 30 && majorVersion >= 45 && majorVersion <= 90) {
          return "jvm-class";
        }
      }
      return "native-macho";
    }
    if (
      magicBE === 0xfeedface ||
      magicBE === 0xcefaedfe ||
      magicBE === 0xfeedfacf ||
      magicBE === 0xcffaedfe ||
      magicBE === 0xbebafeca
    ) {
      return "native-macho";
    }
  }

  // 8. PE binary (`MZ`) or .NET Managed CLR assembly (contains `BSJB` metadata root)
  if (header.length >= 2 && header[0] === 0x4d && header[1] === 0x5a) {
    if (header.includes(Buffer.from("BSJB", "ascii"))) {
      return "dotnet-managed";
    }
    return "native-pe";
  }

  // 9. Electron ASAR archive: Pickles header (uint32LE(0) === 4, uint32LE(12) === jsonLen)
  if (
    ext === ".asar" ||
    (header.length >= 16 &&
      header.readUInt32LE(0) === 4 &&
      header.subarray(16).toString("utf8").trimStart().startsWith('{"files"'))
  ) {
    return "electron-asar";
  }

  // 10. Safetensors model artifact: `.safetensors` or 8-byte uint64 LE header size followed by `{"`
  if (
    ext === ".safetensors" ||
    (header.length >= 10 &&
      header[8] === 0x7b &&
      header[9] === 0x22 &&
      header.readUInt32LE(4) === 0 &&
      header.readUInt32LE(0) > 2 &&
      header.readUInt32LE(0) < 100_000_000)
  ) {
    return "model-safetensors";
  }

  // 11. ZIP / APK archive: `PK\x03\x04`
  if (
    header.length >= 4 &&
    header[0] === 0x50 &&
    header[1] === 0x4b &&
    header[2] === 0x03 &&
    header[3] === 0x04
  ) {
    return ext === ".apk" ? "android-apk" : "archive-zip";
  }

  // 12. CPython `.pyc` bytecode (magic bytes 0x0d 0x0a at offset 2..3)
  if (
    ext === ".pyc" ||
    (header.length >= 16 && header[2] === 0x0d && header[3] === 0x0a)
  ) {
    return "python-pyc";
  }

  // 13. Erlang BEAM IFF: `FOR1....BEAM`
  if (
    header.length >= 12 &&
    header.subarray(0, 4).toString("latin1") === "FOR1" &&
    header.subarray(8, 12).toString("latin1") === "BEAM"
  ) {
    return "erlang-beam";
  }

  // 14. Classic libpcap / pcapng magic
  if (header.length >= 4) {
    const magicLE = header.readUInt32LE(0);
    if (
      magicLE === 0xa1b2c3d4 ||
      magicLE === 0xa1b23c4d ||
      magicLE === 0xd4c3b2a1
    ) {
      return "pcap-capture";
    }
    // pcapng section header block
    if (magicLE === 0x0a0d0d0a) {
      return "pcap-capture";
    }
  }

  // 15. Microsoft UF2 firmware container (three magics on a complete first block)
  if (
    header.length >= 512 &&
    header.readUInt32LE(0) === 0x0a324655 &&
    header.readUInt32LE(4) === 0x9e5d5157 &&
    header.readUInt32LE(508) === 0x0ab16f30
  ) {
    return "firmware-uf2";
  }

  // 16. Extension-based formats

  if ([".js", ".mjs", ".cjs", ".jsx"].includes(ext)) return "javascript";
  if ([".ts", ".mts", ".cts", ".tsx"].includes(ext)) return "typescript";
  if (ext === ".map") return "sourcemap";
  if ([".html", ".htm"].includes(ext)) return "html-bundle";
  if ([".py", ".pyw"].includes(ext)) return "python-source";
  if (ext === ".wasm") return "wasm";
  if ([".sqlite", ".sqlite3", ".db"].includes(ext)) return "sqlite";
  if (ext === ".gguf") return "model-gguf";
  if (ext === ".dex") return "android-dex";
  if ([".plist", ".entitlements", ".mobileprovision"].includes(ext)) return "apple-plist";
  if (ext === ".class") return "jvm-class";
  if (ext === ".beam") return "erlang-beam";
  if ([".evm", ".bin-evm", ".solidity-bin"].includes(ext)) return "evm-bytecode";
  if ([".pcap", ".pcapng", ".cap"].includes(ext)) return "pcap-capture";
  if (ext === ".ptx") return "gpu-ptx";
  if (ext === ".uf2") return "firmware-uf2";

  return "unknown";
}
