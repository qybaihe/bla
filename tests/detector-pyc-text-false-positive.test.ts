import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectArtifactFormat } from "../src/core/detector.js";
import { discoverHardenableArtifacts } from "../src/engine/harden.js";

function pycHeader(magic: number, flags = 0): Buffer {
  const header = Buffer.alloc(16);
  header.writeUInt16LE(magic, 0);
  header[2] = 0x0d;
  header[3] = 0x0a;
  header.writeUInt32LE(flags, 4);
  return Buffer.concat([header, Buffer.from([0xe3, 0x00, 0x00, 0x00])]);
}

describe("extensionless .pyc detection does not swallow CRLF text", () => {
  const dirs: string[] = [];
  const tempDir = (): string => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pyc-detect-"));
    dirs.push(dir);
    return dir;
  };

  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it.each([
    ["two-character JSON first line", '{}\r\n{"name":"demo","version":1}\r\n'],
    ["two-character comment first line", "##\r\nkey=value\r\nother=value\r\n"],
    ["two-character section first line", "[]\r\nentries follow on later lines\r\n"],
  ])("leaves an extensionless CRLF file with a %s unclassified", (_label, text) => {
    const file = join(tempDir(), "config");
    writeFileSync(file, text);
    expect(detectArtifactFormat(file)).toBe("unknown");
  });

  it("does not hand such a file to harden", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "config"), '{}\r\n{"name":"demo","version":1}\r\n');
    const discovered = discoverHardenableArtifacts(dir);
    expect(discovered.map((a) => a.format)).not.toContain("python-pyc");
  });

  it.each([
    ["3.8", 3413],
    ["3.11", 3495],
    ["3.12", 3531],
    ["3.13", 3571],
  ])("still detects an extensionless CPython %s .pyc", (_version, magic) => {
    const file = join(tempDir(), "module");
    writeFileSync(file, pycHeader(magic));
    expect(detectArtifactFormat(file)).toBe("python-pyc");
  });

  it("still detects a hash-based (PEP 552) extensionless .pyc", () => {
    const file = join(tempDir(), "module");
    writeFileSync(file, pycHeader(3495, 3));
    expect(detectArtifactFormat(file)).toBe("python-pyc");
  });

  it("rejects an extensionless header with invalid PEP 552 flags", () => {
    const file = join(tempDir(), "module");
    writeFileSync(file, pycHeader(3495, 0x7b7b7b7b));
    expect(detectArtifactFormat(file)).toBe("unknown");
  });

  it("keeps trusting the .pyc extension", () => {
    const file = join(tempDir(), "module.pyc");
    writeFileSync(file, '{}\r\n{"name":"demo","version":1}\r\n');
    expect(detectArtifactFormat(file)).toBe("python-pyc");
  });
});
