import { describe, expect, it } from "vitest";
import {
  UnsupportedArchiveError,
  validateZipProtectionInput,
  writeZipArchive,
} from "../src/shields/formats/archive.js";

const data = Buffer.from("harmless content ".repeat(8));

describe("archive entry-name traversal admission", () => {
  const cases: [string, string][] = [
    ["../evil.txt", "path traversal above the archive root"],
    ["../../evil.txt", "deep path traversal above the archive root"],
    ["/etc/passwd", "absolute path"],
    ["./assets/bla-shield/x.js", "aliased reserved prefix (dot-slash)"],
    ["assets/./bla-shield/x.js", "aliased reserved prefix (mid-path dot)"],
    ["assets/bla-shield/x.js", "direct reserved prefix"],
  ];

  for (const [name, label] of cases) {
    it(`rejects ${label}: ${name}`, () => {
      const zip = writeZipArchive([{ name, data }]);
      expect(() => validateZipProtectionInput(zip)).toThrow(UnsupportedArchiveError);
    });
  }

  it("still accepts a normal entry name", () => {
    const zip = writeZipArchive([{ name: "file.txt", data }]);
    expect(() => validateZipProtectionInput(zip)).not.toThrow();
  });
});
