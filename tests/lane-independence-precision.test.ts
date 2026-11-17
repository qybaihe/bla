import { describe, expect, it } from "vitest";
import {
  isSecretLikeIdentifier,
  lintLaneIndependence,
} from "../src/engine/lane-independence-lint.js";

/**
 * The lane lint refuses an artifact outright, so it has to stay quiet on
 * ordinary code. Every snippet in the first block was refused by the original
 * rules ("an integer array anywhere + the letters `key` anywhere").
 */
describe("lane-independence lint precision", () => {
  const ordinaryCode: Record<string, string> = {
    "lookup table beside Object.keys": `
      const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
      const totals = { jan: DAYS_IN_MONTH[0], feb: DAYS_IN_MONTH[1] };
      console.log(Object.keys(totals).length, DAYS_IN_MONTH.reduce((a, b) => a + b, 0));
    `,
    "keyboard handler comparing keyCode against a table": `
      const ARROW_KEY_CODES = [37, 38, 39, 40];
      function isArrow(event) {
        for (let i = 0; i < ARROW_KEY_CODES.length; i++) {
          if (event.keyCode === ARROW_KEY_CODES[i]) return true;
        }
        return false;
      }
    `,
    "array equality helper": `
      function sameItems(parts, expected) {
        return parts.length === expected.length && parts.every((part, i) => part === expected[i]);
      }
    `,
    "collection named bytes reduced with every": `
      const bytes = readHeader(file);
      const printable = bytes.every((b) => b >= 0x20 && b < 0x7f);
    `,
    "version check on split segments": `
      const parts = process.version.slice(1).split(".");
      const supported = parts[0] === "22" && parts[1] === "12";
    `,
    "magic-number sniffing": `
      function isPng(input) {
        return input[0] === 0x89 && input[1] === 0x50 && input[2] === 0x4e && input[3] === 0x47;
      }
    `,
    "tokenizer quote detection": `
      function isTripleQuote(code, i) {
        return code.charCodeAt(0) === 34 && code.charCodeAt(1) === 34 && code.charCodeAt(2) === 34;
      }
    `,
    "crc table used in a checksum loop": `
      const CRC_TABLE = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419];
      function crc32(buf) {
        let c = ~0;
        for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
        return ~c >>> 0;
      }
    `,
    "cache keys compared against a table": `
      const SLOTS = [3, 7, 11, 13];
      function lookup(cacheKey, hotKey) {
        return SLOTS.map((slot) => store[cacheKey + ":" + slot] ?? store[hotKey]);
      }
    `,
  };

  for (const [name, source] of Object.entries(ordinaryCode)) {
    it(`stays quiet on ${name}`, () => {
      const report = lintLaneIndependence(source);
      expect(report.findings.map((f) => `${f.id}: ${f.evidence}`)).toEqual([]);
      expect(report.looksLaneIndependent).toBe(false);
    });
  }

  it("still flags a byte table compared per character against the key", () => {
    const inline = lintLaneIndependence(`
      function check(key) {
        return [0x41, 0x42, 0x43, 0x44].every((b, i) => key.charCodeAt(i) === b);
      }
    `);
    expect(inline.findings.map((f) => f.id)).toContain("per-lane-byte-compare-array");

    const named = lintLaneIndependence(`
      const EXPECTED = [0x41, 0x42, 0x43, 0x44, 0x45];
      function unlock(licenseKey) {
        for (let i = 0; i < EXPECTED.length; i++) {
          if ((licenseKey.charCodeAt(i) ^ 0x20) !== EXPECTED[i]) return false;
        }
        return true;
      }
    `);
    expect(named.findings.map((f) => f.id)).toContain("per-lane-byte-compare-array");

    const xorFold = lintLaneIndependence(`
      const table = [12, 99, 7, 41];
      function verify(serial) {
        let acc = 0;
        for (let i = 0; i < 4; i++) acc |= serial[i] ^ table[i];
        return acc === 0;
      }
    `);
    expect(xorFold.findings.map((f) => f.id)).toContain("per-lane-byte-compare-array");
  });

  it("still flags per-index and per-segment checks on a secret-named value", () => {
    expect(
      lintLaneIndependence(
        `const ok = password.charCodeAt(0) === 0x73 && password.charCodeAt(1) === 0x33 && password.charCodeAt(2) === 0x63;`,
      ).findings.map((f) => f.id),
    ).toContain("chained-per-index-compare");
    expect(
      lintLaneIndependence(
        `const segs = opts.licenseKey.split("-"); return segs[0] === "PRO1" && segs[1] === "2026";`,
      ).findings.map((f) => f.id),
    ).toContain("split-segment-lane-compare");
    expect(
      lintLaneIndependence(
        `for (let i = 0; i < 16; i++) { if (guess[i] === target[i]) hits++; }`,
      ).findings.map((f) => f.id),
    ).toContain("indexed-lane-oracle-loop");
  });

  it("recognises secret-named identifiers by word, not by substring", () => {
    for (const id of ["key", "licenseKey", "userSerial", "guess", "PIN", "unlock_code", "apiKey"]) {
      expect(isSecretLikeIdentifier(id), id).toBe(true);
    }
    for (const id of [
      "keys",
      "keyCode",
      "keyboard",
      "onKeyDown",
      "cacheKey",
      "sortKey",
      "monkey",
      "hotkeys",
      "planeOf",
      "KEYWORDS",
      "spinner",
    ]) {
      expect(isSecretLikeIdentifier(id), id).toBe(false);
    }
  });

  it("stays fast on a large single-line bundle", () => {
    const chunk = `var t${"x"}=[1,2,3,4,5,6,7,8];function f(a){return Object.keys(a).map(function(k){return a[k]})}`;
    const bundle = chunk.repeat(6000);
    const started = Date.now();
    const report = lintLaneIndependence(bundle);
    expect(report.looksLaneIndependent).toBe(false);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});
