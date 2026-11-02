import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectArtifactFormat } from "../src/core/detector.js";
import { SeededPrng } from "../src/core/prng.js";
import { buildSarifReport } from "../src/core/sarif.js";
import { auditTarget } from "../src/engine/auditor.js";
import { areLlmDirectivesEnabled, withLlmDirectives } from "../src/core/llm-directives.js";
import {
  assertNoForbiddenMarkers,
  realisticIdentifier,
  realisticIdentifierBatch,
} from "../src/core/identifiers.js";
import { formatBanner, formatAuditReport } from "../src/ui/reporter.js";
import { findPythonPrologueInsertionOffset, protectPythonSource } from "../src/shields/formats/python.js";

describe("core domain modules previously without dedicated tests", () => {
  describe("detector", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-detector-"));
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });
    it("routes extension-only and magic-byte targets to the right format", () => {
      const py = path.join(dir, "app.py");
      const wasm = path.join(dir, "core.wasm");
      const sqlite = path.join(dir, "db.sqlite");
      const missing = path.join(dir, "nope.xyz");
      fs.writeFileSync(py, "x = 1\n", "utf8");
      fs.writeFileSync(wasm, Buffer.from([0x00, 0x61, 0x73, 0x6d]), "utf8");
      fs.writeFileSync(sqlite, Buffer.from("SQLite format 3\0"), "utf8");
      fs.mkdirSync(path.join(dir, "sub"));

      expect(detectArtifactFormat(py)).toBe("python-source");
      expect(detectArtifactFormat(wasm)).toBe("wasm");
      expect(detectArtifactFormat(sqlite)).toBe("sqlite");
      expect(detectArtifactFormat(missing)).toBe("unknown");
      expect(detectArtifactFormat(path.join(dir, "sub"))).toBe("directory");
    });
  });

  describe("SeededPrng", () => {
    it("is deterministic per seed and diverges across seeds", () => {
      const a = new SeededPrng("seed-one");
      const b = new SeededPrng("seed-one");
      const c = new SeededPrng("seed-two");

      const seqA = Array.from({ length: 5 }, () => a.nextUint32());
      expect(Array.from({ length: 5 }, () => b.nextUint32())).toEqual(seqA);
      const seqC = Array.from({ length: 5 }, () => c.nextUint32());
      expect(seqC).not.toEqual(seqA);

      for (let i = 0; i < 1000; i++) {
        expect(a.nextInt(0, 0)).toBe(0);
        const rolled = a.nextInt(1, 6);
        expect(rolled).toBeGreaterThanOrEqual(1);
        expect(rolled).toBeLessThanOrEqual(6);
      }
      expect(a.nextInt(5, 5)).toBe(5);
    });

    it("picks members, shuffles without loss, and hex is fixed-length", () => {
      const p = new SeededPrng("pick");
      expect(p.pick(["a", "b", "c"])).toMatch(/^[abc]$/);
      const items = [1, 2, 3, 4, 5];
      expect(p.shuffle(items).sort()).toEqual(items);
      expect(p.shuffle(items)).not.toEqual(items); // overwhelmingly likely
      expect(p.hex(4)).toMatch(/^[0-9a-f]{4}$/);
    });
  });

  describe("identifiers", () => {
    const prng = new SeededPrng("ident");

    it("renders a valid identifier with hint sanitization", () => {
      const id = realisticIdentifier(prng, {
        style: "camel",
        hint: "customer-def! Weird",
      });
      expect(id).toMatch(/^[A-Za-z_$][A-Za-z0-9_$]*$/);
      // hint specials are stripped
      expect(id).toContain("customerdef");
      expect(id).not.toContain("!");
    });

    it("draws unique batches", () => {
      const batch = realisticIdentifierBatch(new SeededPrng("batch"), 25, {
        style: "snake",
      });
      expect(batch.length).toBe(25);
      expect(new Set(batch).size).toBe(25);
    });

    it("rejects forbidden emitted markers", () => {
      expect(() => assertNoForbiddenMarkers("safe_customer_def")).not.toThrow();
      expect(() => assertNoForbiddenMarkers("nope _bla x")).toThrow();
      expect(() => assertNoForbiddenMarkers("nope __bla x")).toThrow();
      // legacy greppable placeholder is also forbidden
      expect(() => assertNoForbiddenMarkers("clean $00_AAA")).toThrow();
    });
  });

  describe("sarif", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-sarif-"));
    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });
    it("builds a valid SARIF 2.1.0 document for an audit report", () => {
      const target = path.join(dir, "mod.js");
      fs.writeFileSync(target, "export const magic = 414141;\n", "utf8");
      const report = auditTarget(target);
      const sarif = buildSarifReport(report);

      expect(sarif.version).toBe("2.1.0");
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs[0].tool.driver.name).toBeDefined();
      expect(Array.isArray(sarif.runs[0].results)).toBe(true);
      expect(typeof sarif.runs[0].tool.driver.version).toBe("string");
    });
  });

  describe("llm-directives", () => {
    it("defaults OFF and restores stack on nested scope exit", () => {
      expect(areLlmDirectivesEnabled()).toBe(false);

      withLlmDirectives(true, () => {
        expect(areLlmDirectivesEnabled()).toBe(true);
        withLlmDirectives(false, () => {
          expect(areLlmDirectivesEnabled()).toBe(false);
        });
        expect(areLlmDirectivesEnabled()).toBe(true);
      });
      expect(areLlmDirectivesEnabled()).toBe(false);
    });
  });

  describe("reporter", () => {
    it("formats banner and audit report without throwing", () => {
      const banner = formatBanner();
      expect(typeof banner).toBe("string");
      expect(banner.length).toBeGreaterThan(0);

      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-report-"));
      const target = path.join(dir, "x.py");
      fs.writeFileSync(target, "x = 1\n", "utf8");
      const report = auditTarget(target);
      const text = formatAuditReport(report);
      expect(typeof text).toBe("string");
      expect(text.length).toBeGreaterThan(0);
      fs.rmSync(dir, { recursive: true, force: true });
    });
  });

  describe("python", () => {
    const source =
      '"""Module docstring."""\nfrom __future__ import annotations\nx = 1\ndef f(): return x\n';

    it("finds prologue insertion offset after docstring and future imports", () => {
      const analysis = findPythonPrologueInsertionOffset(source);
      expect(analysis.hasDocstring).toBe(true);
      expect(analysis.futureImports.length).toBeGreaterThanOrEqual(1);
      expect(analysis.futureImports.join("\n")).toContain("annotations");
      expect(analysis.insertOffset).toBeGreaterThan(0);
      expect(analysis.insertOffset).toBeLessThan(source.length);
    });

    it("protects source deterministically per seed and keeps customer code", () => {
      const a = protectPythonSource(source, { seed: "py-one" });
      const b = protectPythonSource(source, { seed: "py-one" });
      expect(a.code).toContain("x = 1");
      expect(a.code).toContain("def f(): return x");
      expect(a.decoyFunctionsInjected).toBeGreaterThanOrEqual(0);
      expect(b.code).toBe(a.code);
    });
  });
});
