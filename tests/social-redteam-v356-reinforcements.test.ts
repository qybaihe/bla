import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { parseCliArgs } from "../src/cli.js";
import {
  assertNoForbiddenMarkers,
  realisticIdentifier,
} from "../src/core/identifiers.js";
import { SeededPrng } from "../src/core/prng.js";
import { hardenProject } from "../src/engine/harden.js";
import {
  isSecretLikeIdentifier,
  lintLaneIndependence,
} from "../src/engine/lane-independence-lint.js";
import { protectTarget } from "../src/engine/protector.js";
import {
  computeContainmentCorpusDigest,
  generateCognitiveArmorTrigger,
} from "../src/shields/deception/cognitive-armor-trigger.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import {
  ESM_PREHOIST_CAPTURE_DATA_URL,
  generateSelfSealSnippet,
} from "../src/shields/runtime/self-seal.js";
import {
  generateJsOpaqueFalseExpression,
  generateJsOpaqueTrueExpression,
  generatePythonOpaqueFalseExpression,
} from "../src/shields/tarpit/opaque-predicates.js";

const tmpDirs: string[] = [];
function makeTmp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const d of tmpDirs.splice(0)) {
    rmSync(d, { recursive: true, force: true });
  }
});

const PY3 =
  spawnSync("python3", ["--version"], { encoding: "utf8" }).status === 0;

/** LASIK's `BLA_TAG` regex (`src/js/passes/tree-shake.ts`). */
const LASIK_BLA_TAG_RE = /^_?[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*_[0-9a-f]{3,4}$/;

/** LASIK's four canonical opaque-predicate families (`src/js/passes/opaque.ts`). */
const LASIK_OPAQUE_FAMILY_RES: readonly RegExp[] = [
  /^Math\.imul\(7,Math\.imul\(([A-Za-z_$][\w$]*)\|(\d+),\1\|\2\)\)-1(===|!==)Math\.imul\(\1\^(\d+),\1\^\4\)$/,
  /^\(\(([A-Za-z_$][\w$]*)\^(\d+)\)\+\(\(\1&\2\)<<1\|0\)\|0\)(===|!==)\(\1\+\2\|0\)$/,
  /^\(Math\.imul\(([A-Za-z_$][\w$]*)\|(\d+),\(\1\|\2\)\+1(?:\|0)?\)&1\)(===|!==)([01])$/,
  /^\(([A-Za-z_$][\w$]*)\|~\1\|0\)(===|!==)-1$/,
];

describe("Social-media & red-team reinforcements (GitTested + anti-LASIK)", () => {
  it("1. GitTested shipping quote calculator passes lane-lint and hardens with exact runtime equivalence", () => {
    const quoteJs = `
const SHIPPING_WEIGHTS = [140, 80, 360, 0, 1100];
const TIER_SURCHARGE = [450, 920, 1650, 2900, 4800];
const ZONE_RATES = { domestic: 1.0, regional: 1.25, express: 1.6 };

function computeQuote(weightGrams, zoneKey, tierKey, mapPin) {
  const idx = SHIPPING_WEIGHTS.findIndex((limit) => limit > 0 && weightGrams <= limit);
  const totalBase = SHIPPING_WEIGHTS.reduce((acc, v) => acc + v, 0);
  const tierCost = TIER_SURCHARGE[idx >= 0 ? idx : TIER_SURCHARGE.length - 1];
  const zoneMult = ZONE_RATES[zoneKey] || 1.0;
  const pinExtra = mapPin && mapPin.remote ? 250 : 0;
  const cents = Math.round((tierCost * zoneMult + pinExtra) + (tierKey === "priority" ? 500 : 0) + (totalBase > 0 ? 181 : 0));
  return Number((cents / 100).toFixed(2));
}
module.exports = { computeQuote };
`;
    expect(isSecretLikeIdentifier("zoneKey")).toBe(false);
    expect(isSecretLikeIdentifier("tierKey")).toBe(false);
    expect(isSecretLikeIdentifier("shippingKey")).toBe(false);
    expect(isSecretLikeIdentifier("mapPin")).toBe(false);
    expect(isSecretLikeIdentifier("pinTop")).toBe(false);
    // Genuine secrets stay flagged:
    expect(isSecretLikeIdentifier("PIN")).toBe(true);
    expect(isSecretLikeIdentifier("userPin")).toBe(true);
    expect(isSecretLikeIdentifier("licenseKey")).toBe(true);

    const lint = lintLaneIndependence(quoteJs);
    expect(lint.looksLaneIndependent).toBe(false);
    expect(lint.findings).toEqual([]);

    const root = makeTmp("bla-gittested-quote-");
    const dist = join(root, "dist");
    const outDir = join(root, "out");
    mkdirSync(dist, { recursive: true });
    writeFileSync(
      join(dist, "index.html"),
      '<!doctype html><html><body><script src="./quote.js"></script></body></html>\n',
      "utf8",
    );
    writeFileSync(join(dist, "quote.js"), quoteJs, "utf8");

    const report = hardenProject({
      directory: dist,
      outputDirectory: outDir,
      intensity: "bankrupt",
      seed: "gittested-quote-seed",
    });
    expect(report.overallSuccess).toBe(true);
    expect(report.hardenedCount).toBe(2);
    expect(report.failedCount).toBe(0);

    const run = (code: string) => {
      const mod = { exports: {} as { computeQuote?: (...args: unknown[]) => number } };
      vm.runInNewContext(code, { module: mod, exports: mod.exports, Uint32Array, Math, Number, Array, Object, String, RegExp, Map, Set, process: { pid: 100 } });
      return mod.exports.computeQuote!(300, "regional", "priority", { remote: true });
    };
    const origResult = run(quoteJs);
    const protResult = run(readFileSync(join(outDir, "quote.js"), "utf8"));
    expect(protResult).toBe(origResult);
  });

  it("2. GitTested atomic pre-flight: refusing one lane-independent JS file writes ZERO sibling HTML files", () => {
    const root = makeTmp("bla-atomic-lane-");
    const dist = join(root, "dist");
    const outDir = join(root, "out");
    mkdirSync(dist, { recursive: true });
    writeFileSync(
      join(dist, "index.html"),
      '<!doctype html><html><body><div id="app"></div><script src="./gate.js"></script></body></html>\n',
      "utf8",
    );
    writeFileSync(
      join(dist, "gate.js"),
      `const EXPECTED = [0x41, 0x42, 0x43, 0x44, 0x45];
export function unlock(licenseKey) {
  return EXPECTED.every((b, i) => licenseKey.charCodeAt(i) === b);
}
`,
      "utf8",
    );

    const report = hardenProject({
      directory: dist,
      outputDirectory: outDir,
      intensity: "bankrupt",
      seed: "atomic-lane-seed",
    });
    expect(report.overallSuccess).toBe(false);
    expect(report.hardenedCount).toBe(0);
    expect(report.failedCount).toBe(2);
    expect(
      report.artifacts.some(
        (a) => a.relativePath === "gate.js" && /lane-independent/i.test(a.error ?? ""),
      ),
    ).toBe(true);
    expect(
      report.artifacts.some(
        (a) => a.relativePath === "index.html" && /skipped: run blocked/i.test(a.error ?? ""),
      ),
    ).toBe(true);
    // Crucial: neither index.html nor gate.js was left half-written into outDir.
    expect(existsSync(join(outDir, "index.html"))).toBe(false);
    expect(existsSync(join(outDir, "gate.js"))).toBe(false);
  });

  it("3. CLI typo hints (--mode -> --intensity) and --self-seal post-harden immutability guidance", () => {
    const parsed1 = parseCliArgs(["harden", ".", "--mode", "bankrupt"]);
    expect(parsed1.argErrors.some((e) => e.includes("--mode") && e.includes("--intensity"))).toBe(true);

    const parsed2 = parseCliArgs(["harden", ".", "--mode=bankrupt"]);
    expect(parsed2.argErrors.some((e) => e.includes("--mode=bankrupt") && e.includes("--intensity"))).toBe(true);

    const parsed3 = parseCliArgs(["harden", ".", "--seal"]);
    expect(parsed3.argErrors.some((e) => e.includes("--self-seal"))).toBe(true);

    const root = makeTmp("bla-seal-note-");
    const dist = join(root, "dist");
    const outDir = join(root, "out");
    mkdirSync(dist, { recursive: true });
    writeFileSync(join(dist, "index.cjs"), 'module.exports = { ping: () => "ok-pong" };\n', "utf8");
    const report = hardenProject({
      directory: dist,
      outputDirectory: outDir,
      intensity: "balanced",
      selfSeal: true,
      seed: "seal-note-seed",
    });
    expect(report.overallSuccess).toBe(true);
    expect(
      report.nextSteps?.some((s) => /self_seal pins exact file bytes/i.test(s) && /esbuild/i.test(s)),
    ).toBe(true);
  });

  it("4. Anti-LASIK interlock (Uint32Array) + shadow-heap rolling latch coupling resists stripping while preserving equivalence", () => {
    const prng = new SeededPrng("anti-lasik-interlock-1");
    const armor = generateCognitiveArmorTrigger(prng, "bankrupt");
    // Digest body uses Uint32Array so closed int32 AST evaluators refuse to fold it.
    expect(armor.code).toContain("new Uint32Array(2)");
    const runtimeDigest = vm.runInNewContext(
      `${armor.code}; ${armor.digestFunctionName}(0);`,
      { Uint32Array, Math, Array },
    );
    expect(runtimeDigest).toBe(armor.expectedDigest);
    expect(runtimeDigest).toBe(computeContainmentCorpusDigest(armor.triggersInjected, 0));

    const source = `
function computeToken(user) {
  const prefix = "entitlement-tier-gold";
  return prefix + ":" + user + ":" + "verified-session";
}
module.exports = { computeToken };
`;
    const shielded = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "anti-lasik-latch-1",
      sourceType: "commonjs",
    });

    // Heap object is directly referenced outside its stepper (both in runtimeSeed and masked decoders).
    const heapName = shielded.memoryDiffShield.heapObjectName;
    const latchProp = shielded.memoryDiffShield.latchPropertyName;
    expect(shielded.code).toContain(`${heapName}.${latchProp}`);
    const refMatches = shielded.code.match(new RegExp(`\\b${heapName}\\.${latchProp}\\b`, "g")) ?? [];
    // Stepper uses it once + top-level seed uses it + at least one string decoder uses it.
    expect(refMatches.length).toBeGreaterThanOrEqual(4);

    // Execute 50 times so the rolling latch mutates in-place 50 times while strings stay exact.
    const ctx: Record<string, unknown> = {
      module: { exports: {} as { computeToken?: (u: string) => string } },
      exports: {},
      Uint32Array,
      Math,
      Array,
      Object,
      String,
      Number,
      Boolean,
      RegExp,
      Map,
      Set,
      process: { pid: 99 },
    };
    vm.runInNewContext(
      `${shielded.code}\nglobalThis.__captureHeap = ${heapName};`,
      ctx,
    );
    const fn = (ctx.module as { exports: { computeToken: (u: string) => string } }).exports.computeToken;
    const heapRef = ctx.__captureHeap as Record<string, Uint32Array>;
    const initialW0 = heapRef[latchProp]![0]!;
    const initialW1 = heapRef[latchProp]![1]!;
    for (let i = 0; i < 50; i++) {
      expect(fn(`alice-${i}`)).toBe(`entitlement-tier-gold:alice-${i}:verified-session`);
    }
    // Rolling latch words actually mutated in memory while invariant XOR byte stayed exact:
    expect(heapRef[latchProp]![0] !== initialW0 || heapRef[latchProp]![1] !== initialW1).toBe(true);
    expect((heapRef[latchProp]![0]! ^ heapRef[latchProp]![1]!) & 0xff).toBe(
      shielded.memoryDiffShield.latchInvariantByte,
    );

    // Tampering the heap latch to [0, 0] corrupts live string decoding:
    heapRef[latchProp]![0] = 0;
    heapRef[latchProp]![1] = 0;
    expect(fn("tampered")).not.toBe("entitlement-tier-gold:tampered:verified-session");

    // Detached fn.toString() re-evaluation still succeeds without ReferenceError:
    const detached = new Function(`return (${fn.toString()});`)() as (u: string) => string;
    expect(detached("detached")).toBe("entitlement-tier-gold:detached:verified-session");

    // Stripping the shadow heap declaration triggers a hard ReferenceError at load time:
    const strippedHeap = shielded.code.replace(`var ${heapName} =`, `var _droppedHeap =`);
    expect(() =>
      vm.runInNewContext(strippedHeap, {
        module: { exports: {} },
        exports: {},
        Uint32Array,
        Math,
        Array,
        Object,
        String,
        Number,
        Boolean,
        RegExp,
        Map,
        Set,
        process: { pid: 99 },
      }),
    ).toThrow(/is not defined/);
  });

  it("5. Anti-LASIK full-32-bit MBA opaque predicates (JS & Python) never match LASIK families and hold on all edge values", () => {
    const prng = new SeededPrng("anti-lasik-opaque-1");
    const edgeVals = [0, 1, -1, 2, -2, 7, -7, 0x7fffffff, -0x80000000, 0x55555555, -0x55555556, 0x26b5c67b];

    for (let i = 0; i < 40; i++) {
      const fExpr = generateJsOpaqueFalseExpression(prng, "s");
      const tExpr = generateJsOpaqueTrueExpression(prng, "s");
      const compactF = fExpr.replace(/\s+/g, "");
      const compactT = tExpr.replace(/\s+/g, "");
      for (const re of LASIK_OPAQUE_FAMILY_RES) {
        expect(compactF).not.toMatch(re);
        expect(compactT).not.toMatch(re);
      }
      // No small low-bit output mask reduction (`& 1) ===`, `& 7) ===`, `& 15) ===`).
      expect(compactF).not.toMatch(/&(?:1|3|7|15)\)(?:===|!==)/);
      expect(compactT).not.toMatch(/&(?:1|3|7|15)\)(?:===|!==)/);

      const fnF = new Function("s", `return (${fExpr});`) as (s: number) => boolean;
      const fnT = new Function("s", `return (${tExpr});`) as (s: number) => boolean;
      for (const v of edgeVals) {
        expect(fnF(v)).toBe(false);
        expect(fnT(v)).toBe(true);
      }
    }

    if (PY3) {
      const pyPreds: string[] = [];
      for (let i = 0; i < 24; i++) {
        const expr = generatePythonOpaqueFalseExpression(prng, "s");
        expect(expr).not.toMatch(/&\s*(?:1|7|15)\s*\)\s*[!=]=/);
        pyPreds.push(expr);
      }
      const pyScript = [
        "vals = [0, 1, -1, 2, -2, 7, -999999999999, 0x7fffffff, -0x80000000, 0xdeadbeef, 1 << 65]",
        `preds = [${pyPreds.map((p) => `lambda s: (${p})`).join(", ")}]`,
        "for idx, fn in enumerate(preds):",
        "    for v in vals:",
        "        assert fn(v) is False, f'pred {idx} failed for {v}'",
        "print('PY_MBA_OK')",
      ].join("\n");
      const res = spawnSync("python3", ["-c", pyScript], { encoding: "utf8" });
      expect(res.status, res.stderr).toBe(0);
      expect(res.stdout.trim()).toBe("PY_MBA_OK");
    }
  });

  it("6. Anti-LASIK identifier morphology breaks LASIK BLA_TAG regex across all styles", () => {
    const prng = new SeededPrng("anti-lasik-ident-1");
    const styles = ["camel", "privateCamel", "pascal", "earlySort", "snake"] as const;
    for (const style of styles) {
      for (let i = 0; i < 40; i++) {
        const id = realisticIdentifier(prng, { style, entropy: i % 2 === 0 ? 3 : 4 });
        expect(id).toMatch(/^[A-Za-z_$][A-Za-z0-9_$]*$/);
        expect(id, `style=${style}`).not.toMatch(LASIK_BLA_TAG_RE);
        expect(() => assertNoForbiddenMarkers(id)).not.toThrow();
      }
    }
  });

  it("7. Anti-LASIK self-seal avoids readFileSync across all sites (CJS + ESM) and fails closed on tamper", () => {
    expect(ESM_PREHOIST_CAPTURE_DATA_URL).not.toContain("readFileSync");
    expect(ESM_PREHOIST_CAPTURE_DATA_URL).toContain("openSync");

    const prng = new SeededPrng("self-seal-fd-all-sites");
    const snippet = generateSelfSealSnippet(prng, {
      siblingPaths: ["sib.bin"],
      expectedSiblingSha256: { "sib.bin": "a".repeat(64) },
      hardFailOnSiblingMismatch: true,
      selfDigestCheck: true,
    });
    expect(snippet.code).not.toContain("readFileSync");
    expect(snippet.code).toContain("openSync");
    expect(snippet.code).toContain("readSync");

    // End-to-end ESM self-seal execution with low-level fd pre-hoist capture:
    const root = makeTmp("bla-esm-fd-seal-");
    const entry = join(root, "entry.mjs");
    const out = join(root, "entry.shielded.mjs");
    writeFileSync(entry, 'export const msg = "fd-seal-ok";\nconsole.log("RES:" + msg);\n', "utf8");
    protectTarget({
      inputPath: entry,
      outputPath: out,
      intensity: "balanced",
      selfSeal: true,
      seed: "esm-fd-seal-e2e",
    });

    const ok = spawnSync(process.execPath, [out], { encoding: "utf8" });
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout).toContain("RES:fd-seal-ok");

    // Appending a single comment breaks self-seal cleanly:
    writeFileSync(out, readFileSync(out, "utf8") + "\n// post-harden tamper\n", "utf8");
    const tampered = spawnSync(process.execPath, [out], { encoding: "utf8" });
    expect(tampered.status).not.toBe(0);
    expect(tampered.stderr).toMatch(/integrity check failed/i);
  });
});
