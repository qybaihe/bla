/**
 * What the literal pass does with a value that reads as a secret.
 *
 * `maximum` / `bankrupt` used to split string and template text of 3 to 256
 * characters and nothing else, so the values most worth hiding stayed in the
 * hardened file exactly as written: an embedded PEM block (too long), a digest
 * inside a regular expression, a token used as an object key. They are split
 * now — wherever they are written, up to 4,096 characters — and every test
 * here runs the original and the hardened program and compares the results.
 *
 * The pieces themselves are no longer text either. Each is written masked and
 * the string is decoded where it is used, by a function that is spelled out
 * in place: an analyser that lists every combination of pieces (REA does,
 * once its `semantic_precision` budgets are raised) holds 512 masked strings
 * and no value.
 *
 * The secrets are generated when the test runs. None of them is a real
 * credential and none is written in this file.
 */
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import _generate from "@babel/generator";
import { parse } from "@babel/parser";
import ts from "typescript";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { isShippedSecretLiteral } from "../src/engine/plaintext-secret-lint.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import type { ProtectionIntensity } from "../src/core/types.js";

const ALL: readonly ProtectionIntensity[] = ["stealth", "balanced", "maximum", "bankrupt"];
/** Literal rewriting only exists at these two. */
const LITERAL_REWRITING: readonly ProtectionIntensity[] = ["maximum", "bankrupt"];
const SEEDS = ["secret-coverage-a", "secret-coverage-b", "secret-coverage-c"] as const;

const nodeRequire = createRequire(import.meta.url);

/** Repeatable bytes that look random: a failure reproduces with the same values. */
function bytes(label: string, length: number): Buffer {
  const blocks: Buffer[] = [];
  for (let i = 0; blocks.length * 32 < length; i++) {
    blocks.push(createHash("sha256").update(`${label}:${i}`).digest());
  }
  return Buffer.concat(blocks).subarray(0, length);
}
const hexDigest = (label: string): string => bytes(label, 32).toString("hex");
/** A 40-character generated token: mixed case and digits, no punctuation. */
const token = (label: string): string =>
  bytes(label, 60).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, 40);
function pemBlock(label: string, bodyBytes: number): string {
  const kind = ["PRIVATE", "KEY"].join(" ");
  const body = bytes(label, bodyBytes).toString("base64").match(/.{1,64}/g) ?? [];
  return [`-----BEGIN ${kind}-----`, ...body, `-----END ${kind}-----`].join("\n");
}

function harden(source: string, intensity: ProtectionIntensity, seed: string, filename = "fixture.cjs") {
  return transformJavaScriptWithBlaShield(source, { intensity, seed, filename }).code;
}

/** Evaluate `code` the way Node's CommonJS loader does and return `module.exports`. */
function runCommonJs(code: string): unknown {
  const module = { exports: {} as unknown };
  const wrapper = new Function("exports", "require", "module", "__filename", "__dirname", code);
  wrapper.call(module.exports, module.exports, nodeRequire, module, "/virtual/fixture.cjs", "/virtual");
  return module.exports;
}

/**
 * True when at least `length` consecutive characters of `secret` can be read
 * in `code`. (Any readable run of `length + 2` characters contains one of the
 * windows tried.)
 */
function readableRun(code: string, secret: string, length = 20): string | null {
  for (let i = 0; i + length <= secret.length; i += 3) {
    const window = secret.slice(i, i + length);
    // The window as written in the file: a line break is spelled `\n` there.
    if (code.includes(window) || code.includes(window.replace(/\n/g, "\\n"))) return window;
  }
  return null;
}

const generate = ((_generate as unknown as { default?: typeof _generate }).default ??
  _generate) as typeof _generate;

type Node = Record<string, unknown> & { type?: string };

function walk(node: unknown, visit: (node: Node) => void): void {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit);
    return;
  }
  const n = node as Node;
  if (typeof n.type === "string") visit(n);
  for (const [key, value] of Object.entries(n)) {
    if (key === "loc" || key === "start" || key === "end") continue;
    walk(value, visit);
  }
}

/** A string decoder as the shield writes it: `(function (s, m, c) { … })(pieces, m, c)`. */
function isDecoderCall(node: Node): boolean {
  if (node.type !== "CallExpression") return false;
  const callee = node.callee as Node & { params?: Array<{ name?: string }> };
  const args = node.arguments as Node[];
  return (
    callee.type === "FunctionExpression" &&
    (callee.params ?? []).map((p) => p.name).join(",") === "s,m,c" &&
    args.length === 3 &&
    args[1]!.type === "NumericLiteral" &&
    args[2]!.type === "NumericLiteral"
  );
}

interface Decoder {
  /** Both arms of every choice among the pieces, in order. */
  readonly arms: Array<readonly [string, string]>;
}

function decoders(code: string): Decoder[] {
  const found: Decoder[] = [];
  walk(parse(code, { sourceType: "script", allowReturnOutsideFunction: true }).program, (node) => {
    if (!isDecoderCall(node)) return;
    const arms: Array<readonly [string, string]> = [];
    walk((node.arguments as Node[])[0], (inner) => {
      if (inner.type !== "ConditionalExpression") return;
      const a = inner.consequent as Node;
      const b = inner.alternate as Node;
      if (a.type === "StringLiteral" && b.type === "StringLiteral") {
        arms.push([String(a.value), String(b.value)]);
      }
    });
    found.push({ arms });
  });
  return found;
}

/**
 * The same program with every choice among masked pieces answered the other
 * way: what an attacker reads who picks the wrong arm each time.
 */
function withEveryPieceChoiceFlipped(code: string): string {
  const ast = parse(code, { sourceType: "script", allowReturnOutsideFunction: true });
  walk(ast.program, (node) => {
    if (!isDecoderCall(node)) return;
    walk((node.arguments as Node[])[0], (inner) => {
      if (inner.type !== "ConditionalExpression") return;
      const a = inner.consequent as Node;
      const b = inner.alternate as Node;
      if (a.type === "StringLiteral" && b.type === "StringLiteral") {
        inner.consequent = b;
        inner.alternate = a;
      }
    });
  });
  return generate(ast as never).code;
}

describe("a secret is split wherever it is written", () => {
  const PEM = pemBlock("pem", 1200);
  const BLOB = bytes("blob", 600).toString("base64");
  const DIGEST = hexDigest("regex-digest");
  const ROLE_KEY = token("role-key");
  // Starts with "/", so the call-argument pass sees it before the string pass does.
  const ARGUMENT = `/${bytes("argument", 900).toString("base64")}`;
  const SECRETS = { PEM, BLOB, DIGEST, ROLE_KEY, ARGUMENT };

  const PROGRAM = `
const PEM = ${JSON.stringify(PEM)};
const BLOB = \`${BLOB}\`;
const ROLES = { ${JSON.stringify(ROLE_KEY)}: "admin", plain: "user" };
const GATE = /^${DIGEST}$/i;
const banner = (n) => \`key #\${n}: ${PEM.replace(/\n/g, "\\n")} (\${n + 1} lines follow) end\`;
const decoded = Buffer.from(${JSON.stringify(ARGUMENT)}, "base64");
module.exports = {
  pem: PEM,
  blob: BLOB,
  roles: ROLES,
  role: ROLES[${JSON.stringify(ROLE_KEY)}],
  gate: [GATE.source, GATE.flags, GATE.test(${JSON.stringify(DIGEST.toUpperCase())}), GATE.test("no")],
  banner: banner(7),
  decoded: [decoded.length, decoded.toString("hex").slice(0, 32)],
};
`;
  const expected = runCommonJs(PROGRAM);

  it("the fixture's values are what the plaintext lint calls a shipped secret", () => {
    for (const [name, value] of Object.entries(SECRETS)) {
      expect(isShippedSecretLiteral(value), name).toBe(true);
    }
    expect(PEM.length).toBeGreaterThan(1024);
    expect(PEM.length).toBeLessThanOrEqual(4096);
  });

  for (const intensity of ALL) {
    it(`${intensity}: the hardened program computes what the original does`, () => {
      for (const seed of SEEDS) {
        expect(runCommonJs(harden(PROGRAM, intensity, seed)), seed).toEqual(expected);
      }
    }, 240000);
  }

  for (const intensity of LITERAL_REWRITING) {
    it(`${intensity}: no part of a secret can still be read in the output`, () => {
      for (const seed of SEEDS) {
        const code = harden(PROGRAM, intensity, seed);
        for (const [name, value] of Object.entries(SECRETS)) {
          expect(readableRun(code, value), `${name} with seed ${seed}`).toBeNull();
        }
      }
    }, 240000);
  }

  it("stealth and balanced do not rewrite literals: the values stay as written", () => {
    const code = harden(PROGRAM, "balanced", SEEDS[0]);
    expect(code).toContain(DIGEST);
    expect(code).toContain(ROLE_KEY);
  }, 240000);
});

describe("a secret used as an object key", () => {
  const KEY = token("key-plain");
  const GETTER = token("key-getter");
  const METHOD = token("key-method");
  const NAMED = token("key-named");
  const PROGRAM = `
const TABLE = {
  first: 1,
  ${JSON.stringify(KEY)}: "admin",
  get ${JSON.stringify(GETTER)}() { return "from getter"; },
  ${JSON.stringify(METHOD)}() { return "from method"; },
  ${JSON.stringify(NAMED)}: function () {},
  last: 2,
};
const { ${JSON.stringify(KEY)}: picked, first } = TABLE;
function pick({ ${JSON.stringify(KEY)}: role = "none" } = TABLE) { return role; }
module.exports = {
  order: Object.keys(TABLE),
  picked,
  first,
  viaParameter: [pick(), pick({})],
  getter: TABLE[${JSON.stringify(GETTER)}],
  getterName: Object.getOwnPropertyDescriptor(TABLE, ${JSON.stringify(GETTER)}).get.name,
  method: TABLE[${JSON.stringify(METHOD)}](),
  methodName: TABLE[${JSON.stringify(METHOD)}].name,
  inferredName: TABLE[${JSON.stringify(NAMED)}].name,
  json: JSON.stringify(TABLE),
};
`;
  const expected = runCommonJs(PROGRAM);

  it("defines the same properties, in the same order, with the same function names", () => {
    expect((expected as { inferredName: string }).inferredName).toBe(NAMED);
    for (const intensity of ALL) {
      for (const seed of SEEDS) {
        expect(runCommonJs(harden(PROGRAM, intensity, seed)), `${intensity} ${seed}`).toEqual(expected);
      }
    }
  }, 240000);

  it("is not readable at maximum / bankrupt, and ordinary keys are left alone", () => {
    for (const intensity of LITERAL_REWRITING) {
      const code = harden(PROGRAM, intensity, SEEDS[0]);
      for (const key of [KEY, GETTER, METHOD, NAMED]) {
        expect(readableRun(code, key), intensity).toBeNull();
      }
    }
    const ordinary = `module.exports = { "content-type": "text/plain", "x-request-id": 1, plain: 2 };\n`;
    const code = harden(ordinary, "maximum", SEEDS[0]);
    expect(code).toContain('"content-type":');
    expect(code).toContain('"x-request-id":');
    expect(runCommonJs(code)).toEqual(runCommonJs(ordinary));
  }, 240000);

  it("stays a literal key in a TypeScript source, where it is part of the object's type", () => {
    const source = `
const LIMITS = { ${JSON.stringify(KEY)}: 3, other: 4 };
export const limit: number = LIMITS[${JSON.stringify(KEY)}] + LIMITS.other;
`;
    const compile = (text: string): string =>
      ts.transpileModule(text, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } })
        .outputText;
    const code = harden(source, "maximum", SEEDS[0], "limits.ts");
    // Once: as the key. (The lookup below it is an ordinary string, and split.)
    expect(code.split(KEY).length - 1).toBe(1);
    expect(runCommonJs(compile(code))).toEqual(runCommonJs(compile(source)));
    expect(runCommonJs(compile(code))).toEqual({ limit: 7 });
  }, 240000);
});

describe("a secret inside a regular expression", () => {
  const DIGEST = hexDigest("gate");
  const OTHER = hexDigest("other");
  const PROGRAM = `
const EXACT = /^${DIGEST}$/;
const IN_URL = /^https?:\\/\\/[a-z.]+\\/${OTHER}(?:\\?.*)?$/i;
const STICKY = /${DIGEST}/uy;
function scan(text) {
  // A literal is a new object on every evaluation: lastIndex starts at 0 each call.
  const re = /${DIGEST.slice(0, 32)}/g;
  const first = re.test(text);
  return [first, re.lastIndex, re.test(text), re.lastIndex];
}
const ORDINARY = /^[A-Z]{4}-\\d{4}$/;
const ALPHABET = /^[0123456789abcdefABCDEF0123456789abcdef]+$/;
module.exports = {
  exact: [EXACT.source, EXACT.flags, EXACT.test(${JSON.stringify(DIGEST)}), EXACT.test("x" + ${JSON.stringify(DIGEST)}), EXACT instanceof RegExp, String(EXACT).length],
  inUrl: [IN_URL.source, IN_URL.flags, IN_URL.test("HTTPS://example.invalid/" + ${JSON.stringify(OTHER)} + "?a=1"), IN_URL.test("ftp://example.invalid/x")],
  sticky: [STICKY.sticky, STICKY.unicode, STICKY.test(${JSON.stringify(DIGEST)}), STICKY.lastIndex],
  scans: [scan(${JSON.stringify(DIGEST + DIGEST)}), scan(${JSON.stringify(DIGEST)}), scan("none")],
  replaced: ${JSON.stringify(`a${DIGEST}b`)}.replace(EXACT.source.slice(1, -1), "#"),
  ordinary: [ORDINARY.test("ABCD-1234"), ALPHABET.test("c0ffee")],
};
`;
  const expected = runCommonJs(PROGRAM);

  it("is rebuilt from pieces and matches exactly what the literal matched", () => {
    for (const intensity of ALL) {
      for (const seed of SEEDS) {
        expect(runCommonJs(harden(PROGRAM, intensity, seed)), `${intensity} ${seed}`).toEqual(expected);
      }
    }
  }, 240000);

  it("is not readable at maximum / bankrupt, and ordinary patterns stay literals", () => {
    for (const intensity of LITERAL_REWRITING) {
      const code = harden(PROGRAM, intensity, SEEDS[0]);
      expect(readableRun(code, DIGEST), intensity).toBeNull();
      expect(readableRun(code, OTHER), intensity).toBeNull();
      expect(code).toContain("new RegExp(");
      expect(code).toContain("/^[A-Z]{4}-\\d{4}$/");
      // A character class spells out an alphabet, not a value.
      expect(code).toContain("/^[0123456789abcdefABCDEF0123456789abcdef]+$/");
    }
    expect(harden(PROGRAM, "balanced", SEEDS[0])).toContain(`/^${DIGEST}$/`);
  }, 240000);

  it("stays a literal in a program that declares its own RegExp", () => {
    const shadowing = `
const RegExp = function () { return { test: () => "not the built-in" }; };
const GATE = /^${DIGEST}$/;
module.exports = [GATE.test(${JSON.stringify(DIGEST)}), typeof new RegExp("x").test("x")];
`;
    const code = harden(shadowing, "maximum", SEEDS[0]);
    expect(runCommonJs(code)).toEqual(runCommonJs(shadowing));
    expect(runCommonJs(code)).toEqual([true, "string"]);
    expect(code).toContain(`/^${DIGEST}$/`);
  }, 240000);
});

describe("the wrong piece looks like the right one", () => {
  const DIGEST = hexDigest("decoy-digest");
  const TOKEN = token("decoy-token");

  it("picking every wrong piece gives a value of the same kind: a digest for a digest, a token for a token", () => {
    const source = `module.exports = [${JSON.stringify(DIGEST)}, ${JSON.stringify(TOKEN)}];\n`;
    for (const seed of SEEDS) {
      const code = harden(source, "maximum", seed);
      expect(runCommonJs(code)).toEqual([DIGEST, TOKEN]);

      const [wrongDigest, wrongToken] = runCommonJs(withEveryPieceChoiceFlipped(code)) as [string, string];
      expect(wrongDigest).not.toBe(DIGEST);
      expect(wrongDigest).toMatch(/^[0-9a-f]{64}$/);
      // Not hex noise beside a mixed-case token: letters of both cases, and not only a–f.
      expect(wrongToken).not.toBe(TOKEN);
      expect(wrongToken).toMatch(/^[A-Za-z0-9]{40}$/);
      expect(wrongToken).toMatch(/[A-Z]/);
      expect(wrongToken).toMatch(/[g-z]/);
    }
  }, 240000);

  it("no piece of a long secret is long enough to be reported as one itself", () => {
    const blob = bytes("pieces", 1500).toString("base64");
    const code = harden(`module.exports = ${JSON.stringify(blob)};\n`, "bankrupt", SEEDS[1]);
    expect(runCommonJs(code)).toBe(blob);
    const [decoder] = decoders(code).filter((d) => d.arms.length > 20);
    expect(decoder).toBeDefined();
    // Two letters a character, at most twelve characters a piece.
    expect(decoder!.arms.length).toBeGreaterThanOrEqual(Math.ceil(blob.length / 12));
    for (const arm of decoder!.arms.flat()) {
      expect(arm).toMatch(/^[a-p]*$/);
      expect(arm.length).toBeLessThanOrEqual(24);
      expect(isShippedSecretLiteral(arm)).toBe(false);
    }
  }, 240000);
});

describe("pieces are written masked and decoded where the string is used", () => {
  // Words that appear nowhere in what the shield generates.
  const ENDPOINT = "https://quokka-zeppelin.zanzibar.example/v7/marmalade?tier=obsidian";
  const WORDS = ["quokka", "zeppelin", "zanzibar", "marmalade", "obsidian"];
  const MESSAGE = "Kumquat permit lapsed — renew before the wombat arrives";

  it("leaves no readable fragment of an ordinary string, where pieces used to be plain text", () => {
    const source = `module.exports = { endpoint: ${JSON.stringify(ENDPOINT)}, message: ${JSON.stringify(MESSAGE)} };\n`;
    for (const intensity of LITERAL_REWRITING) {
      for (const seed of SEEDS) {
        const code = harden(source, intensity, seed);
        expect(runCommonJs(code)).toEqual({ endpoint: ENDPOINT, message: MESSAGE });
        for (const word of [...WORDS, "Kumquat", "lapsed", "wombat", "arrives"]) {
          expect(code, `${word} (${intensity}, ${seed})`).not.toContain(word);
        }
        // Nor six characters in a row of it (the scheme aside: the shield's own decoys have URLs).
        expect(readableRun(code, ENDPOINT.slice("https://".length), 6)).toBeNull();
      }
    }
  }, 240000);

  it("decodes in every position an expression can stand in", () => {
    const source = `
"use strict";
const first = (value = ${JSON.stringify(`${ENDPOINT}#default`)}) => value;
class Client {
  url = ${JSON.stringify(`${ENDPOINT}#field`)};
  static label = ${JSON.stringify(`${MESSAGE} (static)`)};
  static { Client.block = ${JSON.stringify(`${MESSAGE} (block)`)}; }
  get [${JSON.stringify("computed member: quokka")}]() { return 1; }
}
const table = { [${JSON.stringify(`${ENDPOINT}#key`)}]: 1 };
const inTemplate = (n) => \`\${n} × ${MESSAGE} × \${n + 1}\`;
function* steps() { yield ${JSON.stringify(`${MESSAGE} (generator)`)}; }
const picked = (kind) => { switch (kind) { case ${JSON.stringify("kind: zanzibar")}: return 1; default: return 0; } };
module.exports = {
  first: first(),
  field: new Client().url,
  statics: [Client.label, Client.block],
  member: Object.getOwnPropertyNames(Client.prototype),
  keys: Object.keys(table),
  template: inTemplate(3),
  generated: [...steps()],
  picked: [picked("kind: zanzibar"), picked("other")],
};
`;
    const expected = runCommonJs(source);
    for (const intensity of ALL) {
      for (const seed of SEEDS) {
        expect(runCommonJs(harden(source, intensity, seed)), `${intensity} ${seed}`).toEqual(expected);
      }
    }
    const code = harden(source, "maximum", SEEDS[0]);
    for (const word of WORDS) expect(code).not.toContain(word);
  }, 240000);

  it("is self-contained: a function rebuilt from its own source in another realm still has its strings", () => {
    const source = `
function describe(n) { return ${JSON.stringify(MESSAGE)} + " #" + n; }
module.exports = { describe, text: describe.toString() };
`;
    for (const intensity of LITERAL_REWRITING) {
      const hardened = runCommonJs(harden(source, intensity, SEEDS[0])) as {
        describe: (n: number) => string;
        text: string;
      };
      expect(hardened.describe(4)).toBe(`${MESSAGE} #4`);
      // No module scope, no helper, nothing of this realm: only the text.
      const rebuilt = vm.runInNewContext(`(${hardened.text})`) as (n: number) => string;
      expect(rebuilt(5)).toBe(`${MESSAGE} #5`);
    }
  }, 240000);

  it("does not depend on a global the program has taken for itself", () => {
    const source = `
const String = null, parseInt = null, Number = null;
function escape() { return "taken"; }
module.exports = [${JSON.stringify(ENDPOINT)}, ${JSON.stringify(MESSAGE)}.length, String, escape()];
`;
    const expected = runCommonJs(source);
    for (const intensity of LITERAL_REWRITING) {
      expect(runCommonJs(harden(source, intensity, SEEDS[0])), intensity).toEqual(expected);
    }
  }, 240000);

  it("runs as a classic script and as an ES module default export", () => {
    const script = `var endpoint = ${JSON.stringify(ENDPOINT)};\n${JSON.stringify(MESSAGE)};\n`;
    for (const intensity of LITERAL_REWRITING) {
      const code = transformJavaScriptWithBlaShield(script, {
        intensity,
        seed: SEEDS[0],
        sourceType: "script",
      }).code;
      const realm = vm.createContext({});
      // The script's completion value is its last expression statement.
      expect(vm.runInContext(code, realm)).toBe(MESSAGE);
      expect((realm as { endpoint?: string }).endpoint).toBe(ENDPOINT);
    }
    // `export default function …` would declare a function: the decoder must be parenthesised.
    const moduleCode = transformJavaScriptWithBlaShield(`export default ${JSON.stringify(MESSAGE)};\n`, {
      intensity: "maximum",
      seed: SEEDS[0],
      filename: "message.mjs",
    }).code;
    expect(() => parse(moduleCode, { sourceType: "module" })).not.toThrow();
    expect(moduleCode).toMatch(/export default \(function \(s, m, c\)/);
    expect(moduleCode).not.toContain("Kumquat");
  }, 240000);

  it("keeps a short plain word in clear pieces: hot comparisons pay no decode", () => {
    const source = `
module.exports = (v) => typeof v === "function" ? "callable" : typeof v === "string" ? "text" : "other";
`;
    const code = harden(source, "maximum", SEEDS[0]);
    expect(decoders(code)).toEqual([]);
    const classify = runCommonJs(code) as (v: unknown) => string;
    expect([classify(() => 1), classify("x"), classify(1)]).toEqual(["callable", "text", "other"]);

    // One character more than a plain word may have, or one that is not a word: masked.
    const masked = harden(`module.exports = ["elevenchars", "two words"];\n`, "maximum", SEEDS[0]);
    expect(decoders(masked)).toHaveLength(2);
    expect(runCommonJs(masked)).toEqual(["elevenchars", "two words"]);
  }, 240000);

  it("hardens and runs the longest secret it splits", () => {
    const longest = bytes("longest", 3072).toString("base64");
    expect(longest).toHaveLength(4096);
    // Characters above U+00FF take four letters each; the cut is finer to match.
    const wide = `${pemBlock("wide", 600)}\n# 密钥备注：仅限内部使用 🔑`;
    expect(isShippedSecretLiteral(wide)).toBe(true);
    const source = `module.exports = [${JSON.stringify(longest)}, ${JSON.stringify(wide)}];\n`;
    const code = harden(source, "bankrupt", SEEDS[2]);
    expect(runCommonJs(code)).toEqual([longest, wide]);
    expect(readableRun(code, longest)).toBeNull();
    expect(readableRun(code, wide)).toBeNull();
  }, 240000);
});

describe("what the literal pass leaves as written", () => {
  it("a long ordinary string is not split: only a secret is worth the bytes", () => {
    const help = "Usage: acme-tool <command> [options]. Run a command with --help for details. ".repeat(8);
    const sql = `SELECT id, name, created_at FROM customers WHERE ${"region = ? OR ".repeat(30)}1 = 0`;
    expect(help.length).toBeGreaterThan(256);
    expect(sql.length).toBeGreaterThan(256);
    const source = `module.exports = { help: ${JSON.stringify(help)}, sql: ${JSON.stringify(sql)} };\n`;
    for (const intensity of LITERAL_REWRITING) {
      const code = harden(source, intensity, SEEDS[0]);
      expect(code).toContain(help);
      expect(code).toContain(sql);
      expect(runCommonJs(code)).toEqual({ help, sql });
    }
  }, 240000);

  it("a secret over 4,096 characters stays readable — the report lists it", () => {
    const huge = bytes("huge", 3300).toString("base64");
    expect(huge.length).toBeGreaterThan(4096);
    const code = harden(`module.exports = ${JSON.stringify(huge)};\n`, "maximum", SEEDS[0]);
    expect(code).toContain(huge);
    expect(runCommonJs(code)).toBe(huge);
  }, 240000);

  it("text outside ASCII survives the split, wherever the cuts fall", () => {
    const mixed = `许可证密钥 ${token("cjk")} 😀🔑 ${hexDigest("cjk")} ключ`;
    const emoji = "😀".repeat(40);
    const source = `module.exports = [${JSON.stringify(mixed)}, ${JSON.stringify(emoji)}, \`${emoji}\${1}${mixed}\`];\n`;
    const expected = runCommonJs(source);
    for (const intensity of LITERAL_REWRITING) {
      for (const seed of SEEDS) {
        expect(runCommonJs(harden(source, intensity, seed)), `${intensity} ${seed}`).toEqual(expected);
      }
    }
  }, 240000);
});
