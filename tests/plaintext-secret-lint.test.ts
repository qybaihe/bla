import { describe, expect, it } from "vitest";
import {
  PLAINTEXT_SECRET_SCHEMA,
  classifySensitiveLiteral,
  extractStringLiterals,
  isSequentialAlphabet,
  lintPlaintextSecretsSource,
  looksLikeNaturalText,
  looksLikeRandomToken,
  shannonEntropy,
} from "../src/engine/plaintext-secret-lint.js";

/**
 * Made-up values in the shapes real providers issue (payment key, source-host
 * token, chat-bot token, cloud API key, JWT). They are assembled here so that
 * no scanner-recognisable token is ever written into the repository.
 */
const PROVIDER_SHAPED: readonly string[] = [
  ["sk", "live", "51HxQm2eZvKYlo2C8rT4bN9pW"].join("_"),
  ["gh", "p_", "16C7e42F292c6912E7710c838347Ae178B4a"].join(""),
  ["xoxb", "123456789012", "AbCdEfGhIjKlMnOpQrStUvWx"].join("-"),
  ["AI", "za", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"].join(""),
  ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"].join("."),
];

describe("plaintext-secret lint (Direction-2)", () => {
  it("flags FLAG{…} and high-entropy tokens as refuse", () => {
    const src = `
      const flag = "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}";
      const token = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c";
      module.exports = { flag, token };
    `;
    const report = lintPlaintextSecretsSource(src, { path: "license.cjs" });
    expect(report.schema).toBe(PLAINTEXT_SECRET_SCHEMA);
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.findings.some((f) => f.id === "plaintext-flag-literal")).toBe(
      true,
    );
    expect(report.findings.some((f) => f.id === "plaintext-high-entropy" || f.id === "plaintext-b64-or-hex")).toBe(
      true,
    );
  });

  it("does not refuse short UI copy (false-positive guard)", () => {
    const src = `
      const title = "Enter license";
      const hint = "16-char key";
      const btn = "Submit";
      module.exports = { title, hint, btn };
    `;
    const report = lintPlaintextSecretsSource(src, { path: "panel.html" });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings.filter((f) => f.severity === "error")).toEqual([]);
  });

  it("flags a sensitive literal written with an escaped byte (bypass guard)", () => {
    // The raw source carries a backslash-n escape, so the unescaped literal
    // can never appear in the raw source. The "literal absent from source"
    // suppression must not hide a real secret just because it was written
    // with an escape sequence.
    const src = `const api = "sk_live_A1\\nB2C3D4E5F6G7H8";`;
    const report = lintPlaintextSecretsSource(src);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.shouldRefuseBankrupt).toBe(true);
  });

  it("treats http(s) URLs as warning, not bankrupt refuse", () => {
    const src = `const ep = "https://enclave.internal/v1/slot/demo";`;
    const report = lintPlaintextSecretsSource(src);
    expect(report.findings.some((f) => f.id === "plaintext-url-endpoint")).toBe(
      true,
    );
    expect(report.shouldRefuseBankrupt).toBe(false);
  });

  it("allowPlaintextString clears refuse", () => {
    const src = `const flag = "FLAG{should_still_be_listed}";`;
    const report = lintPlaintextSecretsSource(src, {
      allowPlaintextString: true,
    });
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.shouldRefuseBankrupt).toBe(false);
  });

  it("shannonEntropy and classify helpers behave", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("7f3a9c2e1b8d4f6a")).toBeGreaterThan(3.5);
    expect(classifySensitiveLiteral("hi")).toBeNull();
    expect(classifySensitiveLiteral("FLAG{abc_def_ghi}")).toBe(
      "plaintext-flag-literal",
    );
    expect(extractStringLiterals(`x("ab"); y('cd');`).sort()).toEqual([
      "ab",
      "cd",
    ]);
  });

  it("reports a digest or an encoded blob inside a regular expression, and nothing else from one", () => {
    const digest = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    const blob = "kJ8s0dP3x9Q2mZ7vB1nL5tR4yU6wE0aH";
    const report = lintPlaintextSecretsSource(
      [
        `const isPro = /^${digest}$/i;`,
        `const isBlob = new RegExp("x").test("y") || /token=${blob}(?:&|$)/.test(location.search);`,
        "module.exports = { isPro, isBlob };",
      ].join("\n"),
      { path: "gate.js" },
    );
    const inRegex = report.findings.filter((f) => f.inRegex === true);
    expect(inRegex.map((f) => [f.id, f.literal, f.line])).toEqual([
      ["plaintext-b64-or-hex", digest, 1],
      ["plaintext-b64-or-hex", blob, 2],
    ]);
    expect(inRegex[0]!.summary).toMatch(/inside a regular expression .* new RegExp\(<string literal>\)/);
    expect(report.shouldRefuseBankrupt).toBe(true);

    // Ordinary patterns are dense with metacharacters; none of that is a secret.
    const ordinary = lintPlaintextSecretsSource(
      [
        "const email = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$/;",
        "const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;",
        "const semver = /^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)))?$/;",
        "const licence = /^ACME-2026-PRO-[0-9A-F]{8}$/;",
        "const sha = /^[a-f0-9]{64}$/;",
        "const hexColor = /^#(?:[0-9a-fA-F]{3}){1,2}$/;",
        "const words = /\\b(?:abcdefghijklmnopqrstuvwxyz|ABCDEFGHIJKLMNOPQRSTUVWXYZ)\\b/;",
        "const base58 = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;",
        "const base36run = /^id-0123456789abcdefghijklmnopqrstuvwxyz$/;",
        "module.exports = { email, uuid, semver, licence, sha, hexColor, words, base58, base36run };",
      ].join("\n"),
      { path: "validators.js" },
    );
    expect(ordinary.findings).toEqual([]);
    expect(ordinary.shouldRefuseBankrupt).toBe(false);
  });

  it("keeps the entropy rule for generated values, not for writing", () => {
    // English runs at about 4.2 bits per character: entropy alone flags all of these.
    const written = [
      "Unexpected token while parsing the configuration file",
      " must have exactly one source file.\n",
      "Assertion.includeStack is deprecated, use chai.config.includeStack instead.",
      "buildMatchMemberExpression",
      "getPackageSubpathDirectoryInfo",
      "Content-Security-Policy-Report-Only",
      "ACCESS_CONTROL_ALLOW_ORIGIN_HEADER",
      "tsx-commonjs-virtual-module-query",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "./shared/loadConfigFile.js",
      "../chunks/execute.2pr0rHgK.js",
      "./package-Dj0mHsMt.mjs",
      "@esbuild/darwin-arm64",
      "sourceMappingURL=data:application/json;charset=utf-8",
      "${html.escape(details.sorter.js)}",
      "(function (exports, require, module, __filename, __dirname) { ",
      "/proc/sys/kernel/osrelease",
    ];
    // Most of them clear the entropy threshold on their own.
    expect(written.filter((text) => shannonEntropy(text) >= 4.0).length).toBeGreaterThanOrEqual(10);
    for (const text of written) expect(classifySensitiveLiteral(text), text).toBeNull();
    const report = lintPlaintextSecretsSource(
      written.map((text, i) => `const M${i} = ${JSON.stringify(text)};`).join("\n"),
      { path: "messages.js" },
    );
    expect(report.findings).toEqual([]);
    expect(looksLikeNaturalText("buildMatchMemberExpression")).toBe(true);

    // Generated values stay findings, with or without a readable prefix.
    const generated = [
      ...PROVIDER_SHAPED,
      "kQmZxvBnLtRyUwEaHpGdCsJfOiTb",
      "p9Vt2Lx7Qw4Zr8Ns",
    ];
    for (const value of generated) {
      expect(looksLikeRandomToken(value), value).toBe(true);
      expect(classifySensitiveLiteral(value), value).not.toBeNull();
    }
  });

  it("does not take an encoding alphabet for a secret", () => {
    const alphabets = [
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
      "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
      "abcdefghijklmnopqrstuvwxyz",
      "0123456789abcdef0123456789ABCDEF",
    ];
    for (const alphabet of alphabets) {
      expect(isSequentialAlphabet(alphabet), alphabet).toBe(true);
      expect(classifySensitiveLiteral(alphabet), alphabet).toBeNull();
    }
    const report = lintPlaintextSecretsSource(
      alphabets.map((a, i) => `const T${i} = ${JSON.stringify(a)};`).join("\n"),
      { path: "codec.js" },
    );
    expect(report.findings).toEqual([]);

    // Real values keep being found: sequence is rare in anything random.
    for (const secret of [
      "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c",
      PROVIDER_SHAPED[0]!,
      "kJ8s0dP3x9Q2mZ7vB1nL5tR4yU6wE0aH",
      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTIz",
    ]) {
      expect(isSequentialAlphabet(secret), secret).toBe(false);
      expect(classifySensitiveLiteral(secret), secret).not.toBeNull();
    }
  });
});
