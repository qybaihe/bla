/**
 * Seed-derived string encryption pass for panel.html / license.cjs (Direction-2).
 *
 * Honesty constraints (competitor-research landing design + js-aes-unwrap-lint):
 *   - Uses XOR keystream from SeededPrng.derive("string.encrypt") — NOT JS AES.
 *   - Never introduces JS-held AES wrap-key + createDecipheriv (lint footgun).
 *   - Runtime stub reconstructs the original UTF-8 string; equivalence is proven
 *     by tests / CrackMe v8 fixture runs — not by claiming "unbreakable".
 *
 * MCP: bla_encrypt_strings.
 */

import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { assertSafeOutDir, writeFileAtomicSync } from "../core/output-path.js";
import { SeededPrng } from "../core/prng.js";
import {
  classifySensitiveLiteral,
  extractStringLiterals,
  lintPlaintextSecretsSource,
} from "./plaintext-secret-lint.js";

type UnwrapDefault<T> = T extends { readonly default: infer D } ? D : T;
type TraverseFn = UnwrapDefault<typeof _traverse>;
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : (_traverse as unknown as { readonly default: TraverseFn }).default;

export const ENCRYPT_STRINGS_SCHEMA = "bla-encrypt-strings/v1" as const;

export interface EncryptStringsOptions {
  readonly path: string;
  readonly seed: string;
  readonly outDir?: string;
  /** Also encrypt warning-class URL literals (default true). */
  readonly includeUrls?: boolean;
  readonly dryRun?: boolean;
}

export interface EncryptStringsFileResult {
  readonly path: string;
  readonly relativeName: string;
  readonly encryptedCount: number;
  readonly skippedCount: number;
  readonly literals: readonly string[];
  readonly written: boolean;
  readonly outPath: string;
}

export interface EncryptStringsReport {
  readonly schema: typeof ENCRYPT_STRINGS_SCHEMA;
  readonly seedTag: string;
  readonly files: readonly EncryptStringsFileResult[];
  readonly totalEncrypted: number;
  readonly postLintClean: boolean;
  readonly honestyNote: string;
  readonly status: "ok" | "noop" | "error";
  readonly wouldOverwrite?: readonly string[];
  readonly error?: string;
}

const TARGET_NAMES = new Set([
  "panel.html",
  "panel.htm",
  "license.cjs",
  "license.js",
  "vault.cjs",
  "gate.cjs",
]);

const SKIP_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  ".bla-hardened",
  "coverage",
  ".next",
  ".turbo",
  "vendor",
  "__pycache__",
]);

const SCAN_EXT = /\.(?:html?|[cm]?js|tsx?|mts|cts)$/i;

function walkEncryptTargets(root: string, depth: number, out: string[]): void {
  if (depth > 6 || out.length >= 48) return;
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (out.length >= 48) break;
    if (ent.name.startsWith(".") && ent.name !== ".fixture") continue;
    const full = join(root, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIR_NAMES.has(ent.name)) continue;
      walkEncryptTargets(full, depth + 1, out);
    } else if (ent.isFile() && SCAN_EXT.test(ent.name)) {
      if (
        /\.d\.ts$/i.test(ent.name) ||
        /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(ent.name) ||
        /\.(?:min|shielded)\.[cm]?js$/i.test(ent.name)
      ) {
        continue;
      }
      out.push(full);
    }
  }
}

function listTargets(pathIn: string): string[] {
  const abs = resolve(pathIn);
  if (!existsSync(abs)) return [];
  const st = statSync(abs);
  if (st.isFile()) return [abs];
  const out: string[] = [];
  for (const name of TARGET_NAMES) {
    const p = join(abs, name);
    if (existsSync(p) && statSync(p).isFile()) out.push(p);
  }
  walkEncryptTargets(abs, 0, out);
  return [...new Set(out)];
}

const HONESTY =
  "XOR string hiding raises static grepping cost only. " +
  "It is NOT white-box AES and does not claim resistance to runtime dump / REA. " +
  "Run BEFORE --self-seal (mutating a sealed sibling invalidates integrity hashes). " +
  "Prove equivalence with verify / CrackMe fixture / REA — never with collision luck.";

function seedTag(seed: string): string {
  return createHash("sha256")
    .update(`string.encrypt|${seed}`)
    .digest("hex")
    .slice(0, 12);
}

/** Deterministic keystream byte for index i under a string.encrypt PRNG. */
export function keystreamByte(prng: SeededPrng, i: number): number {
  const lane = new SeededPrng(
    createHash("sha256")
      .update(prng.seedString)
      .update(`ks:${i >> 2}`)
      .digest("hex"),
  );
  const word = lane.nextUint32();
  return (word >>> ((i & 3) * 8)) & 0xff;
}

export function buildKeystream(prng: SeededPrng, length: number): Buffer {
  const buf = Buffer.alloc(length);
  for (let i = 0; i < length; i++) buf[i] = keystreamByte(prng, i);
  return buf;
}

export function xorEncodeToBytes(plain: string, keystream: Buffer): number[] {
  const buf = Buffer.from(plain, "utf8");
  const out: number[] = new Array(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i]! ^ keystream[i % keystream.length]!;
  }
  return out;
}

export function xorDecodeBytes(bytes: readonly number[], keystream: Buffer): string {
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = (bytes[i]! ^ keystream[i % keystream.length]!) & 0xff;
  }
  return out.toString("utf8");
}

function encodeByteCsv(bytes: readonly number[]): string {
  // Comma-separated decimals — avoids lane-independence "[n,n,n,n]" tables and
  // plaintext-secret hex/base64/high-entropy string classifiers.
  return bytes.join(",");
}

function buildRuntimeStub(
  table: readonly (readonly number[])[],
  keystream: Buffer,
  fnName: string,
  tableName: string,
  ksName: string,
): string {
  const parse = 'split(",").map(Number)';
  const tableLit =
    "[" +
    table.map((row) => JSON.stringify(encodeByteCsv(row)) + "." + parse).join(",") +
    "]";
  const ksLit = JSON.stringify(encodeByteCsv(Array.from(keystream))) + "." + parse;
  return (
    `var ${tableName}=${tableLit};` +
    `var ${ksName}=${ksLit};` +
    `function ${fnName}(i){` +
    `var e=${tableName}[i],k=${ksName},o=new Uint8Array(e.length);` +
    `for(var j=0;j<e.length;j++)o[j]=(e[j]^k[j%k.length])&255;` +
    `return typeof Buffer!=="undefined"?Buffer.from(o).toString("utf8"):` +
    `(typeof TextDecoder!=="undefined"?new TextDecoder().decode(o):` +
    `String.fromCharCode.apply(null,Array.from(o)));` +
    `}` +
    `var _blaS=${fnName};var _blaT=${tableName};`
  );
}

function shouldEncrypt(lit: string, includeUrls: boolean): boolean {
  const id = classifySensitiveLiteral(lit);
  if (!id) return false;
  if (id === "plaintext-url-endpoint" && !includeUrls) return false;
  return true;
}

interface LiteralSpan {
  readonly start: number;
  readonly end: number;
  readonly value: string;
}

function isNonReplaceableStringPosition(path: {
  readonly node: unknown;
  readonly parent: unknown;
  readonly parentPath?: { readonly parent: unknown } | null;
}): boolean {
  const node = path.node as Record<string, unknown>;
  const parent = path.parent as Record<string, unknown> | null | undefined;
  if (!parent) return false;
  const pType = parent.type;

  // Module specifiers in import / export declarations
  if (
    (pType === "ImportDeclaration" ||
      pType === "ExportAllDeclaration" ||
      pType === "ExportNamedDeclaration") &&
    parent.source === node
  ) {
    return true;
  }
  if (pType === "ImportAttribute") {
    return true;
  }
  // TypeScript literal types or module references
  if (
    pType === "TSLiteralType" ||
    pType === "TSExternalModuleReference" ||
    pType === "TSImportType"
  ) {
    return true;
  }
  // Non-computed object / class keys or destructuring pattern keys
  if (
    (pType === "ObjectProperty" ||
      pType === "ObjectMethod" ||
      pType === "ClassProperty" ||
      pType === "ClassMethod" ||
      pType === "TSPropertySignature" ||
      pType === "TSMethodSignature") &&
    parent.key === node &&
    parent.computed !== true
  ) {
    return true;
  }
  if (pType === "ObjectProperty" && path.parentPath?.parent) {
    const grand = path.parentPath.parent as Record<string, unknown>;
    if (grand.type === "ObjectPattern") return true;
  }
  // CommonJS require("...") or dynamic import("...")
  if (pType === "CallExpression") {
    const callee = parent.callee as Record<string, unknown> | undefined;
    const args = parent.arguments as unknown[] | undefined;
    if (
      args?.[0] === node &&
      (callee?.type === "Import" ||
        (callee?.type === "Identifier" && callee.name === "require"))
    ) {
      return true;
    }
  }
  return false;
}

function collectJsLiteralSpans(source: string): LiteralSpan[] {
  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowSuperOutsideMethod: true,
      plugins: ["typescript", "jsx", "decorators-legacy"],
    });
    const spans: LiteralSpan[] = [];
    traverse(ast, {
      StringLiteral(path) {
        if (isNonReplaceableStringPosition(path)) return;
        const { start, end, value } = path.node;
        if (typeof start === "number" && typeof end === "number") {
          spans.push({ start, end, value });
        }
      },
      TemplateLiteral(path) {
        if (
          path.parent.type === "TaggedTemplateExpression" ||
          path.node.expressions.length > 0 ||
          path.node.quasis.length !== 1 ||
          isNonReplaceableStringPosition(path)
        ) {
          return;
        }
        const quasi = path.node.quasis[0];
        const { start, end } = path.node;
        const value = quasi?.value.cooked ?? quasi?.value.raw ?? "";
        if (typeof start === "number" && typeof end === "number") {
          spans.push({ start, end, value });
        }
      },
    });
    spans.sort((a, b) => a.start - b.start);
    return spans;
  } catch {
    // Fallback for non-standard script fragments: match quote/backtick literals while skipping comments
    const spans: LiteralSpan[] = [];
    const tokenRe =
      /\/\/[^\n]*|\/\*[\s\S]*?\*\/|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\$]|\$(?!\{))*`/g;
    let m: RegExpExecArray | null;
    while ((m = tokenRe.exec(source)) !== null) {
      const raw = m[0]!;
      if (raw.startsWith("//") || raw.startsWith("/*")) continue;
      const [decoded] = extractStringLiterals(raw);
      if (decoded !== undefined) {
        spans.push({ start: m.index, end: m.index + raw.length, value: decoded });
      }
    }
    return spans;
  }
}

function transformJsSource(
  source: string,
  prng: SeededPrng,
  includeUrls: boolean,
): {
  readonly code: string;
  readonly encrypted: string[];
  readonly skipped: number;
} {
  // Never re-encrypt a file that already carries the _blaS decrypt stub
  if (source.includes("var _blaS=") && source.includes("var _blaT=")) {
    return { code: source, encrypted: [], skipped: 0 };
  }

  const spans = collectJsLiteralSpans(source);
  const replaceable: LiteralSpan[] = [];
  const unique: string[] = [];
  const seen = new Set<string>();
  let skipped = 0;
  for (const span of spans) {
    if (!shouldEncrypt(span.value, includeUrls)) {
      skipped += 1;
      continue;
    }
    replaceable.push(span);
    if (!seen.has(span.value)) {
      seen.add(span.value);
      unique.push(span.value);
    }
  }
  if (unique.length === 0 || replaceable.length === 0) {
    return { code: source, encrypted: [], skipped };
  }

  const maxLen = Math.max(
    ...unique.map((u) => Buffer.byteLength(u, "utf8")),
    32,
  );
  const keystream = buildKeystream(prng, Math.max(64, maxLen));
  const table = unique.map((u) => xorEncodeToBytes(u, keystream));
  const fnName = prng.identifier({ style: "camel", hint: "blaS", entropy: 3 });
  const tableName = prng.identifier({ style: "camel", hint: "blaT", entropy: 3 });
  const ksName = prng.identifier({ style: "camel", hint: "blaK", entropy: 3 });
  const stub = buildRuntimeStub(table, keystream, fnName, tableName, ksName);

  const indexByLiteral = new Map<string, number>();
  unique.forEach((lit, i) => {
    indexByLiteral.set(lit, i);
  });

  // Splice AST spans in reverse order so earlier offsets stay valid.
  let body = source;
  const descending = [...replaceable].sort((a, b) => b.start - a.start);
  for (const span of descending) {
    const idx = indexByLiteral.get(span.value);
    if (idx === undefined) continue;
    body = `${body.slice(0, span.start)}${fnName}(${idx})${body.slice(span.end)}`;
  }

  // Keep shebang / "use strict" at the very top so Node can still execute the file.
  const shebangMatch = body.match(/^#![^\n]*\n/);
  const shebang = shebangMatch ? shebangMatch[0] : "";
  const rest = shebang ? body.slice(shebang.length) : body;
  const strictMatch = rest.match(/^["']use strict["'];?\r?\n/);
  const strict = strictMatch ? strictMatch[0] : "";
  const afterStrict = strict ? rest.slice(strict.length) : rest;
  return {
    code: shebang + strict + stub + "\n" + afterStrict,
    encrypted: unique,
    skipped,
  };
}

function transformHtml(
  source: string,
  prng: SeededPrng,
  includeUrls: boolean,
): {
  readonly code: string;
  readonly encrypted: string[];
  readonly skipped: number;
} {
  const scriptRe = /(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi;
  const allEncrypted: string[] = [];
  let skipped = 0;
  let any = false;
  const code = source.replace(scriptRe, (_m, open, body, close) => {
    if (/\bsrc\s*=/.test(open) && String(body).trim().length === 0) {
      return `${open}${body}${close}`;
    }
    const result = transformJsSource(
      body,
      prng.derive(`html:${allEncrypted.length}`),
      includeUrls,
    );
    skipped += result.skipped;
    if (result.encrypted.length > 0) {
      any = true;
      allEncrypted.push(...result.encrypted);
      return `${open}${result.code}${close}`;
    }
    return `${open}${body}${close}`;
  });
  if (!any) return { code: source, encrypted: [], skipped };
  return { code, encrypted: allEncrypted, skipped };
}

export function encryptStrings(options: EncryptStringsOptions): EncryptStringsReport {
  try {
    if (typeof options.seed !== "string" || options.seed.length === 0) {
      return {
        schema: ENCRYPT_STRINGS_SCHEMA,
        seedTag: "",
        files: [],
        totalEncrypted: 0,
        postLintClean: false,
        honestyNote: HONESTY,
        status: "error",
        error: "seed is required for reproducible string encryption",
      };
    }
    const targets = listTargets(options.path);
    if (targets.length === 0) {
      return {
        schema: ENCRYPT_STRINGS_SCHEMA,
        seedTag: seedTag(options.seed),
        files: [],
        totalEncrypted: 0,
        postLintClean: true,
        honestyNote: HONESTY,
        status: "noop",
        error: `no panel.html / license.cjs under ${options.path}`,
      };
    }

    const absPath = resolve(options.path);
    const isSingleFileInput = existsSync(absPath) && statSync(absPath).isFile();
    const baseRoot = isSingleFileInput ? dirname(absPath) : absPath;
    const rootPrng = new SeededPrng(options.seed).derive("string.encrypt");
    const includeUrls = options.includeUrls !== false;
    const outDir = options.outDir ? assertSafeOutDir(options.outDir) : null;
    if (outDir && !options.dryRun) mkdirSync(outDir, { recursive: true });

    const files: EncryptStringsFileResult[] = [];
    const wouldOverwrite: string[] = [];
    let totalEncrypted = 0;

    for (const file of targets) {
      const source = readFileSync(file, "utf8");
      const isHtml = /\.html?$/i.test(file);
      const filePrng = rootPrng.derive(basename(file));
      const result = isHtml
        ? transformHtml(source, filePrng, includeUrls)
        : transformJsSource(source, filePrng, includeUrls);

      const relFromRoot = isSingleFileInput
        ? basename(file)
        : relative(baseRoot, file) || basename(file);
      const outPath = outDir ? join(outDir, relFromRoot) : file;
      const alreadyEncryptedInPlace =
        !outDir && source.includes("var _blaS=") && source.includes("var _blaT=");
      if ((outDir !== null && result.encrypted.length > 0 && existsSync(outPath)) || alreadyEncryptedInPlace) {
        wouldOverwrite.push(outPath);
      }
      let written = false;
      if (result.encrypted.length > 0 && !options.dryRun) {
        if (outDir) mkdirSync(dirname(outPath), { recursive: true });
        writeFileAtomicSync(outPath, result.code, "utf8");
        written = true;
      }

      if (
        result.encrypted.length === 0 &&
        !isSingleFileInput &&
        !TARGET_NAMES.has(basename(file).toLowerCase()) &&
        targets.length > 1
      ) {
        continue;
      }

      totalEncrypted += result.encrypted.length;
      files.push({
        path: file,
        relativeName: relFromRoot.replace(/\\/g, "/"),
        encryptedCount: result.encrypted.length,
        skippedCount: result.skipped,
        literals: result.encrypted.map((s) =>
          s.length > 80 ? `${s.slice(0, 80)}…` : s,
        ),
        written,
        outPath,
      });
    }

    let postLintClean = true;
    for (const f of files) {
      if (f.encryptedCount === 0) continue;
      if (options.dryRun) {
        postLintClean = false;
        break;
      }
      const src = readFileSync(f.outPath, "utf8");
      const report = lintPlaintextSecretsSource(src, { path: f.outPath });
      if (report.shouldRefuseBankrupt) {
        postLintClean = false;
        break;
      }
    }

    return {
      schema: ENCRYPT_STRINGS_SCHEMA,
      seedTag: seedTag(options.seed),
      files,
      totalEncrypted,
      postLintClean: totalEncrypted === 0 ? true : postLintClean,
      honestyNote: HONESTY,
      status: totalEncrypted === 0 ? "noop" : "ok",
      wouldOverwrite,
    };
  } catch (err) {
    return {
      schema: ENCRYPT_STRINGS_SCHEMA,
      seedTag: "",
      files: [],
      totalEncrypted: 0,
      postLintClean: false,
      honestyNote: HONESTY,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
