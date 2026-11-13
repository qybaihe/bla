import { parse, type ParserPlugin } from "@babel/parser";
import _traverse, { type Scope } from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";
import { generateProjectSeed } from "../../core/config.js";
import { SeededPrng } from "../../core/prng.js";
import { assertNoForbiddenMarkers } from "../../core/identifiers.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import {
  buildParameterizedMbaBinaryAst,
  deriveParameterizedMbaParams,
} from "../tarpit/mba-substitutions.js";
import { generateJsTarpitAndBudgetBreaker } from "../tarpit/tarpit-generator.js";
import { generateRuntimeDeceptionSnippet } from "../runtime/runtime-shield.js";
import {
  generateShadowHeapChurnShield,
  type ShadowHeapChurnShieldResult,
} from "../runtime/memory-diff-shield.js";
import {
  generateSelfSealSnippet,
  type SelfSealOptions,
} from "../runtime/self-seal.js";
import { generateCounterReaExhaustionSuite } from "../exhaustion/index.js";
import { generateCounterReaDeceptionSuite } from "../deception/index.js";

// Handle ESM/CJS default export interop in NodeNext (Babel 7 & Babel 8)
type UnwrapDefault<T> = T extends { readonly default: infer D } ? D : T;
type TraverseFn = UnwrapDefault<typeof _traverse>;
type GenerateFn = UnwrapDefault<typeof _generate>;
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : (_traverse as unknown as { readonly default: TraverseFn }).default;
const generate: GenerateFn =
  typeof _generate === "function"
    ? (_generate as unknown as GenerateFn)
    : (_generate as unknown as { readonly default: GenerateFn }).default;

export class InvalidJavaScriptCarrierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidJavaScriptCarrierError";
  }
}

export type JsCarrierType = "module" | "script" | "commonjs" | "auto";
export type JsLoaderType = "js" | "jsx" | "ts" | "tsx";

export interface JsTransformOptions {
  readonly intensity?: ProtectionIntensity;
  readonly seed?: string | number;
  readonly filename?: string;
  readonly enableRuntimeShield?: boolean;
  readonly sourceType?: JsCarrierType;
  readonly loader?: JsLoaderType;
  readonly llmDirectives?: boolean;
  /**
   * Opt-in self-seal / sibling-module integrity binding (issue #40.5).
   * When true or an options object, injects a Node self-integrity preamble and
   * entangles the opaque-predicate seed with the measured digest.
   */
  readonly selfSeal?: boolean | SelfSealOptions;
}

export interface JsShieldTransformResult {
  readonly code: string;
  readonly carrierType: "module" | "script" | "commonjs";
  readonly loader: JsLoaderType;
  readonly exportedSymbols: readonly string[];
  readonly decoyFunctionsInjected: number;
  readonly fakeCrossReferencesCreated: number;
  readonly primitiveCandidateBranchesCreated: number;
  readonly aliasSelectionStatesCreated: number;
  readonly ipcAmbiguitySitesInjected: number;
  readonly decoyRoutesInjected: number;
  readonly chaffPayloadsEmbedded: number;
  readonly shadowHeapSlotsChurned: number;
  readonly electronProtocolsProtected?: number;
  readonly memoryDiffShield: ShadowHeapChurnShieldResult;
  /** True when self-seal preamble was injected (issue #40.5). */
  readonly selfSealEnabled?: boolean;
  readonly selfSealBindingName?: string;
}

const DECOY_ROUTES: readonly string[] = [
  "/internal/enclave/v2/attest-quote",
  "/internal/enclave/v2/seal-ledger-state",
  "/kms/v3/quorum/derive-session-ticket",
  "/kms/v3/tpm2/verify-monotonic-counter",
  "/api/v2/hsm/zero-knowledge-challenge",
  "/api/v2/enclave/vsock-tunnel-handshake",
  "/v1/sentinel/hardware-fingerprint-lease",
  "/v1/raft/consensus-state-snapshot",
  "/internal/sgx/quote-verification-service",
  "/internal/nitro/enclave-cid16-dispatch",
];

const IPC_METHODS = new Set([
  "handle",
  "handleOnce",
  "on",
  "once",
  "invoke",
  "send",
  "sendSync",
  "sendToHost",
]);

/**
 * Electron custom URL protocol APIs inspected by REA `electronStaticAnalysisProtocol.ts` (`47fa6ab37`).
 */
const ELECTRON_PROTOCOL_SCHEME_METHODS = new Set([
  "setAsDefaultProtocolClient",
  "removeAsDefaultProtocolClient",
  "isDefaultProtocolClient",
  "handle",
  "registerFileProtocol",
  "registerHttpProtocol",
  "registerStringProtocol",
  "registerBufferProtocol",
  "registerStreamProtocol",
  "interceptFileProtocol",
  "interceptHttpProtocol",
  "interceptStringProtocol",
  "interceptBufferProtocol",
  "interceptStreamProtocol",
  "unhandle",
  "unregisterProtocol",
  "uninterceptProtocol",
  "isProtocolRegistered",
  "isProtocolHandled",
  "isProtocolIntercepted",
]);

const ELECTRON_PRIVILEGE_NAMES = new Set([
  "allowExtensions",
  "allowServiceWorkers",
  "bypassCSP",
  "codeCache",
  "corsEnabled",
  "secure",
  "standard",
  "stream",
  "supportFetchAPI",
]);

function extractMemberChain(node: t.Node | null | undefined): string[] {
  const parts: string[] = [];
  let cur: t.Node | null | undefined = node;
  while (
    t.isMemberExpression(cur) ||
    t.isOptionalMemberExpression(cur)
  ) {
    if (!cur.computed && t.isIdentifier(cur.property)) {
      parts.unshift(cur.property.name);
    } else if (cur.computed && t.isStringLiteral(cur.property)) {
      parts.unshift(cur.property.value);
    } else {
      return [];
    }
    cur = cur.object;
  }
  if (t.isIdentifier(cur)) {
    parts.unshift(cur.name);
  }
  return parts;
}

function getStaticPropName(prop: t.ObjectProperty): string | null {
  if (!prop.computed && t.isIdentifier(prop.key)) return prop.key.name;
  if (t.isStringLiteral(prop.key)) return prop.key.value;
  return null;
}

function isInsideTsConstAssertion(path: { findParent: (cb: (p: any) => boolean) => any }): boolean {
  return Boolean(
    path.findParent((p) => {
      if (p.isTSAsExpression?.() || p.isTSTypeAssertion?.()) {
        const ann = p.node.typeAnnotation;
        return (
          t.isTSTypeReference(ann) &&
          t.isIdentifier(ann.typeName) &&
          ann.typeName.name === "const"
        );
      }
      return false;
    }),
  );
}

export function inferJsLoaderFromPath(filename?: string): JsLoaderType {
  if (!filename) return "js";
  const clean = filename.split(/[?#]/, 1)[0]!.toLowerCase();
  if (clean.endsWith(".tsx")) return "tsx";
  if (clean.endsWith(".jsx")) return "jsx";
  if (
    clean.endsWith(".ts") ||
    clean.endsWith(".mts") ||
    clean.endsWith(".cts")
  ) {
    return "ts";
  }
  return "js";
}

export function inferJsCarrierFromPath(filename?: string): JsCarrierType {
  if (!filename) return "auto";
  const clean = filename.split(/[?#]/, 1)[0]!.toLowerCase();
  if (clean.endsWith(".mjs") || clean.endsWith(".mts")) return "module";
  if (clean.endsWith(".cjs") || clean.endsWith(".cts")) return "commonjs";
  return "auto";
}

/**
 * Module-only syntax without a static import/export: top-level `await` or
 * `import.meta`. Under `sourceType: "unambiguous"` Babel flips
 * `program.sourceType` to "module" for these, and Node (syntax detection, or
 * any ESM loader) evaluates such a file as an ES module — `require` /
 * `__dirname` are undefined there, so it must not be treated as a script.
 */
function hasModuleOnlySyntax(program: t.Program): boolean {
  return program.sourceType === "module";
}

/**
 * Re-detect the runtime carrier of an already-transformed entry (e.g. a
 * protected output read back by a post-pass) using the same rules the shield
 * applies to its own input.
 */
export function detectJsCarrierForSource(
  source: string,
  filename?: string,
): "module" | "script" | "commonjs" {
  const loader = inferJsLoaderFromPath(filename);
  const requested = inferJsCarrierFromPath(filename);
  const parserSourceType =
    requested === "module"
      ? "module"
      : requested === "commonjs" || requested === "script"
        ? "script"
        : "unambiguous";
  try {
    const ast = parse(source, {
      sourceType: parserSourceType,
      plugins: buildParserPlugins(loader, filename !== undefined),
      errorRecovery: false,
    });
    const hasEsmNodes = ast.program.body.some(
      (stmt) =>
        t.isImportDeclaration(stmt) ||
        t.isExportNamedDeclaration(stmt) ||
        t.isExportDefaultDeclaration(stmt) ||
        t.isExportAllDeclaration(stmt),
    );
    if (requested === "module" || hasEsmNodes || hasModuleOnlySyntax(ast.program)) {
      return "module";
    }
    return requested === "commonjs" ? "commonjs" : "script";
  } catch {
    return requested === "module" ? "module" : requested === "commonjs" ? "commonjs" : "script";
  }
}

export function collectEsmExportedSymbols(program: t.Program): string[] {
  const exported: string[] = [];
  for (const stmt of program.body) {
    if (t.isExportDefaultDeclaration(stmt)) {
      exported.push("default");
    } else if (t.isExportAllDeclaration(stmt)) {
      exported.push("*");
    } else if (t.isExportNamedDeclaration(stmt)) {
      for (const spec of stmt.specifiers) {
        if (t.isExportSpecifier(spec)) {
          exported.push(
            t.isIdentifier(spec.exported)
              ? spec.exported.name
              : spec.exported.value,
          );
        } else if (t.isExportNamespaceSpecifier(spec)) {
          const nsExported = spec.exported as t.Identifier | t.StringLiteral;
          exported.push(
            t.isIdentifier(nsExported) ? nsExported.name : nsExported.value,
          );
        }
      }
      const decl = stmt.declaration;
      if (decl) {
        if (
          (t.isFunctionDeclaration(decl) || t.isClassDeclaration(decl)) &&
          decl.id
        ) {
          exported.push(decl.id.name);
        } else if (t.isVariableDeclaration(decl)) {
          const ids = t.getOuterBindingIdentifiers(decl);
          exported.push(...Object.keys(ids));
        } else if (
          "id" in decl &&
          decl.id &&
          t.isIdentifier(decl.id)
        ) {
          exported.push(decl.id.name);
        }
      }
    }
  }
  return exported;
}

/**
 * Splits a string literal into >= 9 conditional chunks `(cond ? realChunk : decoyChunk)`
 * joined with `+`.
 *
 * Why >= 9 chunks?
 * REA's `SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT = 256` (`src/domain/javascript/javascriptSemanticResourceLimits.ts`).
 * When REA's symbolic evaluator sees 9+ binary conditional string terms added together,
 * the cartesian product of candidates is $2^9 = 512 > 256$ (or $2^{10} = 1024 > 256$),
 * which immediately forces REA to bail out with `semanticResourceLimitUnknown("primitive-candidates")`!
 *
 * At runtime, each condition uses `(Math.imul(seed | k, (seed | k) + 1) & 1) === 0`
 * (which is ALWAYS true because the product of two consecutive integers is always even!),
 * so the runtime expression evaluates to the EXACT original string in O(1)!
 */
function buildCombinatorialStringAst(
  value: string,
  prng: SeededPrng,
  seedIdentifierName: string,
): t.Expression {
  const minChunks = 9;
  const chunks: string[] = [];

  if (value.length >= minChunks) {
    const step = Math.max(1, Math.floor(value.length / minChunks));
    let pos = 0;
    for (let i = 0; i < minChunks - 1; i++) {
      chunks.push(value.slice(pos, pos + step));
      pos += step;
    }
    chunks.push(value.slice(pos));
  } else {
    for (const ch of value) {
      chunks.push(ch);
    }
    while (chunks.length < minChunks) {
      chunks.push("");
    }
  }

  const terms: t.Expression[] = chunks.map((realChunk, idx) => {
    const decoyChunk =
      realChunk.length > 0 ? prng.hex(realChunk.length) : prng.hex(2);
    const mode = idx % 3;
    let cond: t.Expression;
    let invertedCond: t.Expression;

    if (mode === 1) {
      // Cognitive-Armor odd-bit entanglement: ((Math.imul(seed ^ 4*k, seed ^ 4*k) & 7) === 1)
      const k = prng.nextInt(1, 31) * 4;
      const seededXor = t.binaryExpression(
        "^",
        t.identifier(seedIdentifierName),
        t.numericLiteral(k),
      );
      const imulCall = t.callExpression(
        t.memberExpression(t.identifier("Math"), t.identifier("imul")),
        [seededXor, t.cloneNode(seededXor)],
      );
      const bitAnd = t.binaryExpression("&", imulCall, t.numericLiteral(7));
      cond = t.binaryExpression("===", bitAnd, t.numericLiteral(1));
      invertedCond = t.binaryExpression("===", t.cloneNode(bitAnd, true), t.numericLiteral(0));
    } else if (mode === 0) {
      // Unsigned-domain MBA inequality: ((u | (u - 1)) >>> 0) >= ((u ^ (u - 1)) >>> 0)
      const k = prng.nextUint32() >>> 0;
      const u = t.binaryExpression(
        ">>>",
        t.binaryExpression("^", t.identifier(seedIdentifierName), t.numericLiteral(k)),
        t.numericLiteral(0),
      );
      const uMinus1 = t.binaryExpression(
        ">>>",
        t.binaryExpression("-", t.cloneNode(u, true), t.numericLiteral(1)),
        t.numericLiteral(0),
      );
      const lhs = t.binaryExpression(
        ">>>",
        t.binaryExpression("|", t.cloneNode(u, true), t.cloneNode(uMinus1, true)),
        t.numericLiteral(0),
      );
      const rhs = t.binaryExpression(
        ">>>",
        t.binaryExpression("^", u, uMinus1),
        t.numericLiteral(0),
      );
      cond = t.binaryExpression(">=", lhs, rhs);
      invertedCond = t.binaryExpression("<", t.cloneNode(lhs, true), t.cloneNode(rhs, true));
    } else {
      // Parameterized affine MBA identity over Z_{2^32}: mbaAdd(seed, k) === ((seed + k) | 0)
      const k = prng.nextInt(3, 125) | 1;
      const mbaExpr = buildParameterizedMbaBinaryAst(
        "+",
        t.identifier(seedIdentifierName),
        t.numericLiteral(k),
        prng,
      );
      const plainExpr = t.binaryExpression(
        "|",
        t.binaryExpression("+", t.identifier(seedIdentifierName), t.numericLiteral(k)),
        t.numericLiteral(0),
      );
      cond = t.binaryExpression("===", mbaExpr, plainExpr);
      invertedCond = t.binaryExpression("!==", t.cloneNode(mbaExpr, true), t.cloneNode(plainExpr, true));
    }

    // Alternate polarity on odd indices so static heuristics see both true/false arms used
    if (idx % 2 === 0) {
      return t.conditionalExpression(
        cond,
        t.stringLiteral(realChunk),
        t.stringLiteral(decoyChunk),
      );
    } else {
      return t.conditionalExpression(
        invertedCond,
        t.stringLiteral(decoyChunk),
        t.stringLiteral(realChunk),
      );
    }
  });

  let expr = terms[0]!;
  for (let i = 1; i < terms.length; i++) {
    expr = t.binaryExpression("+", expr, terms[i]!);
  }
  return expr;
}

function buildOpaqueFalseAst(
  prng: SeededPrng,
  seedIdentifierName: string,
): t.Expression {
  const k4 = prng.nextInt(1, 31) * 4;
  const seededXor = t.binaryExpression(
    "^",
    t.identifier(seedIdentifierName),
    t.numericLiteral(k4),
  );
  const imulCall = t.callExpression(
    t.memberExpression(t.identifier("Math"), t.identifier("imul")),
    [seededXor, t.cloneNode(seededXor)],
  );
  const bitAnd = t.binaryExpression("&", imulCall, t.numericLiteral(7));
  return t.binaryExpression("===", bitAnd, t.numericLiteral(0));
}

/**
 * Opaque TRUE entangled with the runtime Cognitive-Armor digest bit:
 * When untampered, `seedIdentifierName` is odd, so `u = seed ^ (4*k)` is odd
 * and `(Math.imul(u, u) & 7) === 1`. If the Cognitive-Armor corpus is stripped
 * or redacted, `seedIdentifierName` becomes a multiple of 4 and this flips to FALSE.
 */
function buildOpaqueTrueAst(
  prng: SeededPrng,
  seedIdentifierName: string,
): t.Expression {
  const k4 = prng.nextInt(1, 31) * 4;
  const seededXor = t.binaryExpression(
    "^",
    t.identifier(seedIdentifierName),
    t.numericLiteral(k4),
  );
  const imulCall = t.callExpression(
    t.memberExpression(t.identifier("Math"), t.identifier("imul")),
    [seededXor, t.cloneNode(seededXor)],
  );
  const bitAnd = t.binaryExpression("&", imulCall, t.numericLiteral(7));
  return t.binaryExpression("===", bitAnd, t.numericLiteral(1));
}

/**
 * Rewrite an integer literal into an opaque expression that still evaluates to
 * the same Number in O(1). The original bit pattern (e.g. 0x9e3779b9) does not
 * survive as a NumericLiteral, closing the bankrupt cleartext-constant probe
 * tracked in issue #40 while keeping runtime equivalence.
 */
function toNumericExpr(n: number): t.Expression {
  return n < 0
    ? t.unaryExpression("-", t.numericLiteral(Math.abs(n)))
    : t.numericLiteral(n);
}

function buildOpaqueIntegerAst(
  value: number,
  prng: SeededPrng,
  seedIdentifierName: string,
): t.Expression {
  const abs = Math.abs(value);
  const split =
    abs <= 1 ? 1 : prng.nextInt(1, Math.min(0xffff, Math.max(1, abs - 1)));
  const left = value > 0 ? value - split : value + split;
  const right = value > 0 ? split : -split;
  let sum: t.Expression;
  if (Number.isInteger(value) && value >= -0x7fffffff && value <= 0x7fffffff) {
    sum = buildParameterizedMbaBinaryAst(
      "+",
      toNumericExpr(left),
      toNumericExpr(right),
      prng,
    );
  } else if (Number.isInteger(value) && value > 0x7fffffff && value <= 0xffffffff) {
    const xorLeft = (value ^ split) >>> 0;
    sum = t.binaryExpression(
      ">>>",
      buildParameterizedMbaBinaryAst(
        "^",
        t.numericLiteral(xorLeft),
        t.numericLiteral(split >>> 0),
        prng,
      ),
      t.numericLiteral(0),
    );
  } else {
    sum = t.binaryExpression(
      "+",
      toNumericExpr(left),
      toNumericExpr(right),
    );
  }
  // Keep `deriveParameterizedMbaParams` imported for parity checks
  void deriveParameterizedMbaParams;
  const decoy = value ^ (prng.nextInt(1, 0x7fff) | 1);
  if (prng.nextInt(0, 1) === 0) {
    return t.conditionalExpression(
      buildOpaqueTrueAst(prng, seedIdentifierName),
      sum,
      toNumericExpr(decoy),
    );
  }
  return t.conditionalExpression(
    buildOpaqueFalseAst(prng, seedIdentifierName),
    toNumericExpr(decoy),
    sum,
  );
}

const RENAME_RESERVED = new Set([
  "exports", "module", "require", "arguments", "undefined", "NaN", "Infinity",
  "globalThis", "global", "window", "self", "console", "Object", "Array",
  "Promise", "Buffer", "process", "__dirname", "__filename", "JSON", "Date",
  "Error", "TypeError", "RangeError", "Map", "Set", "WeakMap", "WeakSet",
  "Symbol", "Proxy", "Reflect", "parseInt", "parseFloat", "isNaN", "isFinite",
  "encodeURIComponent", "decodeURIComponent", "setTimeout", "clearTimeout",
  "setInterval", "clearInterval", "fetch", "URL", "URLSearchParams",
  "TextEncoder", "TextDecoder", "Uint8Array", "DataView", "ArrayBuffer",
  "SharedArrayBuffer", "Atomics", "WebAssembly", "Intl", "BigInt",
]);

function buildParserPlugins(
  loader: JsLoaderType,
  hasExplicitLoaderOrFilename: boolean,
): ParserPlugin[] {
  const plugins: ParserPlugin[] = [
    "decorators-legacy",
  ];
  if (!hasExplicitLoaderOrFilename) {
    plugins.unshift("typescript", "jsx");
    return plugins;
  }
  if (loader === "ts") {
    plugins.unshift("typescript");
  } else if (loader === "tsx") {
    plugins.unshift("typescript", "jsx");
  } else if (loader === "jsx") {
    plugins.unshift("jsx");
  }
  return plugins;
}

export function transformJavaScriptWithBlaShield(
  source: string,
  options: JsTransformOptions = {},
): JsShieldTransformResult {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? generateProjectSeed());
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const tarpit = generateJsTarpitAndBudgetBreaker(prng, intensity, chaffPayloads);
  const runtimeShield = generateRuntimeDeceptionSnippet(
    prng,
    intensity,
    chaffPayloads,
  );
  const exhaustionSuite = generateCounterReaExhaustionSuite(prng, intensity);
  const deceptionSuite = generateCounterReaDeceptionSuite(prng, intensity);
  const memoryDiffShield = generateShadowHeapChurnShield(prng, intensity);
  // Declared early so every return path can report self-seal status (issue #40.5).
  let selfSealEnabled = false;
  let selfSealBindingName: string | undefined;

  const hasExplicitLoaderOrFilename =
    options.loader !== undefined || options.filename !== undefined;
  const loader: JsLoaderType =
    options.loader ?? inferJsLoaderFromPath(options.filename);
  const requestedCarrier: JsCarrierType =
    options.sourceType ?? inferJsCarrierFromPath(options.filename);

  const parserSourceType =
    requestedCarrier === "script" || requestedCarrier === "commonjs"
      ? "script"
      : requestedCarrier === "module"
        ? "module"
        : "unambiguous";

  let ast: ReturnType<typeof parse>;
  try {
    ast = parse(source, {
      sourceType: parserSourceType,
      plugins: buildParserPlugins(loader, hasExplicitLoaderOrFilename),
      errorRecovery: false,
    });
  } catch (err) {
    throw new InvalidJavaScriptCarrierError(
      `Failed to parse JavaScript/TypeScript input (carrier=${requestedCarrier}, loader=${loader}): ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const hasEsmNodes = ast.program.body.some(
    (stmt) =>
      t.isImportDeclaration(stmt) ||
      t.isExportNamedDeclaration(stmt) ||
      t.isExportDefaultDeclaration(stmt) ||
      t.isExportAllDeclaration(stmt),
  );

  if (
    (requestedCarrier === "script" || requestedCarrier === "commonjs") &&
    hasEsmNodes
  ) {
    throw new InvalidJavaScriptCarrierError(
      `ESM import/export syntax is not allowed in '${requestedCarrier}' carrier`,
    );
  }

  const exportedSymbolsBefore = collectEsmExportedSymbols(ast.program);

  // Collect dynamic-lookup scope before renaming anything. Direct eval can
  // reference parent-scope bindings that Babel cannot see inside the string.
  const bindingsVisibleToDirectEval = new Set<t.Identifier>();
  traverse(ast, {
    CallExpression(path) {
      if (
        t.isIdentifier(path.node.callee) &&
        path.node.callee.name === "eval" &&
        path.scope.getBinding("eval") === undefined
      ) {
        for (const binding of Object.values(path.scope.getAllBindings())) {
          bindingsVisibleToDirectEval.add(binding.identifier);
        }
      }
    },
  });

  // Rename customer-local Math before creating any injected predicates.
  // Renaming after insertion can rewrite BLA's own Math.imul references to
  // the customer's Math parameter, causing a throw or a top-level TDZ.
  traverse(ast, {
    Scope(path) {
      const binding = path.scope.bindings.Math;
      if (binding === undefined) return;
      if (
        binding.kind === "module" ||
        bindingsVisibleToDirectEval.has(binding.identifier) ||
        binding.path.isFunctionDeclaration() ||
        binding.path.isClassDeclaration() ||
        exportedSymbolsBefore.includes("Math")
      ) {
        throw new InvalidJavaScriptCarrierError(
          "Cannot safely protect a lexical Math binding: injected predicates require the ambient Math.imul",
        );
      }
      path.scope.rename("Math", path.scope.generateUidIdentifier("blaLocalMath").name);
    },
  });

  // Preserve observable names without dropping the existing obfuscation
  // of unrelated private helper functions and class declarations.
  const nameObservedBindings = new Set<t.Identifier>();
  const observeNameOf = (scope: Scope, node: t.Node): void => {
    if (t.isIdentifier(node)) {
      let binding = scope.getBinding(node.name);
      while (binding !== undefined && !nameObservedBindings.has(binding.identifier)) {
        nameObservedBindings.add(binding.identifier);
        if (binding.path.isVariableDeclarator()) {
          const init = binding.path.node.init;
          if (t.isIdentifier(init)) {
            binding = binding.scope.getBinding(init.name);
            continue;
          }
          if (t.isNewExpression(init) && t.isIdentifier(init.callee)) {
            observeNameOf(binding.scope, init.callee);
          }
        }
        break;
      }
    } else if (t.isNewExpression(node) && t.isIdentifier(node.callee)) {
      observeNameOf(scope, node.callee);
    } else if (
      (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) &&
      (node.computed
        ? t.isStringLiteral(node.property) && node.property.value === "constructor"
        : t.isIdentifier(node.property) && node.property.name === "constructor")
    ) {
      observeNameOf(scope, node.object);
    }
  };
  const observesName = (node: t.MemberExpression | t.OptionalMemberExpression): boolean =>
    node.computed
      ? t.isStringLiteral(node.property) && node.property.value === "name"
      : t.isIdentifier(node.property) && node.property.name === "name";

  traverse(ast, {
    MemberExpression(path) {
      if (observesName(path.node)) observeNameOf(path.scope, path.node.object);
    },
    OptionalMemberExpression(path) {
      if (observesName(path.node)) observeNameOf(path.scope, path.node.object);
    },
    CallExpression(path) {
      const callee = path.node.callee;
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.object) &&
        t.isIdentifier(callee.property) &&
        ((callee.object.name === "Object" && callee.property.name === "getOwnPropertyDescriptor") ||
          (callee.object.name === "Reflect" && callee.property.name === "get")) &&
        t.isStringLiteral(path.node.arguments[1]) &&
        path.node.arguments[1].value === "name"
      ) {
        const target = path.node.arguments[0];
        if (target && !t.isSpreadElement(target)) observeNameOf(path.scope, target);
      }
    },
  });

  const seedVarName = prng.identifier({ style: "camel", hint: "runtimeSeed", entropy: 4 });
  const observedIpcChannels = new Set<string>();
  const observedProtocolSchemes = new Set<string>();
  const electronEsmBindings = new Map<string, string>();
  let hasProvenElectronRequire = false;
  let electronProtocolsProtected = 0;
  let primitiveCandidateBranchesCreated = 512; // From tarpit budgetFn
  let fakeCrossReferencesCreated = tarpit.crossReferenceEdges;
  let ipcAmbiguitySitesInjected = 0;
  let usesCjsAst = false;

  // Track functions to weave tarpit calls into
  const functionBodies: t.BlockStatement[] = [];

  const handleCallOrOptionalCall = (
    path: {
      node: t.CallExpression | t.OptionalCallExpression;
      findParent: (cb: (p: any) => boolean) => any;
    },
  ): void => {
    const callee = path.node.callee;
    // Leave dynamic eval arguments untouched: they may contain lexical names.
    if (t.isIdentifier(callee) && callee.name === "eval") return;
    if (t.isIdentifier(callee) && callee.name === "require") {
      usesCjsAst = true;
      const reqArg = path.node.arguments[0];
      if (t.isStringLiteral(reqArg) && reqArg.value === "electron") {
        hasProvenElectronRequire = true;
      }
    }

    const inTsConst =
      (loader === "ts" || loader === "tsx") && isInsideTsConstAssertion(path);
    const chain = extractMemberChain(callee);
    const methodName = chain.length >= 2 ? chain[chain.length - 1]! : "";
    const objName = chain.length >= 2 ? chain[chain.length - 2]! : "";
    const rootName = chain.length >= 1 ? chain[0]! : "";

    // 1. Check Electron IPC, contextBridge, and custom URL protocol calls
    if (methodName && !inTsConst) {
      // Electron custom URL protocol registrations (REA 47fa6ab37 `electronStaticAnalysisProtocol.ts`)
      const isProtocolReceiver =
        objName === "protocol" ||
        objName === "app" ||
        rootName === "protocol" ||
        rootName === "app" ||
        chain.includes("protocol") ||
        chain.includes("defaultSession");

      if (
        methodName === "registerSchemesAsPrivileged" &&
        isProtocolReceiver
      ) {
        const listArg = path.node.arguments[0];
        const unwrappedList = t.isTSAsExpression(listArg)
          ? listArg.expression
          : listArg;
        if (t.isArrayExpression(unwrappedList)) {
          for (const elem of unwrappedList.elements) {
            const obj = t.isTSAsExpression(elem) ? elem.expression : elem;
            if (!t.isObjectExpression(obj)) continue;
            for (const prop of obj.properties) {
              if (!t.isObjectProperty(prop)) continue;
              const pName = getStaticPropName(prop);
              if (
                pName === "scheme" &&
                t.isStringLiteral(prop.value) &&
                prop.value.value.length > 0
              ) {
                observedProtocolSchemes.add(prop.value.value);
                prop.value = buildCombinatorialStringAst(
                  prop.value.value,
                  prng,
                  seedVarName,
                );
                electronProtocolsProtected += 1;
                primitiveCandidateBranchesCreated += 512;
              } else if (
                pName === "privileges" &&
                t.isObjectExpression(prop.value)
              ) {
                for (const privProp of prop.value.properties) {
                  if (!t.isObjectProperty(privProp)) continue;
                  const privName = getStaticPropName(privProp);
                  if (
                    privName &&
                    ELECTRON_PRIVILEGE_NAMES.has(privName) &&
                    t.isBooleanLiteral(privProp.value)
                  ) {
                    privProp.value = privProp.value.value
                      ? buildOpaqueTrueAst(prng, seedVarName)
                      : buildOpaqueFalseAst(prng, seedVarName);
                  }
                }
              }
            }
          }
        }
      } else if (
        ELECTRON_PROTOCOL_SCHEME_METHODS.has(methodName) &&
        isProtocolReceiver &&
        !(methodName === "handle" && objName.toLowerCase().includes("ipc"))
      ) {
        const firstArg = path.node.arguments[0];
        if (t.isStringLiteral(firstArg) && firstArg.value.length > 0) {
          observedProtocolSchemes.add(firstArg.value);
          path.node.arguments[0] = buildCombinatorialStringAst(
            firstArg.value,
            prng,
            seedVarName,
          );
          electronProtocolsProtected += 1;
          primitiveCandidateBranchesCreated += 512;
        }
      }

      // Electron IPC calls: ipcMain.handle("channel", ...), ipcRenderer.invoke("channel", ...)
      if (
        IPC_METHODS.has(methodName) &&
        (objName.toLowerCase().includes("ipc") ||
          (methodName === "handle" && !isProtocolReceiver) ||
          methodName === "invoke" ||
          methodName === "sendToHost")
      ) {
        const firstArg = path.node.arguments[0];
        if (t.isStringLiteral(firstArg) && firstArg.value.length > 0) {
          observedIpcChannels.add(firstArg.value);
          path.node.arguments[0] = buildCombinatorialStringAst(
            firstArg.value,
            prng,
            seedVarName,
          );
          primitiveCandidateBranchesCreated += 512;
        }
      }

      // Electron contextBridge.exposeInMainWorld("apiKey", apiObject)
      if (methodName === "exposeInMainWorld") {
        const firstArg = path.node.arguments[0];
        if (t.isStringLiteral(firstArg) && firstArg.value.length > 0) {
          observedIpcChannels.add(`bridge:${firstArg.value}`);
          path.node.arguments[0] = buildCombinatorialStringAst(
            firstArg.value,
            prng,
            seedVarName,
          );
          primitiveCandidateBranchesCreated += 512;
        }
        // Wrap literal API object in an O(1) opaque ternary so runtime passes the exact
        // same object reference while REA's `collectContextBridgeMembers` sees a dynamic node.
        const secondArg = path.node.arguments[1];
        if (t.isObjectExpression(secondArg)) {
          path.node.arguments[1] = t.conditionalExpression(
            buildOpaqueTrueAst(prng, seedVarName),
            secondArg,
            t.objectExpression([]),
          );
        }
      }
    }

    // 2. Check fetch / route / SQL / crypto calls with string literal first arg
    const firstArg = path.node.arguments[0];
    if (
      !inTsConst &&
      t.isStringLiteral(firstArg) &&
      firstArg.value.length >= 4 &&
      !t.isImport(callee) &&
      !(t.isIdentifier(callee) && callee.name === "require")
    ) {
      const val = firstArg.value;
      const looksSensitiveOrRoute =
        val.startsWith("/") ||
        val.startsWith("http") ||
        val.includes("SELECT ") ||
        val.includes("INSERT ") ||
        val.includes("CREATE TABLE") ||
        val.includes("license") ||
        val.includes("secret") ||
        val.includes("token") ||
        val.includes("key") ||
        val.includes("pan") ||
        val.includes("clipboard") ||
        val.endsWith(".wasm");

      if (looksSensitiveOrRoute) {
        path.node.arguments[0] = buildCombinatorialStringAst(
          val,
          prng,
          seedVarName,
        );
        primitiveCandidateBranchesCreated += 512;
      }
    }
  };

  // Pre-pass: Parameterized MBA Instruction Substitution on user 32-bit bitwise ops
  // (`a ^ b`, `a | b`, `a & b`) when program has no BigInt bindings/literals.
  if (intensity === "maximum" || intensity === "bankrupt") {
    let hasBigInt = false;
    let hasShadowedMath = false;
    traverse(ast, {
      BigIntLiteral(path) {
        hasBigInt = true;
        path.stop();
      },
      Identifier(path) {
        if (path.node.name === "BigInt") {
          hasBigInt = true;
          path.stop();
        }
      },
      Scope(path) {
        if (Object.hasOwn(path.scope.bindings, "Math")) {
          hasShadowedMath = true;
          path.stop();
        }
      },
    });
    if (!hasBigInt && !hasShadowedMath) {
      let mbaSubstitutedCount = 0;
      const mbaGeneratedNodes = new WeakSet<t.Node>();
      const isAtomicMbaOperand = (node: t.Node): node is t.Expression =>
        (t.isIdentifier(node) && !RENAME_RESERVED.has(node.name)) ||
        (t.isNumericLiteral(node) &&
          Number.isInteger(node.value) &&
          node.value >= 0 &&
          node.value <= 0xffffffff);

      traverse(ast, {
        BinaryExpression(path) {
          if (mbaSubstitutedCount >= 32) return;
          if (mbaGeneratedNodes.has(path.node)) {
            path.skip();
            return;
          }
          if (
            (loader === "ts" || loader === "tsx") &&
            isInsideTsConstAssertion(path)
          ) {
            return;
          }
          if (path.findParent((p) => p.isTSType())) return;
          const op = path.node.operator;
          if (op !== "^" && op !== "|" && op !== "&") return;
          const { left, right } = path.node;
          if (!isAtomicMbaOperand(left) || !isAtomicMbaOperand(right)) return;
          if (!t.isIdentifier(left) && !t.isIdentifier(right)) return;
          // Preserve idiomatic `(x | 0)` ToInt32 coercions as outer wrappers
          if (op === "|" && t.isNumericLiteral(right) && right.value === 0) return;

          const replacement = buildParameterizedMbaBinaryAst(op, left, right, prng);
          mbaGeneratedNodes.add(replacement);
          path.replaceWith(replacement);
          path.skip();
          mbaSubstitutedCount += 1;
        },
      });
    }
  }

  traverse(ast, {
    ImportDeclaration(path) {
      if (
        path.node.source.value === "electron" &&
        (!path.node.importKind || path.node.importKind === "value")
      ) {
        for (const spec of path.node.specifiers) {
          if (t.isImportSpecifier(spec)) {
            if (spec.importKind === "type") continue;
            const imported = t.isIdentifier(spec.imported)
              ? spec.imported.name
              : spec.imported.value;
            electronEsmBindings.set(imported, spec.local.name);
          } else if (
            t.isImportDefaultSpecifier(spec) ||
            t.isImportNamespaceSpecifier(spec)
          ) {
            electronEsmBindings.set("*", spec.local.name);
          }
        }
      }
    },
    Function(path) {
      if (t.isBlockStatement(path.node.body)) {
        functionBodies.push(path.node.body);
      }
    },
    MemberExpression(path) {
      const { object, property } = path.node;
      if (
        t.isIdentifier(object) &&
        object.name === "module" &&
        t.isIdentifier(property) &&
        property.name === "exports"
      ) {
        usesCjsAst = true;
      } else if (t.isIdentifier(object) && object.name === "exports") {
        usesCjsAst = true;
      }
    },
    CallExpression(path) {
      handleCallOrOptionalCall(path);
    },
    OptionalCallExpression(path) {
      handleCallOrOptionalCall(path);
    },
    ObjectProperty(path) {
      if (
        (loader === "ts" || loader === "tsx") &&
        isInsideTsConstAssertion(path)
      ) {
        return;
      }
      const propName = getStaticPropName(path.node);
      if (
        propName === "webPreferences" &&
        t.isObjectExpression(path.node.value)
      ) {
        for (const pref of path.node.value.properties) {
          if (!t.isObjectProperty(pref)) continue;
          const prefKey = getStaticPropName(pref);
          if (t.isBooleanLiteral(pref.value)) {
            pref.value = pref.value.value
              ? buildOpaqueTrueAst(prng, seedVarName)
              : buildOpaqueFalseAst(prng, seedVarName);
          } else if (prefKey === "preload") {
            if (
              t.isStringLiteral(pref.value) &&
              pref.value.value.length > 0
            ) {
              pref.value = buildCombinatorialStringAst(
                pref.value.value,
                prng,
                seedVarName,
              );
              primitiveCandidateBranchesCreated += 512;
            } else if (t.isCallExpression(pref.value)) {
              pref.value.arguments = pref.value.arguments.map((arg) =>
                t.isStringLiteral(arg) && arg.value.length > 0
                  ? buildCombinatorialStringAst(arg.value, prng, seedVarName)
                  : arg,
              );
              primitiveCandidateBranchesCreated += 512;
            }
          }
        }
      }
    },
    StringLiteral(path) {
      if (intensity !== "bankrupt" && intensity !== "maximum") {
        return;
      }
      if (
        (loader === "ts" || loader === "tsx") &&
        isInsideTsConstAssertion(path)
      ) {
        return;
      }
      const val = path.node.value;
      if (val.length < 3 || val.length > 256) {
        return;
      }
      const parent = path.parent;
      if (
        t.isImportDeclaration(parent) ||
        t.isExportNamedDeclaration(parent) ||
        t.isExportAllDeclaration(parent) ||
        t.isTSLiteralType(parent) ||
        t.isTSImportType(parent) ||
        t.isTSExternalModuleReference(parent) ||
        t.isTSModuleDeclaration(parent) ||
        t.isImportAttribute(parent) ||
        (t.isExpressionStatement(parent) && val.startsWith("use "))
      ) {
        return;
      }
      if (
        path.findParent(
          (p) =>
            p.isTSType() ||
            p.isTSModuleDeclaration() ||
            p.isTSExternalModuleReference() ||
            p.isImportAttribute(),
        )
      ) {
        return;
      }
      if (
        t.isObjectProperty(parent) &&
        parent.key === path.node &&
        !parent.computed
      ) {
        return;
      }
      if (
        t.isClassMethod(parent) ||
        t.isObjectMethod(parent) ||
        t.isClassProperty(parent)
      ) {
        return;
      }
      if (
        t.isCallExpression(parent) &&
        t.isIdentifier(parent.callee) &&
        (parent.callee.name === "require" || parent.callee.name === "eval")
      ) {
        return;
      }
      path.replaceWith(buildCombinatorialStringAst(val, prng, seedVarName));
      path.skip();
      primitiveCandidateBranchesCreated += 256;
    },
    TemplateLiteral(path) {
      if (intensity !== "bankrupt" && intensity !== "maximum") {
        return;
      }
      if (
        (loader === "ts" || loader === "tsx") &&
        isInsideTsConstAssertion(path)
      ) {
        return;
      }
      const parent = path.parent;
      if (
        t.isTaggedTemplateExpression(parent) ||
        t.isTSLiteralType(parent) ||
        t.isTSImportType(parent) ||
        t.isTSExternalModuleReference(parent)
      ) {
        return;
      }
      if (
        path.findParent(
          (p) =>
            p.isTSType() ||
            p.isTSModuleDeclaration() ||
            p.isTSExternalModuleReference() ||
            p.isImportAttribute(),
        )
      ) {
        return;
      }
      const quasis = path.node.quasis;
      const exprs = path.node.expressions;
      // Skip if any quasi lacks a valid cooked value (invalid escape sequence)
      // or contains TypeScript type expressions inside template slots.
      if (
        quasis.some((q) => typeof q.value.cooked !== "string") ||
        exprs.some((ex) => !t.isExpression(ex))
      ) {
        return;
      }
      const totalCookedLen = quasis.reduce(
        (acc, q) => acc + (q.value.cooked?.length ?? 0),
        0,
      );
      if (totalCookedLen < 3 || totalCookedLen > 256) {
        return;
      }
      if (exprs.length === 0) {
        const val = quasis[0]?.value.cooked ?? "";
        path.replaceWith(buildCombinatorialStringAst(val, prng, seedVarName));
        path.skip();
        primitiveCandidateBranchesCreated += 256;
        return;
      }
      // Rewrite `prefix ${a} mid ${b} suffix` into concatenated combinatorial
      // string AST + `String(expr)` coercions, preserving exact JS `ToString`
      // template evaluation order without leaving cleartext backtick chunks.
      const parts: t.Expression[] = [];
      for (let i = 0; i < quasis.length; i++) {
        const chunk = quasis[i]!.value.cooked ?? "";
        if (chunk.length >= 3) {
          parts.push(buildCombinatorialStringAst(chunk, prng, seedVarName));
          primitiveCandidateBranchesCreated += 256;
        } else if (chunk.length > 0 || parts.length === 0) {
          parts.push(t.stringLiteral(chunk));
        }
        if (i < exprs.length) {
          const ex = exprs[i] as t.Expression;
          parts.push(t.binaryExpression("+", t.stringLiteral(""), ex));
        }
      }
      let combined: t.Expression = parts[0] ?? t.stringLiteral("");
      for (let i = 1; i < parts.length; i++) {
        combined = t.binaryExpression("+", combined, parts[i]!);
      }
      path.replaceWith(combined);
      path.skip();
    },
    NumericLiteral(path) {
      // Issue #40: bankrupt/maximum must not leave schedule / magic integers
      // bit-identical in the hardened output (probe: 0x9e3779b9).
      if (intensity !== "bankrupt" && intensity !== "maximum") {
        return;
      }
      if (
        (loader === "ts" || loader === "tsx") &&
        isInsideTsConstAssertion(path)
      ) {
        return;
      }
      const val = path.node.value;
      if (!Number.isInteger(val)) return;
      if (!Number.isSafeInteger(val)) return;
      // Leave tiny integers alone (loop bounds / booleans-as-numbers); rewrite
      // everything at |n| >= 16 so golden-ratio / salt / schedule constants go.
      if (Math.abs(val) < 16) return;
      const parent = path.parent;
      if (
        t.isObjectProperty(parent) &&
        parent.key === path.node &&
        !parent.computed
      ) {
        return;
      }
      if (
        t.isTSLiteralType(parent) ||
        t.isTSEnumMember(parent) ||
        t.isImportAttribute(parent)
      ) {
        return;
      }
      if (
        path.findParent(
          (p) =>
            p.isTSType() ||
            p.isTSEnumDeclaration() ||
            p.isTSModuleDeclaration() ||
            p.isImportAttribute(),
        )
      ) {
        return;
      }
      path.replaceWith(buildOpaqueIntegerAst(val, prng, seedVarName));
      path.skip();
      primitiveCandidateBranchesCreated += 64;
    },
  });

  const effectiveCarrier: "module" | "script" | "commonjs" =
    requestedCarrier === "module" || hasEsmNodes || hasModuleOnlySyntax(ast.program)
      ? "module"
      : requestedCarrier === "commonjs" || usesCjsAst
        ? "commonjs"
        : "script";


  // 2b. Rename non-exported local bindings (including function parameters and private helpers)
  // so original identifiers are not left pristine.
  // Only rename bindings owned by the current scope. Babel mirrors ClassDeclaration
  // names onto the class scope with the SAME binding object; renaming there a second
  // time with a fresh PRNG name desyncs `class Foo` from `new Foo()` (issue #40).
  const exportedNameSet = new Set(exportedSymbolsBefore);
  const generatedNames = new Set<string>();
  // Strip unreferenced Stage-2 encryptStrings marker aliases (`_blaS`, `_blaT`)
  // before scope renaming so hardened artifacts retain zero marker dead-vars.
  traverse(ast, {
    VariableDeclarator(path) {
      if (
        t.isIdentifier(path.node.id) &&
        (path.node.id.name === "_blaS" || path.node.id.name === "_blaT") &&
        path.scope.path.isProgram()
      ) {
        const binding = path.scope.getBinding(path.node.id.name);
        if (binding && binding.references === 0 && !exportedNameSet.has(path.node.id.name)) {
          path.remove();
        }
      }
    },
  });
  traverse(ast, {
    Scope(path) {
      for (const [name, binding] of Object.entries(path.scope.bindings)) {
        if (binding.scope !== path.scope) continue;
        if (bindingsVisibleToDirectEval.has(binding.identifier)) continue;
        // Function/class names remain obfuscated except when the source
        // actually reads their runtime .name (including constructor.name).
        if (nameObservedBindings.has(binding.identifier)) continue;
        if (RENAME_RESERVED.has(name)) continue;
        if (exportedNameSet.has(name)) continue;
        if (binding.kind === "module") continue;
        if (name.startsWith("_") && name.length <= 2) continue;
        if (
          /^(_interlockSafetyCorpus_|_deriveContainmentCorpusDigest_|_DISTRIBUTED_ASL3_|_SELF_SEAL_TARGET)/.test(
            name,
          )
        ) {
          continue;
        }
        if (generatedNames.has(name)) continue;
        if (
          binding.kind !== "let" &&
          binding.kind !== "const" &&
          binding.kind !== "var" &&
          binding.kind !== "hoisted" &&
          binding.kind !== "local" &&
          binding.kind !== "param"
        ) {
          continue;
        }
        if (
          binding.kind === "param" &&
          (binding.path.isTSParameterProperty() ||
            binding.path.parentPath?.isTSParameterProperty())
        ) {
          continue;
        }
        // In classic "script" carrier, top-level hoisted functions may be invoked globally;
        // in "module" / "commonjs" carriers, only preserve pre-tagged decoy identifiers.
        if (
          path.scope.path.isProgram() &&
          binding.kind === "hoisted" &&
          (effectiveCarrier === "script" || /_[0-9a-f]{3,4}$/i.test(name))
        ) {
          continue;
        }
        const newName = prng.identifier({
          style: name.startsWith("_") ? "privateCamel" : "camel",
          hint:
            intensity === "bankrupt" || intensity === "maximum"
              ? undefined
              : name.replace(/^_+/, "").slice(0, 16) || "local",
          entropy: 3,
        });
        if (
          newName === name ||
          RENAME_RESERVED.has(newName) ||
          exportedNameSet.has(newName) ||
          generatedNames.has(newName)
        ) {
          continue;
        }
        try {
          path.scope.rename(name, newName);
          generatedNames.add(newName);
        } catch {
          // Binding may be constant-violating or conflict; skip safely
        }
      }
    },
  });

  // Injected predicates require the ambient Math.imul. Rename supported
  // customer Math bindings, but fail closed for imported/exported or eval-
  // visible bindings that cannot be renamed without breaking the programme.
  traverse(ast, {
    Scope(path) {
      if (Object.hasOwn(path.scope.bindings, "Math")) {
        throw new InvalidJavaScriptCarrierError(
          "Cannot safely protect a lexical Math binding: injected predicates require the ambient Math.imul",
        );
      }
    },
  });

  // 2c. Transform / relocate comments so original Chinese/doc comments are not pristine
  if (ast.comments) {
    for (const c of ast.comments) {
      if (/sourceMappingURL=/i.test(c.value)) continue;
      // Relocate + scramble: destroy verbatim original comments (incl. Chinese docs)
      // while preserving that a comment existed (so AST shape stays similar).
      const theme = prng.pick([
        "reconcile session epoch",
        "derive ledger digest",
        "normalize envelope frame",
        "hydrate runtime cache",
        "project quota policy",
      ]);
      const scrambled = prng.hex(6);
      c.value = c.type === "CommentBlock"
        ? ` ${theme} (${scrambled}) `
        : ` ${theme} (${scrambled})`;
    }
  }

  // 2d. Entangle REAL statements with opaque-TRUE guards so blind deletion breaks behavior
  traverse(ast, {
    BlockStatement(path) {
      // Skip injected blocks that don't exist yet; only original function bodies
      if (!functionBodies.includes(path.node)) return;
      const stmts = path.node.body;
      if (stmts.length === 0) return;
      const next: t.Statement[] = [];
      for (let i = 0; i < stmts.length; i++) {
        const stmt = stmts[i]!;
        // Don't wrap returns/throws/declarations/directives — wrap expression & if stmts
        // NEVER wrap VariableDeclaration / FunctionDeclaration / Return / Throw —
        // that would change block scoping and break the program under our own shield.
        const wrappable =
          t.isExpressionStatement(stmt) ||
          (t.isIfStatement(stmt) && !t.isVariableDeclaration(stmt.consequent));
        if (wrappable && i % 2 === 0) {
          next.push(
            t.ifStatement(
              buildOpaqueTrueAst(prng, seedVarName),
              t.blockStatement([stmt]),
            ),
          );
        } else {
          next.push(stmt);
        }
      }
      path.node.body = next;
    },
  });

  // 3. Weave synchronized shadow-heap churn + unreachable tarpit calls into real function bodies
  for (const body of functionBodies) {
    const stepCallStmt = t.expressionStatement(
      t.callExpression(t.identifier(memoryDiffShield.stepperFunctionName), [
        t.numericLiteral(prng.nextInt(1, 4095)),
      ]),
    );
    if (tarpit.decoyFunctionNames.length >= 2) {
      const d1 = prng.pick(tarpit.decoyFunctionNames);
      const d2 = prng.pick(tarpit.decoyFunctionNames);
      const guard = t.ifStatement(
        buildOpaqueFalseAst(prng, seedVarName),
        t.blockStatement([
          t.expressionStatement(
            t.binaryExpression(
              "^",
              t.callExpression(t.identifier(d1), [
                t.numericLiteral(prng.nextInt(1, 255)),
                t.numericLiteral(2),
              ]),
              t.callExpression(t.identifier(d2), [
                t.numericLiteral(prng.nextInt(1, 255)),
                t.numericLiteral(2),
              ]),
            ),
          ),
        ]),
      );
      body.body.unshift(stepCallStmt, guard);
      fakeCrossReferencesCreated += 3;
    } else {
      body.body.unshift(stepCallStmt);
      fakeCrossReferencesCreated += 1;
    }
  }

  // 4. Build Decoy IPC Ambiguity & Route Mirage block + Cognitive-Armor seed entanglement
  const mirageLines: string[] = [];
  mirageLines.push(deceptionSuite.cognitiveArmor.code);
  // Opt-in self-seal (issue #40.5): sibling-module + env fingerprint digest.
  const selfSealOpt = options.selfSeal;
  let esmSelfSealReqIdent: string | undefined;
  let esmSelfSealMetaUrlIdent: string | undefined;
  if (selfSealOpt) {
    if (effectiveCarrier === "module") {
      esmSelfSealReqIdent = prng.identifier({
        style: "camel",
        hint: "resolveModuleRequire",
        entropy: 4,
      });
      esmSelfSealMetaUrlIdent = prng.identifier({
        style: "camel",
        hint: "moduleEntryUrl",
        entropy: 4,
      });
    }
    const baseSealOpts: SelfSealOptions =
      selfSealOpt === true ? {} : selfSealOpt;
    const sealOpts: SelfSealOptions =
      esmSelfSealReqIdent && esmSelfSealMetaUrlIdent
        ? {
            ...baseSealOpts,
            esmRequireHelperIdent: esmSelfSealReqIdent,
            esmMetaUrlIdent: esmSelfSealMetaUrlIdent,
          }
        : baseSealOpts;
    const seal = generateSelfSealSnippet(prng, sealOpts);
    mirageLines.push(seal.code);
    selfSealEnabled = true;
    selfSealBindingName = seal.bindingName;
  }
  // Deterministic opaque-predicate seed (issue #40.4): never hrtime/Date.now/bit0-only.
  // Draw ~28 bits of PRNG material (two draws xor'd) so weak hrtime/bit0 patterns
  // cannot be guessed; keep low bit free for cognitive-armor entanglement.
  // When self-seal is on, also fold the integrity digest into the seed material.
  const opaqueSeedHi = prng.nextUint32() >>> 0;
  const opaqueSeedLo = prng.nextUint32() >>> 0;
  const opaqueSeedBase =
    (((opaqueSeedHi ^ (opaqueSeedLo << 1)) & 0xfffffffc) >>> 0) || 4096;
  const selfSealFold =
    selfSealEnabled && selfSealBindingName
      ? ` ^ ((${selfSealBindingName} >>> 0) & 0xfffffffc)`
      : "";
  mirageLines.push(
    `const ${seedVarName} = ((${opaqueSeedBase}${selfSealFold}) | ((${deceptionSuite.cognitiveArmor.digestFunctionName}(0) === ${deceptionSuite.cognitiveArmor.expectedDigest}) ? 1 : 0));`,
  );
  mirageLines.push(memoryDiffShield.code);
  const channelsToMirror =
    observedIpcChannels.size > 0
      ? [...observedIpcChannels]
      : ["enclave:attest", "clipboard:bridge-sync", "license:verify-lease"];

  const decoyRouteCount =
    intensity === "stealth" ? 4 : intensity === "balanced" ? 8 : 10;
  const selectedDecoyRoutes = DECOY_ROUTES.slice(0, decoyRouteCount);

  const decoyIpcFnName = prng.identifier({ style: "camel", hint: "registerDecoyIpcAndRoutes", entropy: 4 });
  mirageLines.push(
    `function ${decoyIpcFnName}(_ipcMain, _ipcRenderer, _router) {`,
  );
  mirageLines.push(
    `  const _uIpc = ((${seedVarName} ^ 0x5bd1e995) >>> 0);`,
    `  if ((((_uIpc | ((_uIpc - 1) >>> 0)) >>> 0) < ((_uIpc ^ ((_uIpc - 1) >>> 0)) >>> 0))) {`,
  );
  for (const ch of channelsToMirror) {
    // Register duplicate ambiguous literal channels on both ipcMain and ipcRenderer
    // to defeat REA's unique exact literal IPC channel pairing rule!
    mirageLines.push(
      `    _ipcMain?.handle(${JSON.stringify(ch)}, () => ({ delegatedToEnclave: true, channel: ${JSON.stringify(ch)} }));`,
    );
    mirageLines.push(
      `    _ipcMain?.on(${JSON.stringify(ch)}, () => ({ fallbackStub: true }));`,
    );
    mirageLines.push(
      `    _ipcRenderer?.invoke(${JSON.stringify(ch)}, { probe: "enclave_shadow_1" });`,
    );
    mirageLines.push(
      `    _ipcRenderer?.send(${JSON.stringify(ch)}, { probe: "enclave_shadow_2" });`,
    );
    ipcAmbiguitySitesInjected += 4;
  }
  for (const route of selectedDecoyRoutes) {
    mirageLines.push(`    fetch(${JSON.stringify(route)});`);
    mirageLines.push(
      `    _router?.post?.(${JSON.stringify(route)}, () => null);`,
    );
  }
  const decoySchemes = [
    "enclave-vsock",
    "tee-attest",
    "quorum-kms",
    "sgx-bridge",
    "hsm-lease",
  ]
    .filter((s) => !observedProtocolSchemes.has(s))
    .slice(0, 4);
  if (hasProvenElectronRequire && !hasEsmNodes) {
    const elBind = prng.identifier({ style: "privateCamel", hint: "electronRef", entropy: 3 });
    mirageLines.push(`    const ${elBind} = require("electron");`);
    for (const sch of decoySchemes) {
      mirageLines.push(
        `    ${elBind}.app.setAsDefaultProtocolClient(${JSON.stringify(sch)});`,
        `    ${elBind}.protocol.registerSchemesAsPrivileged([{ scheme: ${JSON.stringify(sch)}, privileges: { secure: true, standard: true, supportFetchAPI: true, stream: true } }]);`,
        `    ${elBind}.protocol.handle(${JSON.stringify(sch)}, () => null);`,
        `    ${elBind}.session.defaultSession.protocol.handle(${JSON.stringify(sch)}, () => null);`,
      );
      ipcAmbiguitySitesInjected += 4;
    }
    for (const ch of channelsToMirror.slice(0, 4)) {
      mirageLines.push(
        `    ${elBind}.ipcMain.handle(${JSON.stringify(ch)}, () => ({ delegatedToEnclave: true }));`,
        `    ${elBind}.ipcRenderer.invoke(${JSON.stringify(ch)}, { probe: 1 });`,
        `    ${elBind}.contextBridge.exposeInMainWorld(${JSON.stringify(`enclave_${prng.hex(2)}`)}, { attest: () => true, verifyLease: () => true });`,
      );
      ipcAmbiguitySitesInjected += 3;
    }
  } else if (electronEsmBindings.size > 0) {
    const ns = electronEsmBindings.get("*");
    const appId = electronEsmBindings.get("app") ?? (ns ? `${ns}.app` : null);
    const protoId = electronEsmBindings.get("protocol") ?? (ns ? `${ns}.protocol` : null);
    const sessId = electronEsmBindings.get("session") ?? (ns ? `${ns}.session` : null);
    const ipcMainId = electronEsmBindings.get("ipcMain") ?? (ns ? `${ns}.ipcMain` : null);
    const ipcRenId = electronEsmBindings.get("ipcRenderer") ?? (ns ? `${ns}.ipcRenderer` : null);
    const cbId = electronEsmBindings.get("contextBridge") ?? (ns ? `${ns}.contextBridge` : null);
    for (const sch of decoySchemes) {
      if (appId) {
        mirageLines.push(`    ${appId}.setAsDefaultProtocolClient(${JSON.stringify(sch)});`);
        ipcAmbiguitySitesInjected += 1;
      }
      if (protoId) {
        mirageLines.push(
          `    ${protoId}.registerSchemesAsPrivileged([{ scheme: ${JSON.stringify(sch)}, privileges: { secure: true, standard: true, supportFetchAPI: true } }]);`,
          `    ${protoId}.handle(${JSON.stringify(sch)}, () => null);`,
        );
        ipcAmbiguitySitesInjected += 2;
      }
      if (sessId) {
        mirageLines.push(`    ${sessId}.defaultSession.protocol.handle(${JSON.stringify(sch)}, () => null);`);
        ipcAmbiguitySitesInjected += 1;
      }
    }
    for (const ch of channelsToMirror.slice(0, 4)) {
      if (ipcMainId) {
        mirageLines.push(`    ${ipcMainId}.handle(${JSON.stringify(ch)}, () => ({ delegatedToEnclave: true }));`);
        ipcAmbiguitySitesInjected += 1;
      }
      if (ipcRenId) {
        mirageLines.push(`    ${ipcRenId}.invoke(${JSON.stringify(ch)}, { probe: 1 });`);
        ipcAmbiguitySitesInjected += 1;
      }
      if (cbId) {
        mirageLines.push(`    ${cbId}.exposeInMainWorld(${JSON.stringify(`enclave_${prng.hex(2)}`)}, { attest: () => true });`);
        ipcAmbiguitySitesInjected += 1;
      }
    }
  }
  mirageLines.push(`  }`);
  mirageLines.push(`}`);
  mirageLines.push(`void ${decoyIpcFnName};`);

  const deceptionWithoutDuplicateArmor = deceptionSuite.combinedJsCode.replace(
    deceptionSuite.cognitiveArmor.code,
    "",
  );

  const injectedBlocks = [
    mirageLines.join("\n"),
    ...(options.enableRuntimeShield !== false ? [runtimeShield.code] : []),
    tarpit.code.replace(/\bexport\s+function\s+/g, "function "),
    exhaustionSuite.combinedJsCode,
    deceptionWithoutDuplicateArmor,
  ];

  const combinedInjectedAst = parse(injectedBlocks.join("\n\n"), {
    sourceType: "script",
    plugins: ["typescript"],
  });

  const sanitizedInjectedStatements: t.Statement[] = [];
  const injectedFnIdentifiers: t.Identifier[] = [];
  for (const stmt of combinedInjectedAst.program.body) {
    if (t.isExportNamedDeclaration(stmt) && stmt.declaration) {
      sanitizedInjectedStatements.push(stmt.declaration);
      if (t.isFunctionDeclaration(stmt.declaration) && stmt.declaration.id) {
        injectedFnIdentifiers.push(t.identifier(stmt.declaration.id.name));
      }
    } else if (
      !t.isImportDeclaration(stmt) &&
      !t.isExportNamedDeclaration(stmt) &&
      !t.isExportDefaultDeclaration(stmt) &&
      !t.isExportAllDeclaration(stmt)
    ) {
      sanitizedInjectedStatements.push(stmt);
      if (t.isFunctionDeclaration(stmt) && stmt.id) {
        injectedFnIdentifiers.push(t.identifier(stmt.id.name));
      }
    }
  }
  if (injectedFnIdentifiers.length > 0) {
    sanitizedInjectedStatements.push(
      t.expressionStatement(
        t.unaryExpression("void", t.arrayExpression(injectedFnIdentifiers)),
      ),
    );
  }

  // Prepend Cognitive-Armor corpus, digest function, `seedVarName`, and shadow heap at top of program
  let insertIndex = 0;
  while (insertIndex < ast.program.body.length) {
    const stmt = ast.program.body[insertIndex]!;
    if (t.isImportDeclaration(stmt)) {
      insertIndex++;
      continue;
    }
    if (
      t.isExpressionStatement(stmt) &&
      t.isStringLiteral(stmt.expression) &&
      stmt.expression.value.startsWith("use ")
    ) {
      insertIndex++;
      continue;
    }
    break;
  }

  // Prepend every injected statement through the opaque-predicate seed decl
  // (cognitive armor + optional self-seal preamble + seed). Self-seal inserts
  // extra statements before the seed; a fixed 4-stmt split pushed the seed to
  // the program end and caused TDZ crashes when top-level consts referenced it
  // (red-blue round-4). Also keep the immediate following shadow-heap decl up top.
  const seedInjectIndex = sanitizedInjectedStatements.findIndex((stmt) => {
    if (!t.isVariableDeclaration(stmt)) return false;
    return stmt.declarations.some(
      (d) => t.isIdentifier(d.id) && d.id.name === seedVarName,
    );
  });
  // Bind all hoisted decoy/tarpit/exhaustion function declarations directly into `seedVarName`
  // so stripping the injected tail throws ReferenceError or zeroes the integrity bit.
  if (seedInjectIndex >= 0 && injectedFnIdentifiers.length > 0) {
    const seedStmt = sanitizedInjectedStatements[seedInjectIndex];
    if (seedStmt && t.isVariableDeclaration(seedStmt)) {
      const decl = seedStmt.declarations.find(
        (d) => t.isIdentifier(d.id) && d.id.name === seedVarName,
      );
      if (
        decl &&
        decl.init &&
        t.isBinaryExpression(decl.init) &&
        decl.init.operator === "|" &&
        t.isConditionalExpression(decl.init.right)
      ) {
        const fnParam = t.identifier("_f");
        const everyCall = t.callExpression(
          t.memberExpression(
            t.arrayExpression(
              injectedFnIdentifiers.map((id) => t.identifier(id.name)),
            ),
            t.identifier("every"),
          ),
          [
            t.arrowFunctionExpression(
              [fnParam],
              t.binaryExpression(
                "===",
                t.unaryExpression("typeof", t.identifier("_f")),
                t.stringLiteral("function"),
              ),
            ),
          ],
        );
        decl.init.right.test = t.logicalExpression(
          "&&",
          everyCall,
          decl.init.right.test,
        );
      }
    }
  }
  const topEnd =
    seedInjectIndex >= 0
      ? Math.min(
          sanitizedInjectedStatements.length,
          seedInjectIndex + 1 /* seed */ + 1 /* shadow heap usually follows */,
        )
      : Math.min(4, sanitizedInjectedStatements.length);
  const topDecls = sanitizedInjectedStatements.slice(0, topEnd);
  const restInjected = sanitizedInjectedStatements.slice(topEnd);
  if (esmSelfSealReqIdent && esmSelfSealMetaUrlIdent) {
    const reqImportDecl = t.importDeclaration(
      [
        t.importSpecifier(
          t.identifier(esmSelfSealReqIdent),
          t.identifier("createRequire"),
        ),
      ],
      t.stringLiteral("node:module"),
    );
    const metaUrlDecl = t.variableDeclaration("const", [
      t.variableDeclarator(
        t.identifier(esmSelfSealMetaUrlIdent),
        t.memberExpression(
          t.metaProperty(t.identifier("import"), t.identifier("meta")),
          t.identifier("url"),
        ),
      ),
    ]);
    ast.program.body.unshift(reqImportDecl);
    insertIndex += 1;
    topDecls.unshift(metaUrlDecl);
  }
  if (topDecls.length > 0) {
    ast.program.body.splice(insertIndex, 0, ...topDecls);
  }
  ast.program.body.push(...restInjected);

  const exportedSymbolsAfter = collectEsmExportedSymbols(ast.program);
  if (
    exportedSymbolsBefore.length !== exportedSymbolsAfter.length ||
    exportedSymbolsBefore.some((sym, idx) => sym !== exportedSymbolsAfter[idx])
  ) {
    throw new InvalidJavaScriptCarrierError(
      "Internal error: BLA JavaScript transform mutated module export surface",
    );
  }

  // Strip any existing `//# sourceMappingURL=` comments from AST
  if (ast.comments) {
    ast.comments = ast.comments.filter(
      (c) => !/sourceMappingURL=/i.test(c.value),
    );
  }

  const generated = generate(
    ast,
    {
      retainLines: false,
      compact: false,
      comments: true,
    },
    source,
  );

  return {
    code: generated.code,
    carrierType: effectiveCarrier,
    loader,
    exportedSymbols: exportedSymbolsAfter,
    decoyFunctionsInjected:
      tarpit.decoyFunctionNames.length +
      exhaustionSuite.totalLabyrinthNodes +
      deceptionSuite.shadowLogic.shadowProceduresCreated.length +
      deceptionSuite.semanticHoneypot.baitSymbols.length +
      2,
    fakeCrossReferencesCreated:
      fakeCrossReferencesCreated + exhaustionSuite.totalCrossReferenceEdges,
    primitiveCandidateBranchesCreated,
    aliasSelectionStatesCreated: 4_194_304, // 2^22 selector states in aliasFn
    ipcAmbiguitySitesInjected:
      ipcAmbiguitySitesInjected + exhaustionSuite.totalDecoyObligations,
    decoyRoutesInjected:
      selectedDecoyRoutes.length +
      deceptionSuite.architectureMirage.decoyRpcMethods.length,
    chaffPayloadsEmbedded:
      chaffPayloads.length + deceptionSuite.evidencePoison.lures.length,
    shadowHeapSlotsChurned: memoryDiffShield.mutableSlotsCount,
    electronProtocolsProtected,
    memoryDiffShield,
    ...(selfSealEnabled ? { selfSealEnabled: true as const, selfSealBindingName: selfSealBindingName! } : {}),
  };
}
