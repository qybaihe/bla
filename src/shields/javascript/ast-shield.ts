import { createHash } from "node:crypto";
import { isBuiltin } from "node:module";
import { parse, type ParserPlugin } from "@babel/parser";
import _traverse, { type Binding, type NodePath, type Scope } from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";
import { generateProjectSeed } from "../../core/config.js";
import { SeededPrng, deriveSeedLabel } from "../../core/prng.js";
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
  ESM_PREHOIST_CAPTURE_DATA_URL,
  generateSelfSealSnippet,
  type SelfSealOptions,
} from "../runtime/self-seal.js";
import { generateCounterReaExhaustionSuite } from "../exhaustion/index.js";
import { generateCounterReaDeceptionSuite } from "../deception/index.js";
import { isShippedSecretLiteral, regexPatternSecretRuns } from "../../engine/plaintext-secret-lint.js";

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

/**
 * True when `node` is the non-computed key of its parent — of an object or
 * class member of any kind (property, method, accessor, field) or a type
 * member. Such a key is syntax, not an expression: `{ 200() {} }`,
 * `class { static 32 = 1 }`, `get 404() {}`.
 */
function isNonComputedMemberKey(parent: t.Node, node: t.Node): boolean {
  const member = parent as { key?: t.Node; computed?: boolean };
  return member.key === node && member.computed !== true;
}

/**
 * True when a string in this position has to stay a literal for the module
 * graph to stay analysable: ES2022 string export / import names
 * (`export { impl as "module.exports" }`) are syntax, and the specifier of
 * `import("./chunk.mjs")` is what a bundler follows to include the chunk —
 * the same reason `require("…")` arguments are left alone. The other spellings
 * of "this file, relative to me" are read the same way by bundlers, packagers
 * and deploy-time file tracers: `require.resolve("./x")`,
 * `import.meta.resolve("./x")` and `new URL("./x", import.meta.url)`.
 */
function isStaticModuleStringPosition(parent: t.Node, node: t.Node): boolean {
  if (
    t.isExportSpecifier(parent) ||
    t.isImportSpecifier(parent) ||
    t.isExportNamespaceSpecifier(parent) ||
    t.isExportDefaultSpecifier(parent)
  ) {
    return true;
  }
  if (t.isImportExpression(parent)) return parent.source === node;
  if (t.isNewExpression(parent)) {
    return (
      t.isIdentifier(parent.callee, { name: "URL" }) &&
      parent.arguments[0] === node &&
      isImportMetaMember(parent.arguments[1], "url")
    );
  }
  if (!(t.isCallExpression(parent) || t.isOptionalCallExpression(parent))) return false;
  if (parent.arguments[0] !== node) return false;
  const callee = parent.callee;
  if (t.isImport(callee)) return true;
  if (isImportMetaMember(callee, "resolve")) return true;
  return (
    (t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee)) &&
    !callee.computed &&
    t.isIdentifier(callee.object, { name: "require" }) &&
    t.isIdentifier(callee.property, { name: "resolve" })
  );
}

/**
 * What Node reads from a CommonJS file, without running it, to decide which
 * names an ES module may import from it (`import { x } from "./lib.cjs"`).
 * Its scanner (`cjs-module-lexer`) recognises a fixed set of shapes in the
 * file's text — the ones TypeScript, Babel and esbuild emit. A shape the shield
 * rewrites is an export the importer no longer has: a `SyntaxError` at link
 * time, before a line of the program runs. The rest of the file is hardened as
 * usual; of these, only the part the scanner matches is left as written:
 *
 *   Object.defineProperty(exports, "x", { enumerable: true, get: function () { return m.x; } });
 *   Object.defineProperty(exports, "__esModule", { value: true });    // the name
 *   exports["x"] = …;                                                  // the name
 *   __exportStar(require("./m"), exports);   __export(require("./m")); // the helper's name
 *   var _m = _interopRequireWildcard(require("./m"));                  // the helper's name
 *   Object.keys(_m).forEach(function (key) { … exports[key] = _m[key]; … });
 *   module.exports = { a, b: c, label: "…" };                          // see `literalMembers`
 */
interface CjsExportSurface {
  /** Subtrees no pass enters: a re-export getter, Babel's export-star loop. */
  readonly glue: WeakSet<t.Node>;
  /** String literals that are an export's name. */
  readonly nameLiterals: t.StringLiteral[];
  /** Helper bindings the scanner knows by name. */
  readonly helperBindings: t.Identifier[];
  /**
   * Members of a `module.exports = { … }` literal, with whether the value
   * began with an identifier in the source. The scanner counts a member as an
   * export exactly when it does, and stops at the first value that is more
   * than a bare identifier.
   */
  readonly literalMembers: Map<t.ObjectProperty, boolean>;
}

const CJS_STAR_EXPORT_HELPERS: ReadonlySet<string> = new Set([
  "__exportStar",
  "__export",
  "_interopRequireWildcard",
]);
const IDENTIFIER_START_RE = /[\p{ID_Start}$_\\]/u;
/** Babel's loop has at most four statements; anything longer is the program's own code. */
const BABEL_EXPORT_STAR_LOOP_MAX_STATEMENTS = 6;

function isObjectStaticCall(callee: t.Node | null | undefined, method: string): boolean {
  return (
    t.isMemberExpression(callee) &&
    !callee.computed &&
    t.isIdentifier(callee.object, { name: "Object" }) &&
    t.isIdentifier(callee.property, { name: method })
  );
}

function isRequireOfLiteral(node: t.Node | null | undefined): boolean {
  return (
    t.isCallExpression(node) &&
    t.isIdentifier(node.callee, { name: "require" }) &&
    node.arguments.length === 1 &&
    t.isStringLiteral(node.arguments[0])
  );
}

/**
 * `exports` or `module.exports`, by name. The scanner reads text and knows
 * nothing of scopes, so the `exports` parameter of a UMD factory or of a
 * bundled module counts for it exactly like the free variable of a file.
 */
function isCommonJsExportsObject(node: t.Node | null | undefined): boolean {
  if (t.isIdentifier(node, { name: "exports" })) return true;
  return (
    t.isMemberExpression(node) &&
    !node.computed &&
    t.isIdentifier(node.object, { name: "module" }) &&
    t.isIdentifier(node.property, { name: "exports" })
  );
}

/**
 * The getter of a re-export — `get: function () { return m.x; }` or
 * `get() { return m["x"]; }`, last in its descriptor — and nothing with more
 * in it than that one `return`: a getter that computes something is the
 * program's code and is hardened like the rest.
 */
function reexportGetterOf(descriptor: t.ObjectExpression): t.Node | null {
  const last = descriptor.properties[descriptor.properties.length - 1];
  let getter: t.FunctionExpression | t.ObjectMethod | null = null;
  if (
    t.isObjectProperty(last) &&
    !last.computed &&
    t.isIdentifier(last.key, { name: "get" }) &&
    t.isFunctionExpression(last.value)
  ) {
    getter = last.value;
  } else if (
    t.isObjectMethod(last) &&
    last.kind === "method" &&
    !last.computed &&
    t.isIdentifier(last.key, { name: "get" })
  ) {
    getter = last;
  }
  if (getter === null || getter.params.length > 0 || getter.async || getter.generator) {
    return null;
  }
  const statements = getter.body.body;
  const only = statements[0];
  if (statements.length !== 1 || !t.isReturnStatement(only)) return null;
  const value = only.argument;
  if (t.isIdentifier(value)) return getter;
  if (
    t.isMemberExpression(value) &&
    t.isIdentifier(value.object) &&
    (value.computed ? t.isStringLiteral(value.property) : t.isIdentifier(value.property))
  ) {
    return getter;
  }
  return null;
}

/** `Object.keys(_m).forEach(function (key) { … })` that copies `_m[key]` onto `exports`. */
function isBabelExportStarLoop(node: t.CallExpression): boolean {
  const callee = node.callee;
  if (
    !t.isMemberExpression(callee) ||
    callee.computed ||
    !t.isIdentifier(callee.property, { name: "forEach" })
  ) {
    return false;
  }
  const keysCall = callee.object;
  if (
    !t.isCallExpression(keysCall) ||
    !isObjectStaticCall(keysCall.callee, "keys") ||
    keysCall.arguments.length !== 1 ||
    !t.isIdentifier(keysCall.arguments[0])
  ) {
    return false;
  }
  const callback = node.arguments[0];
  if (
    node.arguments.length !== 1 ||
    !t.isFunctionExpression(callback) ||
    callback.params.length !== 1
  ) {
    return false;
  }
  const param = callback.params[0];
  if (
    !t.isIdentifier(param) ||
    callback.body.body.length > BABEL_EXPORT_STAR_LOOP_MAX_STATEMENTS
  ) {
    return false;
  }
  let copiesOntoExports = false;
  t.traverseFast(callback.body, (inner) => {
    if (
      t.isMemberExpression(inner) &&
      inner.computed &&
      t.isIdentifier(inner.property, { name: param.name }) &&
      isCommonJsExportsObject(inner.object)
    ) {
      copiesOntoExports = true;
    }
    if (
      t.isCallExpression(inner) &&
      isObjectStaticCall(inner.callee, "defineProperty") &&
      isCommonJsExportsObject(inner.arguments[0]) &&
      t.isIdentifier(inner.arguments[1], { name: param.name })
    ) {
      copiesOntoExports = true;
    }
  });
  return copiesOntoExports;
}

function collectCjsExportSurface(ast: t.File, source: string): CjsExportSurface {
  const glue = new WeakSet<t.Node>();
  const nameLiterals: t.StringLiteral[] = [];
  const helperBindings: t.Identifier[] = [];
  const literalMembers = new Map<t.ObjectProperty, boolean>();
  traverse(ast, {
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if (isObjectStaticCall(callee, "defineProperty")) {
        const [target, name, descriptor] = args;
        if (
          args.length === 3 &&
          isCommonJsExportsObject(target) &&
          t.isStringLiteral(name) &&
          t.isObjectExpression(descriptor)
        ) {
          nameLiterals.push(name);
          const getter = reexportGetterOf(descriptor);
          if (getter !== null) glue.add(getter);
        }
        return;
      }
      if (
        t.isIdentifier(callee) &&
        CJS_STAR_EXPORT_HELPERS.has(callee.name) &&
        isRequireOfLiteral(args[0])
      ) {
        const binding = path.scope.getBinding(callee.name);
        if (binding !== undefined) helperBindings.push(binding.identifier);
        return;
      }
      if (isBabelExportStarLoop(path.node)) {
        glue.add(path.node);
        path.skip();
      }
    },
    AssignmentExpression(path) {
      const { left, right, operator } = path.node;
      if (operator !== "=" || !t.isMemberExpression(left)) return;
      if (
        left.computed &&
        t.isStringLiteral(left.property) &&
        isCommonJsExportsObject(left.object)
      ) {
        nameLiterals.push(left.property);
        return;
      }
      if (!t.isObjectExpression(right) || !isCommonJsExportsObject(left)) return;
      for (const member of right.properties) {
        if (!t.isObjectProperty(member) || member.computed) continue;
        const value = member.value;
        const extra = value.extra as { parenthesized?: boolean; parenStart?: number } | undefined;
        const start = extra?.parenthesized === true ? extra.parenStart : value.start;
        if (typeof start !== "number") continue;
        const first = source.codePointAt(start);
        literalMembers.set(
          member,
          first !== undefined && IDENTIFIER_START_RE.test(String.fromCodePoint(first)),
        );
      }
    },
  });
  return { glue, nameLiterals, helperBindings, literalMembers };
}

/** `import.meta.<name>`, written without a computed key. */
function isImportMetaMember(node: t.Node | null | undefined, name: string): boolean {
  return (
    t.isMemberExpression(node) &&
    !node.computed &&
    t.isMetaProperty(node.object) &&
    node.object.meta.name === "import" &&
    node.object.property.name === "meta" &&
    t.isIdentifier(node.property, { name })
  );
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
 * A top-level `return` is legal only inside the CommonJS module wrapper. The
 * parser accepts it wherever the carrier can still be CommonJS: an explicit
 * request (`.cjs`, `sourceType: "commonjs"`) or a `.js` file whose kind is
 * decided from its content. Explicit `module` / `script` carriers keep
 * rejecting it, exactly like their runtimes do.
 */
function carrierAllowsTopLevelReturn(requested: JsCarrierType): boolean {
  return requested === "commonjs" || requested === "auto";
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
      allowReturnOutsideFunction: carrierAllowsTopLevelReturn(requested),
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

/**
 * True when an ES module has static `import` / `export-from` bindings that the
 * ESM loader will instantiate *before* any statement in the file — including a
 * prepended sidecarEntangle / self-seal IIFE. The BLA preamble's own
 * `import { createRequire } from "node:module"` and other Node builtin
 * static imports (`node:fs`, `node:path`, …) are ignored (they have no
 * user-module side effects). CommonJS `require()` after a preamble is
 * *not* hoisted. User-module `import` / `export-from` still count.
 *
 * Honesty: entry-body fail-closed is not process-start for the hoisted graph.
 */
export function jsModuleHasHoistedDependencyGraph(
  source: string,
  filename?: string,
): boolean {
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
      allowReturnOutsideFunction: carrierAllowsTopLevelReturn(requested),
    });
    if (ast.program.sourceType !== "module") return false;
    return ast.program.body.some((stmt) => isHoistedUserModuleEdge(stmt));
  } catch {
    return false;
  }
}

function isPreambleCreateRequireImport(stmt: t.Node): boolean {
  if (!t.isImportDeclaration(stmt)) return false;
  if (stmt.source.value !== "node:module") return false;
  if (stmt.specifiers.length === 0) return false;
  return stmt.specifiers.every(
    (spec) =>
      t.isImportSpecifier(spec) &&
      t.isIdentifier(spec.imported) &&
      spec.imported.name === "createRequire",
  );
}

function isNodeBuiltinModuleSpecifier(specifier: string): boolean {
  if (typeof specifier !== "string" || specifier.length === 0) return false;
  try {
    return isBuiltin(specifier);
  } catch {
    return false;
  }
}

function isHoistedUserModuleEdge(stmt: t.Node): boolean {
  if (isPreambleCreateRequireImport(stmt)) return false;
  // Node builtin instantiation has no user-module side effects; hoisting
  // `import fs from "node:fs"` (or the WASM loader's createRequire preamble)
  // is not the process-start gap this detector describes.
  if (t.isImportDeclaration(stmt) && stmt.source) {
    return !isNodeBuiltinModuleSpecifier(stmt.source.value);
  }
  if (t.isExportAllDeclaration(stmt) && stmt.source) {
    return !isNodeBuiltinModuleSpecifier(stmt.source.value);
  }
  if (t.isExportNamedDeclaration(stmt) && stmt.source) {
    return !isNodeBuiltinModuleSpecifier(stmt.source.value);
  }
  return false;
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
 * Where an injected predicate reads the opaque seed from.
 *
 * A string names a binding that is certainly initialised wherever the predicate
 * runs: the module-level seed for top-level code, a function's own frame seed
 * inside its body. A factory builds a self-guarding read for the positions that
 * have neither (parameter defaults, class field initialisers, …), so a
 * function whose source text is re-evaluated elsewhere — or that runs before
 * its module body, through an import cycle — never touches a missing binding.
 */
type SeedSource = string | (() => t.Expression);

function seedRead(seed: SeedSource): t.Expression {
  return typeof seed === "string" ? t.identifier(seed) : seed();
}

/**
 * Longest piece of a finely split secret. The plaintext lint needs 16
 * characters to call a string a generated token and 24 for a digest or an
 * encoded blob, so a piece this short is never a finding on its own.
 */
const FINE_CHUNK_MAX_LENGTH = 12;
/**
 * The same bound for a masked piece, counted in the letters it is written
 * with (two per character, four once the string holds a character above
 * U+00FF).
 */
const FINE_MASKED_PIECE_MAX_LETTERS = 24;
/** A masked unit is spelled in sixteen letters, `a` for 0 to `p` for 15. */
const MASK_LETTER_BASE = 97;
/** Shortest string whose pieces are masked; below it a string is split in clear. */
const MASK_MIN_LENGTH = 4;
/**
 * A short plain word — `"function"`, `"string"`, `"click"`, `"POST"` — is what
 * hot code compares and looks up on every pass, and says nothing once read.
 * Up to this length such a word keeps clear pieces and skips the decode.
 */
const MASK_PLAIN_WORD_MAX_LENGTH = 10;
const PLAIN_WORD_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * Decoders the string pass builds — `(function (s, m, c) { … })(pieces, m, c)`.
 * The rename pass leaves their six local names alone.
 */
const MASK_DECODER_FUNCTIONS = new WeakSet<t.Node>();

function wantsMask(value: string): boolean {
  if (value.length < MASK_MIN_LENGTH) return false;
  return value.length > MASK_PLAIN_WORD_MAX_LENGTH || !PLAIN_WORD_RE.test(value);
}

/** Letters per UTF-16 unit: two while every unit fits a byte, otherwise four. */
function maskWidthOf(value: string): 2 | 4 {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0xff) return 4;
  }
  return 2;
}

/**
 * `text` as it is written in the file: each UTF-16 unit XORed with a byte that
 * depends on where the unit sits in the whole string, four bits to a letter
 * (`a`–`p`). `unitOffset` is the index of the piece's first unit, so real and
 * wrong pieces of one position share their key bytes. Letters rather than hex
 * digits: the decoder turns them back with arithmetic alone, and a run of
 * them does not read as a digest.
 */
function maskPiece(text: string, unitOffset: number, width: 2 | 4, m: number, c: number): string {
  let out = "";
  for (let j = 0; j < text.length; j++) {
    const position = (unitOffset + j) * width;
    const masked = text.charCodeAt(j) ^ ((position * m + c) & 255);
    for (let shift = (width - 1) * 4; shift >= 0; shift -= 4) {
      out += String.fromCharCode(MASK_LETTER_BASE + ((masked >> shift) & 15));
    }
  }
  return out;
}

/**
 * The inverse of {@link maskPiece}, applied to the concatenated pieces where
 * the string is used:
 *
 *   (function (s, m, c) {
 *     var r = "", f = r.constructor.fromCharCode, i = 0;
 *     for (; i < s.length; i += 2)
 *       r += f((s.charCodeAt(i) - 97 << 4 | s.charCodeAt(i + 1) - 97) ^ (i * m + c & 255));
 *     return r;
 *   })(pieces, m, c)
 *
 * It is written out at every use and reads nothing but its arguments — no
 * helper to hoist, no global whose name the program may have taken (`String`
 * is reached through a string's own `constructor`). So it works wherever an
 * expression does: a classic script, a function rebuilt from its source text,
 * a parameter default, a field initialiser.
 *
 * The parentheses are part of the node, not left to the printer: `{ kind:
 * function (s, m, c) {…}(…) }` is the same expression, but a tool that reads
 * text — Node's CommonJS export scanner is one — takes a value that starts
 * with a word for a name, and the literal this replaces started with a quote.
 */
function buildMaskDecodeCall(
  pieces: t.Expression,
  width: 2 | 4,
  m: number,
  c: number,
  seedCoupling?: { readonly seedExpr: t.Expression; readonly expectedLowByte: number },
): t.Expression {
  const id = (name: string): t.Identifier => t.identifier(name);
  // Letter `n` of the current unit as its four bits: s.charCodeAt(i + n) - 97
  const nibble = (n: number): t.Expression =>
    t.binaryExpression(
      "-",
      t.callExpression(t.memberExpression(id("s"), id("charCodeAt")), [
        n === 0 ? id("i") : t.binaryExpression("+", id("i"), t.numericLiteral(n)),
      ]),
      t.numericLiteral(MASK_LETTER_BASE),
    );
  let unit: t.Expression = nibble(width - 1);
  for (let n = width - 2; n >= 0; n--) {
    unit = t.binaryExpression(
      "|",
      t.binaryExpression("<<", nibble(n), t.numericLiteral((width - 1 - n) * 4)),
      unit,
    );
  }
  const key = t.binaryExpression(
    "&",
    t.binaryExpression(
      "+",
      t.binaryExpression("*", id("i"), id("m")),
      seedCoupling ? id("k") : id("c"),
    ),
    t.numericLiteral(255),
  );
  const varDecls: t.VariableDeclarator[] = [
    t.variableDeclarator(id("r"), t.stringLiteral("")),
    t.variableDeclarator(
      id("f"),
      t.memberExpression(t.memberExpression(id("r"), id("constructor")), id("fromCharCode")),
    ),
    t.variableDeclarator(id("i"), t.numericLiteral(0)),
  ];
  if (seedCoupling) {
    // Mix the runtime seed's low 8 bits directly inside the decoder body so
    // `args` remains `[pieces, NumericLiteral(m), NumericLiteral(c ^ expectedLowByte)]`
    // while `const seed = 1` or tampered self-seal/cognitive-armor corrupts every
    // masked string in the module.
    varDecls.push(
      t.variableDeclarator(
        id("k"),
        t.binaryExpression(
          "&",
          t.binaryExpression(
            "^",
            id("c"),
            t.binaryExpression("&", seedCoupling.seedExpr, t.numericLiteral(255)),
          ),
          t.numericLiteral(255),
        ),
      ),
    );
  }
  const decoder = t.functionExpression(
    null,
    [id("s"), id("m"), id("c")],
    t.blockStatement([
      t.variableDeclaration("var", varDecls),
      t.forStatement(
        null,
        t.binaryExpression("<", id("i"), t.memberExpression(id("s"), id("length"))),
        t.assignmentExpression("+=", id("i"), t.numericLiteral(width)),
        t.expressionStatement(
          t.assignmentExpression(
            "+=",
            id("r"),
            t.callExpression(id("f"), [t.binaryExpression("^", unit, key)]),
          ),
        ),
      ),
      t.returnStatement(id("r")),
    ]),
  );
  MASK_DECODER_FUNCTIONS.add(decoder);
  const encodedC = seedCoupling ? (c ^ seedCoupling.expectedLowByte) & 255 : c;
  return t.callExpression(t.parenthesizedExpression(decoder), [
    pieces,
    t.numericLiteral(m),
    t.numericLiteral(encodedC),
  ]);
}
/**
 * Longest secret-looking value the literal pass will still split when it sits
 * outside the ordinary 3–256 character range (a PEM block, a JWT, a
 * service-account document). A split value costs about 20 bytes of output per
 * character — two masked letters for the piece, two for the wrong piece beside
 * it, and a condition every 12 characters — so this is also a bound on how
 * much one literal can add to the file (measured: 83 KB).
 */
const SECRET_LITERAL_MAX_LENGTH = 4096;

/** A value the plaintext lint reports as a shipped secret, short enough to split. */
function isSplittableSecret(value: string): boolean {
  return (
    value.length >= 8 &&
    value.length <= SECRET_LITERAL_MAX_LENGTH &&
    isShippedSecretLiteral(value)
  );
}

/**
 * Nine pieces already keep every piece under the fine length for a short
 * value, so only a longer one needs classifying before it is split.
 */
function wantsFineSplit(value: string): boolean {
  const finePieceLength = Math.floor(FINE_MASKED_PIECE_MAX_LETTERS / maskWidthOf(value));
  return value.length > finePieceLength * 9 && isSplittableSecret(value);
}

const HEX_DIGITS_LOWER = "0123456789abcdef";
const HEX_DIGITS_UPPER = "0123456789ABCDEF";

/**
 * The wrong arm for one piece of a split string: the same length and the same
 * kind of text as the real piece, so the two arms cannot be told apart by
 * looking at them. Punctuation stays where it is; a digit becomes a digit and
 * a letter a letter of the same case — and a piece whose letters are all hex
 * digits becomes other hex digits, since `"7ff703d"` beside `"6kd246v"` would
 * give the real one away. A piece with nothing to vary gets plain noise
 * instead of a copy of itself.
 */
function buildDecoyChunk(real: string, prng: SeededPrng): string {
  if (real.length === 0) return prng.hex(2);
  const letters = real.replace(/[^A-Za-z]/g, "");
  const hexAlphabet =
    letters.length === 0
      ? null
      : /^[a-f]+$/.test(letters)
        ? HEX_DIGITS_LOWER
        : /^[A-F]+$/.test(letters)
          ? HEX_DIGITS_UPPER
          : null;
  let decoy = "";
  for (let i = 0; i < real.length; i++) {
    const code = real.charCodeAt(i);
    const digit = code >= 0x30 && code <= 0x39;
    const upper = code >= 0x41 && code <= 0x5a;
    const lower = code >= 0x61 && code <= 0x7a;
    if (!digit && !upper && !lower) decoy += real[i];
    else if (hexAlphabet !== null) decoy += hexAlphabet[prng.nextInt(0, 15)];
    else if (digit) decoy += String.fromCharCode(0x30 + prng.nextInt(0, 9));
    else decoy += String.fromCharCode((upper ? 0x41 : 0x61) + prng.nextInt(0, 25));
  }
  return decoy !== real ? decoy : prng.hex(Math.max(2, real.length));
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
  seedIdentifierName: SeedSource,
  options: { readonly fine?: boolean; readonly mask?: boolean; readonly seedLowByte?: number } = {},
): t.Expression {
  const minChunks = 9;
  const chunks: string[] = [];
  // Pieces are written masked and decoded where the string is used: nothing
  // of the text is readable in the file, and an evaluator that lists every
  // combination of pieces still holds no value. Very short strings stay in
  // clear pieces.
  const mask = options.mask ?? wantsMask(value);
  const width = maskWidthOf(value);
  const keyM = mask ? prng.nextInt(0, 127) * 2 + 1 : 0;
  const keyC = mask ? prng.nextInt(0, 255) : 0;

  if (value.length >= minChunks) {
    // Nine pieces by default. A secret is cut finer, so that no piece left in
    // the file is long enough to be recognised (or reported) as one itself.
    const finePieceLength = mask
      ? Math.floor(FINE_MASKED_PIECE_MAX_LETTERS / width)
      : FINE_CHUNK_MAX_LENGTH;
    const count = options.fine
      ? Math.max(minChunks, Math.ceil(value.length / finePieceLength))
      : minChunks;
    for (let i = 0; i < count; i++) {
      chunks.push(
        value.slice(
          Math.floor((i * value.length) / count),
          Math.floor(((i + 1) * value.length) / count),
        ),
      );
    }
  } else {
    for (const ch of value) {
      chunks.push(ch);
    }
    while (chunks.length < minChunks) {
      chunks.push("");
    }
  }

  let unitOffset = 0;
  const terms: t.Expression[] = chunks.map((realPiece, idx) => {
    const decoyPiece = buildDecoyChunk(realPiece, prng);
    const realChunk = mask ? maskPiece(realPiece, unitOffset, width, keyM, keyC) : realPiece;
    const decoyChunk = mask ? maskPiece(decoyPiece, unitOffset, width, keyM, keyC) : decoyPiece;
    unitOffset += realPiece.length;
    const mode = idx % 3;
    let cond: t.Expression;
    let invertedCond: t.Expression;

    if (mode === 1) {
      // Cognitive-Armor odd-bit entanglement: ((Math.imul(seed ^ 4*k, seed ^ 4*k) & 7) === 1)
      const k = prng.nextInt(1, 31) * 4;
      const seededXor = t.binaryExpression(
        "^",
        seedRead(seedIdentifierName),
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
      // Keep bit 0 of k clear so `odd_seed ^ even_k` is always odd (>= 1, never 0)
      // across all parameter-entangled local seeds.
      const k = (prng.nextUint32() & 0xfffffffe) >>> 0;
      const u = t.binaryExpression(
        ">>>",
        t.binaryExpression("^", seedRead(seedIdentifierName), t.numericLiteral(k)),
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
        seedRead(seedIdentifierName),
        t.numericLiteral(k),
        prng,
      );
      const plainExpr = t.binaryExpression(
        "|",
        t.binaryExpression("+", seedRead(seedIdentifierName), t.numericLiteral(k)),
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

  // Joined as a balanced tree: a finely split secret has hundreds of pieces,
  // and a left-leaning chain that deep is a recursion hazard for every later
  // walk over the tree. (Every operand is a string, so grouping is free.)
  const join = (from: number, to: number): t.Expression => {
    if (to - from === 1) return terms[from]!;
    const middle = from + Math.ceil((to - from) / 2);
    return t.binaryExpression("+", join(from, middle), join(middle, to));
  };
  const pieces = join(0, terms.length);
  return mask
    ? buildMaskDecodeCall(
        pieces,
        width,
        keyM,
        keyC,
        options.seedLowByte !== undefined
          ? { seedExpr: seedRead(seedIdentifierName), expectedLowByte: options.seedLowByte }
          : undefined,
      )
    : pieces;
}

function buildOpaqueFalseAst(
  prng: SeededPrng,
  seedIdentifierName: SeedSource,
): t.Expression {
  const k4 = prng.nextInt(1, 31) * 4;
  const seededXor = t.binaryExpression(
    "^",
    seedRead(seedIdentifierName),
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
  seedIdentifierName: SeedSource,
): t.Expression {
  const k4 = prng.nextInt(1, 31) * 4;
  const seededXor = t.binaryExpression(
    "^",
    seedRead(seedIdentifierName),
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
  seedIdentifierName: SeedSource,
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

/**
 * How a renamed binding gets its observable `.name` back.
 *
 * A function / class name is program-visible state: `fn.name`,
 * `instance.constructor.name`, `String(error)`, an ORM table name, a registry
 * keyed on handler names. Code that reads it usually lives in another module,
 * so no in-file analysis can prove it is unobserved. Every rename of such a
 * binding is therefore paired with one of these restorations.
 */
type NameRestorePlan =
  /** `class Foo {}` — define the name right after the declaration. */
  | { readonly kind: "class-declaration"; readonly path: NodePath<t.ClassDeclaration> }
  /** `function foo() {}` — hoisted, so define the name at the top of its block. */
  | { readonly kind: "function-declaration"; readonly path: NodePath<t.FunctionDeclaration> }
  /**
   * `const foo = () => {}` / `foo = class {}` — the name was inferred from the
   * binding; wrap each anonymous function / class the binding is given.
   */
  | {
      readonly kind: "inferred-name";
      readonly sites: readonly NodePath<t.VariableDeclarator | t.AssignmentExpression>[];
    }
  /** `x = function foo() {}` / `class Foo {}` expression — wrap the expression. */
  | {
      readonly kind: "self-named-expression";
      readonly path: NodePath<t.FunctionExpression | t.ClassExpression>;
    };

/** `pin`: leave the binding un-renamed. `none`: renaming cannot change `.name`. */
type NameRestoreDecision = NameRestorePlan | "pin" | "none";

/**
 * `restore`: safe to rename and re-define `name` after the class is created.
 * `pin`: code that runs *while* the class is being defined (decorators, static
 * blocks, static field initializers) can read the name before any restoration
 * — TypeORM `@Entity()`, `static tag = this.name`. `none`: the class declares
 * its own static `name`, so the binding name never surfaces.
 */
function classNameHandling(node: t.Class): "restore" | "pin" | "none" {
  let observedDuringDefinition = (node.decorators?.length ?? 0) > 0;
  for (const member of node.body.body) {
    if (t.isStaticBlock(member)) {
      observedDuringDefinition = true;
      continue;
    }
    if (t.isTSIndexSignature(member)) continue;
    if (((member as { decorators?: unknown[] | null }).decorators?.length ?? 0) > 0) {
      observedDuringDefinition = true;
    }
    if (
      (t.isClassMethod(member) || t.isClassPrivateMethod(member)) &&
      member.params.some(
        (param) => ((param as { decorators?: unknown[] | null }).decorators?.length ?? 0) > 0,
      )
    ) {
      observedDuringDefinition = true;
    }
    if (member.static !== true) continue;
    const key = member.key;
    const keyName =
      t.isIdentifier(key) && !("computed" in member && member.computed === true)
        ? key.name
        : t.isStringLiteral(key)
          ? key.value
          : undefined;
    if (keyName === "name") return "none";
    if (
      (t.isClassProperty(member) ||
        t.isClassPrivateProperty(member) ||
        t.isClassAccessorProperty(member)) &&
      member.value != null
    ) {
      observedDuringDefinition = true;
    }
  }
  return observedDuringDefinition ? "pin" : "restore";
}

/** `x as T`, `x!`, `<T>x`, `x satisfies T` all erase to `x` and keep name inference. */
function unwrapTsExpression(node: t.Node | null | undefined): t.Node | null | undefined {
  let current = node;
  while (
    current != null &&
    (t.isTSAsExpression(current) ||
      t.isTSSatisfiesExpression(current) ||
      t.isTSNonNullExpression(current) ||
      t.isTSTypeAssertion(current) ||
      t.isParenthesizedExpression(current))
  ) {
    current = current.expression;
  }
  return current;
}

function isAnonymousFunctionValue(node: t.Node | null | undefined): boolean {
  const inner = unwrapTsExpression(node);
  return (
    t.isArrowFunctionExpression(inner) ||
    (t.isFunctionExpression(inner) && inner.id == null)
  );
}

function isAnonymousClassValue(node: t.Node | null | undefined): node is t.Node {
  const inner = unwrapTsExpression(node);
  return t.isClassExpression(inner) && inner.id == null;
}

/**
 * Decide how to keep `.name` stable if `binding` is renamed.
 *
 * `escapes` is true when the bound value is used as anything other than a
 * plain call target — exported, passed, stored, `new`-ed (instances expose
 * `constructor.name`). A function that is only ever called in this file has no
 * observable name and needs nothing. Classes always count as escaping: their
 * instances do.
 */
function decideNameRestore(binding: Binding, escapes: boolean): NameRestoreDecision {
  const bindingPath = binding.path;
  // The restoration calls the intrinsic `Object.defineProperty`.
  const objectIsShadowed = (): boolean =>
    bindingPath.scope.getBinding("Object") !== undefined;

  if (bindingPath.isClassDeclaration()) {
    if (bindingPath.node.declare === true) return "none";
    const handling = classNameHandling(bindingPath.node);
    if (handling !== "restore") return handling;
    const statementPath = bindingPath.parentPath.isExportDeclaration()
      ? bindingPath.parentPath
      : bindingPath;
    if (!Array.isArray(statementPath.container) || objectIsShadowed()) return "pin";
    return { kind: "class-declaration", path: bindingPath };
  }

  let functionDeclarationPath: NodePath<t.FunctionDeclaration> | undefined;
  if (bindingPath.isFunctionDeclaration()) {
    functionDeclarationPath = bindingPath;
  } else if (bindingPath.isTSDeclareFunction()) {
    // TypeScript overload signatures: the binding points at the first
    // signature; the implementation is a later sibling with the same name.
    const implementation = bindingPath
      .getAllNextSiblings()
      .find(
        (sibling) =>
          sibling.isFunctionDeclaration() &&
          sibling.node.id?.name === binding.identifier.name,
      );
    if (implementation?.isFunctionDeclaration()) functionDeclarationPath = implementation;
  }
  if (functionDeclarationPath !== undefined) {
    if (functionDeclarationPath.node.declare === true) return "none";
    const exportedByDefault = functionDeclarationPath.parentPath.isExportDefaultDeclaration();
    if (!escapes && !exportedByDefault) return "none";
    const statementPath = functionDeclarationPath.parentPath.isExportDeclaration()
      ? functionDeclarationPath.parentPath
      : functionDeclarationPath;
    // The definition must run before anything else in the block that hoists the
    // function. A `switch` case or a brace-less `if` body gives no such place.
    const container = statementPath.parentPath;
    const hoistable =
      Array.isArray(statementPath.container) &&
      container !== null &&
      (container.isProgram() || container.isBlockStatement());
    if (!hoistable || objectIsShadowed()) return "pin";
    return { kind: "function-declaration", path: functionDeclarationPath };
  }

  if (bindingPath.isVariableDeclarator() && t.isIdentifier(bindingPath.node.id)) {
    const declaration = bindingPath.parentPath;
    if (declaration.isVariableDeclaration() && declaration.node.declare === true) {
      return "none";
    }
    const sites: NodePath<t.VariableDeclarator | t.AssignmentExpression>[] = [];
    const state: { classHandling: "restore" | "pin" | "none" } = { classHandling: "none" };
    const consider = (
      site: NodePath<t.VariableDeclarator | t.AssignmentExpression>,
      value: t.Node | null | undefined,
    ): void => {
      if (isAnonymousClassValue(value)) {
        const handling = classNameHandling(unwrapTsExpression(value) as t.ClassExpression);
        if (handling === "pin") state.classHandling = "pin";
        else if (handling === "restore") {
          if (state.classHandling !== "pin") state.classHandling = "restore";
          sites.push(site);
        }
      } else if (isAnonymousFunctionValue(value) && escapes) {
        sites.push(site);
      }
    };
    consider(bindingPath, bindingPath.node.init);
    for (const violation of binding.constantViolations) {
      // `foo = () => {}` and `foo ||= class {}` infer the name exactly like a
      // declarator does; compound arithmetic assignments never produce one.
      if (
        violation.isAssignmentExpression() &&
        t.isIdentifier(violation.node.left) &&
        ["=", "||=", "&&=", "??="].includes(violation.node.operator)
      ) {
        consider(violation, violation.node.right);
      }
    }
    if (state.classHandling === "pin") return "pin";
    if (sites.length === 0) return "none";
    if (objectIsShadowed()) return "pin";
    return { kind: "inferred-name", sites };
  }

  if (binding.kind === "local") {
    if (bindingPath.isClassExpression()) {
      const handling = classNameHandling(bindingPath.node);
      if (handling !== "restore") return handling;
      if (objectIsShadowed()) return "pin";
      return { kind: "self-named-expression", path: bindingPath };
    }
    if (bindingPath.isFunctionExpression()) {
      const parent = bindingPath.parent;
      const invokedInPlace =
        (t.isCallExpression(parent) || t.isOptionalCallExpression(parent)) &&
        parent.callee === bindingPath.node;
      // `(function main() { … })()` whose only self-references are recursive
      // calls: nobody can hold the function object, so its name is unobservable.
      if (invokedInPlace && !escapes) return "none";
      if (objectIsShadowed()) return "pin";
      return { kind: "self-named-expression", path: bindingPath };
    }
  }
  return "none";
}

/**
 * Third-party licence notices must stay in every copy of the code (MIT, BSD,
 * Apache-2.0 all require it) and hold no proprietary logic. A comment is one
 * when it is a `/*! … *\/` block — the convention bundlers and minifiers use for
 * "preserve this" — or when its text carries a licence / copyright marker.
 */
const LEGAL_NOTICE_COMMENT_RE =
  /@license\b|@preserve\b|@copyright\b|SPDX-License-Identifier|\bCopyright\b|\(c\)\s*\d{4}|©|\bLicensed under\b|\bAll rights reserved\b/i;

function isLegalNoticeComment(comment: t.Comment): boolean {
  return (
    (comment.type === "CommentBlock" && comment.value.startsWith("!")) ||
    LEGAL_NOTICE_COMMENT_RE.test(comment.value)
  );
}

/**
 * Every node `Scope#rename` would touch, for every binding, found in one walk.
 *
 * Babel's renamer walks the binding's whole scope block once per rename, so
 * renaming the N program-level bindings of a scope-hoisted bundle walks the
 * program N times. With this index a rename costs the sites it rewrites.
 *
 * The visitors are the renamer's own, with one change: instead of asking "is
 * this name the one being renamed, and did no scope on the way down shadow
 * it?", each site is filed under the binding its name resolves to from where
 * it stands. Those are the same question. Like the renamer, the walk goes by
 * the tree as it is now and not by `binding.referencePaths`, which do not know
 * the identifiers that earlier passes cloned into rewritten expressions.
 */
interface RenameSites {
  readonly identifiers: Array<t.Identifier | t.JSXIdentifier>;
  readonly shorthandProperties: t.ObjectProperty[];
  /** Used as `<Name …>`: a tag is a reference only while it does not start with a-z. */
  namesJsxElement: boolean;
}

type RenameSiteIndex = Map<t.Identifier, RenameSites>;

function collectRenameSites(ast: t.File): RenameSiteIndex {
  const index: RenameSiteIndex = new Map();
  const sitesOf = (binding: Binding): RenameSites => {
    let sites = index.get(binding.identifier);
    if (sites === undefined) {
      sites = { identifiers: [], shorthandProperties: [], namesJsxElement: false };
      index.set(binding.identifier, sites);
    }
    return sites;
  };
  const collectLValIdentifiers = (
    lval: t.Node,
    scope: Scope,
    skipOwnScope: boolean,
  ): void => {
    const idGroups = t.getBindingIdentifiers(lval, true) as Record<string, t.Identifier[]>;
    for (const name of Object.keys(idGroups)) {
      const binding = scope.getBinding(name);
      if (binding === undefined) continue;
      // `function f(f) {}`: from inside its own scope the declaration's name
      // resolves to the parameter. The renamer never reaches the declaration
      // for that binding (it is the block being walked, not a node in it).
      if (skipOwnScope && binding.scope === scope) continue;
      const list = idGroups[name];
      if (!list) continue;
      const target = sitesOf(binding).identifiers;
      for (const id of list) target.push(id);
    }
  };
  const collectDeclaredOrAssigned = (
    path: NodePath<t.AssignmentExpression | t.Declaration | t.VariableDeclarator>,
  ): void => {
    if (path.isVariableDeclaration()) return;
    if (path.isAssignmentExpression()) {
      collectLValIdentifiers(path.node.left, path.scope, false);
      return;
    }
    collectLValIdentifiers(path.node, path.scope, path.isScope());
  };
  traverse(ast, {
    ReferencedIdentifier(path) {
      const binding = path.scope.getBinding(path.node.name);
      if (binding === undefined) return;
      const sites = sitesOf(binding);
      sites.identifiers.push(path.node);
      if (
        t.isJSXIdentifier(path.node) &&
        (t.isJSXOpeningElement(path.parent) || t.isJSXClosingElement(path.parent))
      ) {
        sites.namesJsxElement = true;
      }
    },
    ObjectProperty(path) {
      const { node } = path;
      if (!node.shorthand || !t.isIdentifier(node.key)) return;
      const binding = path.scope.getBinding(node.key.name);
      if (binding !== undefined) sitesOf(binding).shorthandProperties.push(node);
    },
    ForXStatement(path) {
      // `for ([k, v] of pairs)` / `for ({ a, b } of items)` / `for ([k] in obj)`
      // assign to existing bindings via an LVal pattern that ReferencedIdentifier
      // does not visit.
      if (!t.isVariableDeclaration(path.node.left) && t.isLVal(path.node.left)) {
        collectLValIdentifiers(path.node.left, path.scope, false);
      }
    },
    AssignmentExpression: collectDeclaredOrAssigned,
    Declaration: collectDeclaredOrAssigned,
    VariableDeclarator: collectDeclaredOrAssigned,
  });
  return index;
}

/**
 * `binding.scope.rename(oldName, newName)` in time proportional to the sites of
 * this one binding. The one thing the renamer does beyond rewriting names —
 * splitting `export default function name() {}` into a declaration plus an
 * export list — is left to the renamer itself.
 */
function renameBindingAtSites(
  binding: Binding,
  oldName: string,
  newName: string,
  index: RenameSiteIndex,
): void {
  const declaration = binding.path.find(
    (p) => p.isDeclaration() || p.isFunctionExpression() || p.isClassExpression(),
  );
  if (
    declaration !== null &&
    declaration.parentPath?.isExportDeclaration() === true &&
    declaration.getOuterBindingIdentifiers()[oldName] === binding.identifier
  ) {
    binding.scope.rename(oldName, newName);
    return;
  }
  const sites = index.get(binding.identifier);
  if (sites !== undefined) {
    for (const property of sites.shorthandProperties) {
      const key = property.key;
      if (
        property.shorthand &&
        t.isIdentifier(key) &&
        (key.name === oldName || key.name === newName)
      ) {
        property.shorthand = false;
      }
    }
    for (const identifier of sites.identifiers) {
      if (identifier.name === oldName) identifier.name = newName;
    }
  }
  binding.scope.removeOwnBinding(oldName);
  binding.scope.bindings[newName] = binding;
  binding.identifier.name = newName;
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

/** Free variables that only exist inside the CommonJS module wrapper. */
const COMMONJS_FREE_VARIABLES: ReadonlySet<string> = new Set(["require", "module", "exports"]);
/**
 * Free names of the injected runtime that are not properties of `globalThis`
 * (the CommonJS wrapper's parameters) or cannot be aliased through it.
 */
const UNALIASABLE_FREE_VARIABLES: ReadonlySet<string> = new Set([
  "require",
  "module",
  "exports",
  "__filename",
  "__dirname",
  "arguments",
  "undefined",
  "globalThis",
  "eval",
]);
/** `typeof <name>` on one of these is a runtime test for a module system. */
const MODULE_SYSTEM_PROBE_TARGETS: ReadonlySet<string> = new Set([
  "require",
  "module",
  "exports",
  "define",
]);

function isModuleSystemProbe(node: t.Node): boolean {
  return (
    t.isUnaryExpression(node, { operator: "typeof" }) &&
    t.isIdentifier(node.argument) &&
    MODULE_SYSTEM_PROBE_TARGETS.has(node.argument.name)
  );
}

function containsModuleSystemProbe(node: t.Node | null | undefined): boolean {
  if (node == null) return false;
  let found = false;
  t.traverseFast(node, (inner) => {
    if (!found && isModuleSystemProbe(inner)) found = true;
  });
  return found;
}

/**
 * Decide from the syntax tree whether a file can only run as a CommonJS module.
 *
 * Merely mentioning `module` / `exports` / `require` proves nothing: a UMD or
 * dual-mode file tests for them (`typeof module !== "undefined" && …`) exactly
 * because it is also loaded as a classic `<script>`, where its top-level
 * declarations are the page's globals and must keep their names. Bundles pass
 * `require` / `module` / `exports` to their module wrappers as parameters,
 * which are local bindings, not the CommonJS free variables.
 *
 * Evidence, strongest first:
 * - a top-level `return` (only the CommonJS wrapper allows one);
 * - a free `require(...)` / `module.x` / `exports.x` that is evaluated
 *   unconditionally at program level — such a file throws as a classic script;
 * - any other use outside an environment check, provided the file never
 *   probes for a module system at all.
 * Everything else is treated as a script, the carrier that renames nothing at
 * program level and therefore stays correct under both loaders.
 */
function analyseCommonJsUsage(ast: t.File): {
  readonly usesCommonJs: boolean;
  readonly hasTopLevelReturn: boolean;
} {
  let unconditionalUse = false;
  let unguardedUse = false;
  let probesModuleSystem = false;
  let hasTopLevelReturn = false;
  traverse(ast, {
    ReturnStatement(path) {
      if (path.getFunctionParent() === null) hasTopLevelReturn = true;
    },
    UnaryExpression(path) {
      if (
        isModuleSystemProbe(path.node) &&
        path.scope.getBinding((path.node.argument as t.Identifier).name) === undefined
      ) {
        probesModuleSystem = true;
      }
    },
    Identifier(path) {
      const name = path.node.name;
      if (!COMMONJS_FREE_VARIABLES.has(name)) return;
      if (!path.isReferencedIdentifier()) return;
      if (path.scope.getBinding(name) !== undefined) return;
      const parent = path.parent;
      if (t.isUnaryExpression(parent, { operator: "typeof" })) return;
      if (
        name === "require" &&
        (t.isCallExpression(parent) || t.isOptionalCallExpression(parent)) &&
        parent.callee === path.node
      ) {
        // AMD: `require(["dep"], callback)` is a call to a page-level loader.
        const first = parent.arguments[0];
        if (first === undefined || t.isArrayExpression(first)) return;
      }
      let unconditional = true;
      let guarded = false;
      let child: NodePath = path;
      for (
        let cur: NodePath | null = path.parentPath;
        cur !== null;
        child = cur, cur = cur.parentPath
      ) {
        if (cur.isIfStatement() || cur.isConditionalExpression()) {
          if (child.key !== "test") unconditional = false;
          if (containsModuleSystemProbe(cur.node.test)) guarded = true;
        } else if (cur.isLogicalExpression()) {
          if (child.key !== "left") unconditional = false;
          if (containsModuleSystemProbe(cur.node.left)) guarded = true;
        } else if (cur.isTryStatement()) {
          unconditional = false;
          if (child.key === "block") guarded = true;
        } else if (
          cur.isFunction() ||
          cur.isClass() ||
          cur.isLoop() ||
          cur.isSwitchStatement() ||
          cur.isCatchClause()
        ) {
          unconditional = false;
        }
      }
      if (unconditional) unconditionalUse = true;
      else if (!guarded) unguardedUse = true;
    },
  });
  return {
    usesCommonJs: unconditionalUse || (unguardedUse && !probesModuleSystem),
    hasTopLevelReturn,
  };
}

export function transformJavaScriptWithBlaShield(
  source: string,
  options: JsTransformOptions = {},
): JsShieldTransformResult {
  const intensity = options.intensity ?? "balanced";
  // One-click `bla harden` uses a single seed for every artifact. Everything the
  // shield injects at program level is named from this stream, and two classic
  // scripts on one page share one global scope — so the stream is keyed by the
  // source text as well. Same (source, seed) still gives byte-identical output.
  const prng = new SeededPrng(
    deriveSeedLabel(
      options.seed ?? generateProjectSeed(),
      `js-shield/source:${createHash("sha256").update(source, "utf8").digest("hex")}`,
    ),
  );
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
      allowReturnOutsideFunction: carrierAllowsTopLevelReturn(requestedCarrier),
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

  // Decide the carrier before any pass runs: several of them depend on it.
  const commonJsEvidence = analyseCommonJsUsage(ast);
  const isEsModule =
    requestedCarrier === "module" || hasEsmNodes || hasModuleOnlySyntax(ast.program);
  if (isEsModule && commonJsEvidence.hasTopLevelReturn) {
    throw new InvalidJavaScriptCarrierError(
      "A top-level return is only valid in a CommonJS module, not in an ES module",
    );
  }
  const effectiveCarrier: "module" | "script" | "commonjs" = isEsModule
    ? "module"
    : requestedCarrier === "commonjs" ||
        commonJsEvidence.usesCommonJs ||
        commonJsEvidence.hasTopLevelReturn
      ? "commonjs"
      : "script";

  const exportedSymbolsBefore = collectEsmExportedSymbols(ast.program);
  // The export shapes Node's scanner reads from a CommonJS file's text. A UMD
  // bundle is a "script" carrier here and CommonJS to Node; only a file that
  // is certainly an ES module is never scanned.
  const cjsExportSurface =
    effectiveCarrier === "module" ? null : collectCjsExportSurface(ast, source);
  const isCjsExportGlue = (node: t.Node): boolean => cjsExportSurface?.glue.has(node) === true;

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
      if (effectiveCarrier === "script" && path.scope.path.isProgram()) {
        // A program-level `Math` of a classic script replaces the page global
        // for every other script; it can be neither renamed nor shared with
        // the injected predicates.
        throw new InvalidJavaScriptCarrierError(
          "Cannot safely protect a program-level Math binding in a classic script: it must keep its name, and injected predicates require the ambient Math.imul",
        );
      }
      // The replacement can survive into the output (a pinned binding is not
      // renamed again below), so it is a realistic name from the start.
      let localMathName = prng.identifier({ style: "camel", hint: "localMath", entropy: 3 });
      while (
        path.scope.hasBinding(localMathName) ||
        path.scope.hasGlobal(localMathName) ||
        path.scope.hasReference(localMathName)
      ) {
        localMathName = prng.identifier({ style: "camel", hint: "localMath", entropy: 3 });
      }
      path.scope.rename("Math", localMathName);
    },
  });

  // Bindings whose runtime meaning Babel's scope model does not capture. A
  // rename follows Babel's idea of which declaration a reference reaches; where
  // the specification disagrees, the only safe move is to keep the names.
  const scopeModelPinnedBindings = new Set<t.Identifier>();
  // `__exportStar(require("./m"), exports)` is a star re-export to Node only
  // under that name.
  for (const helper of cjsExportSurface?.helperBindings ?? []) {
    scopeModelPinnedBindings.add(helper);
  }
  /** Sloppy block-level functions that Annex B also declares as program-level `var`s. */
  const annexBProgramLevelNames = new Set<string>();
  {
    const pinBinding = (binding: Binding | undefined): void => {
      if (binding !== undefined) scopeModelPinnedBindings.add(binding.identifier);
    };
    const hasUseStrict = (directives: readonly t.Directive[] | null | undefined): boolean =>
      directives?.some((directive) => directive.value.value === "use strict") ?? false;
    const isStrictCodeAt = (start: NodePath | null): boolean => {
      if (effectiveCarrier === "module") return true;
      for (let cur = start; cur !== null; cur = cur.parentPath) {
        if (cur.isClass()) return true;
        if (cur.isProgram() && hasUseStrict(cur.node.directives)) return true;
        if (cur.isFunction()) {
          const body = cur.node.body;
          if (t.isBlockStatement(body) && hasUseStrict(body.directives)) return true;
        }
      }
      return false;
    };
    traverse(ast, {
      // Annex B.3.3: in sloppy code a function declared inside a block is also
      // a `var` of the enclosing function / script once the block has run, so
      // `if (x) { function report() {} } report();` works. Babel binds it in
      // the block only, and a rename would cut the outer references loose.
      FunctionDeclaration(path) {
        const id = path.node.id;
        if (id == null) return;
        const declaringScope = path.scope.parent?.getBlockParent();
        if (declaringScope === undefined) return;
        if (declaringScope.path.isProgram() || declaringScope.path.isFunction()) return;
        if (isStrictCodeAt(path.parentPath)) return;
        pinBinding(declaringScope.getOwnBinding(id.name));
        const varScope = declaringScope.getFunctionParent() ?? declaringScope.getProgramParent();
        pinBinding(varScope.getBinding(id.name));
        if (varScope.path.isProgram()) annexBProgramLevelNames.add(id.name);
      },
      // Sloppy `function pick(a, a, b)`: the last duplicate wins at runtime,
      // Babel tracks a single binding for both.
      Function(path) {
        const seen = new Set<string>();
        for (const param of path.node.params) {
          const identifiers = t.getBindingIdentifiers(param, true) as Record<
            string,
            t.Identifier[]
          >;
          for (const [name, occurrences] of Object.entries(identifiers)) {
            if (seen.has(name) || occurrences.length > 1) {
              pinBinding(path.scope.getOwnBinding(name));
            }
            seen.add(name);
          }
        }
      },
      // Annex B.3.5: `catch (e) { var e = 1; }` declares a function-level `e`
      // but its initialiser assigns the catch parameter. Babel attaches that
      // declarator to the function-level binding.
      CatchClause(path) {
        const param = path.node.param;
        if (!t.isIdentifier(param)) return;
        const varScope = path.scope.getFunctionParent() ?? path.scope.getProgramParent();
        const outer = varScope.getOwnBinding(param.name);
        if (outer === undefined || outer.kind !== "var") return;
        pinBinding(outer);
        pinBinding(path.scope.getOwnBinding(param.name));
      },
      // `with (scope) { name }` resolves `name` on the object first; a renamed
      // local would no longer be looked up there under its original name.
      WithStatement(path) {
        for (const binding of Object.values(path.scope.getAllBindings())) {
          pinBinding(binding);
        }
      },
    });
  }

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
  // Code inside a function can run while the module-level seed does not exist
  // *yet* (an exported function declaration called through an import cycle
  // before the module body ran) or *at all* (`new Function("return " + fn)()`,
  // a worker bootstrap, `page.evaluate(fn)`). Functions therefore never read
  // the `const` seed itself — a `const` has a temporal dead zone, and `typeof`
  // does not protect against that — but a hoisted `var` holding the same value,
  // behind a `typeof` guard. In the script carrier the seed is a `var` already.
  const hoistedSeedName =
    effectiveCarrier === "script"
      ? seedVarName
      : prng.identifier({ style: "camel", hint: "runtimeEpoch", entropy: 4 });
  // Deterministic opaque-predicate seed + 8-bit data-flow mask key:
  // Draw ~24 bits of PRNG entropy in bits 8..31, reserve bits 1..7 for a non-zero
  // build-time key byte (`expectedSeedLowByte`, odd and != 1), and reserve bit 0
  // for cognitive-armor + self-seal parity entanglement. Setting `seed = 1` now
  // corrupts every masked string in the module instead of passing silently.
  const opaqueSeedHi = prng.nextUint32() >>> 0;
  const opaqueSeedLo = prng.nextUint32() >>> 0;
  const expectedSeedLowByte = ((prng.nextInt(1, 127) << 1) | 1) >>> 0;
  const opaqueSeedBase =
    (((((opaqueSeedHi ^ (opaqueSeedLo << 1)) & 0xffffff00) >>> 0) || 0x1000) |
      (expectedSeedLowByte & 0xfe)) >>>
    0;
  // Every opaque predicate holds for any odd seed, and masked string decoders
  // also consume `seed & 0xff === expectedSeedLowByte`. Detached `fn.toString()`
  // re-evaluations (`new Function("return " + fn)()`) fall back to an odd constant
  // carrying `expectedSeedLowByte`; a present-but-tampered seed still flips
  // predicates AND corrupts string decoding.
  const drawSeedFallback = (): number =>
    (((prng.nextUint32() & 0xffffff00) >>> 0) | expectedSeedLowByte) >>> 0;
  const buildGuardedSeedRead = (fallback: number = drawSeedFallback()): t.Expression =>
    t.conditionalExpression(
      t.binaryExpression(
        "===",
        t.unaryExpression("typeof", t.identifier(hoistedSeedName)),
        t.stringLiteral("number"),
      ),
      t.identifier(hoistedSeedName),
      t.numericLiteral(fallback),
    );
  /**
   * A guarded read for positions without a frame seed. One predicate reads its
   * seed several times and some compare two functions of it, so every read made
   * through one source must fall back to the same constant.
   */
  const guardedSeedSource = (): SeedSource => {
    let fallback: number | undefined;
    return () => {
      fallback ??= drawSeedFallback();
      return buildGuardedSeedRead(fallback);
    };
  };
  // The completion value of a classic script (`vm.runInContext`, `eval`,
  // userscript hosts) is that of its last value-producing statement, and
  // declarations produce none. Whatever the shield adds outside a function in
  // the script carrier is therefore written as `var <sink> = <expression>;`.
  let completionSinkName: string | undefined;
  const completionNeutralStatement = (expression: t.Expression): t.Statement => {
    completionSinkName ??= prng.identifier({
      style: "privateCamel",
      hint: "bootTrace",
      entropy: 4,
    });
    return t.variableDeclaration("var", [
      t.variableDeclarator(t.identifier(completionSinkName), expression),
    ]);
  };
  /** `typeof <injected binding> === "…"`: the test of a guard built above. */
  const guardedInjectedNames = new Set<string>([hoistedSeedName]);
  const isInjectedBindingGuardTest = (node: t.Node | null | undefined): boolean =>
    t.isBinaryExpression(node, { operator: "===" }) &&
    t.isUnaryExpression(node.left, { operator: "typeof" }) &&
    t.isIdentifier(node.left.argument) &&
    guardedInjectedNames.has(node.left.argument.name);
  const observedIpcChannels = new Set<string>();
  const observedProtocolSchemes = new Set<string>();
  const electronEsmBindings = new Map<string, string>();
  let hasProvenElectronRequire = false;
  let electronProtocolsProtected = 0;
  let primitiveCandidateBranchesCreated = 512; // From tarpit budgetFn
  let fakeCrossReferencesCreated = tarpit.crossReferenceEdges;
  let ipcAmbiguitySitesInjected = 0;

  // Track functions to weave tarpit calls into. Every block-bodied function
  // gets a frame seed of its own (entangled with its first plain parameter when
  // it has one), declared by the prologue woven into it further down.
  const functionBodies: t.BlockStatement[] = [];
  const fnLocalSeedByBody = new Map<
    t.BlockStatement,
    { fn: t.Function; localSeedName: string }
  >();
  traverse(ast, {
    enter(path) {
      // No prologue, no guard, no frame seed inside export glue.
      if (isCjsExportGlue(path.node)) path.skip();
    },
    Function(path) {
      if (!t.isBlockStatement(path.node.body)) return;
      functionBodies.push(path.node.body);
      const localSeedName = prng.identifier({
        style: "privateCamel",
        hint: "frameSeed",
        entropy: 4,
      });
      fnLocalSeedByBody.set(path.node.body, {
        fn: path.node,
        localSeedName,
      });
    },
  });
  // Expression-bodied arrows (`x => "…" + x`) have no block to hold a frame
  // seed. The ones that end up containing a predicate are given one lazily and
  // become `x => { const seed = …; return "…" + x; }` once all passes are done.
  const arrowFrameSeeds = new Map<t.ArrowFunctionExpression, string>();
  const frameSeedForArrow = (arrow: t.ArrowFunctionExpression): string => {
    let name = arrowFrameSeeds.get(arrow);
    if (name === undefined) {
      name = prng.identifier({ style: "privateCamel", hint: "frameSeed", entropy: 4 });
      arrowFrameSeeds.set(arrow, name);
    }
    return name;
  };
  /**
   * The seed a predicate placed at `path` reads:
   * - top-level code → the module seed (initialised before any user statement);
   * - a function body → that function's own frame seed, never an enclosing
   *   function's, so the function stays self-contained as source text;
   * - anywhere else inside a function or class (parameter defaults, computed
   *   keys, field initialisers, static blocks) → a guarded read in place.
   */
  const resolveSeedForPath = (path: NodePath): SeedSource => {
    let child: NodePath = path;
    for (
      let cur: NodePath | null = path.parentPath;
      cur !== null;
      child = cur, cur = cur.parentPath
    ) {
      if (cur.isFunction()) {
        if (child.key === "body") {
          const body = cur.node.body;
          if (t.isBlockStatement(body)) {
            const info = fnLocalSeedByBody.get(body);
            if (info !== undefined) return info.localSeedName;
          } else if (cur.isArrowFunctionExpression()) {
            const arrow = cur.node;
            return () => t.identifier(frameSeedForArrow(arrow));
          }
        }
        return guardedSeedSource();
      }
      if (cur.isClass()) return guardedSeedSource();
    }
    return seedVarName;
  };

  const handleCallOrOptionalCall = (
    path: NodePath<t.CallExpression> | NodePath<t.OptionalCallExpression>,
  ): void => {
    const activeSeedName = resolveSeedForPath(path);
    const callee = path.node.callee;
    // Leave dynamic eval arguments untouched: they may contain lexical names.
    if (t.isIdentifier(callee) && callee.name === "eval") return;
    if (t.isIdentifier(callee) && callee.name === "require") {
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
                  activeSeedName,
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
                      ? buildOpaqueTrueAst(prng, activeSeedName)
                      : buildOpaqueFalseAst(prng, activeSeedName);
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
            activeSeedName,
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
            activeSeedName,
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
            activeSeedName,
          );
          primitiveCandidateBranchesCreated += 512;
        }
        // Wrap literal API object in an O(1) opaque ternary so runtime passes the exact
        // same object reference while REA's `collectContextBridgeMembers` sees a dynamic node.
        const secondArg = path.node.arguments[1];
        if (t.isObjectExpression(secondArg)) {
          path.node.arguments[1] = t.conditionalExpression(
            buildOpaqueTrueAst(prng, activeSeedName),
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
      !(t.isIdentifier(callee) && callee.name === "require") &&
      !isStaticModuleStringPosition(path.node, firstArg)
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
        path.node.arguments[0] = buildCombinatorialStringAst(val, prng, activeSeedName, {
          fine: wantsFineSplit(val),
        });
        primitiveCandidateBranchesCreated += 512;
      }
    }
  };

  // Literals of guards this shield writes itself; the literal passes below leave
  // them readable instead of encoding them again.
  const shieldOwnedLiterals = new WeakSet<t.Node>();
  // An export's name in `Object.defineProperty(exports, "x", …)` / `exports["x"] = …`.
  for (const literal of cjsExportSurface?.nameLiterals ?? []) {
    shieldOwnedLiterals.add(literal);
  }
  /** Template literals rebuilt by the literal pass; never rewritten or entered twice. */
  const rebuiltTemplates = new WeakSet<t.Node>();

  // Pre-pass: Parameterized MBA Instruction Substitution on user 32-bit bitwise ops
  // (`a ^ b`, `a | b`, `a & b`) when program has no BigInt bindings/literals.
  //
  // The arithmetic form is an identity over int32 Numbers only and mentions each
  // operand twice. `a | b` itself accepts BigInts (whose values usually come
  // from an API, with no BigInt literal anywhere in the file) and objects, which
  // it converts exactly once each. So the rewrite keeps the original operator
  // as the path for everything that is not a Number:
  //   typeof a === "number" && typeof b === "number" ? <mba(a, b)> : a | b
  // and is applied only where reading an operand again cannot run code.
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
        // A replacement is queued for another visit; its own `a | b` terms must
        // not be rewritten again.
        ConditionalExpression(path) {
          if (mbaGeneratedNodes.has(path.node)) path.skip();
        },
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
          // An identifier is read several times below. That is unobservable for
          // a local variable; a global may be an accessor on the global object
          // (and every program-level binding of a classic script is a global),
          // and inside `with` any name may be a getter of the scope object.
          const isRepeatableRead = (operand: t.Expression): boolean => {
            if (!t.isIdentifier(operand)) return true;
            const binding = path.scope.getBinding(operand.name);
            if (binding === undefined || binding.kind === "unknown") return false;
            return !(effectiveCarrier === "script" && binding.scope.path.isProgram());
          };
          if (!isRepeatableRead(left) || !isRepeatableRead(right)) return;
          if (path.findParent((p) => p.isWithStatement())) return;

          const isNumberTest = (operand: t.Identifier): t.Expression => {
            const typeName = t.stringLiteral("number");
            shieldOwnedLiterals.add(typeName);
            return t.binaryExpression(
              "===",
              t.unaryExpression("typeof", t.identifier(operand.name)),
              typeName,
            );
          };
          const numberTests = [left, right]
            .filter((operand): operand is t.Identifier => t.isIdentifier(operand))
            .map(isNumberTest);
          const bothNumbers = numberTests.reduce((acc, test) =>
            t.logicalExpression("&&", acc, test),
          );
          const replacement = t.conditionalExpression(
            bothNumbers,
            buildParameterizedMbaBinaryAst(op, left, right, prng),
            t.binaryExpression(op, t.cloneNode(left), t.cloneNode(right)),
          );
          mbaGeneratedNodes.add(replacement);
          path.replaceWith(replacement);
          path.skip();
          mbaSubstitutedCount += 1;
        },
      });
    }
  }

  traverse(ast, {
    enter(path) {
      if (isCjsExportGlue(path.node)) path.skip();
    },
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
      const activeSeedName = resolveSeedForPath(path);
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
              ? buildOpaqueTrueAst(prng, activeSeedName)
              : buildOpaqueFalseAst(prng, activeSeedName);
          } else if (prefKey === "preload") {
            if (
              t.isStringLiteral(pref.value) &&
              pref.value.value.length > 0
            ) {
              pref.value = buildCombinatorialStringAst(
                pref.value.value,
                prng,
                activeSeedName,
              );
              primitiveCandidateBranchesCreated += 512;
            } else if (t.isCallExpression(pref.value)) {
              pref.value.arguments = pref.value.arguments.map((arg) =>
                t.isStringLiteral(arg) && arg.value.length > 0
                  ? buildCombinatorialStringAst(arg.value, prng, activeSeedName)
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
      // Ordinary strings are split up to 256 characters (down to 2 chars at
      // bankrupt so short region/tier codes like "US"/"EU"/"pro" are masked too).
      // What reads as a secret is split wherever it sits and up to a few kilobytes.
      const minLen = intensity === "bankrupt" ? 2 : 3;
      if (val.length < minLen || (val.length > 256 && !isSplittableSecret(val))) {
        return;
      }
      const parent = path.parent;
      // The `"number"` of a guard this shield built a moment ago.
      if (shieldOwnedLiterals.has(path.node) || isInjectedBindingGuardTest(parent)) return;
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
            // `enum E { A = "a" }` is a string enum only while the initializer
            // is a literal; anything else makes tsc emit a reverse mapping too.
            p.isTSEnumDeclaration() ||
            p.isTSModuleDeclaration() ||
            p.isTSExternalModuleReference() ||
            p.isImportAttribute(),
        )
      ) {
        return;
      }
      if (isNonComputedMemberKey(parent, path.node)) {
        // `{ "<secret>": role }`: a key is as readable as any other string.
        // Written as a computed key it defines the same property, in the same
        // order. Ordinary keys stay as they are, and so does every key of a
        // TypeScript source: there the literal key is part of the object's type.
        if (
          loader !== "ts" &&
          loader !== "tsx" &&
          (t.isObjectProperty(parent) || t.isObjectMethod(parent)) &&
          isSplittableSecret(val)
        ) {
          parent.computed = true;
          path.replaceWith(
            buildCombinatorialStringAst(val, prng, resolveSeedForPath(path), {
              fine: true,
              seedLowByte: expectedSeedLowByte,
            }),
          );
          path.skip();
          primitiveCandidateBranchesCreated += 256;
        }
        return;
      }
      if (isStaticModuleStringPosition(parent, path.node)) return;
      // (A member's own name was dealt with above. What is left under a class
      // or object member is a computed key or a field's value — `static
      // endpoint = "https://…"` — and those are strings like any other.)
      if (
        t.isCallExpression(parent) &&
        t.isIdentifier(parent.callee) &&
        (parent.callee.name === "require" || parent.callee.name === "eval")
      ) {
        return;
      }
      const encoded = buildCombinatorialStringAst(val, prng, resolveSeedForPath(path), {
        fine: wantsFineSplit(val),
        ...(intensity === "bankrupt" ? { mask: true } : {}),
        seedLowByte: expectedSeedLowByte,
      });
      // `<a title="…">`: an attribute holds a string or a `{…}` container,
      // never a bare expression. The parser has already decoded entities.
      path.replaceWith(t.isJSXAttribute(parent) ? t.jsxExpressionContainer(encoded) : encoded);
      path.skip();
      primitiveCandidateBranchesCreated += 256;
    },
    TemplateLiteral: {
      enter(path) {
        // A template this pass rebuilt: its substitutions were encoded on the
        // way up, and the rest of it is text the shield generated.
        if (rebuiltTemplates.has(path.node)) path.skip();
      },
      // On the way up, so that the substitutions — `${dev ? "http://…" : "https://…"}`,
      // `${encodeURIComponent("key")}`, nested templates — have been through the
      // string / integer / call visitors like any other expression first.
      exit(path) {
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
        if (isStaticModuleStringPosition(parent, path.node)) return;
        if (
          t.isCallExpression(parent) &&
          t.isIdentifier(parent.callee) &&
          (parent.callee.name === "require" || parent.callee.name === "eval")
        ) {
          return;
        }
        if (
          path.findParent(
            (p) =>
              p.isTSType() ||
              p.isTSEnumDeclaration() ||
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
        // A long template is left alone, except for the static pieces of it
        // that read as a secret.
        const withinOrdinaryRange = totalCookedLen <= 256;
        if (
          totalCookedLen < 3 ||
          (!withinOrdinaryRange && !quasis.some((q) => isSplittableSecret(q.value.cooked ?? "")))
        ) {
          return;
        }
        const activeSeedName = resolveSeedForPath(path);
        if (exprs.length === 0) {
          const val = quasis[0]?.value.cooked ?? "";
          path.replaceWith(
            buildCombinatorialStringAst(val, prng, activeSeedName, {
              fine: wantsFineSplit(val),
              ...(intensity === "bankrupt" ? { mask: true } : {}),
              seedLowByte: expectedSeedLowByte,
            }),
          );
          path.skip();
          primitiveCandidateBranchesCreated += 256;
          return;
        }
        // Rewrite `prefix ${a} mid ${b} suffix` into `${enc("prefix ")}${a}${enc(" mid ")}${b}…`:
        // the result stays a TemplateLiteral, so every user substitution is still
        // converted with ToString (ToPrimitive hint "string") right after it is
        // evaluated, in source order. `"" + x` would use hint "default" — valueOf
        // first — and print the wrong thing (or throw) for money / date / Temporal
        // value objects. Static chunks of three or more characters move into
        // side-effect-free holes of their own; shorter ones stay as quasi text.
        const nextQuasis: t.TemplateElement[] = [];
        const nextExprs: t.Expression[] = [];
        let pendingRaw = "";
        let pendingCooked = "";
        const flushQuasi = (tail: boolean): void => {
          nextQuasis.push(t.templateElement({ raw: pendingRaw, cooked: pendingCooked }, tail));
          pendingRaw = "";
          pendingCooked = "";
        };
        for (let i = 0; i < quasis.length; i++) {
          const quasi = quasis[i]!;
          const chunk = quasi.value.cooked ?? "";
          if (withinOrdinaryRange ? chunk.length >= 3 : isSplittableSecret(chunk)) {
            flushQuasi(false);
            nextExprs.push(
              buildCombinatorialStringAst(chunk, prng, activeSeedName, {
                fine: wantsFineSplit(chunk),
              }),
            );
            primitiveCandidateBranchesCreated += 256;
          } else {
            pendingRaw += quasi.value.raw;
            pendingCooked += chunk;
          }
          if (i < exprs.length) {
            flushQuasi(false);
            nextExprs.push(exprs[i] as t.Expression);
          }
        }
        flushQuasi(true);
        const rebuilt = t.templateLiteral(nextQuasis, nextExprs);
        rebuiltTemplates.add(rebuilt);
        path.replaceWith(rebuilt);
        path.skip();
      },
    },
    RegExpLiteral(path) {
      // `/^5e88…42d8$/`: a digest or an encoded blob inside a pattern is as
      // readable as one inside a string. Such a regex is rebuilt from a split
      // string — `new RegExp(source, flags)` is the same expression object a
      // literal evaluates to, created at the same moment. Ordinary patterns
      // stay literals.
      if (intensity !== "bankrupt" && intensity !== "maximum") {
        return;
      }
      const { pattern, flags } = path.node;
      if (pattern.length > SECRET_LITERAL_MAX_LENGTH) return;
      if (regexPatternSecretRuns(pattern).length === 0) return;
      // (A program that declares its own `RegExp` keeps its literals.)
      if (path.scope.getBinding("RegExp") !== undefined) return;
      const source = buildCombinatorialStringAst(pattern, prng, resolveSeedForPath(path), {
        fine: true,
        seedLowByte: expectedSeedLowByte,
      });
      path.replaceWith(
        t.newExpression(
          t.identifier("RegExp"),
          flags.length > 0 ? [source, t.stringLiteral(flags)] : [source],
        ),
      );
      path.skip();
      primitiveCandidateBranchesCreated += 256;
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
      // The fallback constant of a seed guard this shield built a moment ago.
      if (
        t.isConditionalExpression(parent) &&
        parent.alternate === path.node &&
        isInjectedBindingGuardTest(parent.test)
      ) {
        return;
      }
      if (isNonComputedMemberKey(parent, path.node)) return;
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
      path.replaceWith(
        buildOpaqueIntegerAst(val, prng, resolveSeedForPath(path)),
      );
      path.skip();
      primitiveCandidateBranchesCreated += 64;
    },
  });

  // 2b. Rename non-exported local bindings (including function parameters and private helpers)
  // so original identifiers are not left pristine.
  // Only rename bindings owned by the current scope. Babel mirrors ClassDeclaration
  // names onto the class scope with the SAME binding object; renaming there a second
  // time with a fresh PRNG name desyncs `class Foo` from `new Foo()` (issue #40).
  const exportedNameSet = new Set(exportedSymbolsBefore);
  const generatedNames = new Set<string>([seedVarName]);
  for (const info of fnLocalSeedByBody.values()) {
    generatedNames.add(info.localSeedName);
  }
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
  // 2a. Plan `.name` preservation before any binding changes its name. The
  // in-file observation above only sees reads in *this* file; an exported
  // function, a class whose instances travel, or a handler stored in a table is
  // read by code we never parse. So: classes always, functions whenever the
  // value is used as more than a call target.
  const namePinnedBindings = new Set<t.Identifier>();
  const nameRestorePlans = new Map<t.Identifier, NameRestorePlan>();
  {
    const escapingBindings = new Set<t.Identifier>();
    traverse(ast, {
      ReferencedIdentifier(path) {
        const binding = path.scope.getBinding(path.node.name);
        if (binding === undefined) return;
        const parent = path.parent;
        const isCallTarget =
          (t.isCallExpression(parent) || t.isOptionalCallExpression(parent)) &&
          parent.callee === path.node;
        const isTypeofOperand =
          t.isUnaryExpression(parent) && parent.operator === "typeof";
        if (!isCallTarget && !isTypeofOperand) {
          escapingBindings.add(binding.identifier);
        }
      },
    });
    traverse(ast, {
      Scope(path) {
        for (const binding of Object.values(path.scope.bindings)) {
          if (binding.scope !== path.scope) continue;
          const decision = decideNameRestore(
            binding,
            escapingBindings.has(binding.identifier),
          );
          if (decision === "pin") namePinnedBindings.add(binding.identifier);
          else if (decision !== "none") nameRestorePlans.set(binding.identifier, decision);
        }
      },
    });
  }
  const appliedNameRestores: Array<{
    readonly plan: NameRestorePlan;
    readonly original: string;
    readonly renamed: string;
  }> = [];

  const userRenameSites = collectRenameSites(ast);
  let sourceHasJsx = false;
  t.traverseFast(ast, (node) => {
    if (t.isJSXElement(node) || t.isJSXFragment(node)) sourceHasJsx = true;
  });
  traverse(ast, {
    Scope(path) {
      // The parameters and locals of a string decoder: written at every use,
      // so they stay one letter.
      if (MASK_DECODER_FUNCTIONS.has(path.node)) return;
      // `get: function get() { return m.x; }`: the getter's own name stays, so
      // nothing has to be wrapped around it to restore it.
      if (isCjsExportGlue(path.node)) return;
      for (const [name, binding] of Object.entries(path.scope.bindings)) {
        if (binding.scope !== path.scope) continue;
        if (bindingsVisibleToDirectEval.has(binding.identifier)) continue;
        // Function/class names remain obfuscated except when the source
        // actually reads their runtime .name (including constructor.name).
        if (nameObservedBindings.has(binding.identifier)) continue;
        // …or when the name is readable before a restoration could run.
        if (namePinnedBindings.has(binding.identifier)) continue;
        // …or when Babel's scope model and the specification disagree about it.
        if (scopeModelPinnedBindings.has(binding.identifier)) continue;
        if (RENAME_RESERVED.has(name)) continue;
        if (exportedNameSet.has(name)) continue;
        if (binding.kind === "module") continue;
        // The classic JSX transform turns `<a />` into `React.createElement(…)`
        // after this pass: a reference by name that is not in the tree yet.
        if (name === "React" && sourceHasJsx) continue;
        // `namespace Util { export function helper() {} }`: the member is
        // reached as `Util.helper`, a property name no rename can follow.
        // (Top-level exports are already covered by `exportedNameSet`.)
        if (
          binding.path.parentPath?.isExportNamedDeclaration() === true ||
          binding.path.parentPath?.parentPath?.isExportNamedDeclaration() === true
        ) {
          continue;
        }
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
        // In the classic "script" carrier every program-level binding is a
        // global of the page: `var` / function declarations are properties of
        // the global object and `let` / `const` / `class` live in the global
        // lexical scope, all of them read by other scripts and inline handlers.
        // None of them may change its name. In "module" / "commonjs" carriers
        // only pre-tagged decoy identifiers are preserved.
        if (
          path.scope.path.isProgram() &&
          (effectiveCarrier === "script" ||
            (binding.kind === "hoisted" && /_[0-9a-f]{3,4}$/i.test(name)))
        ) {
          continue;
        }
        const drawnName = prng.identifier({
          style: name.startsWith("_") ? "privateCamel" : "camel",
          hint:
            intensity === "bankrupt" || intensity === "maximum"
              ? undefined
              : name.replace(/^_+/, "").slice(0, 16) || "local",
          entropy: 3,
        });
        // `<Card />` refers to the binding `Card`; `<card />` is the string
        // "card". A binding used as an element name keeps a capital initial.
        const newName =
          userRenameSites.get(binding.identifier)?.namesJsxElement === true
            ? drawnName.replace(/^[a-z]/, (initial) => initial.toUpperCase())
            : drawnName;
        if (
          newName === name ||
          RENAME_RESERVED.has(newName) ||
          exportedNameSet.has(newName) ||
          generatedNames.has(newName)
        ) {
          continue;
        }
        try {
          renameBindingAtSites(binding, name, newName, userRenameSites);
          generatedNames.add(newName);
          const restorePlan = nameRestorePlans.get(binding.identifier);
          if (restorePlan !== undefined) {
            appliedNameRestores.push({
              plan: restorePlan,
              original: name,
              renamed: newName,
            });
          }
        } catch {
          // Binding may be constant-violating or conflict; skip safely
        }
      }
    },
  });

  // 2a (cont.). Give every renamed function / class its original `.name` back.
  // `Object.defineProperty` returns its target, so expressions are wrapped in
  // place; declarations get a statement where the binding is first live.
  if (appliedNameRestores.length > 0) {
    const encodeNames = intensity === "maximum" || intensity === "bankrupt";
    const defineName = (
      target: t.Expression,
      original: string,
      seedName: SeedSource,
    ): t.CallExpression =>
      t.callExpression(
        t.memberExpression(t.identifier("Object"), t.identifier("defineProperty")),
        [
          target,
          t.stringLiteral("name"),
          t.objectExpression([
            t.objectProperty(
              t.identifier("value"),
              encodeNames
                ? buildCombinatorialStringAst(original, prng, seedName)
                : t.stringLiteral(original),
            ),
            t.objectProperty(t.identifier("configurable"), t.booleanLiteral(true)),
          ]),
        ],
      );
    const firstStatementIndex = (statements: readonly t.Statement[]): number => {
      let index = 0;
      while (index < statements.length) {
        const stmt = statements[index]!;
        const isUseDirective =
          t.isExpressionStatement(stmt) &&
          t.isStringLiteral(stmt.expression) &&
          stmt.expression.value.startsWith("use ");
        if (!t.isImportDeclaration(stmt) && !isUseDirective) break;
        index++;
      }
      return index;
    };
    // Paths captured before the rename can be stale by now, so locate every
    // target again in one read-only walk and apply the edits afterwards.
    const declarationTargets = new Map<
      t.Node,
      { readonly original: string; readonly renamed: string; readonly hoisted: boolean }
    >();
    const expressionTargets = new Map<t.Node, string>();
    for (const { plan, original, renamed } of appliedNameRestores) {
      if (plan.kind === "class-declaration") {
        declarationTargets.set(plan.path.node, { original, renamed, hoisted: false });
      } else if (plan.kind === "function-declaration") {
        declarationTargets.set(plan.path.node, { original, renamed, hoisted: true });
      } else if (plan.kind === "inferred-name") {
        for (const sitePath of plan.sites) expressionTargets.set(sitePath.node, original);
      } else {
        expressionTargets.set(plan.path.node, original);
      }
    }
    const edits: Array<() => void> = [];
    traverse(ast, {
      enter(path) {
        const node = path.node;
        const declaration = declarationTargets.get(node);
        if (declaration !== undefined) {
          const statementPath = path.parentPath?.isExportDeclaration()
            ? path.parentPath
            : path;
          const statements = statementPath.container;
          if (!Array.isArray(statements)) return;
          const statementNode = statementPath.node;
          const seedName = resolveSeedForPath(statementPath);
          const affectsScriptCompletion =
            effectiveCarrier === "script" && statementPath.getFunctionParent() === null;
          edits.push(() => {
            const restoreCall = defineName(
              t.identifier(declaration.renamed),
              declaration.original,
              seedName,
            );
            const restore = affectsScriptCompletion
              ? completionNeutralStatement(restoreCall)
              : t.expressionStatement(restoreCall);
            if (declaration.hoisted) {
              statements.splice(
                firstStatementIndex(statements as t.Statement[]),
                0,
                restore,
              );
            } else {
              const at = statements.indexOf(statementNode);
              if (at >= 0) statements.splice(at + 1, 0, restore);
            }
          });
          return;
        }
        const original = expressionTargets.get(node);
        if (original === undefined) return;
        const seedName = resolveSeedForPath(path);
        if (t.isVariableDeclarator(node)) {
          edits.push(() => {
            if (node.init != null) node.init = defineName(node.init, original, seedName);
          });
        } else if (t.isAssignmentExpression(node)) {
          edits.push(() => {
            node.right = defineName(node.right, original, seedName);
          });
        } else if (t.isExpression(node)) {
          const container = path.container as t.Node | (t.Node | null)[] | null;
          const key = path.key;
          edits.push(() => {
            const wrapped = defineName(node, original, seedName);
            if (Array.isArray(container)) {
              const at = container.indexOf(node);
              if (at >= 0) container[at] = wrapped;
            } else if (container !== null && typeof key === "string") {
              (container as unknown as Record<string, unknown>)[key] = wrapped;
            }
          });
        }
      },
    });
    for (const edit of edits) edit();
  }

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
      // Licence banners ship verbatim; everything else is scrambled below.
      if (isLegalNoticeComment(c)) continue;
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
      const blockSeed =
        fnLocalSeedByBody.get(path.node)?.localSeedName ??
        resolveSeedForPath(path);
      const next: t.Statement[] = [];
      for (let i = 0; i < stmts.length; i++) {
        const stmt = stmts[i]!;
        // Don't wrap returns/throws/declarations/directives — wrap expression & if stmts
        // NEVER wrap VariableDeclaration / FunctionDeclaration / Return / Throw —
        // that would change block scoping and break the program under our own shield.
        // `super(...)` stays a root-level statement: TypeScript only emits
        // parameter-property / field initializers after a root-level super
        // call, so `if (opaque) { super(); }` compiles to `this.x = x` running
        // before the base constructor — a ReferenceError in every derived
        // class with `constructor(private x)`.
        const isSuperCall =
          t.isExpressionStatement(stmt) &&
          t.isCallExpression(stmt.expression) &&
          t.isSuper(stmt.expression.callee);
        const wrappable =
          !isSuperCall &&
          (t.isExpressionStatement(stmt) ||
            (t.isIfStatement(stmt) && !t.isVariableDeclaration(stmt.consequent)));
        if (wrappable && i % 2 === 0) {
          next.push(
            t.ifStatement(
              buildOpaqueTrueAst(prng, blockSeed),
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

  // 4. Build Decoy IPC Ambiguity & Route Mirage block + Cognitive-Armor seed entanglement
  const mirageLines: string[] = [];
  mirageLines.push(deceptionSuite.cognitiveArmor.code);
  // Opt-in self-seal (issue #40.5): sibling-module + env fingerprint digest.
  const selfSealOpt = options.selfSeal;
  let esmSelfSealReqIdent: string | undefined;
  let esmSelfSealMetaUrlIdent: string | undefined;
  let esmSelfSealCapReadIdent: string | undefined;
  let esmSelfSealCapHashIdent: string | undefined;
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
      esmSelfSealCapReadIdent = prng.identifier({
        style: "camel",
        hint: "loadStreamBytes",
        entropy: 4,
      });
      esmSelfSealCapHashIdent = prng.identifier({
        style: "camel",
        hint: "openDigestState",
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
            ...(esmSelfSealCapReadIdent ? { esmCapReadIdent: esmSelfSealCapReadIdent } : {}),
            ...(esmSelfSealCapHashIdent ? { esmCapHashIdent: esmSelfSealCapHashIdent } : {}),
          }
        : baseSealOpts;
    const seal = generateSelfSealSnippet(prng, sealOpts);
    mirageLines.push(seal.code);
    selfSealEnabled = true;
    selfSealBindingName = seal.bindingName;
  }
  if (selfSealEnabled && selfSealBindingName) {
    mirageLines.push(
      `const ${seedVarName} = ((${opaqueSeedBase} ^ (${selfSealBindingName} >>> 0)) ^ ((${deceptionSuite.cognitiveArmor.digestFunctionName}(0) === ${deceptionSuite.cognitiveArmor.expectedDigest}) ? 1 : 0));`,
    );
  } else {
    mirageLines.push(
      `const ${seedVarName} = (${opaqueSeedBase} | ((${deceptionSuite.cognitiveArmor.digestFunctionName}(0) === ${deceptionSuite.cognitiveArmor.expectedDigest}) ? 1 : 0));`,
    );
  }
  mirageLines.push(memoryDiffShield.code);
  const channelsToMirror =
    observedIpcChannels.size > 0
      ? [...observedIpcChannels]
      : ["enclave:attest", "clipboard:bridge-sync", "license:verify-lease"];

  const decoyRouteCount =
    intensity === "stealth" ? 4 : intensity === "balanced" ? 8 : 10;
  const selectedDecoyRoutes = DECOY_ROUTES.slice(0, decoyRouteCount);

  const decoyIpcFnName = prng.identifier({ style: "camel", hint: "bindChannelRoutes", entropy: 4 });
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
      `    _ipcMain?.handle(${JSON.stringify(ch)}, () => ({ status: "deferred", channel: ${JSON.stringify(ch)} }));`,
    );
    mirageLines.push(
      `    _ipcMain?.on(${JSON.stringify(ch)}, () => ({ queued: true }));`,
    );
    mirageLines.push(
      `    _ipcRenderer?.invoke(${JSON.stringify(ch)}, { seq: 1 });`,
    );
    mirageLines.push(
      `    _ipcRenderer?.send(${JSON.stringify(ch)}, { seq: 2 });`,
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

  // Names the customer program binds at program level, as they stand after the
  // rename pass (imports, `var` / `let` / `const` / `class` / functions, and
  // the `var`s Annex B derives from sloppy block-level functions).
  const customerProgramLevelNames = new Set<string>(annexBProgramLevelNames);
  traverse(ast, {
    Program(path) {
      for (const name of Object.keys(path.scope.bindings)) customerProgramLevelNames.add(name);
      path.stop();
    },
  });
  const ambientAliasDecls: t.Statement[] = [];

  // Scrub static generator prefixes in combinedInjectedAst so hardened output has
  // zero greppable template stems while preserving _[0-9a-f]{4} auditor entropy tags.
  const INJECTED_RAW_PREFIX_RE =
    /^(?:obligationFlood|scc|labyrinthDispatch|cdpShapeBudgetGuard|fridaCaptureSaturator|fridaRealmRing|regexSearchMagnet|bpeSink|tokenSink|localeCollation|collationSlot|aliasedBufferIllusion|diffFrontier|crashSignalHandler|canaryCredentialHoneypot|probeCanaryHoneypot|collectEnvironmentDiagnostics|systemDiagnosticLog|grpcServiceMirage|evidenceLedger|_shadowVault|readSplitShare|verifyShamirEd25519LicenseQuorum|computeEnterpriseSettlementLedger|decodeRatchetWireFrame|validateTpm2Pcr0Quote|verifyEnterpriseMasterLicense)_[A-Za-z0-9_]+$/i;
  const injectedRenameSites = collectRenameSites(combinedInjectedAst);
  traverse(combinedInjectedAst, {
    Program(progPath) {
      for (const [name, binding] of Object.entries(progPath.scope.bindings)) {
        if (!INJECTED_RAW_PREFIX_RE.test(name)) continue;
        const preserveDecoyTag = /_[a-f0-9]{4}$/i.test(name);
        const idEntropy = preserveDecoyTag ? 4 : 3;
        let fresh = prng.identifier({
          style: name.startsWith("_") ? "privateCamel" : "camel",
          entropy: idEntropy,
        });
        while (
          progPath.scope.hasBinding(fresh) ||
          generatedNames.has(fresh) ||
          exportedNameSet.has(fresh) ||
          RENAME_RESERVED.has(fresh)
        ) {
          fresh = prng.identifier({
            style: name.startsWith("_") ? "privateCamel" : "camel",
            entropy: idEntropy,
          });
        }
        try {
          renameBindingAtSites(binding, name, fresh, injectedRenameSites);
          generatedNames.add(fresh);
        } catch {
          /* keep original if scope refuses */
        }
      }

      // The injected runtime shares the program scope with the customer's code,
      // so a program-level `var Array = root.Array` or `var Object = { … }`
      // captures its free `Array` / `Object` too — as `undefined` while a
      // hoisted `var` is not assigned yet, in a temporal dead zone for `const`,
      // or as a partial stand-in afterwards. Wherever that happens the runtime
      // reads the real intrinsic through an alias taken from `globalThis`
      // before any customer statement runs. The customer's binding is left
      // alone, which is also right for exports, direct `eval` and classic
      // scripts, where it is a global other scripts use.
      const shadowed = Object.keys(progPath.scope.globals)
        .filter(
          (name) =>
            customerProgramLevelNames.has(name) && !UNALIASABLE_FREE_VARIABLES.has(name),
        )
        .sort();
      if (shadowed.length > 0) {
        if (customerProgramLevelNames.has("globalThis")) {
          throw new InvalidJavaScriptCarrierError(
            `Cannot safely protect a program that rebinds both globalThis and ${shadowed.join(", ")} at program level: the injected runtime cannot reach the real ${shadowed.join(" / ")}`,
          );
        }
        const aliasByGlobal = new Map<string, string>();
        for (const name of shadowed) {
          let alias = prng.identifier({ style: "camel", hint: "ambient", entropy: 4 });
          while (
            progPath.scope.hasBinding(alias) ||
            generatedNames.has(alias) ||
            customerProgramLevelNames.has(alias)
          ) {
            alias = prng.identifier({ style: "camel", hint: "ambient", entropy: 4 });
          }
          generatedNames.add(alias);
          aliasByGlobal.set(name, alias);
          ambientAliasDecls.push(
            t.variableDeclaration("var", [
              t.variableDeclarator(
                t.identifier(alias),
                t.memberExpression(t.identifier("globalThis"), t.identifier(name)),
              ),
            ]),
          );
        }
        progPath.traverse({
          Identifier(idPath) {
            const alias = aliasByGlobal.get(idPath.node.name);
            if (alias === undefined) return;
            if (!idPath.isReferencedIdentifier()) return;
            if (idPath.scope.getBinding(idPath.node.name) !== undefined) return;
            idPath.node.name = alias;
          },
        });
      }
      progPath.stop();
    },
  });

  const sanitizedInjectedStatements: t.Statement[] = [];
  for (const stmt of combinedInjectedAst.program.body) {
    if (t.isExportNamedDeclaration(stmt) && stmt.declaration) {
      sanitizedInjectedStatements.push(stmt.declaration);
    } else if (
      !t.isImportDeclaration(stmt) &&
      !t.isExportNamedDeclaration(stmt) &&
      !t.isExportDefaultDeclaration(stmt) &&
      !t.isExportAllDeclaration(stmt)
    ) {
      sanitizedInjectedStatements.push(stmt);
    }
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

  const topEnd =
    seedInjectIndex >= 0
      ? Math.min(
          sanitizedInjectedStatements.length,
          seedInjectIndex + 1 /* seed */ + 1 /* shadow heap usually follows */,
        )
      : Math.min(4, sanitizedInjectedStatements.length);
  const topDecls = sanitizedInjectedStatements.slice(0, topEnd);
  const restInjected = sanitizedInjectedStatements.slice(topEnd);

  // Build a cyclic cross-call mesh across all post-seed injected functions so
  // every decoy/tarpit/exhaustion function belongs to a single live SCC without
  // any self-snitching `void [...]` or `[...].every(...)` array manifest.
  const meshFns: t.FunctionDeclaration[] = [];
  const meshTables: string[] = [];
  for (const stmt of restInjected) {
    if (t.isFunctionDeclaration(stmt) && stmt.id && t.isBlockStatement(stmt.body)) {
      meshFns.push(stmt);
    } else if (t.isVariableDeclaration(stmt)) {
      for (const d of stmt.declarations) {
        if (t.isIdentifier(d.id)) meshTables.push(d.id.name);
      }
    }
  }
  if (meshFns.length >= 2) {
    for (let i = 0; i < meshFns.length; i++) {
      const nextA = meshFns[(i + 1) % meshFns.length]!.id!.name;
      const stmts = meshFns[i]!.body.body;
      // Read through the hoisted seed: the stepper is called from customer
      // prologues, which can run before the module-level `const` is initialised.
      // In that state `undefined & 1` is 0 and the function returns at once.
      const parityZeroCond = t.binaryExpression(
        "===",
        t.binaryExpression("&", t.identifier(hoistedSeedName), t.numericLiteral(1)),
        t.numericLiteral(0),
      );
      // Also wire orphaned deception tables (`evidenceLedger`, `grpcServiceMirage`,
      // `regexSearchMagnet`, `localeCollation`) into the live cyclic SCC so pure
      // DCE cannot drop them, guarded behind `typeof hoistedSeed === "number"`
      // so ESM import-cycle calls before module init never hit `const` TDZ.
      const tableName = i < meshTables.length ? meshTables[i] : undefined;
      const baseLinkExpr = t.memberExpression(t.identifier(nextA), t.identifier("length"));
      const linkExpr =
        tableName !== undefined
          ? t.conditionalExpression(
              t.binaryExpression(
                "===",
                t.unaryExpression("typeof", t.identifier(hoistedSeedName)),
                t.stringLiteral("number"),
              ),
              t.binaryExpression(
                "+",
                baseLinkExpr,
                t.conditionalExpression(
                  t.binaryExpression(
                    "!==",
                    t.unaryExpression("typeof", t.identifier(tableName)),
                    t.stringLiteral("undefined"),
                  ),
                  t.numericLiteral(1),
                  t.numericLiteral(0),
                ),
              ),
              t.cloneNode(baseLinkExpr, true),
            )
          : baseLinkExpr;
      if (stmts.length === 1 && t.isReturnStatement(stmts[0]) && stmts[0].argument) {
        stmts[0] = t.returnStatement(
          t.conditionalExpression(parityZeroCond, linkExpr, stmts[0].argument),
        );
      } else {
        stmts.unshift(t.ifStatement(parityZeroCond, t.returnStatement(linkExpr)));
      }
    }
  }

  // 3. Weave synchronized shadow-heap churn + cyclic mesh calls + parameter-entangled
  // local seeds into real customer function bodies.
  const decoyBridgePool =
    meshFns.length >= 2
      ? meshFns.map((fn) => fn.id!.name)
      : [...tarpit.decoyFunctionNames];
  // The prologue touches nothing that may be missing: the frame seed falls back
  // to an odd constant when the module seed is absent or not yet initialised,
  // and the stepper is only called when it is in scope. With both present the
  // behaviour is exactly the unguarded one.
  for (let bIdx = 0; bIdx < functionBodies.length; bIdx++) {
    const body = functionBodies[bIdx]!;
    const localInfo = fnLocalSeedByBody.get(body);
    const blockSeed: SeedSource = localInfo?.localSeedName ?? guardedSeedSource();
    const stepCallStmt = t.expressionStatement(
      t.logicalExpression(
        "&&",
        t.binaryExpression(
          "===",
          t.unaryExpression("typeof", t.identifier(memoryDiffShield.stepperFunctionName)),
          t.stringLiteral("function"),
        ),
        t.callExpression(t.identifier(memoryDiffShield.stepperFunctionName), [
          t.numericLiteral(prng.nextInt(1, 4095)),
        ]),
      ),
    );
    const prefixStmts: t.Statement[] = [];
    if (localInfo) {
      let paramName: string | undefined;
      for (const p of localInfo.fn.params) {
        if (t.isIdentifier(p) && p.name !== "this" && p.name !== "arguments") {
          paramName = p.name;
          break;
        }
      }
      const seedInitExpr: t.Expression = paramName
        ? t.binaryExpression(
            ">>>",
            t.binaryExpression(
              "^",
              buildGuardedSeedRead(),
              t.conditionalExpression(
                t.binaryExpression(
                  "===",
                  t.unaryExpression("typeof", t.identifier(paramName)),
                  t.stringLiteral("string"),
                ),
                t.binaryExpression(
                  "<<",
                  t.binaryExpression(
                    "&",
                    t.memberExpression(
                      t.identifier(paramName),
                      t.identifier("length"),
                    ),
                    t.numericLiteral(1023),
                  ),
                  t.numericLiteral(8),
                ),
                t.conditionalExpression(
                  t.binaryExpression(
                    "===",
                    t.unaryExpression("typeof", t.identifier(paramName)),
                    t.stringLiteral("number"),
                  ),
                  t.binaryExpression(
                    "<<",
                    t.binaryExpression(
                      "&",
                      t.identifier(paramName),
                      t.numericLiteral(255),
                    ),
                    t.numericLiteral(8),
                  ),
                  t.numericLiteral(0),
                ),
              ),
            ),
            t.numericLiteral(0),
          )
        : buildGuardedSeedRead();
      prefixStmts.push(
        t.variableDeclaration("const", [
          t.variableDeclarator(t.identifier(localInfo.localSeedName), seedInitExpr),
        ]),
      );
    }
    prefixStmts.push(stepCallStmt);
    if (decoyBridgePool.length >= 2) {
      const d1 = decoyBridgePool[(bIdx * 2) % decoyBridgePool.length]!;
      const d2 = decoyBridgePool[(bIdx * 2 + 1) % decoyBridgePool.length]!;
      prefixStmts.push(
        t.ifStatement(
          buildOpaqueFalseAst(prng, blockSeed),
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
        ),
      );
      fakeCrossReferencesCreated += 3;
    } else {
      fakeCrossReferencesCreated += 1;
    }
    body.body.unshift(...prefixStmts);
  }
  // Expression-bodied arrows that needed a frame seed get a block body now that
  // no pass will look at them again; `x => e` and `x => { return e; }` are the
  // same function.
  for (const [arrow, localSeedName] of arrowFrameSeeds) {
    if (t.isBlockStatement(arrow.body)) continue;
    arrow.body = t.blockStatement([
      t.variableDeclaration("const", [
        t.variableDeclarator(t.identifier(localSeedName), buildGuardedSeedRead()),
      ]),
      t.returnStatement(arrow.body),
    ]);
    if ("expression" in arrow) (arrow as { expression?: boolean }).expression = false;
  }

  // Entangle every post-seed decoy function directly into `seedVarName` so stripping
  // any injected declaration triggers an immediate ReferenceError or flips seed parity.
  if (seedInjectIndex >= 0 && meshFns.length > 0) {
    const seedStmt = sanitizedInjectedStatements[seedInjectIndex];
    if (seedStmt && t.isVariableDeclaration(seedStmt)) {
      const decl = seedStmt.declarations.find(
        (d) => t.isIdentifier(d.id) && d.id.name === seedVarName,
      );
      if (
        decl &&
        decl.init &&
        t.isBinaryExpression(decl.init) &&
        (decl.init.operator === "|" || decl.init.operator === "^") &&
        t.isConditionalExpression(decl.init.right)
      ) {
        const checkParam = prng.identifier({ style: "camel", hint: "fn", entropy: 2 });
        const everyCheck = t.callExpression(
          t.memberExpression(
            t.arrayExpression(meshFns.map((fn) => t.identifier(fn.id!.name))),
            t.identifier("every"),
          ),
          [
            t.arrowFunctionExpression(
              [t.identifier(checkParam)],
              t.binaryExpression(
                "===",
                t.unaryExpression("typeof", t.identifier(checkParam)),
                t.stringLiteral("function"),
              ),
            ),
          ],
        );
        decl.init.right.test = t.logicalExpression(
          "&&",
          everyCheck,
          decl.init.right.test,
        );
      }
    }
  }
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
    if (esmSelfSealCapReadIdent && esmSelfSealCapHashIdent) {
      // Must be the very first static import so it evaluates BEFORE any user
      // sibling `import` (e.g. `./quota.mjs`), capturing unpatched `node:fs`
      // and `node:crypto` references before a tampered sibling can hook them.
      const capImportDecl = t.importDeclaration(
        [
          t.importSpecifier(t.identifier(esmSelfSealCapReadIdent), t.identifier("r")),
          t.importSpecifier(t.identifier(esmSelfSealCapHashIdent), t.identifier("h")),
        ],
        t.stringLiteral(ESM_PREHOIST_CAPTURE_DATA_URL),
      );
      ast.program.body.unshift(capImportDecl);
      insertIndex += 1;
    }
    topDecls.unshift(metaUrlDecl);
  }
  if (effectiveCarrier === "script") {
    // Classic scripts on one page share the global scope. A `let` / `const`
    // there can be declared once per realm — loading the same hardened script
    // twice, or two scripts that happen to draw one name, is a SyntaxError that
    // the un-hardened scripts do not have. `var` and function declarations may
    // repeat, so nothing injected at program level is lexical here.
    for (const stmt of [...topDecls, ...restInjected]) {
      if (t.isVariableDeclaration(stmt) && stmt.kind !== "var") stmt.kind = "var";
    }
    // Every injected statement after the customer's code is a declaration, so
    // the script's completion value stays the customer's.
    for (let i = 0; i < restInjected.length; i++) {
      const stmt = restInjected[i]!;
      if (t.isExpressionStatement(stmt)) {
        restInjected[i] = completionNeutralStatement(stmt.expression);
      }
    }
  } else {
    // The TDZ-free copy of the seed that function prologues read.
    const seedStmt = seedInjectIndex >= 0 ? sanitizedInjectedStatements[seedInjectIndex] : undefined;
    const seedAt = seedStmt === undefined ? -1 : topDecls.indexOf(seedStmt);
    if (seedAt >= 0) {
      topDecls.splice(
        seedAt + 1,
        0,
        t.variableDeclaration("var", [
          t.variableDeclarator(t.identifier(hoistedSeedName), t.identifier(seedVarName)),
        ]),
      );
    }
  }
  topDecls.unshift(...ambientAliasDecls);
  if (topDecls.length > 0) {
    ast.program.body.splice(insertIndex, 0, ...topDecls);
  }
  // Break the "contiguous real-code island" tell by interleaving pure hoisted
  // decoy FunctionDeclarations across customer top-level statements in module/CJS
  // files (JS hoists FunctionDeclarations regardless of lexical position, so
  // runtime execution order & TDZ stay 100% identical).
  const customerStart = insertIndex + topDecls.length;
  const customerCount = ast.program.body.length - customerStart;
  if (effectiveCarrier !== "script" && customerCount >= 2 && restInjected.length > 0) {
    const hoistedDecoys: t.Statement[] = [];
    for (const stmt of restInjected) {
      if (t.isFunctionDeclaration(stmt)) {
        hoistedDecoys.push(stmt);
      }
    }
    const interleaveCount = Math.min(
      Math.floor(hoistedDecoys.length * 0.45),
      Math.max(2, customerCount * 3),
    );
    if (interleaveCount > 0) {
      const toWeave = hoistedDecoys.slice(0, interleaveCount);
      const customerBody = ast.program.body.slice(customerStart);
      const merged: t.Statement[] = [];
      const perGap = Math.max(1, Math.ceil(toWeave.length / customerBody.length));
      let wIdx = 0;
      for (let ci = 0; ci < customerBody.length; ci++) {
        merged.push(customerBody[ci]!);
        if (ci + 1 < customerBody.length && wIdx < toWeave.length) {
          const end = Math.min(wIdx + perGap, toWeave.length);
          for (; wIdx < end; wIdx++) merged.push(toWeave[wIdx]!);
        }
      }
      while (wIdx < toWeave.length) merged.push(toWeave[wIdx++]!);
      const wovenSet = new Set<t.Statement>(toWeave);
      const restPreserved = restInjected.filter((stmt) => !wovenSet.has(stmt));
      ast.program.body.splice(customerStart, customerCount, ...merged, ...restPreserved);
    } else {
      ast.program.body.push(...restInjected);
    }
  } else {
    ast.program.body.push(...restInjected);
  }

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

  // `module.exports = { label: "…" }`: a string or number the shield rewrote
  // into an expression that starts with a word would turn up as a new named
  // export. In parentheses it reads to the scanner the way the literal did.
  for (const [member, startedWithIdentifier] of cjsExportSurface?.literalMembers ?? []) {
    if (startedWithIdentifier) continue;
    const value = member.value;
    if (!t.isExpression(value) || t.isParenthesizedExpression(value)) continue;
    // These print with a quote, a digit, a bracket or a brace first.
    if (
      t.isStringLiteral(value) ||
      t.isNumericLiteral(value) ||
      t.isTemplateLiteral(value) ||
      t.isArrayExpression(value) ||
      t.isObjectExpression(value) ||
      t.isRegExpLiteral(value)
    ) {
      continue;
    }
    const printed = generate(value, { compact: true, comments: false }).code;
    const first = printed.codePointAt(0);
    if (first !== undefined && IDENTIFIER_START_RE.test(String.fromCodePoint(first))) {
      member.value = t.parenthesizedExpression(value);
    }
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

  // The injected shield is untyped JavaScript and the opaque guards hide the
  // customer's control-flow narrowing, so hardened TypeScript can never pass a
  // type-check (hundreds of TS7006 / TS2339). `@ts-nocheck` keeps `tsc` builds
  // of the hardened source working; emit and exported declarations are
  // unaffected. It must be the first comment, but after a `#!` line.
  let emittedCode = generated.code;
  if ((loader === "ts" || loader === "tsx") && !/^(?:#![^\n]*\n)?\/\/ @ts-nocheck\b/.test(emittedCode)) {
    const shebangEnd = emittedCode.startsWith("#!") ? emittedCode.indexOf("\n") + 1 : 0;
    emittedCode =
      shebangEnd > 0
        ? `${emittedCode.slice(0, shebangEnd)}// @ts-nocheck\n${emittedCode.slice(shebangEnd)}`
        : `// @ts-nocheck\n${emittedCode}`;
  }

  return {
    code: emittedCode,
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
