import { parse, type ParserPlugin } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";
import { generateProjectSeed } from "../../core/config.js";
import { SeededPrng } from "../../core/prng.js";
import { assertNoForbiddenMarkers } from "../../core/identifiers.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { generateJsTarpitAndBudgetBreaker } from "../tarpit/tarpit-generator.js";
import { generateRuntimeDeceptionSnippet } from "../runtime/runtime-shield.js";
import {
  generateShadowHeapChurnShield,
  type ShadowHeapChurnShieldResult,
} from "../runtime/memory-diff-shield.js";
import { generateCounterReaExhaustionSuite } from "../exhaustion/index.js";
import { generateCounterReaDeceptionSuite } from "../deception/index.js";

// Handle ESM/CJS default export interop in NodeNext
type TraverseFn = (typeof _traverse)["default"];
type GenerateFn = (typeof _generate)["default"];
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : _traverse.default;
const generate: GenerateFn =
  typeof _generate === "function"
    ? (_generate as unknown as GenerateFn)
    : _generate.default;

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
          exported.push(spec.exported.name);
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
    const useOddSq = idx % 3 === 1;
    const k = useOddSq ? prng.nextInt(1, 31) * 4 : (prng.nextInt(3, 125) | 1);
    const decoyChunk =
      realChunk.length > 0 ? prng.hex(realChunk.length) : prng.hex(2);
    const seededOr = t.binaryExpression(
      useOddSq ? "^" : "|",
      t.identifier(seedIdentifierName),
      t.numericLiteral(k),
    );
    const rhs = useOddSq
      ? t.cloneNode(seededOr)
      : t.binaryExpression("+", t.cloneNode(seededOr), t.numericLiteral(1));
    const imulCall = t.callExpression(
      t.memberExpression(t.identifier("Math"), t.identifier("imul")),
      [seededOr, rhs],
    );
    const mask = useOddSq ? 7 : 1;
    const trueVal = useOddSq ? 1 : 0;
    const falseVal = useOddSq ? 0 : 1;
    const bitAnd = t.binaryExpression("&", imulCall, t.numericLiteral(mask));
    const cond = t.binaryExpression("===", bitAnd, t.numericLiteral(trueVal));

    // Alternate polarity on odd indices so static heuristics see both true/false arms used
    if (idx % 2 === 0) {
      return t.conditionalExpression(
        cond,
        t.stringLiteral(realChunk),
        t.stringLiteral(decoyChunk),
      );
    } else {
      const invertedCond = t.binaryExpression(
        "===",
        bitAnd,
        t.numericLiteral(falseVal),
      );
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

const RENAME_RESERVED = new Set([
  "exports", "module", "require", "arguments", "undefined", "NaN", "Infinity",
  "globalThis", "global", "window", "self", "console", "Math", "Object", "Array",
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
    "importAttributes",
    "dynamicImport",
    "classProperties",
    "topLevelAwait",
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
        parent.callee.name === "require"
      ) {
        return;
      }
      path.replaceWith(buildCombinatorialStringAst(val, prng, seedVarName));
      path.skip();
      primitiveCandidateBranchesCreated += 256;
    },
  });

  const effectiveCarrier: "module" | "script" | "commonjs" =
    requestedCarrier === "module" || hasEsmNodes
      ? "module"
      : requestedCarrier === "commonjs" || usesCjsAst
        ? "commonjs"
        : "script";


  // 2b. Rename non-exported local bindings (including function parameters and private helpers)
  // so original identifiers are not left pristine
  const exportedNameSet = new Set(exportedSymbolsBefore);
  const generatedNames = new Set<string>();
  traverse(ast, {
    Scope(path) {
      for (const [name, binding] of Object.entries(path.scope.bindings)) {
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
  mirageLines.push(
    `const ${seedVarName} = (((typeof process !== "undefined" && typeof process?.hrtime?.bigint === "function" ? Number(process.hrtime.bigint() & 0x7fffcn) : (typeof Date !== "undefined" ? (Date.now() & 0x7fffc) : 4)) & 0x7fffc) | ((typeof ${deceptionSuite.cognitiveArmor.digestFunctionName} === "function" && ${deceptionSuite.cognitiveArmor.digestFunctionName}(0) === ${deceptionSuite.cognitiveArmor.expectedDigest}) ? 1 : 0));`,
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
    `  if (((Math.imul(${seedVarName} | 11, (${seedVarName} | 11) + 1) & 1) === 1)) {`,
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

  const [corpusDecl, digestFnDecl, seedDecl, heapDecl, ...restInjected] =
    sanitizedInjectedStatements;
  const topDecls = [corpusDecl, digestFnDecl, seedDecl, heapDecl].filter(
    (s): s is t.Statement => s !== undefined,
  );
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
  };
}
