/**
 * JS ← WASM hydrate memory-dump lint (red-blue round-5 residual).
 *
 * Detects the footgun where entitlement params are XOR-/cipher-unwrapped
 * *inside* WASM, then copied into JS via `memory.buffer` at a fixed dst
 * (salt || rounds || clen || cipher). Host-side dump recovers plaintext
 * params with no Node create*iv — bankrupt rename does not help when
 * ~all arity-1 exports alias hydrate.
 *
 * Bankrupt harden/protect refuses error findings unless
 * `allowJsWasmHydrateDump` / `--allow-js-wasm-hydrate-dump` /
 * `allow_js_wasm_hydrate_dump`.
 *
 * DEFENSIVE ONLY — prefer keep ARX+certify inside WASM so params never
 * re-enter JS. This gate does not implement white-box crypto.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";

export const JS_WASM_HYDRATE_DUMP_SCHEMA = "bla-js-wasm-hydrate-dump-lint/v1" as const;

export type JsWasmHydrateDumpFindingId =
  | "js-wasm-memory-buffer-read"
  | "js-wasm-hydrate-call"
  | "js-wasm-param-layout-decode"
  | "js-wasm-hydrate-param-dump";

export type JsWasmHydrateDumpSeverity = "warning" | "error";

export interface JsWasmHydrateDumpFinding {
  readonly id: JsWasmHydrateDumpFindingId;
  readonly severity: JsWasmHydrateDumpSeverity;
  readonly summary: string;
  readonly evidence: string;
}

export interface JsWasmHydrateDumpReport {
  readonly schema: typeof JS_WASM_HYDRATE_DUMP_SCHEMA;
  readonly path: string;
  readonly sha256Prefix: string;
  readonly findings: readonly JsWasmHydrateDumpFinding[];
  readonly looksExposed: boolean;
  /** True when bankrupt harden/protect should refuse (combo error). */
  readonly shouldRefuseBankrupt: boolean;
  readonly hasMemoryBufferRead: boolean;
  readonly hasHydrateCall: boolean;
  readonly hasParamLayoutDecode: boolean;
  readonly oneLineAdvice: string;
}

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

const MAX_WALK_DEPTH = 6;
const MAX_JS_FILES = 48;
const MAX_SCAN_CHARS = 800_000;

/** Host reads WASM linear memory into a JS typed array / Buffer. */
const MEMORY_BUFFER_READ =
  /(?:new\s+Uint8Array\s*\(\s*(?:[a-zA-Z_$][\w$]*\.)?buffer\b|Buffer\.from\s*\(\s*new\s+Uint8Array\s*\([^)]*\.buffer\b|instanceof\s+WebAssembly\.Memory)/;

/** Hydrate-style entry: named hydrate, or arity/export probe next to Memory. */
const HYDRATE_CALL =
  /\.hydrate\s*\(|\bhydrate\s*\(\s*\w+|\bexp\.hydrate\b|fn\.length\s*!==\s*1|fn\.length\s*===\s*1/;

/**
 * salt||rounds||clen||cipher layout decode in JS (R3–R5 entitlement pack).
 * Require at least two strong signals to avoid hashing false positives.
 */
const READ_I32_LE = /\.readInt32LE\s*\(|\.readUInt32LE\s*\(/;
const READ_U16_LE = /\.readUInt16LE\s*\(/;
const SALT_NAME = /\b(?:salt|SALT)\b/;
const ROUNDS_NAME = /\b(?:rounds|ROUNDS)\b/;
const CIPHER_NAME = /\b(?:cipherHex|cipher|CIPHER)\b/;
const CLEN_NAME = /\b(?:clen|cLen|cipherLen)\b/;

const WASM_INSTANTIATE = /WebAssembly\.instantiate\b/;

const JS_EXT = /\.(?:[cm]?js|tsx?|mts|cts)$/i;

function finding(
  id: JsWasmHydrateDumpFindingId,
  severity: JsWasmHydrateDumpSeverity,
  summary: string,
  evidence: string,
): JsWasmHydrateDumpFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 160),
  };
}

function detectSignals(text: string): {
  hasMemoryBufferRead: boolean;
  hasHydrateCall: boolean;
  hasParamLayoutDecode: boolean;
  hasWasmInstantiate: boolean;
  evidence: { memory?: string; hydrate?: string; layout?: string };
} {
  const memMatch = text.match(MEMORY_BUFFER_READ);
  const hasMemoryBufferRead = Boolean(memMatch);

  const hydMatch = text.match(HYDRATE_CALL);
  const hasHydrateCall = Boolean(hydMatch);

  const hasWasmInstantiate = WASM_INSTANTIATE.test(text);

  let layoutBits = 0;
  const layoutEv: string[] = [];
  if (READ_I32_LE.test(text)) {
    layoutBits++;
    layoutEv.push("readInt32LE/readUInt32LE");
  }
  if (READ_U16_LE.test(text)) {
    layoutBits++;
    layoutEv.push("readUInt16LE");
  }
  if (SALT_NAME.test(text) && ROUNDS_NAME.test(text)) {
    layoutBits++;
    layoutEv.push("salt+rounds names");
  }
  if (CIPHER_NAME.test(text) || CLEN_NAME.test(text)) {
    layoutBits++;
    layoutEv.push("cipher/clen");
  }
  const hasParamLayoutDecode = layoutBits >= 2;

  return {
    hasMemoryBufferRead,
    hasHydrateCall,
    hasParamLayoutDecode,
    hasWasmInstantiate,
    evidence: {
      ...(memMatch ? { memory: memMatch[0].slice(0, 80) } : {}),
      ...(hydMatch ? { hydrate: hydMatch[0].slice(0, 80) } : {}),
      ...(hasParamLayoutDecode ? { layout: layoutEv.join("+") } : {}),
    },
  };
}

/**
 * Lint a JS/TS (or HTML-inline-script) UTF-8 body for WASM hydrate→JS dump footguns.
 */
export function lintJsWasmHydrateDumpSource(
  source: string,
  options: { readonly path?: string } = {},
): JsWasmHydrateDumpReport {
  const pathLabel = options.path ?? "<memory>";
  const text = source.length > MAX_SCAN_CHARS ? source.slice(0, MAX_SCAN_CHARS) : source;
  const sha256Prefix = createHash("sha256").update(text, "utf8").digest("hex").slice(0, 12);
  const signals = detectSignals(text);
  const findings: JsWasmHydrateDumpFinding[] = [];

  if (signals.hasMemoryBufferRead) {
    findings.push(
      finding(
        "js-wasm-memory-buffer-read",
        signals.hasParamLayoutDecode ? "error" : "warning",
        "JS reads WebAssembly.Memory / memory.buffer into a host typed array — post-hydrate plaintext is dumpable without Node crypto.",
        signals.evidence.memory ?? "memory.buffer",
      ),
    );
  }
  if (signals.hasHydrateCall) {
    findings.push(
      finding(
        "js-wasm-hydrate-call",
        signals.hasMemoryBufferRead && signals.hasParamLayoutDecode ? "error" : "warning",
        "JS invokes hydrate (or arity===1 export probe) then consumes WASM memory — typical host-side param unwrap.",
        signals.evidence.hydrate ?? "hydrate/arity-probe",
      ),
    );
  }
  if (signals.hasParamLayoutDecode) {
    findings.push(
      finding(
        "js-wasm-param-layout-decode",
        signals.hasMemoryBufferRead ? "error" : "warning",
        "JS decodes salt||rounds||clen||cipher-style entitlement layout from a buffer (readInt32LE / salt+rounds / cipher).",
        signals.evidence.layout ?? "param-layout",
      ),
    );
  }

  const combo =
    signals.hasMemoryBufferRead &&
    signals.hasParamLayoutDecode &&
    (signals.hasHydrateCall || signals.hasWasmInstantiate);
  if (combo) {
    findings.push(
      finding(
        "js-wasm-hydrate-param-dump",
        "error",
        "JS WASM hydrate param-dump footgun: memory.buffer read + salt/rounds/cipher layout decode after hydrate/instantiate — bankrupt harden refuses. Keep ARX+certify inside WASM so params never re-enter JS; export rename alone does not close this.",
        [
          signals.evidence.memory,
          signals.evidence.hydrate,
          signals.evidence.layout,
        ]
          .filter(Boolean)
          .join("; "),
      ),
    );
  }

  const byId = new Map<JsWasmHydrateDumpFindingId, JsWasmHydrateDumpFinding>();
  for (const f of findings) {
    const prev = byId.get(f.id);
    if (!prev || (prev.severity === "warning" && f.severity === "error")) {
      byId.set(f.id, f);
    }
  }
  const deduped = [...byId.values()];
  const shouldRefuseBankrupt = combo;

  return {
    schema: JS_WASM_HYDRATE_DUMP_SCHEMA,
    path: pathLabel,
    sha256Prefix,
    findings: deduped,
    looksExposed: deduped.length > 0,
    shouldRefuseBankrupt,
    hasMemoryBufferRead: signals.hasMemoryBufferRead,
    hasHydrateCall: signals.hasHydrateCall,
    hasParamLayoutDecode: signals.hasParamLayoutDecode,
    oneLineAdvice:
      deduped.length === 0
        ? "No JS←WASM hydrate memory-dump footgun detected (heuristic)."
        : shouldRefuseBankrupt
          ? "ERROR: JS dumps salt/rounds/cipher from WebAssembly.Memory after hydrate. Keep entitlement crypto inside WASM; bankrupt refuses unless allowJsWasmHydrateDump / --allow-js-wasm-hydrate-dump / allow_js_wasm_hydrate_dump. Defensive gate only."
          : "WARNING: Partial JS←WASM memory/param signals — avoid copying hydrate plaintext into JS for entitlement checks.",
  };
}

export function lintJsWasmHydrateDumpFile(filePath: string): JsWasmHydrateDumpReport {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    throw new Error(`js-wasm-hydrate-dump target not found: ${abs}`);
  }
  return lintJsWasmHydrateDumpSource(readFileSync(abs, "utf8"), { path: abs });
}

function walkJsCandidates(dir: string, depth: number, out: string[]): void {
  if (out.length >= MAX_JS_FILES || depth > MAX_WALK_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= MAX_JS_FILES) return;
    if (entry.isDirectory()) {
      if (SKIP_DIR_NAMES.has(entry.name) || entry.name.startsWith(".")) continue;
      walkJsCandidates(join(dir, entry.name), depth + 1, out);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!JS_EXT.test(entry.name) && !/\.html?$/i.test(entry.name)) continue;
    out.push(join(dir, entry.name));
  }
}

export function discoverAndLintJsWasmHydrateDump(
  directory: string,
): readonly JsWasmHydrateDumpReport[] {
  const abs = resolve(directory);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintJsWasmHydrateDumpFile(abs)];
  }
  const candidates: string[] = [];
  walkJsCandidates(abs, 0, candidates);
  return candidates.map((p) => lintJsWasmHydrateDumpFile(p));
}

export function jsWasmHydrateDumpRefuseMessage(
  report: JsWasmHydrateDumpReport,
  filePath: string,
): string {
  return (
    `Refusing bankrupt harden/protect: JS←WASM hydrate param-dump footgun at ${filePath}` +
    ` (memory.buffer read + salt/rounds/cipher layout after hydrate/instantiate). ` +
    `Keep ARX+certify inside WASM so plaintext params never re-enter JS. ` +
    `Export rename alone does not close host memory dumps. ` +
    `To override (lab fixture only), pass allowJsWasmHydrateDump / --allow-js-wasm-hydrate-dump / allow_js_wasm_hydrate_dump:true.`
  );
}

export function intensityEnforcesJsWasmHydrateDumpRefusal(intensity: string): boolean {
  return intensity === "bankrupt";
}

/** Minimal R5-shaped footgun source for tests. */
export function buildTestJsWasmHydrateDumpFootgun(options: {
  readonly omitMemory?: boolean;
  readonly omitHydrate?: boolean;
  readonly omitLayout?: boolean;
} = {}): string {
  const parts: string[] = [
    'const fs = require("fs");',
    "async function loadRuntimeFromWasm() {",
    '  const bytes = fs.readFileSync("core.wasm");',
  ];
  if (!options.omitHydrate) {
    parts.push("  const { instance } = await WebAssembly.instantiate(bytes, {});");
    parts.push("  const exp = instance.exports;");
    parts.push("  let memory = null;");
    parts.push("  for (const v of Object.values(exp)) {");
    parts.push("    if (v instanceof WebAssembly.Memory) { memory = v; break; }");
    parts.push("  }");
    parts.push("  let hydrate = typeof exp.hydrate === 'function' ? exp.hydrate : null;");
    parts.push("  if (!hydrate) {");
    parts.push("    for (const [nm, fn] of Object.entries(exp)) {");
    parts.push("      if (typeof fn !== 'function' || fn.length !== 1) continue;");
    parts.push("      hydrate = fn; break;");
    parts.push("    }");
    parts.push("  }");
    parts.push("  const n = hydrate(4096) | 0;");
  } else {
    parts.push("  const n = 42;");
    parts.push("  const memory = { buffer: new ArrayBuffer(8192) };");
  }
  if (!options.omitMemory) {
    parts.push("  const view = new Uint8Array(memory.buffer, 4096, n);");
    parts.push("  const buf = Buffer.from(view);");
  } else {
    parts.push("  const buf = Buffer.alloc(42);");
  }
  if (!options.omitLayout) {
    parts.push("  const salt = buf.readInt32LE(0);");
    parts.push("  const rounds = buf[4];");
    parts.push("  const clen = buf.readUInt16LE(5);");
    parts.push("  const cipherHex = buf.subarray(7, 7 + clen).toString('hex');");
    parts.push("  return { salt, rounds, cipherHex };");
  } else {
    parts.push("  return { buf };");
  }
  parts.push("}");
  parts.push("module.exports = { loadRuntimeFromWasm };");
  return parts.join("\n") + "\n";
}
