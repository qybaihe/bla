/**
 * Honest code-lock / bind-scope (competitor absorption Direction-4).
 *
 * Public domain/date binding written as an auditable contract — never a
 * covert backdoor. Default OFF: only runs when bla_bind_scope is invoked.
 *
 * Schema: bla-bind-scope/v1
 * MCP: bla_bind_scope, bla_lint_bind_scope
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

export const BIND_SCOPE_SCHEMA = "bla-bind-scope/v1" as const;
export const BIND_SCOPE_FILE_NAME = "bind-scope.json" as const;
/** Greppable runtime marker — lint looks for this exact token. */
export const BIND_SCOPE_RUNTIME_MARKER = "BLA_BIND_SCOPE_CHECK" as const;

export interface BindScopeContract {
  readonly schema: typeof BIND_SCOPE_SCHEMA;
  /** MUST be true. Hidden / non-public locks are refused. */
  readonly public: true;
  /** Allowed hostnames (exact) or suffix globs like "*.example.com". */
  readonly domains?: readonly string[];
  /** Inclusive start (ISO 8601). */
  readonly validFrom?: string;
  /** Inclusive end (ISO 8601). */
  readonly validUntil?: string;
  readonly honestyNote: string;
}

export type BindScopeRefuseReason =
  | "not-public"
  | "empty-constraints"
  | "invalid-domain"
  | "invalid-date"
  | "date-order"
  | "hidden-field"
  | "missing-runtime-check"
  | "schema-mismatch"
  | "parse-error";

export interface BindScopeLintReport {
  readonly schema: typeof BIND_SCOPE_SCHEMA;
  readonly path: string;
  readonly ok: boolean;
  readonly shouldRefuseBankrupt: boolean;
  readonly reasons: readonly BindScopeRefuseReason[];
  readonly contract?: BindScopeContract;
  readonly runtimeCheckPresent: boolean;
  readonly oneLineAdvice: string;
  readonly honestyNote: string;
}

export interface BindScopeApplyOptions {
  readonly directory: string;
  readonly domains?: readonly string[];
  readonly validFrom?: string;
  readonly validUntil?: string;
  /** Entry JS/CJS to inject the runtime check into (auto-detect license.cjs if omitted). */
  readonly entryPath?: string;
  readonly outDir?: string;
  readonly dryRun?: boolean;
}

export interface BindScopeApplyReport {
  readonly schema: typeof BIND_SCOPE_SCHEMA;
  readonly status: "ok" | "noop" | "error";
  readonly contract: BindScopeContract;
  readonly contractPath: string;
  readonly entryPath?: string;
  readonly written: boolean;
  readonly runtimeInjected: boolean;
  readonly lint: BindScopeLintReport;
  readonly honestyNote: string;
  readonly error?: string;
}

const HONESTY =
  "Bind-scope is a PUBLIC license/environment contract (domains + validity window). " +
  "It is NOT a covert DRM/backdoor. Conditions must be auditable in bind-scope.json; " +
  "runtime refusal is deterministic. Default OFF — only applied when bla_bind_scope runs. " +
  "Prove in-scope behaviour with verify / fixture unlock; out-of-scope must hard-fail.";

const ALLOWED_KEYS = new Set([
  "schema",
  "public",
  "domains",
  "validFrom",
  "validUntil",
  "honestyNote",
]);

const HIDDEN_KEY_HINTS = [
  "secret",
  "covert",
  "hidden",
  "backdoor",
  "stealth",
  "privateDomains",
  "internalOnly",
];

function isIsoDate(value: string): boolean {
  if (typeof value !== "string" || value.trim().length === 0) return false;
  const t = Date.parse(value);
  return Number.isFinite(t);
}

function isValidDomainPattern(d: string): boolean {
  if (typeof d !== "string") return false;
  const s = d.trim().toLowerCase();
  if (s.length < 1 || s.length > 253) return false;
  if (s.includes("/") || s.includes(":") || s.includes(" ")) return false;
  // exact hostname or *.suffix (single leading wildcard label only)
  if (s.startsWith("*.")) {
    const rest = s.slice(2);
    if (!rest || rest.includes("*")) return false;
    return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(
      rest,
    );
  }
  if (s.includes("*")) return false;
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(
    s,
  );
}

/**
 * Hostname match for public bind-scope domains.
 * Exported for unit tests / host hooks.
 */
export function hostMatchesBindDomain(
  host: string,
  pattern: string,
): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  const p = pattern.trim().toLowerCase();
  if (!h || !p) return false;
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

export function evaluateBindHost(
  host: string,
  domains: readonly string[],
): boolean {
  if (domains.length === 0) return true;
  return domains.some((d) => hostMatchesBindDomain(host, d));
}

export function evaluateBindTime(
  nowMs: number,
  validFrom?: string,
  validUntil?: string,
): boolean {
  if (validFrom) {
    const from = Date.parse(validFrom);
    if (!Number.isFinite(from) || nowMs < from) return false;
  }
  if (validUntil) {
    const until = Date.parse(validUntil);
    if (!Number.isFinite(until) || nowMs > until) return false;
  }
  return true;
}

export function buildBindScopeContract(input: {
  readonly domains?: readonly string[];
  readonly validFrom?: string;
  readonly validUntil?: string;
}): BindScopeContract {
  const domains = (input.domains ?? [])
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  return {
    schema: BIND_SCOPE_SCHEMA,
    public: true,
    ...(domains.length > 0 ? { domains } : {}),
    ...(input.validFrom ? { validFrom: input.validFrom } : {}),
    ...(input.validUntil ? { validUntil: input.validUntil } : {}),
    honestyNote: HONESTY,
  };
}

/**
 * Validate a parsed JSON value as bla-bind-scope/v1.
 * Does not check runtime injection — use lintBindScopeTree for that.
 */
export function validateBindScopeContract(
  raw: unknown,
): {
  readonly ok: boolean;
  readonly reasons: BindScopeRefuseReason[];
  readonly contract?: BindScopeContract;
} {
  const reasons: BindScopeRefuseReason[] = [];
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, reasons: ["parse-error"] };
  }
  const obj = raw as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (!ALLOWED_KEYS.has(key)) {
      reasons.push("hidden-field");
      break;
    }
    const lower = key.toLowerCase();
    if (HIDDEN_KEY_HINTS.some((h) => lower.includes(h.toLowerCase()))) {
      reasons.push("hidden-field");
      break;
    }
  }

  if (obj.schema !== BIND_SCOPE_SCHEMA) {
    reasons.push("schema-mismatch");
  }
  if (obj.public !== true) {
    reasons.push("not-public");
  }

  const domains = Array.isArray(obj.domains)
    ? obj.domains.filter((d): d is string => typeof d === "string")
    : undefined;
  if (domains) {
    for (const d of domains) {
      if (!isValidDomainPattern(d)) {
        reasons.push("invalid-domain");
        break;
      }
    }
  }

  const validFrom =
    typeof obj.validFrom === "string" ? obj.validFrom : undefined;
  const validUntil =
    typeof obj.validUntil === "string" ? obj.validUntil : undefined;
  if (validFrom !== undefined && !isIsoDate(validFrom)) {
    reasons.push("invalid-date");
  }
  if (validUntil !== undefined && !isIsoDate(validUntil)) {
    reasons.push("invalid-date");
  }
  if (
    validFrom &&
    validUntil &&
    isIsoDate(validFrom) &&
    isIsoDate(validUntil) &&
    Date.parse(validFrom) > Date.parse(validUntil)
  ) {
    reasons.push("date-order");
  }

  const hasDomains = (domains?.length ?? 0) > 0;
  const hasDates = Boolean(validFrom || validUntil);
  if (!hasDomains && !hasDates) {
    reasons.push("empty-constraints");
  }

  if (reasons.length > 0) {
    return { ok: false, reasons: [...new Set(reasons)] };
  }

  return {
    ok: true,
    reasons: [],
    contract: buildBindScopeContract({
      domains,
      validFrom,
      validUntil,
    }),
  };
}

/** Runtime check snippet — marker token required for lint. */
export function buildBindScopeRuntimeSnippet(
  contract: BindScopeContract,
): string {
  const payload = {
    schema: contract.schema,
    public: true as const,
    domains: contract.domains ?? [],
    validFrom: contract.validFrom ?? null,
    validUntil: contract.validUntil ?? null,
  };
  const json = JSON.stringify(payload);
  // Keep readable: public contract inlined on purpose (honesty).
  return (
    `/* ${BIND_SCOPE_RUNTIME_MARKER} — public bind-scope; not a covert lock */\n` +
    `(function ${BIND_SCOPE_RUNTIME_MARKER}(){\n` +
    `  var S = ${json};\n` +
    `  var now = Date.now();\n` +
    `  if (S.validFrom && now < Date.parse(S.validFrom)) {\n` +
    `    throw new Error("BLA bind-scope: before validFrom (" + S.validFrom + ")");\n` +
    `  }\n` +
    `  if (S.validUntil && now > Date.parse(S.validUntil)) {\n` +
    `    throw new Error("BLA bind-scope: after validUntil (" + S.validUntil + ")");\n` +
    `  }\n` +
    `  var domains = S.domains || [];\n` +
    `  if (domains.length) {\n` +
    `    var host = "";\n` +
    `    if (typeof location !== "undefined" && location && location.hostname) {\n` +
    `      host = String(location.hostname);\n` +
    `    } else if (typeof process !== "undefined" && process.env && process.env.BLA_BIND_HOST) {\n` +
    `      host = String(process.env.BLA_BIND_HOST);\n` +
    `    }\n` +
    `    host = host.trim().toLowerCase().replace(/\\.$/, "");\n` +
    `    var ok = false;\n` +
    `    for (var i = 0; i < domains.length; i++) {\n` +
    `      var p = String(domains[i] || "").trim().toLowerCase();\n` +
    `      if (!p) continue;\n` +
    `      if (p.charAt(0) === "*" && p.charAt(1) === ".") {\n` +
    `        var suf = p.slice(1);\n` +
    `        if (host.length > suf.length && host.slice(host.length - suf.length) === suf) { ok = true; break; }\n` +
    `      } else if (host === p) { ok = true; break; }\n` +
    `    }\n` +
    `    if (!ok) {\n` +
    `      throw new Error("BLA bind-scope: host not in public domains (host=" + host + ")");\n` +
    `    }\n` +
    `  }\n` +
    `})();\n`
  );
}

function injectRuntimeIntoEntry(
  source: string,
  snippet: string,
): string {
  if (source.includes(BIND_SCOPE_RUNTIME_MARKER)) {
    const markerComment = "/* " + BIND_SCOPE_RUNTIME_MARKER;
    const startIdx = source.indexOf(markerComment);
    if (startIdx >= 0) {
      const iife = source.indexOf(
        "(function " + BIND_SCOPE_RUNTIME_MARKER + "()",
        startIdx,
      );
      if (iife >= 0) {
        const endIdx = source.indexOf("})();", iife);
        if (endIdx >= 0) {
          const after = endIdx + "})();".length;
          const cutEnd = source[after] === "\n" ? after + 1 : after;
          return source.slice(0, startIdx) + snippet + source.slice(cutEnd);
        }
      }
    }
  }
  let shebang = "";
  let rest = source;
  if (source.startsWith("#!")) {
    const nl = source.indexOf("\n");
    if (nl >= 0) {
      shebang = source.slice(0, nl + 1);
      rest = source.slice(nl + 1);
    }
  }
  let strict = "";
  if (rest.startsWith('"use strict"') || rest.startsWith("'use strict'")) {
    const nl = rest.indexOf("\n");
    if (nl >= 0) {
      strict = rest.slice(0, nl + 1);
      rest = rest.slice(nl + 1);
    }
  }
  return shebang + strict + snippet + rest;
}

function findDefaultEntry(dir: string): string | undefined {
  const candidates = [
    "license.cjs",
    "license.js",
    "vault.cjs",
    "index.cjs",
    "index.js",
    "main.js",
  ];
  for (const name of candidates) {
    const p = join(dir, name);
    if (existsSync(p) && statSync(p).isFile()) return p;
  }
  // Also look one level under dist/
  const dist = join(dir, "dist");
  if (existsSync(dist) && statSync(dist).isDirectory()) {
    for (const name of candidates) {
      const p = join(dist, name);
      if (existsSync(p) && statSync(p).isFile()) return p;
    }
  }
  return undefined;
}

function adviceFor(reasons: readonly BindScopeRefuseReason[]): string {
  if (reasons.length === 0) {
    return "Bind-scope contract OK (public + runtime check present).";
  }
  if (reasons.includes("not-public")) {
    return "ERROR: bind-scope must set public:true — hidden locks are refused.";
  }
  if (reasons.includes("hidden-field")) {
    return "ERROR: bind-scope has non-public/unknown fields — strip covert keys.";
  }
  if (reasons.includes("missing-runtime-check")) {
    return "ERROR: bind-scope.json present but entry lacks BLA_BIND_SCOPE_CHECK — run bla_bind_scope.";
  }
  if (reasons.includes("empty-constraints")) {
    return "ERROR: bind-scope needs domains and/or validFrom/validUntil.";
  }
  return `ERROR: bind-scope refused (${reasons.join(", ")}).`;
}

export function lintBindScopeFile(
  contractPath: string,
  entryPath?: string,
): BindScopeLintReport {
  const abs = resolve(contractPath);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(abs, "utf8"));
  } catch {
    return {
      schema: BIND_SCOPE_SCHEMA,
      path: abs,
      ok: false,
      shouldRefuseBankrupt: true,
      reasons: ["parse-error"],
      runtimeCheckPresent: false,
      oneLineAdvice: "ERROR: bind-scope.json is not valid JSON.",
      honestyNote: HONESTY,
    };
  }
  const validated = validateBindScopeContract(raw);
  let runtimeCheckPresent = false;
  const reasons = [...validated.reasons];
  if (entryPath && existsSync(entryPath)) {
    const src = readFileSync(entryPath, "utf8");
    runtimeCheckPresent = src.includes(BIND_SCOPE_RUNTIME_MARKER);
    if (!runtimeCheckPresent) {
      reasons.push("missing-runtime-check");
    }
  } else if (validated.ok) {
    // Contract alone without an entry to check → still require caller to supply entry.
    // Discovery path pairs contract with a sibling entry when possible.
    reasons.push("missing-runtime-check");
  }
  const uniq = [...new Set(reasons)];
  const ok = uniq.length === 0;
  return {
    schema: BIND_SCOPE_SCHEMA,
    path: abs,
    ok,
    shouldRefuseBankrupt: !ok,
    reasons: uniq,
    ...(validated.contract ? { contract: validated.contract } : {}),
    runtimeCheckPresent,
    oneLineAdvice: adviceFor(uniq),
    honestyNote: HONESTY,
  };
}

function walkFiles(dir: string, out: string[], depth = 0): void {
  if (depth > 6 || out.length > 200) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".git" || e.name === ".bla-hardened") {
      continue;
    }
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      walkFiles(full, out, depth + 1);
      continue;
    }
    if (e.name === BIND_SCOPE_FILE_NAME || e.name.endsWith(".bind-scope.json")) {
      out.push(full);
    }
  }
}

/**
 * Discover bind-scope.json under a tree and lint each (paired with sibling entry).
 */
export function discoverAndLintBindScope(
  directory: string,
): readonly BindScopeLintReport[] {
  const abs = resolve(directory);
  if (!existsSync(abs)) return [];
  const files: string[] = [];
  const st = statSync(abs);
  if (st.isFile()) {
    files.push(abs);
  } else {
    walkFiles(abs, files);
  }
  return files.map((f) => {
    const entry = findDefaultEntry(dirname(f)) ?? findDefaultEntry(abs);
    return lintBindScopeFile(f, entry);
  });
}

export function bindScopeRefuseMessage(
  report: BindScopeLintReport,
  path = report.path,
): string {
  return `Bind-scope refuse at ${path}: ${report.reasons.join(", ")}. ${report.oneLineAdvice}`;
}

export function intensityEnforcesBindScopeRefusal(
  intensity: string,
): boolean {
  return intensity === "bankrupt" || intensity === "maximum";
}

/**
 * Write public bind-scope.json and inject runtime check into entry.
 * Default OFF capability — only runs when explicitly invoked.
 */
export function applyBindScope(
  options: BindScopeApplyOptions,
): BindScopeApplyReport {
  const absDir = resolve(options.directory);
  const contract = buildBindScopeContract({
    domains: options.domains,
    validFrom: options.validFrom,
    validUntil: options.validUntil,
  });
  const validated = validateBindScopeContract(contract);
  if (!validated.ok || !validated.contract) {
    const lint: BindScopeLintReport = {
      schema: BIND_SCOPE_SCHEMA,
      path: join(absDir, BIND_SCOPE_FILE_NAME),
      ok: false,
      shouldRefuseBankrupt: true,
      reasons: validated.reasons,
      runtimeCheckPresent: false,
      oneLineAdvice: adviceFor(validated.reasons),
      honestyNote: HONESTY,
    };
    return {
      schema: BIND_SCOPE_SCHEMA,
      status: "error",
      contract,
      contractPath: lint.path,
      written: false,
      runtimeInjected: false,
      lint,
      honestyNote: HONESTY,
      error: lint.oneLineAdvice,
    };
  }

  const outRoot = options.outDir ? resolve(options.outDir) : absDir;
  const contractPath = join(outRoot, BIND_SCOPE_FILE_NAME);
  const entrySrc =
    options.entryPath ??
    findDefaultEntry(absDir) ??
    findDefaultEntry(outRoot);

  if (!entrySrc || !existsSync(entrySrc)) {
    const lint: BindScopeLintReport = {
      schema: BIND_SCOPE_SCHEMA,
      path: contractPath,
      ok: false,
      shouldRefuseBankrupt: true,
      reasons: ["missing-runtime-check"],
      contract: validated.contract,
      runtimeCheckPresent: false,
      oneLineAdvice:
        "ERROR: no license.cjs/entry found to inject BLA_BIND_SCOPE_CHECK — pass entry_path.",
      honestyNote: HONESTY,
    };
    return {
      schema: BIND_SCOPE_SCHEMA,
      status: "error",
      contract: validated.contract,
      contractPath,
      written: false,
      runtimeInjected: false,
      lint,
      honestyNote: HONESTY,
      error: lint.oneLineAdvice,
    };
  }

  const entryAbs = resolve(entrySrc);
  const entryOut = options.outDir
    ? join(outRoot, basename(entryAbs))
    : entryAbs;
  const snippet = buildBindScopeRuntimeSnippet(validated.contract);
  const original = readFileSync(entryAbs, "utf8");
  const rewritten = injectRuntimeIntoEntry(original, snippet);

  if (!options.dryRun) {
    mkdirSync(dirname(contractPath), { recursive: true });
    writeFileSync(
      contractPath,
      JSON.stringify(validated.contract, null, 2) + "\n",
      "utf8",
    );
    mkdirSync(dirname(entryOut), { recursive: true });
    writeFileSync(entryOut, rewritten, "utf8");
  }

  // Dry-run synthesizes lint against the in-memory rewrite (no disk read).
  const finalLint: BindScopeLintReport = options.dryRun
    ? {
        schema: BIND_SCOPE_SCHEMA,
        path: contractPath,
        ok: rewritten.includes(BIND_SCOPE_RUNTIME_MARKER),
        shouldRefuseBankrupt: !rewritten.includes(BIND_SCOPE_RUNTIME_MARKER),
        reasons: rewritten.includes(BIND_SCOPE_RUNTIME_MARKER)
          ? []
          : ["missing-runtime-check"],
        contract: validated.contract,
        runtimeCheckPresent: rewritten.includes(BIND_SCOPE_RUNTIME_MARKER),
        oneLineAdvice: "Dry-run: bind-scope would write public contract + runtime check.",
        honestyNote: HONESTY,
      }
    : lintBindScopeFile(contractPath, entryOut);

  return {
    schema: BIND_SCOPE_SCHEMA,
    status: "ok",
    contract: validated.contract,
    contractPath,
    entryPath: entryOut,
    written: !options.dryRun,
    runtimeInjected: rewritten.includes(BIND_SCOPE_RUNTIME_MARKER),
    lint: finalLint,
    honestyNote: HONESTY,
  };
}

export function relBindPath(absDir: string, filePath: string): string {
  return (relative(absDir, filePath) || basename(filePath)).split(sep).join("/");
}
