/**
 * Stable panel-derive ABI lint + rewrite (red-blue round-3 / round-4 residual).
 *
 * Detects durable entitlement panel helpers such as `__vaultPanelDerive_r3`,
 * local `deriveLocal` entrypoints, classic FNV prime literals, and the
 * offline-oracle packaging of a callable derive beside plaintext
 * `panelTokenSha256` (seal digest or in-source compare target).
 *
 * At maximum/bankrupt, protect rewrites `__vaultPanelDerive*` and `deriveLocal`
 * to seed-stable `_blaPd_*` / `_blaPdLocal_*` names (same root seed → same
 * rename across JS + HTML). Round-4 oracle combo (deriveLocal + panelTokenSha256,
 * including sibling seal.json) is severity **error** and bankrupt refuses
 * unless `allowPanelOfflineOracle`.
 *
 * Lab fixtures that must keep the stable ABI / oracle packaging can pass
 * `allowStablePanelDeriveAbi` / `--allow-stable-panel-derive` and/or
 * `allowPanelOfflineOracle` / `--allow-panel-offline-oracle`.
 *
 * DEFENSIVE ONLY — rename is not a cryptographic fix for the oracle; honesty
 * bound: scrub digests / avoid shipping callable derive UI when possible.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { findSiblingSealSidecars } from "./seal-commitment-lint.js";

export const PANEL_DERIVE_ABI_SCHEMA = "bla-panel-derive-abi-lint/v1" as const;

export type PanelDeriveFindingId =
  | "stable-panel-derive-global"
  | "stable-local-derive"
  | "classic-fnv-prime-literal"
  | "panel-token-sha-oracle";

export type PanelDeriveSeverity = "warning" | "error";

export interface PanelDeriveFinding {
  readonly id: PanelDeriveFindingId;
  readonly severity: PanelDeriveSeverity;
  readonly summary: string;
  readonly evidence: string;
}

export interface PanelDeriveAbiReport {
  readonly schema: typeof PANEL_DERIVE_ABI_SCHEMA;
  readonly path: string;
  readonly findings: readonly PanelDeriveFinding[];
  readonly looksExposed: boolean;
  /** True when bankrupt/maximum should rewrite stable symbols. */
  readonly shouldRewriteOrRefuse: boolean;
  /**
   * True when bankrupt should refuse: callable local derive + plaintext
   * panelTokenSha256 offline-oracle packaging (same file or sibling seal).
   */
  readonly shouldRefuseBankrupt: boolean;
  readonly oneLineAdvice: string;
  readonly stableSymbols: readonly string[];
  readonly localDeriveSymbols: readonly string[];
}

const STABLE_PANEL_DERIVE = /__vaultPanelDerive(?:_[A-Za-z0-9]+)?/g;

/** Stable local panel derive name that survived R3 global rewrite. */
const LOCAL_DERIVE_DECL =
  /\bfunction\s+deriveLocal\b|\b(?:const|let|var)\s+deriveLocal\s*=/;

const PANEL_TOKEN_SHA = /\bpanelTokenSha256\b/;

const CLASSIC_FNV =
  /\b0x811c9dc5\b|\b2166136261\b|\b0x01000193\b|\b16777619\b/gi;

function finding(
  id: PanelDeriveFindingId,
  severity: PanelDeriveSeverity,
  summary: string,
  evidence: string,
): PanelDeriveFinding {
  return {
    id,
    severity,
    summary,
    evidence: evidence.slice(0, 160),
  };
}

/**
 * Strip protect-internal seed suffixes so JS + HTML inline scripts share
 * the same panel-derive rename under one harden/protect seed.
 */
export function panelDeriveSeedRoot(seed: string): string {
  return seed
    .replace(/:html-script-\d+$/i, "")
    .replace(/:html-bootstrap$/i, "");
}

export function panelDeriveReplacementName(seedRoot: string, original: string): string {
  const hex = createHash("sha256")
    .update(seedRoot, "utf8")
    .update("\0", "utf8")
    .update(original, "utf8")
    .digest("hex")
    .slice(0, 10);
  return `_blaPd_${hex}`;
}

export function panelLocalDeriveReplacementName(seedRoot: string, original: string): string {
  const hex = createHash("sha256")
    .update(seedRoot, "utf8")
    .update("\0local\0", "utf8")
    .update(original, "utf8")
    .digest("hex")
    .slice(0, 10);
  return `_blaPdLocal_${hex}`;
}

function siblingSealHasPanelTokenSha(filePath: string | undefined): boolean {
  if (!filePath || filePath === "<memory>") return false;
  try {
    const dir = dirname(resolve(filePath));
    for (const sealPath of findSiblingSealSidecars(dir)) {
      const body = readFileSync(sealPath, "utf8");
      if (PANEL_TOKEN_SHA.test(body)) return true;
    }
  } catch {
    return false;
  }
  return false;
}

export function lintPanelDeriveAbiSource(
  source: string,
  options: { readonly path?: string } = {},
): PanelDeriveAbiReport {
  const pathLabel = options.path ?? "<memory>";
  const text = source.length > 500_000 ? source.slice(0, 500_000) : source;
  const findings: PanelDeriveFinding[] = [];
  const symbols = new Set<string>();
  const localSymbols = new Set<string>();

  STABLE_PANEL_DERIVE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = STABLE_PANEL_DERIVE.exec(text)) !== null) {
    symbols.add(m[0]!);
  }
  if (symbols.size > 0) {
    const list = [...symbols].sort();
    findings.push(
      finding(
        "stable-panel-derive-global",
        "error",
        "Stable panel derive global/ABI survived — rename or let bankrupt protect rewrite to _blaPd_*.",
        list.join(","),
      ),
    );
  }

  const hasLocalDecl = /\bfunction\s+deriveLocal\b/.test(text) || LOCAL_DERIVE_DECL.test(text);
  if (hasLocalDecl) {
    localSymbols.add("deriveLocal");
    findings.push(
      finding(
        "stable-local-derive",
        "error",
        "Stable local deriveLocal panel entrypoint — rename or let maximum/bankrupt protect rewrite to _blaPdLocal_*.",
        "deriveLocal",
      ),
    );
  }

  CLASSIC_FNV.lastIndex = 0;
  const fnvHit = text.match(CLASSIC_FNV);
  if (fnvHit && fnvHit.length > 0) {
    findings.push(
      finding(
        "classic-fnv-prime-literal",
        "warning",
        "Classic FNV prime literal(s) near panel/token code — prefer opaque/split constants when they back entitlement tokens.",
        [...new Set(fnvHit.map((s) => s.toLowerCase()))].join(","),
      ),
    );
  }

  const hasPanelTokenSha = PANEL_TOKEN_SHA.test(text);
  const siblingOracle = siblingSealHasPanelTokenSha(
    pathLabel.includes("#") ? pathLabel.replace(/#.*$/, "") : pathLabel,
  );
  const hasLocalDerive = localSymbols.size > 0;
  if ((hasPanelTokenSha && hasLocalDerive) || (hasLocalDerive && siblingOracle)) {
    findings.push(
      finding(
        "panel-token-sha-oracle",
        "error",
        "Panel offline oracle: callable deriveLocal (or local derive) beside plaintext panelTokenSha256 (in-source or sibling seal.json) — scrub digest, avoid shipping derive UI, or refuse bankrupt.",
        hasPanelTokenSha
          ? "deriveLocal+panelTokenSha256(same-file)"
          : "deriveLocal+sibling seal.json panelTokenSha256",
      ),
    );
  } else if (hasPanelTokenSha) {
    findings.push(
      finding(
        "panel-token-sha-oracle",
        "warning",
        "Plaintext panelTokenSha256 compare target in source — offline oracle if a callable derive UI ships nearby.",
        "panelTokenSha256",
      ),
    );
  }

  const shouldRewriteOrRefuse = findings.some(
    (f) =>
      (f.id === "stable-panel-derive-global" || f.id === "stable-local-derive") &&
      f.severity === "error",
  );
  const shouldRefuseBankrupt = findings.some(
    (f) => f.id === "panel-token-sha-oracle" && f.severity === "error",
  );

  return {
    schema: PANEL_DERIVE_ABI_SCHEMA,
    path: pathLabel,
    findings,
    looksExposed: findings.length > 0,
    shouldRewriteOrRefuse,
    shouldRefuseBankrupt,
    stableSymbols: [...symbols].sort(),
    localDeriveSymbols: [...localSymbols].sort(),
    oneLineAdvice:
      findings.length === 0
        ? "No stable panel-derive ABI / local deriveLocal / panelTokenSha256 oracle footgun detected (heuristic)."
        : shouldRefuseBankrupt
          ? "ERROR: Panel offline oracle (deriveLocal + panelTokenSha256). Bankrupt refuses unless allowPanelOfflineOracle / --allow-panel-offline-oracle. Rename alone is not a crypto fix — scrub digests / avoid derive UI. Defensive guidance only."
          : shouldRewriteOrRefuse
            ? "ERROR: Stable __vaultPanelDerive_* / deriveLocal ABI. Maximum/bankrupt protect rewrites to _blaPd_* / _blaPdLocal_*; pass allowStablePanelDeriveAbi / --allow-stable-panel-derive to keep. Defensive guidance only."
            : "WARNING: Classic FNV primes and/or panelTokenSha256 remain as readable literals — scrub or split when feasible.",
  };
}

export function lintPanelDeriveAbiFile(filePath: string): PanelDeriveAbiReport {
  const abs = resolve(filePath);
  if (!existsSync(abs)) {
    throw new Error(`panel-derive-abi target not found: ${abs}`);
  }
  return lintPanelDeriveAbiSource(readFileSync(abs, "utf8"), { path: abs });
}

export interface PanelDeriveRewriteResult {
  readonly code: string;
  readonly rewrote: boolean;
  readonly renames: ReadonlyArray<{ readonly from: string; readonly to: string }>;
}

/**
 * Rewrite stable `__vaultPanelDerive*` and `deriveLocal` tokens to seed-stable
 * `_blaPd_<hex>` / `_blaPdLocal_<hex>`. Same seedRoot + original → same
 * replacement (cross JS/HTML under one protect seed).
 */
export function rewriteStablePanelDeriveSymbols(
  source: string,
  seed: string,
): PanelDeriveRewriteResult {
  const seedRoot = panelDeriveSeedRoot(seed);
  const symbols = new Set<string>();
  STABLE_PANEL_DERIVE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = STABLE_PANEL_DERIVE.exec(source)) !== null) {
    symbols.add(m[0]!);
  }
  const hasLocal = LOCAL_DERIVE_DECL.test(source) || /\bfunction\s+deriveLocal\b/.test(source);
  if (symbols.size === 0 && !hasLocal) {
    return { code: source, rewrote: false, renames: [] };
  }
  const renames = [...symbols]
    .sort()
    .map((from) => ({ from, to: panelDeriveReplacementName(seedRoot, from) }));
  if (hasLocal) {
    renames.push({
      from: "deriveLocal",
      to: panelLocalDeriveReplacementName(seedRoot, "deriveLocal"),
    });
  }
  // Replace longer names first to avoid partial overlap (none expected, but safe).
  let code = source;
  for (const { from, to } of [...renames].sort((a, b) => b.from.length - a.from.length)) {
    if (from === "deriveLocal") {
      // Word-boundary safe replace for the local identifier.
      code = code.replace(/\bderiveLocal\b/g, to);
    } else {
      code = code.split(from).join(to);
    }
  }
  return { code, rewrote: true, renames };
}

export function panelDeriveRefuseMessage(
  report: PanelDeriveAbiReport,
  filePath: string,
): string {
  if (report.shouldRefuseBankrupt) {
    return (
      `Refusing bankrupt harden/protect: panel offline oracle at ${filePath}` +
      ` [deriveLocal + panelTokenSha256]. ` +
      `Scrub plaintext panel token digests and avoid shipping a callable derive UI beside them. ` +
      `Rename alone is not a cryptographic fix. ` +
      `To override (lab fixture only), pass allowPanelOfflineOracle / --allow-panel-offline-oracle / allow_panel_offline_oracle:true.`
    );
  }
  const syms = [...report.stableSymbols, ...report.localDeriveSymbols].join(", ");
  return (
    `Refusing bankrupt harden/protect: stable panel-derive ABI at ${filePath}` +
    (syms ? ` [${syms}]` : "") +
    `. Rename the helper or allow protect to rewrite it. ` +
    `To keep the stable ABI (lab only), pass allowStablePanelDeriveAbi / --allow-stable-panel-derive / allow_stable_panel_derive:true.`
  );
}

export function intensityRewritesPanelDerive(intensity: string): boolean {
  return intensity === "maximum" || intensity === "bankrupt";
}

export function intensityEnforcesPanelOracleRefusal(intensity: string): boolean {
  return intensity === "bankrupt";
}

const PANEL_SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  ".bla-hardened",
  "coverage",
  ".turbo",
  ".cache",
  "__pycache__",
  ".venv",
  "venv",
]);

const PANEL_JS_EXT = /\.(?:[cm]?[jt]s|tsx?|html?)$/i;
const PANEL_MAX_FILES = 64;
const PANEL_MAX_DEPTH = 8;

function walkPanelCandidates(dir: string, depth: number, out: string[]): void {
  if (out.length >= PANEL_MAX_FILES || depth > PANEL_MAX_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= PANEL_MAX_FILES) return;
    if (entry.isDirectory()) {
      if (PANEL_SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
      walkPanelCandidates(join(dir, entry.name), depth + 1, out);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!PANEL_JS_EXT.test(entry.name)) continue;
    out.push(join(dir, entry.name));
  }
}

/**
 * Discover JS/TS/HTML under a directory and lint each for panel-derive footguns.
 * Used by unified `bla lint` / packaging-gates.
 */
export function discoverAndLintPanelDerive(
  directory: string,
): readonly PanelDeriveAbiReport[] {
  const abs = resolve(directory);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${abs}`);
  }
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintPanelDeriveAbiFile(abs)];
  }
  const candidates: string[] = [];
  walkPanelCandidates(abs, 0, candidates);
  return candidates.map((p) => lintPanelDeriveAbiFile(p));
}
