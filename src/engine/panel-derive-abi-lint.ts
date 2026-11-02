/**
 * Stable panel-derive ABI lint + rewrite (red-blue round-3 residual).
 *
 * Detects durable entitlement panel helpers such as `__vaultPanelDerive_r3`
 * and classic FNV prime literals that survive HTML/JS protect. At
 * maximum/bankrupt, protect rewrites matching symbols to a seed-stable
 * `_blaPd_<hex>` name (same root seed → same rename across JS + HTML).
 *
 * Lab fixtures that must keep the stable ABI can pass
 * `allowStablePanelDeriveAbi` / `--allow-stable-panel-derive`.
 *
 * DEFENSIVE ONLY — no crack advice.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const PANEL_DERIVE_ABI_SCHEMA = "bla-panel-derive-abi-lint/v1" as const;

export type PanelDeriveFindingId =
  | "stable-panel-derive-global"
  | "classic-fnv-prime-literal";

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
  /** True when bankrupt should rewrite (or refuse if rewrite disabled). */
  readonly shouldRewriteOrRefuse: boolean;
  readonly oneLineAdvice: string;
  readonly stableSymbols: readonly string[];
}

const STABLE_PANEL_DERIVE = /__vaultPanelDerive(?:_[A-Za-z0-9]+)?/g;

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

export function lintPanelDeriveAbiSource(
  source: string,
  options: { readonly path?: string } = {},
): PanelDeriveAbiReport {
  const pathLabel = options.path ?? "<memory>";
  const text = source.length > 500_000 ? source.slice(0, 500_000) : source;
  const findings: PanelDeriveFinding[] = [];
  const symbols = new Set<string>();

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

  const shouldRewriteOrRefuse = findings.some(
    (f) => f.id === "stable-panel-derive-global" && f.severity === "error",
  );

  return {
    schema: PANEL_DERIVE_ABI_SCHEMA,
    path: pathLabel,
    findings,
    looksExposed: findings.length > 0,
    shouldRewriteOrRefuse,
    stableSymbols: [...symbols].sort(),
    oneLineAdvice:
      findings.length === 0
        ? "No stable panel-derive ABI / classic FNV prime footgun detected (heuristic)."
        : shouldRewriteOrRefuse
          ? "ERROR: Stable __vaultPanelDerive_* ABI. Bankrupt/maximum protect rewrites to seed-stable _blaPd_*; pass allowStablePanelDeriveAbi / --allow-stable-panel-derive to keep. Defensive guidance only."
          : "WARNING: Classic FNV primes remain as readable literals — scrub or split when feasible.",
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
 * Rewrite stable `__vaultPanelDerive*` tokens to seed-stable `_blaPd_<hex>`.
 * Same seedRoot + original → same replacement (cross JS/HTML under one protect seed).
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
  if (symbols.size === 0) {
    return { code: source, rewrote: false, renames: [] };
  }
  const renames = [...symbols]
    .sort()
    .map((from) => ({ from, to: panelDeriveReplacementName(seedRoot, from) }));
  // Replace longer names first to avoid partial overlap (none expected, but safe).
  let code = source;
  for (const { from, to } of [...renames].sort((a, b) => b.from.length - a.from.length)) {
    code = code.split(from).join(to);
  }
  return { code, rewrote: true, renames };
}

export function panelDeriveRefuseMessage(
  report: PanelDeriveAbiReport,
  filePath: string,
): string {
  const syms = report.stableSymbols.join(", ");
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
