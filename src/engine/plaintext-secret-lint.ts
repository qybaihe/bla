/**
 * Plaintext sensitive-literal lint (Direction-2).
 *
 * Flags structural / high-entropy secrets that still sit as cleartext string
 * literals in panel.html / license.cjs (and sibling JS). Does **not** claim
 * encrypted strings are unrecoverable — only that cleartext footguns are gone.
 *
 * Sensitive (hit → finding):
 *   1. Shannon entropy ≥ 4.0 bit/char AND length ≥ 16 (key/token-shaped)
 *   2. FLAG{…}, http(s):// endpoints, -----BEGIN…, base64/hex ≥ 24
 *   3. Derive/unlock contract key-name literals outside a small allowlist
 *
 * Avoid false positives:
 *   - length < 8 → skip
 *   - pure UI copy (no high entropy, no structural markers) → skip
 *   - strings already behind the XOR decrypt stub (_blaS(i) / table) → skip
 *   - allowPlaintextString escapes bankrupt refuse
 *
 * DEFENSIVE ONLY.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { ProtectionIntensity } from "../core/types.js";

export const PLAINTEXT_SECRET_SCHEMA = "bla-plaintext-secret-lint/v1" as const;

export type PlaintextSecretFindingId =
  | "plaintext-flag-literal"
  | "plaintext-high-entropy"
  | "plaintext-url-endpoint"
  | "plaintext-pem-header"
  | "plaintext-b64-or-hex"
  | "plaintext-derive-keyname";

export type PlaintextSecretSeverity = "warning" | "error";

export interface PlaintextSecretFinding {
  readonly id: PlaintextSecretFindingId;
  readonly severity: PlaintextSecretSeverity;
  readonly summary: string;
  readonly evidence: string;
  readonly literal: string;
}

export interface PlaintextSecretReport {
  readonly schema: typeof PLAINTEXT_SECRET_SCHEMA;
  readonly path: string;
  readonly sha256Prefix: string;
  readonly findings: readonly PlaintextSecretFinding[];
  readonly looksExposed: boolean;
  readonly shouldRefuseBankrupt: boolean;
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
const MAX_FILES = 48;
const MAX_SCAN_CHARS = 800_000;

const TARGET_BASENAME =
  /^(?:panel\.html?|license\.cjs|license\.js|vault\.cjs|gate\.cjs)$/i;
const SCAN_EXT = /\.(?:html?|[cm]?js|tsx?|mts|cts)$/i;

/** Safe UI / ABI tokens that must stay greppable. */
const KEYNAME_ALLOWLIST = new Set([
  "exports",
  "module",
  "require",
  "default",
  "length",
  "message",
  "error",
  "name",
  "type",
  "value",
  "status",
  "ok",
  "sha256",
  "digest",
]);

const DERIVE_KEYNAME =
  /\b(?:deriveLocal|panelTokenSha256|unwrapKey|unlockFlag|secretKey|masterKey|licenseKey)\b/;

function sha256Prefix(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex").slice(0, 16);
}

/** Shannon entropy in bits/char. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isHexish(s: string): boolean {
  return s.length >= 24 && /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
}

function isBase64ish(s: string): boolean {
  if (s.length < 24) return false;
  if (!/^[A-Za-z0-9+/]+=*$/.test(s)) return false;
  // Reject mostly-alpha words that happen to match base64 charset.
  const digitOrPlus = (s.match(/[0-9+/=]/g) ?? []).join("").length;
  return digitOrPlus / s.length >= 0.15;
}

/**
 * Extract JS / HTML string literals. Skips template expressions' outer form
 * only (simple "'…'" / "…" / `…` without ${}).
 */
export function extractStringLiterals(source: string): string[] {
  const out: string[] = [];
  const re =
    /'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\$]|\$(?!\{))*`/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const raw = m[0]!;
    // Strip quotes.
    let inner = raw.slice(1, -1);
    try {
      // Unescape common sequences without full JS parse.
      inner = inner
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t")
        .replace(/\\'/g, "'")
        .replace(/\\"/g, '"')
        .replace(/\\`/g, "`")
        .replace(/\\\\/g, "\\");
    } catch {
      /* keep raw inner */
    }
    out.push(inner);
  }
  return out;
}

/**
 * True when a literal already lives inside the XOR encrypt-strings table
 * (opaque payload / index calls) — do not re-flag.
 */
export function looksAlreadyEncrypted(source: string, literal: string): boolean {
  if (source.includes("_blaS(") && source.includes("_blaT")) {
    // After encrypt, cleartext literal should be absent from source.
    if (!source.includes(JSON.stringify(literal)) && !source.includes(`'${literal}'`) && !source.includes(`"${literal}"`)) {
      return true;
    }
  }
  // Combinatorial AST leaves chunks but not the full literal as one piece ≥8.
  if (literal.length >= 8 && !source.includes(literal)) return true;
  return false;
}

export function classifySensitiveLiteral(
  literal: string,
): PlaintextSecretFindingId | null {
  if (literal.length < 8) return null;

  if (/^FLAG\{[\s\S]*\}$/.test(literal) || /FLAG\{[A-Za-z0-9_\-]{8,}\}/.test(literal)) {
    return "plaintext-flag-literal";
  }
  if (/-----BEGIN [A-Z0-9 ]+-----/.test(literal)) {
    return "plaintext-pem-header";
  }
  if (/https?:\/\/[^\s"'<>]+/i.test(literal)) {
    return "plaintext-url-endpoint";
  }
  if (isHexish(literal) || isBase64ish(literal)) {
    return "plaintext-b64-or-hex";
  }
  if (literal.length >= 16 && shannonEntropy(literal) >= 4.0) {
    return "plaintext-high-entropy";
  }
  if (DERIVE_KEYNAME.test(literal) && !KEYNAME_ALLOWLIST.has(literal)) {
    return "plaintext-derive-keyname";
  }
  return null;
}

function severityFor(id: PlaintextSecretFindingId): PlaintextSecretSeverity {
  switch (id) {
    case "plaintext-url-endpoint":
      return "warning";
    default:
      return "error";
  }
}

export function lintPlaintextSecretsSource(
  source: string,
  options: { readonly path?: string; readonly allowPlaintextString?: boolean } = {},
): PlaintextSecretReport {
  const path = options.path ?? "<memory>";
  const truncated =
    source.length > MAX_SCAN_CHARS ? source.slice(0, MAX_SCAN_CHARS) : source;
  const findings: PlaintextSecretFinding[] = [];
  const seen = new Set<string>();

  for (const lit of extractStringLiterals(truncated)) {
    if (looksAlreadyEncrypted(truncated, lit)) continue;
    const id = classifySensitiveLiteral(lit);
    if (!id) continue;
    const key = `${id}:${lit}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      id,
      severity: severityFor(id),
      summary: `Cleartext sensitive literal (${id})`,
      evidence: lit.slice(0, 120),
      literal: lit.length > 200 ? `${lit.slice(0, 200)}…` : lit,
    });
  }

  const errorFindings = findings.filter((f) => f.severity === "error");
  const looksExposed = findings.length > 0;
  const shouldRefuseBankrupt =
    errorFindings.length > 0 && options.allowPlaintextString !== true;

  const oneLineAdvice = shouldRefuseBankrupt
    ? "ERROR: Cleartext sensitive literals remain — run bla_encrypt_strings (XOR/combinatorial; never JS AES) or pass allow_plaintext_string (lab only)."
    : looksExposed
      ? "WARNING: Non-refusing sensitive literals (e.g. URLs) still in cleartext — prefer bla_encrypt_strings."
      : "No cleartext sensitive-literal findings (heuristic).";

  return {
    schema: PLAINTEXT_SECRET_SCHEMA,
    path,
    sha256Prefix: sha256Prefix(truncated),
    findings,
    looksExposed,
    shouldRefuseBankrupt,
    oneLineAdvice,
  };
}

export function lintPlaintextSecretsFile(
  filePath: string,
  options: { readonly allowPlaintextString?: boolean } = {},
): PlaintextSecretReport {
  const abs = resolve(filePath);
  const source = readFileSync(abs, "utf8");
  return lintPlaintextSecretsSource(source, {
    path: abs,
    allowPlaintextString: options.allowPlaintextString,
  });
}

function walkTargets(root: string, depth: number, out: string[]): void {
  if (depth > MAX_WALK_DEPTH || out.length >= MAX_FILES) return;
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (out.length >= MAX_FILES) return;
    if (ent.name.startsWith(".") && ent.name !== ".fixture") continue;
    const full = join(root, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIR_NAMES.has(ent.name)) continue;
      walkTargets(full, depth + 1, out);
    } else if (ent.isFile()) {
      if (TARGET_BASENAME.test(ent.name) || SCAN_EXT.test(ent.name)) {
        // Prefer entitlement-shaped basenames; still accept other JS/HTML but
        // only if basename matches target OR path contains panel/license/vault.
        if (
          TARGET_BASENAME.test(ent.name) ||
          /(?:^|\/)(?:panel|license|vault)[^/]*$/i.test(ent.name)
        ) {
          out.push(full);
        }
      }
    }
  }
}

export function discoverAndLintPlaintextSecrets(
  directory: string,
  options: { readonly allowPlaintextString?: boolean } = {},
): PlaintextSecretReport[] {
  const abs = resolve(directory);
  const reports: PlaintextSecretReport[] = [];
  if (!existsSync(abs)) return reports;
  const st = statSync(abs);
  if (st.isFile()) {
    return [lintPlaintextSecretsFile(abs, options)];
  }
  const files: string[] = [];
  walkTargets(abs, 0, files);
  for (const f of files) {
    try {
      reports.push(lintPlaintextSecretsFile(f, options));
    } catch {
      /* skip unreadable */
    }
  }
  return reports;
}

export function plaintextSecretRefuseMessage(
  report: PlaintextSecretReport,
  filePath: string,
): string {
  const ids = [...new Set(report.findings.map((f) => f.id))].join(", ");
  return (
    `Plaintext sensitive literals in ${basename(filePath)} (${ids}). ` +
    `Encrypt with bla_encrypt_strings (seed-derived XOR — never JS-side AES wrap-key) ` +
    `or pass allowPlaintextString / --allow-plaintext-string / allow_plaintext_string (lab only).`
  );
}

export function intensityEnforcesPlaintextSecretRefusal(
  intensity: ProtectionIntensity,
): boolean {
  return intensity === "bankrupt";
}
