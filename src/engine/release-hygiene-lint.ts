import { closeSync, openSync, readSync, statSync } from "node:fs";
import { basename, extname, resolve, sep } from "node:path";
import type { ProtectionIntensity } from "../core/types.js";
import { walkBounded } from "../core/walk.js";

export type ReleaseHygieneLeakKind =
  | "leaked-solution-or-writeup"
  | "leaked-dotenv-secrets"
  | "leaked-private-key"
  | "leaked-debug-symbols";

export interface ReleaseHygieneFinding {
  readonly kind: ReleaseHygieneLeakKind;
  readonly summary: string;
}

export interface ReleaseHygieneFileReport {
  readonly path: string;
  readonly findings: readonly ReleaseHygieneFinding[];
  readonly shouldRefuseBankrupt: boolean;
  readonly oneLineAdvice: string;
}

const SKIP_DIRS: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  ".bla-protected",
  "__pycache__",
]);

const SOLUTION_FILE_NAMES: ReadonlySet<string> = new Set([
  "solution.txt",
  "solution.md",
  "answers.txt",
  "answers.md",
  "writeup.txt",
  "writeup.md",
]);

const PRIVATE_KEY_EXACT_NAMES: ReadonlySet<string> = new Set([
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
]);

const DOTENV_TEMPLATE_SUFFIXES = [".example", ".sample", ".template", ".dist"];

function readBoundedHeadUtf8(filePath: string, maxBytes = 4096): string {
  let fd: number | undefined;
  try {
    fd = openSync(filePath, "r");
    const buf = Buffer.alloc(maxBytes);
    const n = readSync(fd, buf, 0, maxBytes, 0);
    return buf.subarray(0, n).toString("utf8");
  } catch {
    return "";
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

export function intensityEnforcesReleaseHygieneRefusal(
  intensity: ProtectionIntensity,
): boolean {
  return intensity === "bankrupt" || intensity === "maximum";
}

export function releaseHygieneRefuseMessage(
  report: ReleaseHygieneFileReport,
  filePath = report.path,
): string {
  const kinds = report.findings.map((f) => f.kind).join(", ");
  return (
    `Refusing bankrupt/maximum harden on leaked release environment artifact ${filePath} (${kinds}). ` +
    `Autonomous RE agents routinely bypass binary obfuscation by reading residual SOLUTION/writeup notes, ` +
    `.env credentials, private keys, or unstripped .pdb/.dSYM/.dwp debug databases in the shipping directory. ` +
    `Purge the file from the release bundle before hardening (or pass allowReleaseHygieneLeak: true in lab harnesses).`
  );
}

export function lintReleaseHygieneFile(filePath: string): ReleaseHygieneFileReport {
  const abs = resolve(filePath);
  const name = basename(abs);
  const lower = name.toLowerCase();
  const ext = extname(lower);
  const normalizedSegments = abs.split(sep);
  const findings: ReleaseHygieneFinding[] = [];

  if (SOLUTION_FILE_NAMES.has(lower)) {
    findings.push({
      kind: "leaked-solution-or-writeup",
      summary: `Residual solution/writeup file "${name}" allows an RE agent to read answers directly without analyzing the binary`,
    });
  }

  if (
    lower === ".env" ||
    (lower.startsWith(".env.") &&
      !DOTENV_TEMPLATE_SUFFIXES.some((sfx) => lower.endsWith(sfx)))
  ) {
    const head = readBoundedHeadUtf8(abs, 4096);
    if (/(?:^|\r?\n)\s*[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|FLAG)[A-Z0-9_]*\s*=\s*\S+/i.test(head)) {
      findings.push({
        kind: "leaked-dotenv-secrets",
        summary: `Dotenv file "${name}" contains populated secret/key/token assignments inside the target directory`,
      });
    }
  }

  if (PRIVATE_KEY_EXACT_NAMES.has(lower)) {
    findings.push({
      kind: "leaked-private-key",
      summary: `SSH private key file "${name}" is present in the target directory`,
    });
  } else if (ext === ".pem" || ext === ".key" || ext === ".p8") {
    const head = readBoundedHeadUtf8(abs, 4096);
    if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(head)) {
      findings.push({
        kind: "leaked-private-key",
        summary: `PEM private key "${name}" is present in the target directory`,
      });
    }
  }

  if (
    ext === ".pdb" ||
    ext === ".dwp" ||
    normalizedSegments.some((seg) => seg.toLowerCase().endsWith(".dsym"))
  ) {
    findings.push({
      kind: "leaked-debug-symbols",
      summary: `Unstripped native debug symbol artifact "${name}" exposes full function/type names to Ghidra/IDA/REA`,
    });
  }

  const shouldRefuseBankrupt = findings.length > 0;
  const oneLineAdvice = shouldRefuseBankrupt
    ? `Remove leaked release-environment artifact "${name}" (${findings.map((f) => f.kind).join(", ")}) from the shipping tree before hardening.`
    : "No release-hygiene leaks detected.";

  return {
    path: abs,
    findings,
    shouldRefuseBankrupt,
    oneLineAdvice,
  };
}

export function discoverAndLintReleaseHygiene(
  targetPath: string,
): ReleaseHygieneFileReport[] {
  const abs = resolve(targetPath);
  let st;
  try {
    st = statSync(abs);
  } catch {
    return [];
  }

  if (st.isFile()) {
    const single = lintReleaseHygieneFile(abs);
    return single.findings.length > 0 ? [single] : [];
  }
  if (!st.isDirectory()) return [];

  const candidateFiles = walkBounded(abs, {
    maxDepth: 8,
    maxFiles: 4096,
    skipDirs: SKIP_DIRS,
    sortEntries: true,
    accept: (fullPath, name) => {
      const lower = name.toLowerCase();
      const ext = extname(lower);
      if (SOLUTION_FILE_NAMES.has(lower)) return true;
      if (lower === ".env" || lower.startsWith(".env.")) return true;
      if (PRIVATE_KEY_EXACT_NAMES.has(lower)) return true;
      if (ext === ".pem" || ext === ".key" || ext === ".p8") return true;
      if (ext === ".pdb" || ext === ".dwp") return true;
      if (fullPath.toLowerCase().includes(".dsym")) return true;
      return false;
    },
  });

  const out: ReleaseHygieneFileReport[] = [];
  for (const file of candidateFiles) {
    const r = lintReleaseHygieneFile(file);
    if (r.findings.length > 0) {
      out.push(r);
    }
  }
  return out;
}
