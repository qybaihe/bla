/**
 * Interleaved integrity coverage matrix (Direction-3).
 *
 * Hash-only topology for multi-checker self-seal / sidecar entanglement.
 * Packaging gates refuse bankrupt when the matrix fails the four predicates
 * below — no probabilistic claims, no forged lint.
 *
 * Schema: bla-integrity-coverage/v1
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

export const INTEGRITY_COVERAGE_SCHEMA = "bla-integrity-coverage/v1" as const;

export interface CoverageMatrix {
  readonly schema: typeof INTEGRITY_COVERAGE_SCHEMA;
  /** Protected artifact paths (and optional colocated checker site ids). */
  readonly nodes: readonly string[];
  /** checker id → nodes that checker verifies (SHA-256 hard-fail targets). */
  readonly edges: Readonly<Record<string, readonly string[]>>;
  /** node → build-time SHA-256 hex (64 lowercase hex). */
  readonly expectedSha256: Readonly<Record<string, string>>;
}

export type CoverageRefuseReason =
  | "uncovered-node"
  | "checker-not-covered"
  | "missing-hash"
  | "invalid-hash"
  | "disconnected"
  | "no-checkers";

export interface CoverageEvaluation {
  readonly schema: typeof INTEGRITY_COVERAGE_SCHEMA;
  readonly ok: boolean;
  readonly shouldRefuseBankrupt: boolean;
  readonly reasons: readonly CoverageRefuseReason[];
  readonly uncoveredNodes: readonly string[];
  readonly uncoveredCheckers: readonly string[];
  readonly missingHashNodes: readonly string[];
  readonly invalidHashNodes: readonly string[];
  readonly checkerCount: number;
  readonly oneLineAdvice: string;
}

const HEX64 = /^[0-9a-f]{64}$/;

function uniqueSorted(xs: readonly string[]): string[] {
  return [...new Set(xs)].sort();
}

/** Weakly connected: treat edges as undirected for the connectivity warning. */
function isWeaklyConnected(
  nodes: readonly string[],
  edges: Readonly<Record<string, readonly string[]>>,
): boolean {
  if (nodes.length <= 1) return true;
  const adj = new Map<string, Set<string>>();
  for (const n of nodes) adj.set(n, new Set());
  for (const [c, targets] of Object.entries(edges)) {
    if (!adj.has(c)) adj.set(c, new Set());
    for (const t of targets) {
      if (!adj.has(t)) adj.set(t, new Set());
      adj.get(c)!.add(t);
      adj.get(t)!.add(c);
    }
  }
  const start = nodes[0]!;
  const seen = new Set<string>();
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const nxt of adj.get(cur) ?? []) {
      if (!seen.has(nxt)) stack.push(nxt);
    }
  }
  return nodes.every((n) => seen.has(n));
}

/**
 * Refuse predicates (bankrupt):
 *  1. Full coverage — every node is listed in at least one edge's targets
 *  2. Anti-single-point — every checker id is itself covered by a *different* checker
 *  3. Hash completeness — every node has a 64-hex expectedSha256
 *  4. Connectivity — undirected coverage graph is weakly connected (else refuse)
 */
export function evaluateCoverageMatrix(matrix: CoverageMatrix): CoverageEvaluation {
  const nodes = uniqueSorted(matrix.nodes ?? []);
  const edges = matrix.edges ?? {};
  const checkers = uniqueSorted(Object.keys(edges));
  const expected = matrix.expectedSha256 ?? {};

  const covered = new Set<string>();
  for (const targets of Object.values(edges)) {
    for (const t of targets) covered.add(t);
  }

  const uncoveredNodes = nodes.filter((n) => !covered.has(n));
  const uncoveredCheckers = checkers.filter((c) => {
    // Covered by a different checker.
    for (const [other, targets] of Object.entries(edges)) {
      if (other === c) continue;
      if (targets.includes(c)) return false;
    }
    return true;
  });

  const missingHashNodes: string[] = [];
  const invalidHashNodes: string[] = [];
  for (const n of nodes) {
    const h = expected[n];
    if (h === undefined || h === "") {
      missingHashNodes.push(n);
    } else if (!HEX64.test(h.toLowerCase())) {
      invalidHashNodes.push(n);
    }
  }

  const reasons: CoverageRefuseReason[] = [];
  if (checkers.length === 0) reasons.push("no-checkers");
  if (uncoveredNodes.length > 0) reasons.push("uncovered-node");
  if (uncoveredCheckers.length > 0) reasons.push("checker-not-covered");
  if (missingHashNodes.length > 0) reasons.push("missing-hash");
  if (invalidHashNodes.length > 0) reasons.push("invalid-hash");

  // Connectivity over the union of nodes ∪ checker ids.
  const connNodes = uniqueSorted([...nodes, ...checkers]);
  const connected = isWeaklyConnected(connNodes, edges);
  if (!connected) reasons.push("disconnected");

  const ok = reasons.length === 0;
  const advice = ok
    ? "Integrity coverage matrix satisfies full coverage, anti-single-point, hashes, and connectivity."
    : `ERROR: Integrity coverage refuse [${reasons.join(", ")}]. ` +
      `Need ≥2 interleaved checkers that cover each other and every node, with sha256 hex for each node.`;

  return {
    schema: INTEGRITY_COVERAGE_SCHEMA,
    ok,
    shouldRefuseBankrupt: !ok,
    reasons,
    uncoveredNodes,
    uncoveredCheckers,
    missingHashNodes,
    invalidHashNodes,
    checkerCount: checkers.length,
    oneLineAdvice: advice,
  };
}

export interface BuildCoverageOptions {
  /** File paths under protection. */
  readonly fileNodes: readonly string[];
  /**
   * Checker host paths (JS modules that can run sha256). When fewer than 2,
   * colocated virtual sites `${host}#site0` / `#site1` are synthesized on the
   * first host so anti-single-point is expressible without a second file.
   */
  readonly checkerHosts: readonly string[];
  /** Build-time hashes for file nodes (and optional virtual checker sites). */
  readonly expectedSha256: Readonly<Record<string, string>>;
  /** How many colocated sites to emit when only one host (default 2). */
  readonly colocatedSites?: number;
}

/**
 * Build a ring/colocated coverage matrix.
 * - ≥2 hosts: ring — host[i] covers host[i+1] plus every file node.
 * - 1 host: colocated sites host#site0 / host#site1 covering each other + files.
 */
export function buildInterleavedCoverageMatrix(
  options: BuildCoverageOptions,
): CoverageMatrix {
  const fileNodes = uniqueSorted(options.fileNodes.filter((p) => p.length > 0));
  const hosts = uniqueSorted(options.checkerHosts.filter((p) => p.length > 0));
  const expectedSha256: Record<string, string> = {};
  for (const [k, v] of Object.entries(options.expectedSha256 ?? {})) {
    if (typeof v === "string" && HEX64.test(v.toLowerCase())) {
      expectedSha256[k] = v.toLowerCase();
    }
  }

  const edges: Record<string, string[]> = {};
  let nodes: string[] = [...fileNodes];

  if (hosts.length >= 2) {
    for (let i = 0; i < hosts.length; i++) {
      const me = hosts[i]!;
      const peer = hosts[(i + 1) % hosts.length]!;
      const targets = uniqueSorted([...fileNodes, peer]);
      edges[me] = targets;
    }
    nodes = uniqueSorted([...fileNodes, ...hosts]);
  } else if (hosts.length === 1) {
    const host = hosts[0]!;
    const nSites = Math.max(2, options.colocatedSites ?? 2);
    const sites: string[] = [];
    for (let i = 0; i < nSites; i++) sites.push(`${host}#site${i}`);
    for (let i = 0; i < sites.length; i++) {
      const me = sites[i]!;
      const peer = sites[(i + 1) % sites.length]!;
      edges[me] = uniqueSorted([...fileNodes, peer]);
    }
    nodes = uniqueSorted([...fileNodes, ...sites]);
    // Virtual checker sites inherit the host file hash when available.
    const hostHash = expectedSha256[host];
    if (hostHash) {
      for (const s of sites) expectedSha256[s] = hostHash;
    }
  }

  return {
    schema: INTEGRITY_COVERAGE_SCHEMA,
    nodes,
    edges,
    expectedSha256,
  };
}

/**
 * Honesty downgrade: drop every edge by which `host#siteN` checkers claim to
 * verify their own host file or sibling sites. Use when the host's runtime self
 * check cannot hard-fail (e.g. self-digest not finalized) — editing the host
 * removes all colocated sites at once, so the matrix must not count them as
 * covering it. Re-evaluate afterwards; single-host trees will then refuse.
 */
export function withoutHostSelfCoverage(
  matrix: CoverageMatrix,
  host: string,
): CoverageMatrix {
  const prefix = `${host}#site`;
  const isSelf = (n: string): boolean => n === host || n.startsWith(prefix);
  const edges: Record<string, readonly string[]> = {};
  for (const [checker, targets] of Object.entries(matrix.edges)) {
    edges[checker] = isSelf(checker) ? targets.filter((t) => !isSelf(t)) : [...targets];
  }
  return {
    schema: INTEGRITY_COVERAGE_SCHEMA,
    nodes: matrix.nodes,
    edges,
    expectedSha256: matrix.expectedSha256,
  };
}

export function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * After checker hosts are written, fill expectedSha256 for file nodes and any
 * colocated virtual sites (`path#siteN` inherits the host file digest).
 */
export function finalizeCoverageMatrixHashes(
  matrix: CoverageMatrix,
  fileBytes: Readonly<Record<string, Buffer | string>>,
): CoverageMatrix {
  const expectedSha256: Record<string, string> = { ...matrix.expectedSha256 };
  for (const [path, bytes] of Object.entries(fileBytes)) {
    const hex = sha256Hex(typeof bytes === "string" ? Buffer.from(bytes) : bytes);
    expectedSha256[path] = hex;
  }
  for (const node of matrix.nodes) {
    const hashIdx = node.indexOf("#site");
    if (hashIdx > 0) {
      const host = node.slice(0, hashIdx);
      if (expectedSha256[host]) expectedSha256[node] = expectedSha256[host]!;
    }
  }
  return {
    schema: INTEGRITY_COVERAGE_SCHEMA,
    nodes: matrix.nodes,
    edges: matrix.edges,
    expectedSha256,
  };
}



const MATRIX_NAMES = new Set([
  "integrity-coverage.json",
  ".bla-integrity-coverage.json",
]);

export interface IntegrityCoverageFileReport extends CoverageEvaluation {
  readonly path: string;
  readonly matrix: CoverageMatrix | null;
  readonly parseError?: string;
}

/**
 * Discover integrity-coverage.json artifacts under a project tree and evaluate
 * each. Missing matrices are not findings — only present-but-failing matrices
 * refuse bankrupt (migration-safe).
 */
export function discoverAndLintIntegrityCoverage(
  directory: string,
): IntegrityCoverageFileReport[] {
  const abs = resolve(directory);
  const out: IntegrityCoverageFileReport[] = [];
  const stack: { dir: string; depth: number }[] = [{ dir: abs, depth: 0 }];
  let files = 0;
  while (stack.length && files < 32) {
    const { dir, depth } = stack.pop()!;
    if (depth > 5) continue;
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (name === "node_modules" || name === ".git") continue;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!MATRIX_NAMES.has(name)) continue;
      files += 1;
      try {
        const raw = JSON.parse(readFileSync(full, "utf8")) as CoverageMatrix;
        const ev = evaluateCoverageMatrix(raw);
        out.push({ ...ev, path: full, matrix: raw });
      } catch (err) {
        out.push({
          schema: INTEGRITY_COVERAGE_SCHEMA,
          ok: false,
          shouldRefuseBankrupt: true,
          reasons: ["invalid-hash"],
          uncoveredNodes: [],
          uncoveredCheckers: [],
          missingHashNodes: [],
          invalidHashNodes: [],
          checkerCount: 0,
          oneLineAdvice: "ERROR: integrity-coverage.json is not valid bla-integrity-coverage/v1 JSON.",
          path: full,
          matrix: null,
          parseError: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }
  return out;
}

export function integrityCoverageRefuseMessage(
  report: IntegrityCoverageFileReport,
  pathLabel: string,
): string {
  return (
    `Refusing integrity-coverage gate at ${pathLabel} [${report.reasons.join(", ")}]. ` +
    report.oneLineAdvice
  );
}
