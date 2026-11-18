/**
 * Which files on this machine did BLA itself write?
 *
 * Hardened output is full of deliberate bait: decoy routes, attestation
 * strings, per-byte comparison tables. Fed back into BLA it reads as an
 * unprotected program with a hundred plaintext secrets and a lane-independent
 * gate — so `bla_harden` after a `bla_defend` that wrote `dist/app.hard.js`
 * refused the run on BLA's own decoys, and `bla_lint` told the agent to
 * "refactor" a file nobody should edit. Skipping `.bla-hardened/` by name does
 * not cover an explicit output path or build output promoted in place.
 *
 * Hardened files carry no in-band marker (a recognisable signature would be a
 * gift to the reverse engineer), so recognition is out-of-band: every user
 * facing write records the SHA-256 of what it wrote in a per-user state
 * directory. A file is "BLA output" exactly while its bytes are still the ones
 * BLA wrote — rebuild or edit it and it is an ordinary input again.
 *
 * Layout: `<state root>/outputs/<byte size>/<sha256>` (empty marker files). The
 * size level lets a lookup reject nearly every file with one `stat`, without
 * hashing it. Everything here is best effort: a read-only cache directory
 * must never fail a hardening run.
 */

import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { homedir, platform } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { walkBounded } from "./walk.js";

const OUTPUTS_DIR_NAME = "outputs";
/** Prune only once the registry is large; markers are empty files. */
const PRUNE_THRESHOLD_DIRS = 4096;
const PRUNE_MAX_AGE_MS = 120 * 24 * 60 * 60 * 1000;

/**
 * Per-user BLA state root. `BLA_STATE_DIR` overrides it (tests, sandboxes, CI
 * caches); an explicit `stateRoot` argument overrides both.
 */
export function resolveBlaStateRoot(stateRoot?: string): string {
  if (stateRoot !== undefined && stateRoot.trim().length > 0) return resolve(stateRoot);
  const override = process.env.BLA_STATE_DIR;
  if (override !== undefined && override.trim().length > 0) return resolve(override);
  const home = homedir();
  if (platform() === "darwin") return join(home, "Library", "Caches", "bla-agents");
  if (platform() === "win32") {
    const local = process.env.LOCALAPPDATA;
    return join(
      local !== undefined && local.length > 0 ? local : join(home, "AppData", "Local"),
      "bla-agents",
    );
  }
  const xdg = process.env.XDG_CACHE_HOME;
  return join(xdg !== undefined && xdg.length > 0 ? xdg : join(home, ".cache"), "bla-agents");
}

/** Hash cache: a lint run asks about the same file once per gate. */
const hashCache = new Map<string, { size: number; mtimeMs: number; sha256: string }>();
const HASH_CACHE_LIMIT = 4096;

function sha256Cached(path: string, size: number, mtimeMs: number): string {
  const hit = hashCache.get(path);
  if (hit !== undefined && hit.size === size && hit.mtimeMs === mtimeMs) return hit.sha256;
  const sha256 = createHash("sha256").update(readFileSync(path)).digest("hex");
  if (hashCache.size >= HASH_CACHE_LIMIT) hashCache.clear();
  hashCache.set(path, { size, mtimeMs, sha256 });
  return sha256;
}

function pruneOutputs(outputsRoot: string): void {
  let names: string[];
  try {
    names = readdirSync(outputsRoot);
  } catch {
    return;
  }
  if (names.length <= PRUNE_THRESHOLD_DIRS) return;
  const cutoff = Date.now() - PRUNE_MAX_AGE_MS;
  for (const name of names) {
    const dir = join(outputsRoot, name);
    try {
      if (statSync(dir).mtimeMs < cutoff) rmSync(dir, { recursive: true, force: true });
    } catch {
      /* raced with another process — nothing to do */
    }
  }
}

/**
 * Record that `path` currently holds bytes BLA wrote. Never throws.
 */
export function registerBlaOutput(path: string, stateRoot?: string): void {
  try {
    const abs = resolve(path);
    const stat = statSync(abs);
    if (!stat.isFile()) return;
    const sha256 = sha256Cached(abs, stat.size, stat.mtimeMs);
    const outputsRoot = join(resolveBlaStateRoot(stateRoot), OUTPUTS_DIR_NAME);
    const sizeDir = join(outputsRoot, String(stat.size));
    const marker = join(sizeDir, sha256);
    if (existsSync(marker)) return;
    mkdirSync(sizeDir, { recursive: true });
    closeSync(openSync(marker, "w"));
    pruneOutputs(outputsRoot);
  } catch {
    /* best effort — an unwritable cache must not fail the run */
  }
}

/**
 * `true` while `path` still holds exactly the bytes a BLA run on this machine
 * wrote. Never throws; an unreadable file or registry answers `false`.
 */
export function isKnownBlaOutput(path: string, stateRoot?: string): boolean {
  try {
    const abs = resolve(path);
    const stat = statSync(abs);
    if (!stat.isFile()) return false;
    const sizeDir = join(resolveBlaStateRoot(stateRoot), OUTPUTS_DIR_NAME, String(stat.size));
    if (!existsSync(sizeDir)) return false;
    return existsSync(join(sizeDir, sha256Cached(abs, stat.size, stat.mtimeMs)));
  } catch {
    return false;
  }
}

/**
 * BLA output files under `directory` (project-relative POSIX paths, sorted,
 * capped) — what a directory lint leaves out. `.bla-hardened/` is skipped by
 * name everywhere, so it is not listed.
 */
export function listKnownBlaOutputs(
  directory: string,
  options: { readonly stateRoot?: string; readonly maxListed?: number } = {},
): string[] {
  const root = resolve(directory);
  const maxListed = options.maxListed ?? 24;
  try {
    if (!existsSync(join(resolveBlaStateRoot(options.stateRoot), OUTPUTS_DIR_NAME))) return [];
    if (!statSync(root).isDirectory()) return [];
  } catch {
    return [];
  }
  return walkBounded(root, {
    maxDepth: 8,
    maxFiles: maxListed,
    skipDirs: new Set(["node_modules", ".git", ".bla-hardened"]),
    skipHiddenDirs: true,
    sortEntries: true,
    accept: (full) => isKnownBlaOutput(full, options.stateRoot),
  }).map((full) => relative(root, full).split(sep).join("/"));
}

/** Directory-walk filter: drop files that are BLA's own output. */
export function withoutKnownBlaOutputs(
  paths: readonly string[],
  stateRoot?: string,
): string[] {
  return paths.filter((path) => !isKnownBlaOutput(path, stateRoot));
}
