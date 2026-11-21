/**
 * The last mile of `bla harden`: getting hardened bytes into the tree that
 * actually ships.
 *
 * `hardenProject` writes a *partial mirror* (`.bla-hardened/`) holding only the
 * hardened artifacts. Until someone copies those over the build output, the
 * project still ships the unprotected originals — and the mirror cannot be run
 * on its own, because every file BLA did not touch (JSON, CSS, assets) is
 * missing from it. `apply` performs that promotion safely:
 *
 * - **Build output only.** A file is promoted only when it lives inside a
 *   build-output directory. Source files are never overwritten: hardened code
 *   is unreadable, and replacing `src/` with it destroys the project.
 * - **Originals are kept — outside the project.** Each overwritten file is
 *   backed up first so `restore` can undo the promotion. The backups live in a
 *   per-user state directory, never under the project: a `.originals/` folder
 *   beside `dist/` would be swept into an npm tarball or an Electron `.asar` and
 *   ship the unprotected code next to the protected one.
 * - **Re-runs are idempotent.** The state records the hash of every promoted
 *   file. A later run recognises build output that is still the hardened bytes
 *   and re-hardens from the saved originals instead of hardening twice; a file
 *   that changed since (the project was rebuilt) is simply a new original.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { physicalPath } from "../core/output-path.js";
import { resolveBlaStateRoot } from "../core/output-registry.js";
import { writeFileAtomicSync } from "./protector.js";

export const HARDEN_APPLY_STATE_SCHEMA = "bla-apply-state/v1" as const;
const STATE_FILE_NAME = "apply-state.json";
const ORIGINALS_DIR_NAME = "originals";
const SUSPENDED_DIR_NAME = "suspended";

/** One promoted file: what it was, and what it became. */
export interface HardenApplyFileState {
  /** Project-relative POSIX path of the promoted file. */
  readonly relativePath: string;
  /** SHA-256 of the hardened bytes written in place. */
  readonly hardenedSha256: string;
  /** SHA-256 of the file that was there before; `null` when apply created it. */
  readonly originalSha256: string | null;
}

export interface HardenApplyState {
  readonly schema: typeof HARDEN_APPLY_STATE_SCHEMA;
  readonly projectDirectory: string;
  readonly runId: string;
  readonly appliedAtIso: string;
  readonly files: readonly HardenApplyFileState[];
}

export type HardenApplyStatus =
  | "applied"
  /** Dry run: `applied` lists what a real run would overwrite. */
  | "planned"
  | "refused"
  | "failed"
  | "restored"
  | "nothing-to-restore";

export interface HardenApplyReport {
  readonly status: HardenApplyStatus;
  /** Why the promotion was refused or failed. */
  readonly reason?: string;
  /** Project-relative files that now hold hardened bytes. */
  readonly applied?: readonly string[];
  /** Project-relative files apply created (manifests / sidecars beside an artifact). */
  readonly added?: readonly string[];
  /** Project-relative files put back by `restore`. */
  readonly restored?: readonly string[];
  /** Project-relative files `restore` deleted because apply had created them. */
  readonly removed?: readonly string[];
  /** Files `restore` left alone because they changed after the promotion. */
  readonly skippedModified?: readonly string[];
  /** Hardened files that are source code, not build output (refusal detail). */
  readonly sourceFiles?: readonly string[];
  /** Where the originals are kept (outside the project). */
  readonly backupDirectory?: string;
}

export interface HardenApplyCandidate {
  /** Absolute path of the hardened file inside the mirror tree. */
  readonly outputPath: string;
  /** Absolute path it replaces inside the project. */
  readonly destinationPath: string;
}

function sha256OfFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

/**
 * Per-project state directory (backups + `apply-state.json`). Keyed on the
 * project's physical path so `/tmp/x` and `/private/tmp/x` share one state.
 * `stateRoot` overrides the per-user root (tests, sandboxes, CI caches).
 */
export function resolveApplyStateDirectory(
  projectDirectory: string,
  stateRoot?: string,
): string {
  const physical = physicalPath(resolve(projectDirectory));
  const key = createHash("sha256").update(physical).digest("hex").slice(0, 24);
  return join(resolveBlaStateRoot(stateRoot), "apply", key);
}

export function loadApplyState(stateDirectory: string): HardenApplyState | undefined {
  try {
    const parsed: unknown = JSON.parse(
      readFileSync(join(stateDirectory, STATE_FILE_NAME), "utf8"),
    );
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const state = parsed as Partial<HardenApplyState>;
    if (state.schema !== HARDEN_APPLY_STATE_SCHEMA || !Array.isArray(state.files)) {
      return undefined;
    }
    const files = state.files.filter(
      (f): f is HardenApplyFileState =>
        typeof f === "object" &&
        f !== null &&
        typeof f.relativePath === "string" &&
        f.relativePath.length > 0 &&
        !f.relativePath.split("/").includes("..") &&
        !f.relativePath.startsWith("/") &&
        typeof f.hardenedSha256 === "string" &&
        (f.originalSha256 === null || typeof f.originalSha256 === "string"),
    );
    return {
      schema: HARDEN_APPLY_STATE_SCHEMA,
      projectDirectory: typeof state.projectDirectory === "string" ? state.projectDirectory : "",
      runId: typeof state.runId === "string" ? state.runId : "",
      appliedAtIso: typeof state.appliedAtIso === "string" ? state.appliedAtIso : "",
      files,
    };
  } catch {
    return undefined;
  }
}

function writeApplyState(stateDirectory: string, state: HardenApplyState): void {
  mkdirSync(stateDirectory, { recursive: true });
  writeFileAtomicSync(
    join(stateDirectory, STATE_FILE_NAME),
    `${JSON.stringify(state, null, 2)}\n`,
    "utf8",
  );
}

function clearApplyState(stateDirectory: string): void {
  rmSync(stateDirectory, { recursive: true, force: true });
}

/**
 * Replace `destination` with a copy of `source` without a torn intermediate file.
 *
 * Goes through the shared `writeFileAtomicSync` rather than its own
 * `${destination}.${process.pid}.bla-tmp` copy: the shared writer refuses to write
 * through a symlink or hardlink planted at the destination and creates its temp
 * with `flag: "wx"` plus a random suffix, so a pre-planted temp path cannot be
 * followed. Promotion must keep the artifact runnable, and the writer takes the
 * permission bits of an existing destination, so the promoted file's mode is
 * carried over explicitly.
 */
function replaceFile(source: string, destination: string): void {
  const content = readFileSync(source);
  const sourceMode = statSync(source).mode & 0o7777;
  writeFileAtomicSync(destination, content);
  chmodSync(destination, sourceMode);
}

/**
 * Project-relative paths that currently hold the hardened bytes of an earlier
 * promotion — i.e. files that must not be fed to the hardener again as-is.
 */
export function listAppliedFiles(
  projectDirectory: string,
  stateDirectory: string,
): readonly string[] {
  const state = loadApplyState(stateDirectory);
  if (state === undefined) return [];
  const root = resolve(projectDirectory);
  const applied: string[] = [];
  for (const file of state.files) {
    const abs = join(root, file.relativePath);
    try {
      if (statSync(abs).isFile() && sha256OfFile(abs) === file.hardenedSha256) {
        applied.push(file.relativePath);
      }
    } catch {
      /* gone: nothing to protect against */
    }
  }
  return applied;
}

export interface AppliedOutputSuspension {
  /** True when at least one hardened file was swapped back to its original. */
  readonly active: boolean;
  /** Put the hardened files back (the run did not end in a new promotion). */
  resume(): void;
  /** Drop the parked hardened files (a new promotion replaced them). */
  discard(): void;
}

/**
 * Temporarily swap the hardened files of an earlier promotion back to their
 * originals so a re-harden starts from what the build produced. The hardened
 * bytes are parked in the state directory: `resume()` reinstates them, so a
 * re-harden that fails leaves the project exactly as protected as it was.
 */
export function suspendAppliedOutputs(
  projectDirectory: string,
  stateDirectory: string,
): AppliedOutputSuspension {
  const inactive: AppliedOutputSuspension = { active: false, resume() {}, discard() {} };
  const state = loadApplyState(stateDirectory);
  if (state === undefined) return inactive;
  const root = resolve(projectDirectory);
  const originalsDir = join(stateDirectory, ORIGINALS_DIR_NAME);
  const suspendedDir = join(stateDirectory, SUSPENDED_DIR_NAME);
  rmSync(suspendedDir, { recursive: true, force: true });
  const parked: HardenApplyFileState[] = [];
  const reinstate = (): void => {
    for (const file of parked) {
      const parkedCopy = join(suspendedDir, file.relativePath);
      if (existsSync(parkedCopy)) replaceFile(parkedCopy, join(root, file.relativePath));
    }
    rmSync(suspendedDir, { recursive: true, force: true });
  };
  try {
    for (const file of state.files) {
      const abs = join(root, file.relativePath);
      let isHardened = false;
      try {
        isHardened = statSync(abs).isFile() && sha256OfFile(abs) === file.hardenedSha256;
      } catch {
        isHardened = false;
      }
      if (!isHardened) continue;
      const backup = join(originalsDir, file.relativePath);
      if (
        file.originalSha256 !== null &&
        (!existsSync(backup) || sha256OfFile(backup) !== file.originalSha256)
      ) {
        throw new Error(
          `the saved original of ${file.relativePath} is missing or damaged, so it cannot be re-hardened from its original. Rebuild the project, then re-run.`,
        );
      }
      const parkedCopy = join(suspendedDir, file.relativePath);
      mkdirSync(dirname(parkedCopy), { recursive: true });
      copyFileSync(abs, parkedCopy);
      parked.push(file);
      if (file.originalSha256 === null) unlinkSync(abs);
      else replaceFile(backup, abs);
    }
  } catch (err) {
    reinstate();
    throw err;
  }
  if (parked.length === 0) return inactive;
  return {
    active: true,
    resume: reinstate,
    discard: () => rmSync(suspendedDir, { recursive: true, force: true }),
  };
}

/**
 * Undo a promotion: put every original back, delete what apply created, and
 * drop the state. A file whose bytes are no longer the hardened ones (the
 * project was rebuilt, or someone edited it) is left alone and reported.
 */
export function restoreAppliedOriginals(
  projectDirectory: string,
  stateDirectory: string,
): HardenApplyReport {
  const state = loadApplyState(stateDirectory);
  if (state === undefined || state.files.length === 0) {
    clearApplyState(stateDirectory);
    return { status: "nothing-to-restore" };
  }
  const root = resolve(projectDirectory);
  const originalsDir = join(stateDirectory, ORIGINALS_DIR_NAME);
  const restored: string[] = [];
  const removed: string[] = [];
  const skippedModified: string[] = [];
  const failures: string[] = [];
  for (const file of state.files) {
    const abs = join(root, file.relativePath);
    let current: string | undefined;
    try {
      current = statSync(abs).isFile() ? sha256OfFile(abs) : undefined;
    } catch {
      current = undefined;
    }
    if (current === undefined) continue; // deleted since: nothing to undo
    if (file.originalSha256 !== null && current === file.originalSha256) continue; // already original
    if (current !== file.hardenedSha256) {
      skippedModified.push(file.relativePath);
      continue;
    }
    try {
      if (file.originalSha256 === null) {
        unlinkSync(abs);
        removed.push(file.relativePath);
      } else {
        const backup = join(originalsDir, file.relativePath);
        if (!existsSync(backup) || sha256OfFile(backup) !== file.originalSha256) {
          failures.push(`${file.relativePath}: backup missing or damaged`);
          continue;
        }
        replaceFile(backup, abs);
        restored.push(file.relativePath);
      }
    } catch (err) {
      failures.push(`${file.relativePath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (failures.length > 0) {
    // Keep the state: the backups are still the only copy of those originals.
    return {
      status: "failed",
      reason: `Could not restore ${failures.length} file(s): ${failures.join("; ")}. Rebuild the project to regenerate them.`,
      restored,
      ...(removed.length > 0 ? { removed } : {}),
      ...(skippedModified.length > 0 ? { skippedModified } : {}),
      backupDirectory: originalsDir,
    };
  }
  clearApplyState(stateDirectory);
  return {
    status: restored.length + removed.length > 0 ? "restored" : "nothing-to-restore",
    restored,
    ...(removed.length > 0 ? { removed } : {}),
    ...(skippedModified.length > 0 ? { skippedModified } : {}),
  };
}

/** Preferred build-output directory names, searched first under a project root. */
export const BLA_BUILD_OUTPUT_DIR_NAMES = Object.freeze([
  "dist",
  "build",
  "out",
  "release",
  "Release",
  "Debug",
  "x64",
  "Win32",
  "bin",
  ".next",
  "target",
] as const);

/** True when `relativePath` (POSIX, project-relative) lies in a build-output directory. */
export function isInsideBuildOutput(
  relativePath: string,
  projectDirectory: string,
  buildDirNames: readonly string[],
): boolean {
  const names = new Set(buildDirNames);
  const segments = relativePath.split("/").filter((s) => s.length > 0);
  if (segments.slice(0, -1).some((segment) => names.has(segment))) return true;
  // `bla harden dist`: the target itself is the build output.
  return names.has(resolve(projectDirectory).split(sep).pop() ?? "");
}

/**
 * Hardened files under `outputRoot` that mirror a project path: the artifacts
 * themselves plus whatever this run wrote right beside one
 * (`app.js.bla-manifest.json`). Stale leftovers of earlier runs are excluded by
 * `notBeforeMs`.
 */
export function collectApplyCandidates(params: {
  readonly projectDirectory: string;
  readonly outputRoot: string;
  readonly artifactOutputPaths: readonly string[];
  readonly notBeforeMs: number;
}): HardenApplyCandidate[] {
  const outputRoot = resolve(params.outputRoot);
  const projectRoot = resolve(params.projectDirectory);
  const artifacts = new Set(params.artifactOutputPaths.map((p) => resolve(p)));
  const candidates: HardenApplyCandidate[] = [];
  const seen = new Set<string>();
  const push = (outputPath: string): void => {
    if (seen.has(outputPath)) return;
    const rel = relative(outputRoot, outputPath);
    if (rel.length === 0 || rel.startsWith("..")) return;
    seen.add(outputPath);
    candidates.push({ outputPath, destinationPath: join(projectRoot, rel) });
  };
  for (const artifact of artifacts) {
    if (!existsSync(artifact)) continue;
    push(artifact);
    let siblings: string[];
    try {
      siblings = readdirSync(dirname(artifact));
    } catch {
      continue;
    }
    const prefix = `${artifact.split(sep).pop() ?? ""}.`;
    for (const name of siblings) {
      if (!name.startsWith(prefix)) continue;
      const sibling = join(dirname(artifact), name);
      if (artifacts.has(sibling)) continue;
      try {
        const st = statSync(sibling);
        // 2 s of slack for coarse filesystem timestamps.
        if (st.isFile() && st.mtimeMs >= params.notBeforeMs - 2000) push(sibling);
      } catch {
        /* raced away */
      }
    }
  }
  return candidates;
}

/**
 * Promote hardened files over the originals. All-or-nothing: originals are
 * backed up and the state is written before the first overwrite, and a failed
 * copy rolls back everything already promoted.
 */
export function applyHardenedOutputs(params: {
  readonly projectDirectory: string;
  readonly stateDirectory: string;
  readonly runId: string;
  readonly candidates: readonly HardenApplyCandidate[];
  readonly buildDirNames: readonly string[];
}): HardenApplyReport {
  const projectRoot = resolve(params.projectDirectory);
  const relOf = (abs: string): string => toPosix(relative(projectRoot, abs));

  if (params.candidates.length === 0) {
    return { status: "refused", reason: "No hardened files to promote." };
  }
  const sourceFiles = params.candidates
    .map((c) => relOf(c.destinationPath))
    .filter((rel) => !isInsideBuildOutput(rel, projectRoot, params.buildDirNames));
  if (sourceFiles.length > 0) {
    return {
      status: "refused",
      reason:
        `apply only promotes build output, and ${sourceFiles.length} hardened file(s) are not inside a build-output directory ` +
        `(${params.buildDirNames.slice(0, 4).join(", ")}, …). Overwriting them would replace your source code with hardened output. ` +
        "Build the project first and harden the build directory, or copy the project to a staging directory and overlay the hardened mirror there.",
      sourceFiles,
    };
  }

  const originalsDir = join(params.stateDirectory, ORIGINALS_DIR_NAME);
  const previous = loadApplyState(params.stateDirectory);
  const previousByPath = new Map((previous?.files ?? []).map((f) => [f.relativePath, f]));
  const entries: HardenApplyFileState[] = [];
  const plan: Array<{
    readonly candidate: HardenApplyCandidate;
    readonly entry: HardenApplyFileState;
    readonly backupPath: string;
  }> = [];

  try {
    // 1. Back up every original before a single byte of the project changes.
    for (const candidate of params.candidates) {
      const rel = relOf(candidate.destinationPath);
      const backupPath = join(originalsDir, rel);
      const hardenedSha256 = sha256OfFile(candidate.outputPath);
      let originalSha256: string | null = null;
      if (existsSync(candidate.destinationPath)) {
        const currentSha = sha256OfFile(candidate.destinationPath);
        const earlier = previousByPath.get(rel);
        if (
          earlier !== undefined &&
          currentSha === earlier.hardenedSha256 &&
          earlier.originalSha256 !== null &&
          existsSync(backupPath) &&
          sha256OfFile(backupPath) === earlier.originalSha256
        ) {
          // Still the hardened bytes of the previous promotion: the backup we
          // already hold is the real original — never back up hardened output.
          originalSha256 = earlier.originalSha256;
        } else if (earlier !== undefined && currentSha === earlier.hardenedSha256) {
          originalSha256 = earlier.originalSha256;
        } else {
          mkdirSync(dirname(backupPath), { recursive: true });
          copyFileSync(candidate.destinationPath, backupPath);
          originalSha256 = currentSha;
        }
      }
      const entry: HardenApplyFileState = { relativePath: rel, hardenedSha256, originalSha256 };
      entries.push(entry);
      plan.push({ candidate, entry, backupPath });
    }
    // Keep entries of earlier promotions this run did not touch.
    const touched = new Set(entries.map((e) => e.relativePath));
    const carried = (previous?.files ?? []).filter((f) => !touched.has(f.relativePath));

    // 2. Record intent, then 3. overwrite.
    writeApplyState(params.stateDirectory, {
      schema: HARDEN_APPLY_STATE_SCHEMA,
      projectDirectory: projectRoot,
      runId: params.runId,
      appliedAtIso: new Date().toISOString(),
      files: [...carried, ...entries],
    });
  } catch (err) {
    return {
      status: "failed",
      reason: `Could not back up the originals (${err instanceof Error ? err.message : String(err)}); nothing in the project was changed.`,
    };
  }

  const promoted: typeof plan = [];
  try {
    for (const step of plan) {
      replaceFile(step.candidate.outputPath, step.candidate.destinationPath);
      promoted.push(step);
    }
  } catch (err) {
    const rollbackFailures: string[] = [];
    for (const step of promoted) {
      try {
        if (step.entry.originalSha256 === null) unlinkSync(step.candidate.destinationPath);
        else replaceFile(step.backupPath, step.candidate.destinationPath);
      } catch (rollbackErr) {
        rollbackFailures.push(
          `${step.entry.relativePath}: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`,
        );
      }
    }
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: "failed",
      reason:
        rollbackFailures.length === 0
          ? `Promotion failed (${message}); every file already promoted was rolled back.`
          : `Promotion failed (${message}) and ${rollbackFailures.length} file(s) could not be rolled back: ${rollbackFailures.join("; ")}. Run restore, or rebuild the project.`,
      backupDirectory: originalsDir,
    };
  }

  return {
    status: "applied",
    applied: entries.filter((e) => e.originalSha256 !== null).map((e) => e.relativePath),
    ...(entries.some((e) => e.originalSha256 === null)
      ? { added: entries.filter((e) => e.originalSha256 === null).map((e) => e.relativePath) }
      : {}),
    backupDirectory: originalsDir,
  };
}
