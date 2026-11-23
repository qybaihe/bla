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

import { createHash, randomBytes } from "node:crypto";
import {
  constants,
  copyFileSync,
  mkdirSync,
  readFileSync,
  rmSync,
  rmdirSync,
  unlinkSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { physicalPath } from "../core/output-path.js";
import { resolveBlaStateRoot } from "../core/output-registry.js";
import {
  isMissingPath,
  lstatUnlinkedPath,
  realpathOnDisk,
  writeRawFileAtomicSync,
} from "./protector.js";

export const HARDEN_APPLY_STATE_SCHEMA = "bla-apply-state/v1" as const;
const STATE_FILE_NAME = "apply-state.json";
const ORIGINALS_DIR_NAME = "originals";
const APPLY_LOCK_NAME = "transaction.lock";

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
  readonly backupGeneration?: string;
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
  requireFile(path);
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
  const root = resolve(projectDirectory);
  const physical = lstatUnlinkedPath(root) ? realpathOnDisk(root) : physicalPath(root);
  const key = createHash("sha256").update(physical).digest("hex").slice(0, 24);
  return join(resolveBlaStateRoot(stateRoot), "apply", key);
}

function validRelativePath(path: string): boolean {
  return !/[\\:\0]/.test(path) && path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function fileAt(path: string) {
  const stat = lstatUnlinkedPath(path);
  if (stat && !stat.isFile()) throw new Error(`Expected a regular file: ${path}`);
  return stat;
}

function requireFile(path: string) {
  const stat = fileAt(path);
  if (!stat) throw new Error(`File is missing: ${path}`);
  return stat;
}

function destinationExists(path: string): boolean {
  const stat = fileAt(path);
  if (stat && stat.nlink > 1) {
    throw new Error(`Refusing to write through a symlink or hardlinked output: ${path}`);
  }
  return stat !== undefined;
}

function confinedPath(root: string, rel: string): string {
  if (!validRelativePath(rel)) throw new Error(`Path is outside its root: ${rel}`);
  return join(root, rel);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function loadApplyState(stateDirectory: string): HardenApplyState | undefined {
  const path = join(stateDirectory, STATE_FILE_NAME);
  let bytes: string;
  try {
    if (!destinationExists(path)) return undefined;
    bytes = readFileSync(path, "utf8");
  } catch (error) {
    if (isMissingPath(error)) return undefined;
    throw error;
  }

  try {
    const state = JSON.parse(bytes) as Partial<HardenApplyState> | null;
    const seen = new Set<string>();
    const isDigest = (value: unknown): value is string =>
      typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
    if (
      state === null ||
      state.schema !== HARDEN_APPLY_STATE_SCHEMA ||
      typeof state.projectDirectory !== "string" || !isAbsolute(state.projectDirectory) ||
      typeof state.runId !== "string" || state.runId.length === 0 ||
      typeof state.appliedAtIso !== "string" || !Number.isFinite(Date.parse(state.appliedAtIso)) ||
      (state.backupGeneration !== undefined &&
        (typeof state.backupGeneration !== "string" || !/^[a-f0-9]{32}$/.test(state.backupGeneration))) ||
      !Array.isArray(state.files) ||
      !state.files.every((file) => {
        if (
          file === null || typeof file !== "object" ||
          typeof file.relativePath !== "string" || !validRelativePath(file.relativePath) ||
          !isDigest(file.hardenedSha256) ||
          (file.originalSha256 !== null && !isDigest(file.originalSha256)) ||
          seen.has(file.relativePath)
        ) return false;
        seen.add(file.relativePath);
        return true;
      })
    ) {
      throw new Error("invalid apply-state schema");
    }
    return state as HardenApplyState;
  } catch (error) {
    throw new Error(`Cannot use apply state at ${path}: ${errorMessage(error)}`, { cause: error });
  }
}

function loadProjectApplyState(root: string, stateDirectory: string): HardenApplyState | undefined {
  lstatUnlinkedPath(root);
  lstatUnlinkedPath(stateDirectory);
  const rel = relative(physicalPath(root), physicalPath(resolve(stateDirectory)));
  if (rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`))) {
    throw new Error("Apply backups must be stored outside the project.");
  }
  const state = loadApplyState(stateDirectory);
  if (state) {
    lstatUnlinkedPath(state.projectDirectory);
    if (physicalPath(root) !== physicalPath(state.projectDirectory)) {
      throw new Error(`Apply state belongs to a different project: ${state.projectDirectory}`);
    }
  }
  return state;
}

function originalsDirectory(stateDirectory: string, generation?: string): string {
  return join(stateDirectory, generation === undefined ? ORIGINALS_DIR_NAME : `originals-${generation}`);
}

function removeTree(path: string): void {
  if (lstatUnlinkedPath(path)) rmSync(path, { recursive: true, force: true });
}

/** Serialize apply, suspension and restore across processes sharing this state. */
export function withApplyTransaction<T>(stateDirectory: string, action: () => T): T {
  lstatUnlinkedPath(stateDirectory);
  mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
  const lockPath = join(stateDirectory, APPLY_LOCK_NAME);
  lstatUnlinkedPath(lockPath);
  try {
    mkdirSync(lockPath, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`Another apply or restore owns ${lockPath}. If that run exited, check the saved backups before removing the stale lock.`, { cause: error });
    }
    throw error;
  }
  try {
    return action();
  } finally {
    if (lstatUnlinkedPath(lockPath)?.isDirectory()) rmdirSync(lockPath);
  }
}

function unlinkDestination(path: string): void {
  if (destinationExists(path)) unlinkSync(path);
}

/** Copy a regular file into private backup storage. */
function backupFile(source: string, destination: string): void {
  requireFile(source);
  lstatUnlinkedPath(destination);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
}

function replaceFile(source: string, destination: string): void {
  const { mode } = requireFile(source);
  writeRawFileAtomicSync(destination, readFileSync(source), undefined, { mode: mode & 0o7777 });
}

function requireBackup(path: string, digest: string): void {
  if (!fileAt(path) || sha256OfFile(path) !== digest) {
    throw new Error(`Saved original is missing or damaged: ${path}. Rebuild the project if the backup cannot be recovered.`);
  }
}

/**
 * Project-relative paths that currently hold the hardened bytes of an earlier
 * promotion — i.e. files that must not be fed to the hardener again as-is.
 */
export function listAppliedFiles(
  projectDirectory: string,
  stateDirectory: string,
): readonly string[] {
  const root = resolve(projectDirectory);
  const state = loadProjectApplyState(root, stateDirectory);
  if (state === undefined) return [];
  const applied: string[] = [];
  for (const file of state.files) {
    const abs = confinedPath(root, file.relativePath);
    if (fileAt(abs) && sha256OfFile(abs) === file.hardenedSha256) applied.push(file.relativePath);
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
  const root = resolve(projectDirectory);
  const state = loadProjectApplyState(root, stateDirectory);
  if (state === undefined) return inactive;
  const originalsDir = originalsDirectory(stateDirectory, state.backupGeneration);
  const suspendedDir = join(stateDirectory, `suspended-${randomBytes(16).toString("hex")}`);
  const parked: HardenApplyFileState[] = [];
  const reinstate = (): void => {
    for (const file of parked) {
      replaceFile(confinedPath(suspendedDir, file.relativePath), confinedPath(root, file.relativePath));
    }
    removeTree(suspendedDir);
  };
  try {
    for (const file of state.files) {
      const abs = confinedPath(root, file.relativePath);
      if (!fileAt(abs) || sha256OfFile(abs) !== file.hardenedSha256) continue;
      destinationExists(abs);
      const backup = confinedPath(originalsDir, file.relativePath);
      if (file.originalSha256 !== null) requireBackup(backup, file.originalSha256);
      backupFile(abs, confinedPath(suspendedDir, file.relativePath));
      if (file.originalSha256 === null) unlinkDestination(abs);
      else replaceFile(backup, abs);
      parked.push(file);
    }
  } catch (error) {
    reinstate();
    throw error;
  }
  if (parked.length === 0) return inactive;
  return {
    active: true,
    resume: reinstate,
    discard: () => removeTree(suspendedDir),
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
  try {
    if (loadProjectApplyState(resolve(projectDirectory), stateDirectory) === undefined) {
      return { status: "nothing-to-restore" };
    }
    return withApplyTransaction(stateDirectory, () => restoreAppliedOriginalsLocked(projectDirectory, stateDirectory));
  } catch (error) {
    return { status: "failed", reason: `Could not restore applied outputs: ${errorMessage(error)}` };
  }
}

function restoreAppliedOriginalsLocked(
  projectDirectory: string,
  stateDirectory: string,
): HardenApplyReport {
  const root = resolve(projectDirectory);
  let originalsDir: string | undefined;
  const restored: string[] = [];
  const removed: string[] = [];
  const skippedModified: string[] = [];
  try {
    const state = loadProjectApplyState(root, stateDirectory);
    if (state === undefined) return { status: "nothing-to-restore" };
    originalsDir = originalsDirectory(stateDirectory, state.backupGeneration);
    const plan: { file: HardenApplyFileState; destination: string; backup?: string }[] = [];
    for (const file of state.files) {
      const destination = confinedPath(root, file.relativePath);
      if (!fileAt(destination)) continue;
      const current = sha256OfFile(destination);
      if (current === file.originalSha256) continue;
      if (current !== file.hardenedSha256) {
        skippedModified.push(file.relativePath);
        continue;
      }
      destinationExists(destination);
      if (file.originalSha256 === null) {
        plan.push({ file, destination });
      } else {
        const backup = confinedPath(originalsDir, file.relativePath);
        requireBackup(backup, file.originalSha256);
        plan.push({ file, destination, backup });
      }
    }
    for (const step of plan) {
      if (step.backup) {
        replaceFile(step.backup, step.destination);
        restored.push(step.file.relativePath);
      } else {
        unlinkDestination(step.destination);
        removed.push(step.file.relativePath);
      }
    }
    unlinkDestination(join(stateDirectory, STATE_FILE_NAME));
    // The state entry is gone and all restores succeeded. Clean the committed
    // generation without touching a custom staging directory or orphaned backups.
    try {
      removeTree(originalsDir);
    } catch {
      // Restore is committed; an undeletable backup can be reclaimed later.
    }
  } catch (error) {
    return {
      status: "failed",
      reason: `Could not restore applied outputs: ${errorMessage(error)}`,
      restored,
      ...(removed.length > 0 ? { removed } : {}),
      ...(skippedModified.length > 0 ? { skippedModified } : {}),
      ...(originalsDir ? { backupDirectory: originalsDir } : {}),
    };
  }
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
  buildRoots: readonly string[] = [],
): boolean {
  if (!validRelativePath(relativePath)) return false;
  const [topLevel, ...rest] = relativePath.split("/");
  return (rest.length > 0 && buildDirNames.includes(topLevel!)) ||
    buildDirNames.includes(resolve(projectDirectory).split(sep).pop() ?? "") ||
    buildRoots.some((root) => relativePath.startsWith(`${root}/`));
}

/** Map only paths explicitly written by this harden run back into the project. */
export function collectApplyCandidates(params: {
  readonly projectDirectory: string;
  readonly outputRoot: string;
  readonly writtenOutputPaths: readonly string[];
}): HardenApplyCandidate[] {
  const outputRoot = resolve(params.outputRoot);
  const projectRoot = resolve(params.projectDirectory);
  lstatUnlinkedPath(outputRoot);
  lstatUnlinkedPath(projectRoot);
  return [...new Set(params.writtenOutputPaths.map((path) => resolve(path)))].map((outputPath) => {
    const rel = toPosix(relative(outputRoot, outputPath));
    return { outputPath, destinationPath: confinedPath(projectRoot, rel) };
  });
}

/** Promote with private backups and an atomic commit of the new backup index. */
export function applyHardenedOutputs(params: {
  readonly projectDirectory: string;
  readonly stateDirectory: string;
  readonly runId: string;
  readonly candidates: readonly HardenApplyCandidate[];
  readonly buildDirNames: readonly string[];
  readonly buildRoots?: readonly string[];
}, transactionAlreadyHeld = false): HardenApplyReport {
  if (!transactionAlreadyHeld) {
    try {
      loadProjectApplyState(resolve(params.projectDirectory), params.stateDirectory);
      return withApplyTransaction(params.stateDirectory, () => applyHardenedOutputs(params, true));
    } catch (error) {
      return { status: "failed", reason: `Could not start apply: ${errorMessage(error)}` };
    }
  }
  const projectRoot = resolve(params.projectDirectory);
  const relOf = (abs: string): string => toPosix(relative(projectRoot, abs));

  if (params.candidates.length === 0) {
    return { status: "refused", reason: "No hardened files to promote." };
  }
  const sourceFiles = params.candidates
    .map((c) => relOf(c.destinationPath))
    .filter((rel) => !isInsideBuildOutput(rel, projectRoot, params.buildDirNames, params.buildRoots));
  if (sourceFiles.length > 0) {
    return {
      status: "refused",
      reason: "Apply only promotes files under a recognized build output directory. Build the project first or choose an explicit build output directory.",
      sourceFiles,
    };
  }

  if (new Set(params.candidates.map((candidate) => relOf(candidate.destinationPath))).size !== params.candidates.length) {
    return { status: "refused", reason: "Multiple artifacts target the same apply destination." };
  }

  const generation = randomBytes(16).toString("hex");
  const originalsDir = originalsDirectory(params.stateDirectory, generation);
  const rollbackDir = join(params.stateDirectory, `rollback-${generation}`);
  const entries: HardenApplyFileState[] = [];
  const promoted: { destination: string; rollbackPath?: string }[] = [];
  let previousOriginals: string | undefined;
  try {
    const previous = loadProjectApplyState(projectRoot, params.stateDirectory);
    previousOriginals = previous && originalsDirectory(params.stateDirectory, previous.backupGeneration);
    const previousByPath = new Map((previous?.files ?? []).map((file) => [file.relativePath, file]));
    const plan = params.candidates.map((candidate) => {
      const relativePath = relOf(candidate.destinationPath);
      const destination = confinedPath(projectRoot, relativePath);
      const hardenedSha256 = sha256OfFile(candidate.outputPath);
      const currentSha = destinationExists(destination) ? sha256OfFile(destination) : null;
      const earlier = previousByPath.get(relativePath);
      const reuseOriginal = earlier !== undefined && currentSha === earlier.hardenedSha256;
      const originalSha256 = reuseOriginal ? earlier.originalSha256 : currentSha;
      if (originalSha256 !== null) {
        const original = reuseOriginal ? confinedPath(previousOriginals!, relativePath) : destination;
        if (reuseOriginal) requireBackup(original, originalSha256);
        backupFile(original, confinedPath(originalsDir, relativePath));
      }
      let rollbackPath: string | undefined;
      if (currentSha !== null) {
        rollbackPath = confinedPath(rollbackDir, relativePath);
        backupFile(destination, rollbackPath);
      }
      entries.push({ relativePath, hardenedSha256, originalSha256 });
      previousByPath.delete(relativePath);
      return { candidate, destination, rollbackPath };
    });

    const carried = [...previousByPath.values()];
    for (const file of carried) {
      if (file.originalSha256 === null) continue;
      const previousBackup = confinedPath(previousOriginals!, file.relativePath);
      requireBackup(previousBackup, file.originalSha256);
      backupFile(previousBackup, confinedPath(originalsDir, file.relativePath));
    }

    for (const step of plan) {
      replaceFile(step.candidate.outputPath, step.destination);
      promoted.push(step);
    }
    const state: HardenApplyState = {
      schema: HARDEN_APPLY_STATE_SCHEMA,
      projectDirectory: projectRoot,
      runId: params.runId,
      appliedAtIso: new Date().toISOString(),
      backupGeneration: generation,
      files: [...carried, ...entries],
    };
    writeRawFileAtomicSync(join(params.stateDirectory, STATE_FILE_NAME), `${JSON.stringify(state, null, 2)}\n`, "utf8");
  } catch (error) {
    const rollbackFailures: string[] = [];
    for (const step of promoted.reverse()) {
      try {
        if (step.rollbackPath) replaceFile(step.rollbackPath, step.destination);
        else unlinkDestination(step.destination);
      } catch (rollbackError) {
        rollbackFailures.push(errorMessage(rollbackError));
      }
    }
    if (rollbackFailures.length === 0) {
      for (const dir of [originalsDir, rollbackDir]) {
        try { removeTree(dir); } catch { /* leave uncommitted backup data intact */ }
      }
    }
    return {
      status: "failed",
      reason: rollbackFailures.length === 0
        ? `Promotion failed (${errorMessage(error)}); no promotion was committed.`
        : `Promotion failed (${errorMessage(error)}); rollback also failed: ${rollbackFailures.join("; ")}. Pre-promotion copies are in ${rollbackDir}.`,
      ...(previousOriginals !== undefined ? { backupDirectory: previousOriginals } : {}),
    };
  }

  for (const dir of [previousOriginals, rollbackDir]) {
    if (dir === undefined) continue;
    try { removeTree(dir); } catch { /* new state is already committed */ }
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
