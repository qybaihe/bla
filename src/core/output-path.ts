import { randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const PROTECTED_PATH_SEGMENTS = new Set([".git", ".hg", ".svn", "node_modules"]);

function exists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export function physicalPath(path: string): string {
  const suffix: string[] = [];
  let ancestor = path;
  while (!exists(ancestor)) {
    suffix.unshift(basename(ancestor));
    const parent = dirname(ancestor);
    if (parent === ancestor) throw new Error(`Cannot resolve output path: ${path}`);
    ancestor = parent;
  }
  return join(realpathSync(ancestor), ...suffix);
}

/**
 * Validate an auxiliary output directory (`out_dir` / `outDir`) before creating
 * or writing files inside it. Rejects filesystem roots, `.git`/`.hg`/`.svn`/`node_modules`
 * segments, and existing non-directory targets.
 */
export function assertSafeOutDir(outDir: string): string {
  if (typeof outDir !== "string" || outDir.trim().length === 0) {
    throw new Error("Output directory must be a non-empty path.");
  }
  const abs = resolve(outDir);
  const physical = physicalPath(abs);
  if (dirname(physical) === physical) {
    throw new Error(`Refusing to use filesystem root as output directory: ${outDir}`);
  }
  const segments = physical.split(/[\\/]+/).filter(Boolean);
  for (const seg of segments) {
    if (PROTECTED_PATH_SEGMENTS.has(seg)) {
      throw new Error(
        `Refusing to write into protected directory segment "${seg}": ${outDir}`,
      );
    }
  }
  if (exists(abs)) {
    const st = statSync(abs);
    if (!st.isDirectory()) {
      throw new Error(`Output directory path exists and is not a directory: ${outDir}`);
    }
  }
  return abs;
}

/**
 * Crash-safe atomic file write via exclusive temp-file (`wx`) + `renameSync`.
 * Preserves symlink/hardlink target semantics when explicitly overwriting an aliased file.
 */
export function writeFileAtomicSync(
  targetPath: string,
  content: string | Uint8Array,
  encoding?: BufferEncoding,
): void {
  try {
    const st = lstatSync(targetPath);
    if (st.isSymbolicLink() || st.nlink > 1) {
      if (encoding && typeof content === "string") {
        writeFileSync(targetPath, content, encoding);
      } else {
        writeFileSync(targetPath, content);
      }
      return;
    }
  } catch {
    /* target does not exist yet — proceed with the atomic path */
  }
  const tmpPath = `${targetPath}.bla-tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    if (encoding && typeof content === "string") {
      writeFileSync(tmpPath, content, { encoding, flag: "wx" });
    } else {
      writeFileSync(tmpPath, content, { flag: "wx" });
    }
    renameSync(tmpPath, targetPath);
  } catch (err) {
    try {
      if (existsSync(tmpPath)) unlinkSync(tmpPath);
    } catch {
      // Ignore cleanup failure
    }
    throw err;
  }
}

/** Admission checks before any output is created. */
export function assertSafeOutputPath(
  input: string,
  output: string,
  directory: boolean,
  inPlace = false,
): void {
  const physicalInput = realpathSync(input);
  const physicalOutput = physicalPath(output);
  if (directory) {
    const rel = relative(physicalInput, physicalOutput);
    const withinInput =
      rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
    if (inPlace || withinInput) {
      throw new Error(
        "Directory output must be outside the input directory; in-place directory protection is not supported.",
      );
    }
    if (exists(output)) {
      throw new Error("Directory output must be a new path; existing outputs are not overwritten.");
    }
    return;
  }

  let sameFile = physicalInput === physicalOutput;
  if (!sameFile && exists(output)) {
    const source = statSync(input);
    const destination = statSync(output);
    sameFile = source.dev === destination.dev && source.ino === destination.ino;
  }
  if (sameFile && !inPlace) {
    throw new Error("Output refers to the input file; explicitly enable inPlace to overwrite it.");
  }
}
