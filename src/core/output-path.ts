import { randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";

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

/**
 * Crash-safe atomic file write via exclusive temp-file (`wx`) + `renameSync`.
 * Creates the parent directory if it does not exist.
 * Preserves symlink/hardlink target semantics when explicitly overwriting an aliased file.
 */
export function writeFileAtomicSync(
  targetPath: string,
  content: string | NodeJS.ArrayBufferView,
  encoding?: BufferEncoding,
): void {
  const dir = dirname(targetPath);
  mkdirSync(dir, { recursive: true });
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
