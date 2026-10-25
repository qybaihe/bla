import { lstatSync, realpathSync, statSync } from "node:fs";
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

// Resolve existing ancestors too: the destination itself may not exist yet.
// Existing dangling symlinks fail closed rather than being treated as absent.
function physicalPath(path: string): string {
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

/** Admission checks before any output is created. Not a concurrent-writer sandbox. */
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
    const withinInput = rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
    if (inPlace || withinInput) {
      throw new Error("Directory output must be outside the input directory; in-place directory protection is not supported.");
    }
    // Reusing a tree could follow a nested destination symlink into the input
    // or another unrelated directory. Do not merge or delete existing outputs.
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
