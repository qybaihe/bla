import { lstatSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const realpath = realpathSync.native ?? realpathSync;

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
  let ancestor = resolve(path);
  while (!exists(ancestor)) {
    suffix.unshift(basename(ancestor));
    const parent = dirname(ancestor);
    if (parent === ancestor) throw new Error(`Cannot resolve output path: ${path}`);
    ancestor = parent;
  }
  return join(realpath(ancestor), ...suffix);
}

function containsPath(parent: string, path: string): boolean {
  const rel = relative(parent, path);
  return !isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`);
}

function assertNoSymlinkedOutputParents(input: string, output: string): void {
  // Shared ancestry was already chosen by the caller for the input. Only
  // inspect the output-specific components (including any existing prefixes
  // of a path whose immediate parent has yet to be created).
  const source = resolve(input);
  for (let parent = dirname(resolve(output)); !containsPath(parent, source); parent = dirname(parent)) {
    if (lstatSync(parent, { throwIfNoEntry: false })?.isSymbolicLink()) {
      throw new Error(`Refusing symlinked output ancestor: ${parent}`);
    }
    if (parent === dirname(parent)) break;
  }
}

/** Admission checks before any output is created. */
export function assertSafeOutputPath(
  input: string,
  output: string,
  directory: boolean,
  inPlace = false,
): void {
  const physicalInput = realpath(input);
  const physicalOutput = physicalPath(output);
  if (directory) {
    if (inPlace || containsPath(physicalInput, physicalOutput)) {
      throw new Error(
        "Directory output must be outside the input directory; in-place directory protection is not supported.",
      );
    }
    if (exists(output)) {
      throw new Error("Directory output must be a new path; existing outputs are not overwritten.");
    }
    assertNoSymlinkedOutputParents(input, output);
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
  if (!sameFile || !inPlace) assertNoSymlinkedOutputParents(input, output);
}
