import { execFileSync } from "node:child_process";

/**
 * Resolves a usable Python 3 interpreter for tests.
 *
 * Prefers `python3`, falls back to `python` (Windows installs often expose the
 * real interpreter only as `python`, while `python3` resolves to the Microsoft
 * Store stub that always fails). Requires Python >= 3.8 so the produced .pyc
 * matches a layout the weave understands. Returns null when nothing usable
 * exists — callers must `it.skipIf(...)` instead of failing.
 */
export function resolvePython3(): string | null {
  for (const candidate of ["python3", "python"]) {
    try {
      execFileSync(
        candidate,
        ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"],
        { stdio: "pipe" },
      );
      return candidate;
    } catch {
      /* try the next candidate */
    }
  }
  return null;
}

/** Interpreter resolved once per test file. Null when unavailable. */
export const PY3: string | null = resolvePython3();

/**
 * Non-null accessor for use inside tests guarded by `it.skipIf(!PY3)`.
 * Throws instead of silently passing `null` to `execFileSync`.
 */
export function python3(): string {
  if (!PY3) {
    throw new Error("No Python >= 3.8 interpreter available (test should be skipped)");
  }
  return PY3;
}
