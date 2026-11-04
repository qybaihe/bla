import { createHash, createHmac } from "node:crypto";
import {
  realisticIdentifier,
  type IdentifierStyle,
  type RealisticIdentifierOptions,
} from "./identifiers.js";

/**
 * Derive an independent, deterministic sub-seed from a root seed + label via
 * HMAC-SHA256. Same (root, label) → same child seed; different labels do not
 * share PRNG state. Prefer this over string-concat (`${seed}:${name}`) so
 * substreams stay cryptographically independent.
 */
export function deriveSeedLabel(
  rootSeed: string | number,
  label: string,
): string {
  if (typeof label !== "string" || label.length === 0) {
    throw new Error("deriveSeedLabel: label must be a non-empty string");
  }
  return createHmac("sha256", String(rootSeed))
    .update(label, "utf8")
    .digest("hex");
}

/**
 * Deterministic seeded PRNG (SplitMix32 / Mulberry32) so BLA builds can be
 * 100% reproducible given a seed while producing high-entropy decoy identifiers,
 * bogus constants, and opaque predicate coefficients.
 */
export class SeededPrng {
  #state: number;
  readonly seedString: string;

  constructor(seed: string | number = "bla-default-seed-v1") {
    this.seedString = String(seed);
    const digest = createHash("sha256").update(this.seedString).digest();
    this.#state = digest.readUInt32LE(0) ^ digest.readUInt32LE(4) ^ 0x9e3779b9;
    if (this.#state === 0) this.#state = 0x6d2b79f5;
  }

  /**
   * Fork an independent substream keyed by `label` (HMAC-SHA256 of root seed).
   * Drawing from the child does not advance this instance's state.
   */
  derive(label: string): SeededPrng {
    return new SeededPrng(deriveSeedLabel(this.seedString, label));
  }

  nextUint32(): number {
    let t = (this.#state += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }

  nextFloat(): number {
    return this.nextUint32() / 0x1_0000_0000;
  }

  nextInt(minInclusive: number, maxInclusive: number): number {
    if (maxInclusive <= minInclusive) return minInclusive;
    const span = maxInclusive - minInclusive + 1;
    return minInclusive + (this.nextUint32() % span);
  }

  pick<T>(items: readonly T[]): T {
    if (items.length === 0) {
      throw new Error("Cannot pick from an empty array");
    }
    return items[this.nextInt(0, items.length - 1)]!;
  }

  shuffle<T>(items: readonly T[]): T[] {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = this.nextInt(0, i);
      const tmp = copy[i]!;
      copy[i] = copy[j]!;
      copy[j] = tmp;
    }
    return copy;
  }

  hex(length: number): string {
    const chars = "0123456789abcdef";
    let out = "";
    for (let i = 0; i < length; i++) {
      out += chars[this.nextUint32() & 0x0f];
    }
    return out;
  }

  /**
   * Emit a realistic identifier. The legacy `prefix` argument is IGNORED for
   * emitted output — every call draws from the realistic vocabulary so that
   * hardened artifacts contain no greppable `_bla` / `$00_AAA` markers.
   *
   * Pass `style` / `hint` via the second argument (or as RealisticIdentifierOptions)
   * when a specific casing convention is needed.
   */
  identifier(
    prefixOrOptions: string | RealisticIdentifierOptions = "camel",
    maybeOptions?: RealisticIdentifierOptions,
  ): string {
    let options: RealisticIdentifierOptions;
    if (typeof prefixOrOptions === "string") {
      // Legacy callers passed a prefix like "_bla". Map common prefixes to styles;
      // never emit the prefix literally.
      const style: IdentifierStyle =
        prefixOrOptions.startsWith("__")
          ? "privateCamel"
          : prefixOrOptions.startsWith("$")
            ? "earlySort"
            : prefixOrOptions.startsWith("_")
              ? "privateCamel"
              : maybeOptions?.style ?? "camel";
      options = { style, ...(maybeOptions ?? {}) };
    } else {
      options = prefixOrOptions;
    }
    return realisticIdentifier(this, options);
  }
}
