import type { ProtectionIntensity } from "../core/types.js";
import { SeededPrng, deriveSeedLabel } from "../core/prng.js";
import { generateChaffPayloads } from "../shields/chaff/chaff-generator.js";
import { generateHoneySourceMap } from "../shields/formats/sourcemap.js";
import {
  inferJsCarrierFromPath,
  inferJsLoaderFromPath,
  transformJavaScriptWithBlaShield,
  type JsCarrierType,
  type JsLoaderType,
} from "../shields/javascript/ast-shield.js";

export interface BlaBundlerPluginOptions {
  /** Protection intensity preset (default: `"balanced"`). */
  readonly intensity?: ProtectionIntensity;
  /** Deterministic PRNG seed for reproducible builds. */
  readonly seed?: string | number;
  /** File regex filter for chunks/modules to shield (default: `/\.(?:m?js|cjs)$/i`). */
  readonly include?: RegExp;
  /** Emit a companion `.map` honey source map for each protected chunk (default: `true`). */
  readonly honeySourceMap?: boolean;
  /**
   * When `true`, a transform failure throws and fails the build. When `false`
   * (the default), a transform failure logs a warning and passes the chunk
   * through unshielded so one bad module does not break the whole build.
   */
  readonly failBuildOnError?: boolean;
}

/**
 * Infers the exact esbuild loader (`"js" | "jsx" | "ts" | "tsx"`) from a module path.
 */
export function inferEsbuildLoader(filePath: string): JsLoaderType {
  return inferJsLoaderFromPath(filePath);
}

/**
 * Maps a Rollup/Vite output format (`"es"`, `"cjs"`, `"iife"`, `"umd"`, `"amd"`, `"system"`)
 * or chunk filename to a BLA JavaScript carrier contract.
 */
export function inferCarrierFromRollupFormat(
  format?: string,
  fileName?: string,
): JsCarrierType {
  if (format) {
    const normalized = format.toLowerCase().trim();
    if (
      normalized === "es" ||
      normalized === "esm" ||
      normalized === "module"
    ) {
      return "module";
    }
    if (normalized === "cjs" || normalized === "commonjs") {
      return "commonjs";
    }
    if (
      normalized === "iife" ||
      normalized === "umd" ||
      normalized === "amd" ||
      normalized === "system"
    ) {
      return "script";
    }
  }
  return inferJsCarrierFromPath(fileName);
}

/**
 * Runs a transform and either returns its code or, when
 * `failBuildOnError` is false, warns and returns `null` so the caller can
 * pass the original code through unshielded.
 */
function shieldOrPassThrough(
  transform: () => { code: string },
  ctx: {
    readonly fileName: string;
    readonly failBuildOnError: boolean;
    readonly onSkip?: (fileName: string) => void;
  },
): string | null {
  try {
    return transform().code;
  } catch (err) {
    if (ctx.failBuildOnError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    console.warn(
      `[bla-shield] skipped protection for ${ctx.fileName}: ${message}`,
    );
    ctx.onSkip?.(ctx.fileName);
    return null;
  }
}

/**
 * Collects the chunks that shipped unshielded so a build can end with one
 * honest summary. A per-chunk `console.warn` alone is easy to lose in a large
 * build log, and a partial shield is exactly the kind of claim the rest of BLA
 * refuses to leave implicit.
 */
function createSkipTracker(pluginName: string) {
  const skipped: string[] = [];
  return {
    note(fileName: string): void {
      skipped.push(fileName);
    },
    summary(): string | null {
      if (skipped.length === 0) return null;
      return (
        `[bla-shield] ${pluginName}: ${skipped.length} chunk(s) shipped UNPROTECTED ` +
        `(transform failed, failBuildOnError is false): ${skipped.join(", ")}. ` +
        "Fix the parse/transform errors or set failBuildOnError: true."
      );
    },
  };
}

/**
 * Vite & Rollup plugin (`blaVitePlugin` / `blaRollupPlugin`) that automatically
 * injects BLA's three-stage adversarial shield into generated JS chunks during `renderChunk`.
 *
 * Usage in `vite.config.ts`:
 * ```ts
 * import { defineConfig } from "vite";
 * import { blaVitePlugin } from "bla-agents/bundler";
 *
 * export default defineConfig({
 *   plugins: [blaVitePlugin({ intensity: "bankrupt" })],
 * });
 * ```
 */
export function blaRollupPlugin(options: BlaBundlerPluginOptions = {}) {
  const intensity = options.intensity ?? "balanced";
  const include = options.include ?? /\.(?:m?js|cjs)$/i;
  const emitMap = options.honeySourceMap ?? true;
  const failBuildOnError = options.failBuildOnError ?? false;
  const skips = createSkipTracker("rollup/vite");

  return {
    name: "bla-shield-rollup-plugin",
    buildEnd() {
      const summary = skips.summary();
      if (summary !== null) console.warn(summary);
    },
    renderChunk(
      code: string,
      chunk: { fileName: string; isEntry?: boolean },
      outputOptions?: { format?: string },
    ) {
      if (!include.test(chunk.fileName)) {
        return null;
      }
      const seed = deriveSeedLabel(options.seed ?? "bla-rollup", chunk.fileName);
      const sourceType = inferCarrierFromRollupFormat(
        outputOptions?.format,
        chunk.fileName,
      );
      const loader = inferEsbuildLoader(chunk.fileName);
      const shieldedCode = shieldOrPassThrough(
        () =>
          transformJavaScriptWithBlaShield(code, {
            intensity,
            seed,
            filename: chunk.fileName,
            sourceType,
            loader,
          }),
        { fileName: chunk.fileName, failBuildOnError, onSkip: (f) => skips.note(f) },
      );
      if (shieldedCode === null) {
        return null; // Rollup treats null as "no change": chunk passes through.
      }
      const transformed = { code: shieldedCode };

      if (!emitMap) {
        return { code: transformed.code, map: null };
      }

      const prng = new SeededPrng(seed);
      const chaff = generateChaffPayloads(prng, intensity);
      const lineCount = transformed.code.split("\n").length;
      const honeyMap = generateHoneySourceMap(
        chunk.fileName,
        lineCount,
        prng,
        chaff,
      );

      return {
        code: transformed.code,
        map: honeyMap.mapObject,
      };
    },
  };
}

/**
 * Alias of `blaRollupPlugin` with `enforce: "post"` for Vite 4/5/6.
 */
export function blaVitePlugin(options: BlaBundlerPluginOptions = {}) {
  return {
    ...blaRollupPlugin(options),
    name: "vite-plugin-bla-shield",
    enforce: "post" as const,
  };
}

function createWebpackRawSource(content: string) {
  const byteBuf = Buffer.from(content, "utf8");
  return {
    source: () => content,
    size: () => byteBuf.length,
    buffer: () => byteBuf,
    map: () => null,
    sourceAndMap: () => ({ source: content, map: null }),
    updateHash: (hash: { update: (data: string | Buffer) => void }) => {
      hash.update(byteBuf);
    },
  };
}

/**
 * Webpack 5 / Rspack plugin class (`BlaWebpackPlugin`) that shields emitted JS assets.
 */
export class BlaWebpackPlugin {
  readonly options: BlaBundlerPluginOptions;

  constructor(options: BlaBundlerPluginOptions = {}) {
    this.options = options;
  }

  apply(compiler: {
    hooks: {
      compilation: {
        tap: (
          name: string,
          cb: (compilation: {
            hooks: {
              processAssets: {
                tap: (
                  opts: { name: string; stage: number },
                  fn: (
                    assets: Record<
                      string,
                      { source: () => string | Buffer; size: () => number }
                    >,
                  ) => void,
                ) => void;
              };
            };
            updateAsset: (
              name: string,
              newSource: { source: () => string; size: () => number },
            ) => void;
            emitAsset?: (
              name: string,
              newSource: { source: () => string; size: () => number },
            ) => void;
          }) => void,
        ) => void;
      };
    };
  }): void {
    const intensity = this.options.intensity ?? "balanced";
    const include = this.options.include ?? /\.(?:m?js|cjs)$/i;
    const emitMap = this.options.honeySourceMap ?? true;
    const failBuildOnError = this.options.failBuildOnError ?? false;
    const skips = createSkipTracker("webpack");

    compiler.hooks.compilation.tap("BlaWebpackPlugin", (compilation) => {
      compilation.hooks.processAssets.tap(
        {
          name: "BlaWebpackPlugin",
          stage: 2000, // PROCESS_ASSETS_STAGE_OPTIMIZE_TRANSFER (post-minify so Terser cannot fold shields)
        },
        (assets) => {
          for (const assetName of Object.keys(assets)) {
            if (!include.test(assetName)) continue;
            const rawAsset = assets[assetName];
            if (!rawAsset) continue;
            const rawSource = rawAsset.source().toString("utf8");
            const seed = deriveSeedLabel(this.options.seed ?? "bla-webpack", assetName);
            const sourceType = inferJsCarrierFromPath(assetName);
            const loader = inferEsbuildLoader(assetName);
            const shieldedCode = shieldOrPassThrough(
              () =>
                transformJavaScriptWithBlaShield(rawSource, {
                  intensity,
                  seed,
                  filename: assetName,
                  sourceType,
                  loader,
                }),
              { fileName: assetName, failBuildOnError, onSkip: (f) => skips.note(f) },
            );
            if (shieldedCode === null) {
              continue; // Webpack leaves the already-emitted asset untouched.
            }
            compilation.updateAsset(assetName, createWebpackRawSource(shieldedCode));
            if (emitMap && typeof compilation.emitAsset === "function" && !assets[`${assetName}.map`]) {
              const prng = new SeededPrng(seed);
              const chaff = generateChaffPayloads(prng, intensity);
              const honeyMap = generateHoneySourceMap(
                assetName,
                shieldedCode.split("\n").length,
                prng,
                chaff,
              );
              compilation.emitAsset(`${assetName}.map`, createWebpackRawSource(honeyMap.jsonString));
            }
          }
          // Same honest build-end summary the Rollup plugin prints; webpack only
          // exposes the asset stage to a structural plugin type.
          const summary = skips.summary();
          if (summary !== null) console.warn(summary);
        },
      );
    });
  }
}

/**
 * esbuild plugin (`blaEsbuildPlugin`) that shields JS/TS/JSX/TSX entrypoints or modules
 * while preserving the exact esbuild loader (`js`, `jsx`, `ts`, `tsx`) and module carrier.
 */
export function blaEsbuildPlugin(options: BlaBundlerPluginOptions = {}) {
  const intensity = options.intensity ?? "balanced";
  const include = options.include ?? /\.(?:[cm]?[jt]sx?)$/i;
  const failBuildOnError = options.failBuildOnError ?? false;

  return {
    name: "bla-shield-esbuild-plugin",
    setup(build: {
      onLoad: (
        opts: { filter: RegExp },
        cb: (args: {
          path: string;
        }) => Promise<{ contents: string; loader: JsLoaderType } | null>,
      ) => void;
      onEnd?: (cb: () => void) => void;
    }) {
      const skips = createSkipTracker("esbuild");
      // Real esbuild always provides onEnd; tolerate structural test doubles.
      if (typeof build.onEnd === "function") {
        build.onEnd(() => {
          const summary = skips.summary();
          if (summary !== null) console.warn(summary);
        });
      }
      build.onLoad({ filter: include }, async (args) => {
        if (args.path.includes("node_modules")) return null;
        const fs = await import("node:fs/promises");
        const source = await fs.readFile(args.path, "utf8");
        const loader = inferEsbuildLoader(args.path);
        const pathCarrier = inferJsCarrierFromPath(args.path);
        const sourceType: JsCarrierType =
          pathCarrier === "script" &&
          /(?:^|\n)\s*(?:import\s+(?:[\w*{]|["'])|export\s+(?:default\b|const\b|let\b|var\b|function\b|async\b|class\b|type\b|interface\b|enum\b|\{|\*))/m.test(
            source,
          )
            ? "module"
            : pathCarrier;
        const shieldedCode = shieldOrPassThrough(
          () =>
            transformJavaScriptWithBlaShield(source, {
              intensity,
              seed: deriveSeedLabel(options.seed ?? "bla-esbuild", args.path),
              filename: args.path,
              loader,
              sourceType,
            }),
          { fileName: args.path, failBuildOnError, onSkip: (f) => skips.note(f) },
        );
        if (shieldedCode === null) {
          return null; // esbuild falls back to reading the file as-is.
        }
        return {
          contents: shieldedCode,
          loader,
        };
      });
    },
  };
}
