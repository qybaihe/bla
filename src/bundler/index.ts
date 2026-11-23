import { posix } from "node:path";
import { parse } from "@babel/parser";
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
  /** File regex filter for chunks/modules to leave untouched. */
  readonly exclude?: RegExp;
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
  const skipped = new Set<string>();
  return {
    note(fileName: string): void {
      skipped.add(fileName);
    },
    report(): void {
      if (skipped.size === 0) return;
      console.warn(
        `[bla-shield] ${pluginName}: ${skipped.size} chunk(s) shipped UNPROTECTED ` +
        `(transform failed, failBuildOnError is false): ${[...skipped].join(", ")}. ` +
        "Fix the parse/transform errors or set failBuildOnError: true."
      );
      skipped.clear();
    },
  };
}

function createFileFilter(include: RegExp, exclude?: RegExp) {
  const included = new RegExp(include);
  const excluded = exclude && new RegExp(exclude);
  return (fileName: string): boolean => {
    included.lastIndex = 0;
    if (excluded) excluded.lastIndex = 0;
    return included.test(fileName) && !excluded?.test(fileName);
  };
}

type RollupOutputOptions = {
  readonly format?: string;
  readonly sourcemap?: boolean | "inline" | "hidden";
  readonly sourcemapBaseUrl?: string;
};

type RollupOutputChunk = {
  type: "chunk";
  fileName: string;
  preliminaryFileName?: string;
  sourcemapFileName?: string | null;
  code: string;
  map: unknown;
};

type RollupOutputBundle = Record<string, { type: "asset" } | RollupOutputChunk>;

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
  const acceptsFile = createFileFilter(include, options.exclude);
  const emitMap = options.honeySourceMap ?? true;
  const failBuildOnError = options.failBuildOnError ?? false;
  const outputs = new WeakMap<RollupOutputOptions, {
    skips: ReturnType<typeof createSkipTracker>;
    protectedChunks: Map<string, string>;
  }>();
  const defaultOutput: RollupOutputOptions = {};
  const outputState = (outputOptions: RollupOutputOptions) => {
    let state = outputs.get(outputOptions);
    if (!state) {
      state = { skips: createSkipTracker("rollup/vite"), protectedChunks: new Map() };
      outputs.set(outputOptions, state);
    }
    return state;
  };

  return {
    name: "bla-shield-rollup-plugin",
    renderChunk(
      code: string,
      chunk: { fileName: string; isEntry?: boolean },
      outputOptions: RollupOutputOptions = defaultOutput,
    ) {
      if (!acceptsFile(chunk.fileName)) {
        return null;
      }
      const seed = deriveSeedLabel(options.seed ?? "bla-rollup", chunk.fileName);
      const sourceType = inferCarrierFromRollupFormat(
        outputOptions?.format,
        chunk.fileName,
      );
      const loader = inferEsbuildLoader(chunk.fileName);
      const { skips, protectedChunks } = outputState(outputOptions);
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
      protectedChunks.set(chunk.fileName, seed);
      // An empty transform map breaks Rollup's mapping chain. A null map here
      // would leave the original mappings (and source contents) in the chain.
      return {
        code: shieldedCode,
        map: outputOptions.sourcemap ? { mappings: "" as const } : null,
      };
    },
    generateBundle(
      this: { emitFile(asset: { type: "asset"; fileName: string; source: string }): string },
      outputOptions: RollupOutputOptions = defaultOutput,
      bundle: RollupOutputBundle,
    ) {
      const { skips, protectedChunks } = outputState(outputOptions);
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== "chunk") continue;
        const seed = protectedChunks.get(chunk.preliminaryFileName ?? chunk.fileName);
        if (seed === undefined) continue;
        const mapName = chunk.sourcemapFileName ?? `${chunk.fileName}.map`;
        if (bundle[mapName]?.type === "asset") delete bundle[mapName];
        chunk.map = null;
        chunk.sourcemapFileName = null;
        chunk.code = chunk.code.replace(/(?:^|\r?\n)\/\/# sourceMappingURL=[^\r\n]*\r?\n?$/, "\n");
        if (!emitMap) continue;

        const prng = new SeededPrng(seed);
        const chaff = generateChaffPayloads(prng, intensity);
        const honeyMap = generateHoneySourceMap(
          chunk.fileName,
          chunk.code.split("\n").length,
          prng,
          chaff,
        );
        this.emitFile({ type: "asset", fileName: mapName, source: honeyMap.jsonString });
        if (outputOptions.sourcemap && outputOptions.sourcemap !== "hidden") {
          const mapUrl = outputOptions.sourcemapBaseUrl
            ? new URL(posix.basename(mapName), outputOptions.sourcemapBaseUrl).toString()
            : posix.relative(posix.dirname(chunk.fileName), mapName);
          chunk.code += `\n//# sourceMappingURL=${mapUrl}\n`;
        }
      }
      outputs.delete(outputOptions);
      skips.report();
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

function declaredWebpackSourceMaps(code: string, assetName: string): string[] {
  if (!/sourceMappingURL\s*=/.test(code)) return [];
  try {
    const ast = parse(code, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      plugins: ["decorators-legacy"],
    });
    const paths: string[] = [];
    for (const comment of ast.comments ?? []) {
      const url = /^\s*[@#]\s*sourceMappingURL\s*=\s*([^\s?#]+)/.exec(comment.value)?.[1];
      if (url && !url.startsWith("//") && !/^[a-z][a-z0-9+.-]*:/i.test(url)) {
        let decoded: string;
        try {
          decoded = decodeURIComponent(url);
        } catch {
          continue;
        }
        const path = posix.isAbsolute(decoded)
          ? posix.normalize(decoded).slice(1)
          : posix.join(posix.dirname(assetName), decoded);
        if (path.endsWith(".map")) paths.push(path);
      }
    }
    return paths;
  } catch {
    return [];
  }
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
            deleteAsset?: (name: string) => void;
            getAsset?: (name: string) => {
              info: { related?: { sourceMap?: string | string[] } };
            } | undefined;
          }) => void,
        ) => void;
      };
    };
  }): void {
    const intensity = this.options.intensity ?? "balanced";
    const include = this.options.include ?? /\.(?:m?js|cjs)$/i;
    const acceptsFile = createFileFilter(include, this.options.exclude);
    const emitMap = this.options.honeySourceMap ?? true;
    const failBuildOnError = this.options.failBuildOnError ?? false;

    compiler.hooks.compilation.tap("BlaWebpackPlugin", (compilation) => {
      const skips = createSkipTracker("webpack");
      compilation.hooks.processAssets.tap(
        {
          name: "BlaWebpackPlugin",
          stage: 2000, // PROCESS_ASSETS_STAGE_OPTIMIZE_TRANSFER (post-minify so Terser cannot fold shields)
        },
        (assets) => {
          for (const assetName of Object.keys(assets)) {
            if (!acceptsFile(assetName)) continue;
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
            const mapName = `${assetName}.map`;
            const related = compilation.getAsset?.(assetName)?.info.related?.sourceMap;
            const relatedMaps = new Set([
              mapName,
              ...(typeof related === "string" ? [related] : related ?? []),
              ...declaredWebpackSourceMaps(rawSource, assetName),
            ]);
            compilation.updateAsset(assetName, createWebpackRawSource(shieldedCode));
            for (const relatedMap of relatedMaps) {
              if (!assets[relatedMap] || (emitMap && relatedMap === mapName)) continue;
              if (compilation.deleteAsset) compilation.deleteAsset(relatedMap);
              else delete assets[relatedMap];
            }
            if (emitMap) {
              const prng = new SeededPrng(seed);
              const chaff = generateChaffPayloads(prng, intensity);
              const honeyMap = generateHoneySourceMap(
                assetName,
                shieldedCode.split("\n").length,
                prng,
                chaff,
              );
              const honeySource = createWebpackRawSource(honeyMap.jsonString);
              if (assets[mapName]) compilation.updateAsset(mapName, honeySource);
              else compilation.emitAsset?.(mapName, honeySource);
            }
          }
          // Same honest build-end summary the Rollup plugin prints; webpack only
          // exposes the asset stage to a structural plugin type.
          skips.report();
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
  const acceptsFile = createFileFilter(include, options.exclude);
  const failBuildOnError = options.failBuildOnError ?? false;

  return {
    name: "bla-shield-esbuild-plugin",
    setup(build: {
      onLoad: (
        opts: { filter: RegExp; namespace: "file" },
        cb: (args: {
          path: string;
          namespace?: string;
        }) => Promise<{ contents: string; loader: JsLoaderType } | null>,
      ) => void;
      onEnd?: (cb: () => void) => void;
    }) {
      const skips = createSkipTracker("esbuild");
      // Real esbuild always provides onEnd; tolerate structural test doubles.
      if (typeof build.onEnd === "function") {
        build.onEnd(() => {
          skips.report();
        });
      }
      // esbuild's Go regex engine does not implement all JavaScript flags or syntax.
      build.onLoad({ filter: /.*/, namespace: "file" }, async (args) => {
        if ((args.namespace !== undefined && args.namespace !== "file") || !acceptsFile(args.path)) return null;
        // Match the dependency directory as a path segment: a project folder
        // named "my-node_modules-backup" is application code, not a dependency.
        if (args.path.split(/[/\\]/).includes("node_modules")) return null;
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
