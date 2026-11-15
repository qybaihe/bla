# Bundler & CI/CD One-Click Defense Integration

## 1. Vite / Rollup / Webpack / esbuild Integration

```ts
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-agents/bundler";

export default defineConfig({
  plugins: [
    blaVitePlugin({
      intensity: "bankrupt",
      honeySourceMap: true,
    }),
  ],
});
```

Chunk-level protection is never silently partial. When a chunk fails to parse or transform and `failBuildOnError` is `false` (the default), that chunk ships **unshielded**, and the plugin prints one build-end summary listing every affected chunk:

```text
[bla-shield] rollup/vite: 2 chunk(s) shipped UNPROTECTED (transform failed, failBuildOnError is false): a.js, b.js. Fix the parse/transform errors or set failBuildOnError: true.
```

Set `failBuildOnError: true` to fail the build at the first bad chunk instead. The Rollup/Vite and esbuild plugins print the summary from their build-end hook; the Webpack plugin prints it at the end of the asset stage.

## 2. GitHub Actions Post-Build Hardening

Add a single step after `npm run build` in your release workflow:

```yaml
- name: Harden release build against REA (One-Click BLA Blue Shield)
  run: npx -y bla-agents@latest defend ./dist -o ./dist-shielded --manifest
```
