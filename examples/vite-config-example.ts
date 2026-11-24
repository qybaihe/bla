import { blaVitePlugin } from "../src/bundler/index.js";

export default {
  plugins: [
    blaVitePlugin({
      intensity: "bankrupt",
      seed: "enterprise-release-2026",
      honeySourceMap: true,
    }),
  ],
};
