/**
 * Weave-decoy theory + read-only planner for Counter-REA hardening.
 *
 * DEFENSIVE ONLY: helps agents entangle decoys with real customer call graphs
 * so REA/WorkBuddy-style peel cannot dismiss them as a separate noise layer.
 * No crack / RE / bypass playbooks.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { detectArtifactFormat } from "../../core/detector.js";
import type { ArtifactFormat } from "../../core/types.js";

export const WEAVE_DECOY_DOC_PATH = "docs/weave-decoy-mcp.md" as const;
export const WEAVE_DECOY_SCHEMA = "bla-weave-plan/v1" as const;
export const WEAVE_DIRECTIVES_URI = "bla://directives/weave-decoy" as const;

/** How far today's pipeline already weaves decoys into customer logic. */
export type WeaveMaturity =
  | "woven"
  | "warm-init-only"
  | "sidecar-decoy"
  | "not-applicable"
  | "gap";

export type WeavePlanStatus = "ready" | "partial" | "gap" | "unsupported";

export interface WeavePrinciple {
  readonly id: string;
  readonly titleZh: string;
  readonly titleEn: string;
  readonly summaryZh: string;
}

export interface WeaveForbiddenPattern {
  readonly id: string;
  readonly titleZh: string;
  readonly whyZh: string;
}

export interface WeaveAcceptanceTest {
  readonly id: string;
  readonly titleZh: string;
  readonly checkEn: string;
}

export interface WeaveChecklistStep {
  readonly id: string;
  readonly phase: "analyze" | "apply" | "verify";
  readonly titleZh: string;
  readonly actionEn: string;
}

export interface WeaveTargetEntry {
  readonly path: string;
  readonly relativePath: string;
  readonly format: ArtifactFormat;
  readonly maturity: WeaveMaturity;
  readonly status: WeavePlanStatus;
  readonly notesZh: string;
  readonly recommendedActions: readonly string[];
}

export interface WeavePlan {
  readonly schema: typeof WEAVE_DECOY_SCHEMA;
  readonly docPath: typeof WEAVE_DECOY_DOC_PATH;
  readonly directivesUri: typeof WEAVE_DIRECTIVES_URI;
  readonly targetPath: string;
  readonly analyzedAtIso: string;
  readonly overallStatus: WeavePlanStatus;
  readonly summaryZh: string;
  readonly targets: readonly WeaveTargetEntry[];
  readonly principles: readonly WeavePrinciple[];
  readonly forbidden: readonly WeaveForbiddenPattern[];
  readonly acceptanceTests: readonly WeaveAcceptanceTest[];
  readonly checklist: readonly WeaveChecklistStep[];
  readonly pipelineHook: {
    readonly mcpFlag: "weave_decoys";
    readonly hardenOption: "weaveDecoys";
    readonly todayBehaviorZh: string;
    readonly followUpZh: string;
  };
}

export const WEAVE_PRINCIPLES: readonly WeavePrinciple[] = Object.freeze([
  {
    id: "shared-state",
    titleZh: "与真实代码共享可变状态",
    titleEn: "Shared mutable state with real code",
    summaryZh:
      "诱饵必须读写与业务路径同一批运行时槽位（epoch / peer / digest），不能只是孤立局部变量或空 pass。",
  },
  {
    id: "customer-reachable",
    titleZh: "从客户入口可达",
    titleEn: "Reachable from customer entry",
    summaryZh:
      "诱饵调用必须落在真实入口、路由处理器或导出 API 的调用图上；仅靠模块顶层 warm-init 不够对抗会过滤「独立层」的智能体。",
  },
  {
    id: "mixed-vocab",
    titleZh: "平凡业务名与安全诱饵名混用",
    titleEn: "Mixed mundane + security vocabulary",
    summaryZh:
      "标识符约 2/3 用 invoice/session/cache/locale 等平凡词干，约 1/3 用 enclave/TPM 等诱饵词干，避免一次 grep 整层丢弃。",
  },
  {
    id: "opaque-true-happy-path",
    titleZh: "快乐路径用不透明真谓词缠绕",
    titleEn: "Opaque-true on happy path / no dead-only graphs",
    summaryZh:
      "真实语句用不透明-真守卫包裹，使盲目删除破坏行为；不可只用不透明-假把诱饵塞进永不到达的死图。",
  },
  {
    id: "call-graph-entanglement",
    titleZh: "调用图纠缠",
    titleEn: "Call graph entanglement",
    summaryZh:
      "在真实函数体内织入步进器 / 诱饵互调 / 影子堆搅动，使 xref 与过程搜索看到业务与诱饵同图。",
  },
  {
    id: "optional-self-seal",
    titleZh: "可选自密封绑定",
    titleEn: "Optional self-seal binding",
    summaryZh:
      "可选：把入口结果与完整字节 / 认知装甲 digest 绑定，使剥离诱饵层的篡改在运行期失败（产品缺口见 issue #40）。",
  },
]);

export const WEAVE_FORBIDDEN: readonly WeaveForbiddenPattern[] = Object.freeze([
  {
    id: "pure-noise-layer",
    titleZh: "纯噪声层 / 可整层剥离的 honeypot 文件",
    whyZh:
      "WorkBuddy 类智能体会把空 `_bla_*`、同质 scare 包、与业务无关的 sidecar 识别为可丢弃噪声，难度不升反降。",
  },
  {
    id: "greppable-banners",
    titleZh: "可 grep 的 BLA-SHIELD / `_bla_` 横幅",
    whyZh: "提供「这是防护层」的明确证据，方便过滤器一刀切。",
  },
  {
    id: "tee-only-vocab",
    titleZh: "仅 TEE/TPM/Nitro/enclave 词表",
    whyZh: "同质 scare 词汇让一次正则即可丢弃整图；必须混入平凡业务词干。",
  },
  {
    id: "dead-only-decoys",
    titleZh: "仅死代码 / 永不调用的 pass 桩",
    whyZh: "静态可达性与 xref 会标为未引用；暖启动或入口织入才能保住图连通。",
  },
  {
    id: "offensive-content",
    titleZh: "破解 / RE / 绕过 PoC 与攻击剧本",
    whyZh: "BLA 只做防御加固；MCP 与文档不得提供进攻内容。",
  },
]);

export const WEAVE_ACCEPTANCE_TESTS: readonly WeaveAcceptanceTest[] =
  Object.freeze([
    {
      id: "no-forbidden-markers",
      titleZh: "无禁止标记",
      checkEn:
        "Hardened output has no greppable `_bla_` / `BLA-SHIELD` banners (auditor phrase `runtime attestation boundary` may remain).",
    },
    {
      id: "mixed-stems",
      titleZh: "词干混用",
      checkEn:
        "Decoy identifier stems are not 100% TEE/enclave; mundane stems appear in the same graph.",
    },
    {
      id: "shared-state-mutation",
      titleZh: "共享状态变异",
      checkEn:
        "Decoy bodies mutate a shared runtime slot/dict that customer-path code also touches or depends on after weave.",
    },
    {
      id: "customer-entry-edges",
      titleZh: "客户入口边",
      checkEn:
        "Static xref from customer entry / exported handlers reaches at least one decoy call (not warm-init alone for JS; Python warm-init is interim only).",
    },
    {
      id: "opaque-true-entanglement",
      titleZh: "不透明真缠绕",
      checkEn:
        "A sample of real happy-path statements is guarded by opaque-true; deleting those guards or decoy callees changes behavior or verification.",
    },
    {
      id: "filter-resistance",
      titleZh: "抗「独立层」过滤",
      checkEn:
        "An agent cannot classify the decoy set as a separate dismissible layer using empty-body / homogeneous-scare / unreferenced heuristics alone.",
    },
  ]);

export const WEAVE_EXECUTOR_CHECKLIST: readonly WeaveChecklistStep[] =
  Object.freeze([
    {
      id: "read-theory",
      phase: "analyze",
      titleZh: "读取理论包",
      actionEn: `Read ${WEAVE_DECOY_DOC_PATH} or MCP resource ${WEAVE_DIRECTIVES_URI}; do not invent offensive steps.`,
    },
    {
      id: "run-weave-plan",
      phase: "analyze",
      titleZh: "生成织入计划",
      actionEn:
        "Call MCP `bla_weave_plan` on the project/build path; keep the returned JSON as the work order.",
    },
    {
      id: "prefer-pipeline-flag",
      phase: "apply",
      titleZh: "走 harden 管线旗标",
      actionEn:
        "Call `bla_harden` / `bla_defend` / `bla_protect` with `weave_decoys: true` so the run is labeled and future AST weave hooks activate.",
    },
    {
      id: "js-entangle",
      phase: "apply",
      titleZh: "确认 JS 已织入",
      actionEn:
        "For JS/TS: existing `ast-shield` already weaves opaque-true + tarpit calls into real function bodies — verify, do not add a second noise sidecar.",
    },
    {
      id: "python-gap",
      phase: "apply",
      titleZh: "Python 缺口标注",
      actionEn:
        "For Python: today is warm-init-only after densify (#51). Full weave into customer defs is a follow-up PR — do not pile empty scare modules as a substitute.",
    },
    {
      id: "acceptance",
      phase: "verify",
      titleZh: "跑验收检查",
      actionEn:
        "Execute WEAVE_ACCEPTANCE_TESTS checks on hardened output; fail the job if pure-noise or TEE-only vocab remains.",
    },
  ]);

function maturityForFormat(format: ArtifactFormat): WeaveMaturity {
  switch (format) {
    case "javascript":
    case "typescript":
    case "html-bundle":
      return "woven";
    case "python-source":
    case "python-pyc":
      return "warm-init-only";
    case "electron-asar":
    case "firmware-uf2":
    case "android-dex":
    case "android-apk":
    case "archive-zip":
      return "sidecar-decoy";
    case "directory":
    case "unknown":
      return "not-applicable";
    default:
      return "gap";
  }
}

function statusForMaturity(maturity: WeaveMaturity): WeavePlanStatus {
  switch (maturity) {
    case "woven":
      return "ready";
    case "warm-init-only":
    case "sidecar-decoy":
      return "partial";
    case "gap":
      return "gap";
    default:
      return "unsupported";
  }
}

function notesForMaturity(maturity: WeaveMaturity): string {
  switch (maturity) {
    case "woven":
      return "JS AST 已将诱饵织入真实函数体（opaque-true + tarpit/xref）。保持此路径，禁止再加可剥离噪声层。";
    case "warm-init-only":
      return "Python 在 #51 后有稠密诱饵 + 模块 warm-init，但尚未织入客户 def 调用图；后续 PR 做 AST weave。";
    case "sidecar-decoy":
      return "格式以 sidecar / 附加块诱饵为主；织入原则仍适用：避免空同质 scare，保持可达与词干混用。";
    case "gap":
      return "该格式尚无客户入口织入钩子；先跑标准 harden，织入改造列入后续。";
    default:
      return "跳过不可保护或不识别目标。";
  }
}

function actionsForMaturity(maturity: WeaveMaturity): readonly string[] {
  switch (maturity) {
    case "woven":
      return Object.freeze([
        "Run bla_harden/bla_protect with weave_decoys:true (label + future hooks).",
        "Verify opaque-true entanglement and mixed stems on output.",
      ]);
    case "warm-init-only":
      return Object.freeze([
        "Keep densified tarpit + warm-init; do not add empty honeypot modules.",
        "Track follow-up: AST weave decoy calls into customer Python defs.",
        "Optional: self-seal binding (issue #40) after weave lands.",
      ]);
    case "sidecar-decoy":
      return Object.freeze([
        "Keep format-specific decoy blocks reachable / mixed-vocab.",
        "Refuse greppable banners and TEE-only homogeneous packs.",
      ]);
    case "gap":
      return Object.freeze([
        "Use standard bla_harden today.",
        "File follow-up only for defensive customer-path entanglement.",
      ]);
    default:
      return Object.freeze([]);
  }
}

const SCAN_SKIP = new Set([
  ".git",
  "node_modules",
  ".bla-hardened",
  "dist",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
]);

const INTERESTING_EXT = new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".pyc",
  ".asar",
  ".wasm",
  ".uf2",
  ".dex",
  ".apk",
  ".so",
  ".dll",
  ".exe",
  ".sqlite",
  ".db",
]);

function listCandidateFiles(root: string, limit: number): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0 && out.length < limit) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (out.length >= limit) break;
      if (ent.name.startsWith(".") && ent.name !== ".blarc") {
        if (SCAN_SKIP.has(ent.name)) continue;
      }
      if (SCAN_SKIP.has(ent.name)) continue;
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      const ext = extname(ent.name).toLowerCase();
      if (INTERESTING_EXT.has(ext) || ent.name === "global-metadata.dat") {
        out.push(full);
      }
    }
  }
  return out;
}

function buildTargetEntry(
  absPath: string,
  rootAbs: string,
): WeaveTargetEntry {
  const format = detectArtifactFormat(absPath);
  const maturity = maturityForFormat(format);
  return {
    path: absPath,
    relativePath: relative(rootAbs, absPath) || ".",
    format,
    maturity,
    status: statusForMaturity(maturity),
    notesZh: notesForMaturity(maturity),
    recommendedActions: actionsForMaturity(maturity),
  };
}

function overallFromTargets(
  targets: readonly WeaveTargetEntry[],
): WeavePlanStatus {
  if (targets.length === 0) return "unsupported";
  if (targets.every((t) => t.status === "ready")) return "ready";
  if (targets.some((t) => t.status === "gap")) return "gap";
  if (targets.some((t) => t.status === "partial" || t.status === "ready")) {
    return "partial";
  }
  return "unsupported";
}

/**
 * Read-only weave planner: classify targets and return an executable checklist
 * JSON so a later AI can apply theory without chat history.
 */
export function buildWeavePlan(
  targetPath: string,
  options: { readonly maxTargets?: number } = {},
): WeavePlan {
  const abs = resolve(targetPath);
  const maxTargets = options.maxTargets ?? 48;
  const targets: WeaveTargetEntry[] = [];

  if (!existsSync(abs)) {
    return {
      schema: WEAVE_DECOY_SCHEMA,
      docPath: WEAVE_DECOY_DOC_PATH,
      directivesUri: WEAVE_DIRECTIVES_URI,
      targetPath: abs,
      analyzedAtIso: new Date().toISOString(),
      overallStatus: "unsupported",
      summaryZh: `路径不存在：${abs}`,
      targets: [],
      principles: WEAVE_PRINCIPLES,
      forbidden: WEAVE_FORBIDDEN,
      acceptanceTests: WEAVE_ACCEPTANCE_TESTS,
      checklist: WEAVE_EXECUTOR_CHECKLIST,
      pipelineHook: PIPELINE_HOOK,
    };
  }

  const st = statSync(abs);
  if (st.isDirectory()) {
    for (const file of listCandidateFiles(abs, maxTargets)) {
      targets.push(buildTargetEntry(file, abs));
    }
  } else {
    targets.push(buildTargetEntry(abs, abs.endsWith(extname(abs)) ? resolve(abs, "..") : abs));
  }

  const overallStatus = overallFromTargets(targets);
  const summaryZh =
    overallStatus === "ready"
      ? "目标以 JS 织入成熟度为主；可直接 bla_harden(weave_decoys:true) 并跑验收。"
      : overallStatus === "partial"
        ? "部分格式已织入或仅有 warm-init/sidecar；按 checklist 执行，Python 客户 def 织入留给后续 PR。"
        : overallStatus === "gap"
          ? "存在尚无织入钩子的格式；先标准 harden，勿堆噪声层。"
          : "未发现可分析产物；请指向源码或构建目录。";

  return {
    schema: WEAVE_DECOY_SCHEMA,
    docPath: WEAVE_DECOY_DOC_PATH,
    directivesUri: WEAVE_DIRECTIVES_URI,
    targetPath: abs,
    analyzedAtIso: new Date().toISOString(),
    overallStatus,
    summaryZh,
    targets,
    principles: WEAVE_PRINCIPLES,
    forbidden: WEAVE_FORBIDDEN,
    acceptanceTests: WEAVE_ACCEPTANCE_TESTS,
    checklist: WEAVE_EXECUTOR_CHECKLIST,
    pipelineHook: PIPELINE_HOOK,
  };
}

const PIPELINE_HOOK = Object.freeze({
  mcpFlag: "weave_decoys" as const,
  hardenOption: "weaveDecoys" as const,
  todayBehaviorZh:
    "weave_decoys=true 时：JS 保持现有 AST 织入；Python 保持 #51 稠密 + warm-init（尚未改客户 def）；报告标注 weaveDecoys。完整 Python/多格式 AST 织入为后续 PR。",
  followUpZh:
    "Follow-up：把诱饵调用织进 Python 客户函数体；可选 self-seal；扩展 sidecar 格式的入口纠缠验收。",
});

/** Markdown theory pack returned by MCP resources/read (Chinese-friendly). */
export function getWeaveDirectivesMarkdown(): string {
  const principles = WEAVE_PRINCIPLES.map(
    (p) => `- **${p.id}** — ${p.titleZh} / ${p.titleEn}\n  ${p.summaryZh}`,
  ).join("\n");
  const forbidden = WEAVE_FORBIDDEN.map(
    (f) => `- **${f.id}** — ${f.titleZh}\n  原因：${f.whyZh}`,
  ).join("\n");
  const acceptance = WEAVE_ACCEPTANCE_TESTS.map(
    (a) => `- **${a.id}** — ${a.titleZh}: ${a.checkEn}`,
  ).join("\n");
  const checklist = WEAVE_EXECUTOR_CHECKLIST.map(
    (s) => `- [${s.phase}] **${s.id}** — ${s.titleZh}: ${s.actionEn}`,
  ).join("\n");

  return `# Weave-decoy directives (BLA Counter-REA)

> 防御专用。禁止输出破解 / RE / 绕过 PoC。完整叙述见 \`${WEAVE_DECOY_DOC_PATH}\`。

## 为何空/同质 scare 诱饵失败（WorkBuddy）

可剥离的空 \`_bla_*\`、同质 TEE 词表、与业务无关的 honeypot 层会被智能体整层过滤，难度不升。诱饵必须巧妙织入真实业务路径。

## 织入原则

${principles}

## 明确禁止

${forbidden}

## 执行清单（给后续 AI）

${checklist}

## 验收（apply 后必须通过）

${acceptance}

## MCP

1. \`resources/read\` → \`${WEAVE_DIRECTIVES_URI}\`
2. \`bla_weave_plan\` → 只读计划 JSON（\`${WEAVE_DECOY_SCHEMA}\`）
3. \`bla_harden\` / \`bla_defend\` / \`bla_protect\` 传 \`weave_decoys: true\`

## 管线现状

${PIPELINE_HOOK.todayBehaviorZh}

${PIPELINE_HOOK.followUpZh}
`;
}

/**
 * Lightweight source hint for stubs: whether a JS/Python buffer already shows
 * weave / warm-init markers (defensive telemetry only).
 */
export function inspectWeaveHints(source: string, format: ArtifactFormat): {
  readonly maturity: WeaveMaturity;
  readonly hints: readonly string[];
} {
  const hints: string[] = [];
  if (format === "javascript" || format === "typescript" || format === "html-bundle") {
    if (/opaque|runtimeSeed|warmRuntime|stepper/i.test(source)) {
      hints.push("possible-js-shield-markers");
    }
    return { maturity: "woven", hints };
  }
  if (format === "python-source" || format === "python-pyc") {
    if (/\["warm"\]\s*=/.test(source) || /warm_runtime|warmRuntime/i.test(source)) {
      hints.push("python-warm-init");
    }
    if (/runtime attestation boundary/.test(source)) {
      hints.push("python-tarpit-banner-phrase");
    }
    return { maturity: "warm-init-only", hints };
  }
  return { maturity: maturityForFormat(format), hints };
}

/** Optional helper when reading the on-disk theory doc from repo root. */
export function tryReadWeaveTheoryDoc(repoRoot: string): string | null {
  const path = join(repoRoot, WEAVE_DECOY_DOC_PATH);
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}
