/**
 * Weave-decoy theory + surgical AST planner + structural weave verifier
 * for Counter-REA Agent-Driven Hardening (BLA 3.0).
 *
 * DEFENSIVE ONLY: helps host coding agents entangle business-plausible decoys
 * with real customer call graphs and shared mutable state so REA/WorkBuddy-style
 * peel cannot dismiss them as a separate noise layer.
 * No crack / RE / bypass playbooks.
 */

import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative, resolve } from "node:path";
import { detectArtifactFormat } from "../../core/detector.js";
import type { ArtifactFormat } from "../../core/types.js";
import { lintLaneIndependence } from "../../engine/lane-independence-lint.js";

type UnwrapDefault<T> = T extends { readonly default: infer D } ? D : T;
type TraverseFn = UnwrapDefault<typeof _traverse>;
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : (_traverse as unknown as { readonly default: TraverseFn }).default;

export const WEAVE_DECOY_DOC_PATH = "docs/weave-decoy-mcp.md" as const;
export const WEAVE_DECOY_SCHEMA = "bla-weave-plan/v1" as const;
export const WEAVE_VERIFY_SCHEMA = "bla-weave-verify/v1" as const;
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

export interface WeaveFunctionCandidate {
  readonly name: string;
  readonly line: number;
  readonly exported: boolean;
  readonly paramCount: number;
  readonly role:
    | "exported-api"
    | "route-handler"
    | "gate-or-auth"
    | "internal-helper";
}

export interface WeaveStateSlotCandidate {
  readonly name: string;
  readonly kind:
    | "existing-mutable"
    | "existing-container"
    | "recommended-carrier";
  readonly line?: number;
  readonly touchRecipe: string;
}

export interface WeaveBranchCandidate {
  readonly functionName: string;
  readonly line: number;
  readonly statementKind: "if-branch" | "return-gate" | "state-mutation";
  readonly rewriteHint: string;
}

export interface WeaveCrownJewelCandidate {
  readonly functionName: string;
  readonly line: number;
  readonly vulnerabilityKind:
    | "single-point-boolean-gate"
    | "isolated-verify-oracle"
    | "cleartext-comparison"
    | "unentangled-export";
  readonly riskSummary: string;
  readonly agentRefactorDirective: string;
}

export interface WeaveDataFlowEntanglementPlan {
  readonly stateCarrierName: string;
  readonly antiPatchStrategy: string;
  readonly codeTransformSteps: readonly string[];
  readonly crossModuleBindingRecipe?: string;
}

export interface WeaveSurgicalWorkorder {
  readonly language: "javascript-ts" | "python" | "native-source" | "other";
  readonly entryFunctions: readonly WeaveFunctionCandidate[];
  readonly sharedStateSlots: readonly WeaveStateSlotCandidate[];
  readonly branchCandidates: readonly WeaveBranchCandidate[];
  readonly crownJewelCandidates: readonly WeaveCrownJewelCandidate[];
  readonly dataFlowEntanglementPlan: WeaveDataFlowEntanglementPlan;
  readonly suggestedIdentifierStems: {
    readonly mundane: readonly string[];
    readonly security: readonly string[];
  };
  readonly agentRewriteRecipe: readonly string[];
}

export interface WeaveTargetEntry {
  readonly path: string;
  readonly relativePath: string;
  readonly format: ArtifactFormat;
  readonly maturity: WeaveMaturity;
  readonly status: WeavePlanStatus;
  readonly notesZh: string;
  readonly recommendedActions: readonly string[];
  readonly surgicalWorkorder?: WeaveSurgicalWorkorder;
}

export interface WeaveAgentPlaybookPhase {
  readonly stage: 1 | 2 | 3 | 4;
  readonly id:
    | "recon-and-gates"
    | "agent-source-surgery"
    | "build-and-exhaustion-harden"
    | "verify-equivalence-and-weave";
  readonly title: string;
  readonly owner: "agent+mcp" | "agent-primary" | "mcp-primary";
  readonly tools: readonly string[];
  readonly goal: string;
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
  readonly surgicalTargetsCount: number;
  readonly siblingEntanglementCandidates: readonly string[];
  readonly agentPlaybook: readonly WeaveAgentPlaybookPhase[];
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

export interface WeaveCheckResult {
  readonly id: string;
  readonly titleZh: string;
  readonly passed: boolean;
  readonly evidence: string;
  readonly remediation?: string;
}

export interface WeaveAgentAction {
  readonly priority: "high" | "medium";
  readonly file: string;
  readonly checkId: string;
  readonly targetSymbol?: string;
  readonly instruction: string;
  readonly verifyTool: "bla_verify_weave" | "bla_lint" | "bla_verify";
}

export interface WeaveFileVerification {
  readonly path: string;
  readonly relativePath: string;
  readonly format: ArtifactFormat | "native-source";
  readonly passed: boolean;
  readonly score: number;
  readonly checks: readonly WeaveCheckResult[];
  readonly discoveredFunctions: readonly string[];
  readonly reachableFunctions: readonly string[];
  readonly unreferencedFunctions: readonly string[];
  readonly sharedStateVars: readonly string[];
  readonly syntaxValid?: boolean;
}

export interface WeaveVerificationReport {
  readonly schema: typeof WEAVE_VERIFY_SCHEMA;
  readonly targetPath: string;
  readonly verifiedAtIso: string;
  readonly overallPassed: boolean;
  readonly weaveScore: number;
  readonly files: readonly WeaveFileVerification[];
  readonly agentActions: readonly WeaveAgentAction[];
  readonly summary: string;
}

export const WEAVE_AGENT_PLAYBOOK: readonly WeaveAgentPlaybookPhase[] =
  Object.freeze([
    {
      stage: 1,
      id: "recon-and-gates",
      title: "Stage 1: Recon, Packaging Gates & Surgical Workorder",
      owner: "agent+mcp",
      tools: ["bla_discover", "bla_lint", "bla_weave_plan", "bla_audit"],
      goal: "Inventory targets, run bla_lint to catch packaging footguns (lane-independent gates, plaintext secrets, JS AES unwrap), and generate AST-level surgical workorders via bla_weave_plan.",
    },
    {
      stage: 2,
      id: "agent-source-surgery",
      title: "Stage 2: Agent-Led Source Refactoring & Structural Decoy Weave",
      owner: "agent-primary",
      tools: [
        "bla_verify_weave",
        "bla_encrypt_strings",
        "bla_emit_headers",
        "bla_bind_scope",
      ],
      goal: "Host Agent refactors any blocking bla_lint gates in source code, weaves domain-plausible shadow business logic sharing mutable state slots per surgicalWorkorder, and validates source edits with bla_verify_weave.",
    },
    {
      stage: 3,
      id: "build-and-exhaustion-harden",
      title: "Stage 3: Build Artifacts & Inject Counter-REA Exhaustion Shield",
      owner: "mcp-primary",
      tools: ["bla_harden", "bla_defend"],
      goal: "Run project build (if applicable), then invoke bla_harden with weave_decoys:true and self_seal:true (or sidecar_entangle:true) to inject BPE token amplifiers, callgraph labyrinths, and format shields.",
    },
    {
      stage: 4,
      id: "verify-equivalence-and-weave",
      title: "Stage 4: Equivalence, Weave Acceptance & Bankruptcy Verification",
      owner: "agent+mcp",
      tools: ["bla_verify", "bla_verify_weave", "bla_polymorph_report"],
      goal: "Run project test suite to prove 100% functional equivalence, run bla_verify_weave and bla_verify to confirm 0 agentActions remaining and >=10x token bankruptcy amplification.",
    },
  ]);

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
        "Static xref from customer entry / exported handlers reaches at least one decoy call (JS always; Python with weave_decoys:true via customer-def weave, not warm-init alone).",
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
    {
      id: "crown-jewel-entanglement",
      titleZh: "皇冠逻辑消解与抗Patch耦合",
      checkEn:
        "Gate/auth functions eliminate single-point boolean literal returns, cleartext secret equality, and lane-independent byte checks, and entangle verification decisions with shared state or whole-input digest derivation (no side-effect-only cosmetic weave).",
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
        "Call MCP `bla_weave_plan` on the project/build path; inspect each target's `surgicalWorkorder` (entryFunctions, sharedStateSlots, branchCandidates).",
    },
    {
      id: "agent-source-weave",
      phase: "apply",
      titleZh: "Agent 源码级结构织入（可选但强推）",
      actionEn:
        "Follow `surgicalWorkorder.agentRewriteRecipe` to weave domain-plausible helpers that read/write `sharedStateSlots` and are called from `entryFunctions`, then run `bla_verify_weave`.",
    },
    {
      id: "prefer-pipeline-flag",
      phase: "apply",
      titleZh: "走 harden 管线旗标",
      actionEn:
        "Call `bla_harden` / `bla_defend` / `bla_protect` with `weave_decoys: true` so Python structural customer-def weave runs (JS AST weave is always on).",
    },
    {
      id: "js-entangle",
      phase: "apply",
      titleZh: "确认 JS 已织入",
      actionEn:
        "For JS/TS: existing `ast-shield` already weaves opaque-true + tarpit calls into real function bodies — verify, do not add a second noise sidecar.",
    },
    {
      id: "python-weave",
      phase: "apply",
      titleZh: "确认 Python 结构织入",
      actionEn:
        "For Python `.py`: with weave_decoys:true, `python-ast-weave` inserts shared-slot touch + opaque-false decoy calls into customer defs (identity-skip tarpit names). Do not pile empty scare modules.",
    },
    {
      id: "acceptance",
      phase: "verify",
      titleZh: "跑验收检查",
      actionEn:
        "Call MCP `bla_verify_weave` (or CLI `bla verify-weave`) to execute WEAVE_ACCEPTANCE_TESTS checks; resolve any returned `agentActions` until `overallPassed: true`.",
    },
  ]);

function maturityForFormat(format: ArtifactFormat): WeaveMaturity {
  switch (format) {
    case "javascript":
    case "typescript":
    case "html-bundle":
      return "woven";
    case "python-source":
      return "woven";
    case "python-pyc":
      return "woven";
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
      return "JS AST / Python 结构织入已将诱饵织入真实函数体（opaque + tarpit/xref）。支持宿主 Agent 按 surgicalWorkorder 进一步织入业务级共享状态诱饵，并用 bla_verify_weave 验收。";
    case "warm-init-only":
      return "该格式目前以稠密诱饵 + 模块 warm-init / sidecar 为主；完整客户入口织入仍有限。";
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
        "Inspect surgicalWorkorder (entryFunctions, sharedStateSlots, branchCandidates) for source-level Agent weave.",
        "Run bla_harden/bla_protect with weave_decoys:true (JS always weaves; Python structural customer-def weave).",
        "Run bla_verify_weave to verify opaque entanglement, shared-slot touch, and mixed stems on output.",
      ]);
    case "warm-init-only":
      return Object.freeze([
        "Keep densified tarpit + warm-init; do not add empty honeypot modules.",
        "Prefer .py sources (or .pyc with weave_decoys:true for co_consts CODE weave) when customer-def weave is required.",
        "Optional: self-seal binding (issue #40).",
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

const DEFAULT_MUNDANE_STEMS = [
  "session",
  "ledger",
  "quota",
  "cursor",
  "epoch",
  "invoice",
  "locale",
  "cache",
  "policy",
  "checkpoint",
];

const DEFAULT_SECURITY_STEMS = [
  "attest",
  "commitment",
  "enclave",
  "seal",
];

const TEE_SCARE_REGEX =
  /\b(?:tee|tpm|tpm2|nitro|enclave|sgx|sev|hsm|trustzone|honeypot|decoy|tarpit)\b/i;

function hasScareStem(identifier: string): boolean {
  const normalized = identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([a-zA-Z])(\d)/g, "$1 $2")
    .replace(/_/g, " ")
    .toLowerCase();
  return TEE_SCARE_REGEX.test(normalized);
}

const FORBIDDEN_BANNER_REGEX =
  /(?:\b_bla_[a-zA-Z0-9_]*|\bBLA[-_]SHIELD\b|\bTODO:\s*decoy\b|\bfake_honeypot\b)/;

function classifyFunctionRole(
  name: string,
  exported: boolean,
): WeaveFunctionCandidate["role"] {
  const cleaned = name.replace(/checkpoint/gi, "");
  if (/auth|verify|license|unlock|token|check|gate|seal|validate|sign/i.test(cleaned)) {
    return "gate-or-auth";
  }
  if (/route|handle|controller|dispatch|request|endpoint|api|main|init/i.test(cleaned)) {
    return "route-handler";
  }
  return exported ? "exported-api" : "internal-helper";
}

function extractJsFunctionName(path: any): string {
  if (path.getFunctionParent && path.getFunctionParent() !== null) {
    return "";
  }
  const node = path.node;
  const parent = path.parent;
  if (t.isFunctionDeclaration(node) && node.id) {
    return node.id.name;
  }
  if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) {
    return parent.id.name;
  }
  if (t.isClassMethod(node) && t.isIdentifier(node.key)) {
    return node.key.name === "constructor" ? "" : node.key.name;
  }
  if (t.isClassPrivateMethod(node) && t.isPrivateName(node.key)) {
    return node.key.id.name;
  }
  if (
    t.isAssignmentExpression(parent) &&
    t.isMemberExpression(parent.left) &&
    t.isIdentifier(parent.left.property)
  ) {
    return parent.left.property.name;
  }
  if (
    (t.isObjectProperty(parent) && t.isIdentifier(parent.key)) ||
    (t.isObjectMethod(node) && t.isIdentifier(node.key))
  ) {
    const objExprPath = t.isObjectMethod(node)
      ? path.parentPath
      : path.parentPath?.parentPath;
    const objParent = objExprPath?.parent;
    const isExportedObj =
      t.isExportDefaultDeclaration(objParent) ||
      (t.isAssignmentExpression(objParent) &&
        t.isMemberExpression(objParent.left) &&
        t.isIdentifier(objParent.left.object) &&
        (objParent.left.object.name === "module" ||
          objParent.left.object.name === "exports"));
    if (isExportedObj) {
      const keyNode = t.isObjectMethod(node) ? node.key : parent.key;
      return t.isIdentifier(keyNode) ? keyNode.name : "";
    }
  }
  return "";
}

function extractStaticStringOrTemplate(node: t.Node | null | undefined): string | null {
  if (!node) return null;
  if (t.isStringLiteral(node)) return node.value;
  if (
    t.isTemplateLiteral(node) &&
    node.expressions.length === 0 &&
    node.quasis.length === 1
  ) {
    return node.quasis[0]?.value.cooked ?? node.quasis[0]?.value.raw ?? null;
  }
  return null;
}

function inspectRawBooleanReturnValue(
  node: t.Node | null | undefined,
): { readonly isRawBool: boolean; readonly isTrueBranch: boolean } {
  if (!node) return { isRawBool: false, isTrueBranch: false };
  if (t.isBooleanLiteral(node)) {
    return { isRawBool: true, isTrueBranch: node.value === true };
  }
  if (
    t.isUnaryExpression(node) &&
    node.operator === "!" &&
    t.isNumericLiteral(node.argument) &&
    (node.argument.value === 0 || node.argument.value === 1)
  ) {
    return { isRawBool: true, isTrueBranch: node.argument.value === 0 };
  }
  if (t.isConditionalExpression(node)) {
    const c = inspectRawBooleanReturnValue(node.consequent);
    const a = inspectRawBooleanReturnValue(node.alternate);
    if (c.isRawBool && a.isRawBool) {
      return {
        isRawBool: true,
        isTrueBranch: c.isTrueBranch || a.isTrueBranch,
      };
    }
  }
  return { isRawBool: false, isTrueBranch: false };
}

function buildJsSurgicalWorkorder(
  source: string,
  relPath: string,
): WeaveSurgicalWorkorder {
  const entryFunctions: WeaveFunctionCandidate[] = [];
  const sharedStateSlots: WeaveStateSlotCandidate[] = [];
  const branchCandidates: WeaveBranchCandidate[] = [];
  const crownJewelCandidates: WeaveCrownJewelCandidate[] = [];
  const discoveredMundaneStems = new Set<string>();

  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      plugins: ["typescript", "jsx", "decorators-legacy"],
      errorRecovery: true,
    });

    const exportedNames = new Set<string>();

    traverse(ast, {
      ExportNamedDeclaration(path) {
        const decl = path.node.declaration;
        if (t.isFunctionDeclaration(decl) && decl.id) {
          exportedNames.add(decl.id.name);
        } else if (t.isClassDeclaration(decl)) {
          if (decl.id) exportedNames.add(decl.id.name);
          for (const item of decl.body.body) {
            if (
              t.isClassMethod(item) &&
              t.isIdentifier(item.key) &&
              item.key.name !== "constructor"
            ) {
              exportedNames.add(item.key.name);
            }
          }
        } else if (t.isVariableDeclaration(decl)) {
          for (const d of decl.declarations) {
            if (t.isIdentifier(d.id)) exportedNames.add(d.id.name);
          }
        }
        for (const spec of path.node.specifiers) {
          if (t.isExportSpecifier(spec) && t.isIdentifier(spec.local)) {
            exportedNames.add(spec.local.name);
          }
        }
      },
      ExportDefaultDeclaration(path) {
        const decl = path.node.declaration;
        if (t.isFunctionDeclaration(decl) && decl.id) {
          exportedNames.add(decl.id.name);
        } else if (t.isIdentifier(decl)) {
          exportedNames.add(decl.name);
        } else if (t.isClassDeclaration(decl)) {
          for (const item of decl.body.body) {
            if (
              t.isClassMethod(item) &&
              t.isIdentifier(item.key) &&
              item.key.name !== "constructor"
            ) {
              exportedNames.add(item.key.name);
            }
          }
        }
      },
      AssignmentExpression(path) {
        const left = path.node.left;
        if (t.isMemberExpression(left)) {
          if (
            t.isIdentifier(left.object) &&
            (left.object.name === "exports" || left.object.name === "module")
          ) {
            if (t.isIdentifier(left.property)) {
              exportedNames.add(left.property.name);
            }
            if (t.isIdentifier(path.node.right)) {
              exportedNames.add(path.node.right.name);
            } else if (t.isObjectExpression(path.node.right)) {
              for (const prop of path.node.right.properties) {
                if (
                  (t.isObjectProperty(prop) || t.isObjectMethod(prop)) &&
                  t.isIdentifier(prop.key)
                ) {
                  exportedNames.add(prop.key.name);
                }
              }
            }
          }
        }
      },
    });

    traverse(ast, {
      Program(progPath) {
        for (const stmt of progPath.node.body) {
          const varDecl = t.isExportNamedDeclaration(stmt) && t.isVariableDeclaration(stmt.declaration)
            ? stmt.declaration
            : t.isVariableDeclaration(stmt)
              ? stmt
              : null;
          if (!varDecl) continue;
          for (const decl of varDecl.declarations) {
            if (!t.isIdentifier(decl.id)) continue;
            const name = decl.id.name;
            const line = decl.loc?.start.line ?? 1;
            if (varDecl.kind === "let" || varDecl.kind === "var") {
              sharedStateSlots.push({
                name,
                kind: "existing-mutable",
                line,
                touchRecipe: `Mutate and read \`${name}\` inside both customer entry functions and woven helper functions so static slice analysis cannot separate them.`,
              });
            } else if (
              t.isObjectExpression(decl.init) ||
              t.isArrayExpression(decl.init) ||
              (t.isNewExpression(decl.init) &&
                t.isIdentifier(decl.init.callee) &&
                /^(?:Map|Set|Uint8Array|Uint32Array)$/.test(decl.init.callee.name))
            ) {
              sharedStateSlots.push({
                name,
                kind: "existing-container",
                line,
                touchRecipe: `Read/update keys or properties on \`${name}\` across real business paths and woven shadow helpers.`,
              });
            }
          }
        }
      },
      Function(path) {
        const fnName = extractJsFunctionName(path);
        if (!fnName) return;

        const words = fnName
          .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
          .toLowerCase()
          .split(/[^a-z0-9]+/)
          .filter((w) => w.length >= 4 && !hasScareStem(w));
        for (const w of words) {
          if (discoveredMundaneStems.size < 6) discoveredMundaneStems.add(w);
        }

        const exported =
          exportedNames.has(fnName) ||
          t.isExportNamedDeclaration(path.parent) ||
          t.isExportDefaultDeclaration(path.parent);
        const line = path.node.loc?.start.line ?? 1;
        const role = classifyFunctionRole(fnName, exported);
        if (entryFunctions.length < 12) {
          entryFunctions.push({
            name: fnName,
            line,
            exported,
            paramCount: path.node.params.length,
            role,
          });
        }

        let hasTrueLiteralReturn = false;
        let hasFalseLiteralReturn = false;
        let hasComputedReturn = false;
        let hasCleartextComparison = false;
        let boolReturnLine = line;
        let cleartextLine = line;

        if (!t.isBlockStatement(path.node.body)) {
          const b = inspectRawBooleanReturnValue(path.node.body);
          if (b.isRawBool) {
            if (b.isTrueBranch) hasTrueLiteralReturn = true;
            else hasFalseLiteralReturn = true;
          } else {
            hasComputedReturn = true;
          }
        }

        path.traverse({
          Function(innerPath) {
            innerPath.skip();
          },
          ReturnStatement(retPath) {
            const arg = retPath.node.argument;
            const b = inspectRawBooleanReturnValue(arg);
            if (b.isRawBool) {
              if (b.isTrueBranch) hasTrueLiteralReturn = true;
              else hasFalseLiteralReturn = true;
              boolReturnLine = retPath.node.loc?.start.line ?? line;
            } else if (arg) {
              hasComputedReturn = true;
            }
          },
          BinaryExpression(binPath) {
            if (
              binPath.node.operator === "===" ||
              binPath.node.operator === "==" ||
              binPath.node.operator === "!==" ||
              binPath.node.operator === "!="
            ) {
              const left = binPath.node.left;
              const right = binPath.node.right;
              const strVal =
                extractStaticStringOrTemplate(left) ??
                extractStaticStringOrTemplate(right);
              if (
                strVal &&
                strVal.length >= 4 &&
                !BENIGN_COMPARE_STRING_REGEX.test(strVal) &&
                !HEX_SHA256_LITERAL_REGEX.test(strVal)
              ) {
                hasCleartextComparison = true;
                cleartextLine = binPath.node.loc?.start.line ?? line;
              }
            }
          },
        });

        const hasBooleanLiteralReturn =
          hasTrueLiteralReturn || (hasFalseLiteralReturn && !hasComputedReturn);

        if (crownJewelCandidates.length < 10) {
          if (hasBooleanLiteralReturn && (role === "gate-or-auth" || exported)) {
            crownJewelCandidates.push({
              functionName: fnName,
              line: boolReturnLine,
              vulnerabilityKind: "single-point-boolean-gate",
              riskSummary: `Function \`${fnName}\` (line ${boolReturnLine}) returns a raw boolean literal — an AI RE agent can 1-byte patch or NOP this branch without computing the real key/state.`,
              agentRefactorDirective: `Refactor \`${fnName}\` so it accumulates a state digest on the shared carrier (e.g. FNV-1a / ARX mix into \`sessionLedgerState.digest\`) and couples downstream return values to that digest instead of an isolated \`true/false\` branch.`,
            });
          } else if (role === "gate-or-auth") {
            crownJewelCandidates.push({
              functionName: fnName,
              line,
              vulnerabilityKind: "isolated-verify-oracle",
              riskSummary: `Auth/gate function \`${fnName}\` (line ${line}) acts as a standalone verification boundary.`,
              agentRefactorDirective: `Entangle \`${fnName}\` with module-level shared state and invoke 2–3 domain-plausible shadow helpers so static call-graph slicing cannot isolate the verification oracle.`,
            });
          }
          if (hasCleartextComparison && crownJewelCandidates.length < 10) {
            crownJewelCandidates.push({
              functionName: fnName,
              line: cleartextLine,
              vulnerabilityKind: "cleartext-comparison",
              riskSummary: `Function \`${fnName}\` (line ${cleartextLine}) compares against a cleartext string literal — trivial to recover via AST/strings scan.`,
              agentRefactorDirective: `Replace cleartext string equality in \`${fnName}\` with a whole-input chained digest comparison (FNV-1a / SHA-256) or mask literals via MCP \`bla_encrypt_strings\`.`,
            });
          }
        }

        if (t.isBlockStatement(path.node.body) && branchCandidates.length < 12) {
          for (const stmt of path.node.body.body) {
            const stmtLine = stmt.loc?.start.line ?? line;
            if (t.isIfStatement(stmt)) {
              branchCandidates.push({
                functionName: fnName,
                line: stmtLine,
                statementKind: "if-branch",
                rewriteHint: `Entangle condition in \`${fnName}\` (line ${stmtLine}) with a shared-state invariant check and route the alternate/shadow path through a domain-plausible helper.`,
              });
            } else if (t.isReturnStatement(stmt) && stmt.argument) {
              branchCandidates.push({
                functionName: fnName,
                line: stmtLine,
                statementKind: "return-gate",
                rewriteHint: `Before returning from \`${fnName}\` (line ${stmtLine}), update shared state slot and fold an opaque-true invariant into the return value or guard.`,
              });
            }
            if (branchCandidates.length >= 12) break;
          }
        }
      },
    });
  } catch {
    // Fallback if syntax is non-standard
  }

  if (sharedStateSlots.length === 0) {
    sharedStateSlots.push({
      name: "sessionLedgerState",
      kind: "recommended-carrier",
      touchRecipe:
        "Declare module-scoped `const sessionLedgerState = { epoch: 1, cursor: 0, digest: 0x5f3759df };` and read/mutate it inside both entry functions and shadow business helpers.",
    });
  }

  const rolePriority: Record<WeaveFunctionCandidate["role"], number> = {
    "gate-or-auth": 0,
    "route-handler": 1,
    "exported-api": 2,
    "internal-helper": 3,
  };
  entryFunctions.sort((a, b) => {
    if (a.exported !== b.exported) return a.exported ? -1 : 1;
    return rolePriority[a.role] - rolePriority[b.role];
  });

  const mundaneStems = [
    ...discoveredMundaneStems,
    ...DEFAULT_MUNDANE_STEMS.filter((s) => !discoveredMundaneStems.has(s)),
  ].slice(0, 8);
  const primarySlot = sharedStateSlots[0]!.name;
  const primaryEntry = entryFunctions[0]?.name ?? "mainEntry";

  if (crownJewelCandidates.length === 0 && entryFunctions.length > 0) {
    crownJewelCandidates.push({
      functionName: primaryEntry,
      line: entryFunctions[0]!.line,
      vulnerabilityKind: "unentangled-export",
      riskSummary: `Exported entry \`${primaryEntry}\` has not yet been entangled with shared mutable state and shadow business helpers.`,
      agentRefactorDirective: `Couple \`${primaryEntry}\` to \`${primarySlot}\` and invoke 2–3 domain-plausible helpers before returning.`,
    });
  }

  const dataFlowEntanglementPlan: WeaveDataFlowEntanglementPlan = {
    stateCarrierName: primarySlot,
    antiPatchStrategy: `Eliminate single-point boolean/constant patch targets in \`${primaryEntry}\` by folding inputs into \`${primarySlot}.digest\` via chained arithmetic/bitwise mixing and gating downstream values on \`(${primarySlot}.epoch & 1) !== 0\`.`,
    codeTransformSteps: [
      `Step 1 (Crown-Jewel Anti-Patch): In \`${relPath}\`, inspect \`crownJewelCandidates\` (${crownJewelCandidates.map((c) => `${c.functionName}:${c.line}`).join(", ") || primaryEntry}). Replace direct cleartext or per-byte checks with a whole-input accumulator mixed into \`${primarySlot}\`.`,
      `Step 2 (Shadow Business Helpers): Define 2–3 non-trivial helpers using mundane stems (${mundaneStems.slice(0, 3).join(", ")}) + security stems (${DEFAULT_SECURITY_STEMS.slice(0, 2).join(", ")}) that read and mutate \`${primarySlot}\`.`,
      `Step 3 (Call-Graph & Return Coupling): Invoke the shadow helpers along the live execution path of \`${primaryEntry}\` and read \`${primarySlot}\` in the return expression or guard so static dead-code elimination cannot strip them.`,
    ],
    crossModuleBindingRecipe:
      "When hardening a multi-file project, export or pass the state digest across module boundaries and run `bla_harden` with `self_seal: true` and `sidecar_entangle: true`.",
  };

  const agentRewriteRecipe = [
    `1. Crown-Jewel Refactor: ${crownJewelCandidates[0]?.agentRefactorDirective ?? `Entangle \`${primaryEntry}\` with shared state.`}`,
    `2. Shared State Carrier: Use \`${primarySlot}\` (${sharedStateSlots[0]!.kind}) in \`${relPath}\` so real business logic and shadow helpers mutate and read the same runtime state.`,
    `3. Shadow Business Logic: Author 2–3 helper functions using 2/3 mundane stems (${mundaneStems.slice(0, 3).join(", ")}) and 1/3 security stems (${DEFAULT_SECURITY_STEMS.slice(0, 2).join(", ")}) that compute non-trivial state transitions on \`${primarySlot}\` (never empty stubs or \`_bla_*\` names).`,
    `4. Entry Entanglement & Verification: In \`${primaryEntry}\`${entryFunctions.length > 1 ? ` (and ${entryFunctions.slice(1, 3).map((f) => f.name).join(", ")})` : ""}, invoke the shadow helpers, guard the happy path with an opaque-true predicate over \`${primarySlot}\`, and run MCP \`bla_verify_weave\` on \`${relPath}\` until \`overallPassed: true\`.`,
  ];

  return {
    language: "javascript-ts",
    entryFunctions,
    sharedStateSlots,
    branchCandidates,
    crownJewelCandidates,
    dataFlowEntanglementPlan,
    suggestedIdentifierStems: {
      mundane: mundaneStems,
      security: DEFAULT_SECURITY_STEMS,
    },
    agentRewriteRecipe,
  };
}

interface ParsedPythonFunction {
  readonly name: string;
  readonly startLine: number;
  readonly indent: number;
  readonly paramCount: number;
  readonly body: string;
}

function measureIndentWidth(line: string): number {
  let width = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === " ") width += 1;
    else if (ch === "\t") width += 4;
    else break;
  }
  return width;
}

function extractPythonFunctions(source: string): ParsedPythonFunction[] {
  const lines = source.split(/\r?\n/);
  const results: ParsedPythonFunction[] = [];

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i]!;
    const headerStart = lineText.match(
      /^([ \t]*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/,
    );
    if (!headerStart) continue;

    const indent = measureIndentWidth(headerStart[1]!);
    const fnName = headerStart[2]!;
    const startLine = i + 1;

    // Advance through multi-line signature until parentheses balance and ':' is reached
    let sigLines = lineText;
    let sigEndLineIdx = i;
    let parenDepth = 0;
    let openFound = false;
    let colonAfterClose = false;

    for (let j = i; j < lines.length && j <= i + 20; j++) {
      const l = lines[j]!.replace(/#.*$/, "");
      if (j > i) sigLines += " " + l.trim();
      for (let k = 0; k < l.length; k++) {
        const ch = l[k];
        if (ch === "(") {
          parenDepth += 1;
          openFound = true;
        } else if (ch === ")") {
          parenDepth = Math.max(0, parenDepth - 1);
        } else if (ch === ":" && openFound && parenDepth === 0) {
          colonAfterClose = true;
        }
      }
      sigEndLineIdx = j;
      if (openFound && parenDepth === 0 && colonAfterClose) break;
    }

    const paramsMatch = sigLines.match(/\bdef\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([\s\S]*?)\)/);
    const paramsRaw = paramsMatch?.[1]?.trim() ?? "";
    const paramCount =
      paramsRaw.length === 0
        ? 0
        : paramsRaw
            .split(",")
            .map((p) => p.trim())
            .filter((p) => p.length > 0 && p !== "self" && p !== "cls" && p !== "*" && p !== "/")
            .length;

    // Collect single-line body (e.g. `def f(): pass`) or indented block body
    const singleLineAfterColon = lines[sigEndLineIdx]!
      .replace(/#.*$/, "")
      .match(/\)\s*(?:->[^:]+)?:\s*(.+)$/);
    const bodyLines: string[] = [];
    if (singleLineAfterColon && singleLineAfterColon[1]!.trim().length > 0) {
      bodyLines.push("    " + singleLineAfterColon[1]!.trim());
    } else {
      for (let b = sigEndLineIdx + 1; b < lines.length; b++) {
        const bLine = lines[b]!;
        const trimmed = bLine.trim();
        if (trimmed.length === 0 || trimmed.startsWith("#")) {
          bodyLines.push(bLine);
          continue;
        }
        const bIndent = measureIndentWidth(bLine);
        if (bIndent <= indent) break;
        bodyLines.push(bLine);
      }
    }

    results.push({
      name: fnName,
      startLine,
      indent,
      paramCount,
      body: bodyLines.join("\n"),
    });
  }

  return results;
}

function buildPythonSurgicalWorkorder(
  source: string,
  relPath: string,
): WeaveSurgicalWorkorder {
  const entryFunctions: WeaveFunctionCandidate[] = [];
  const sharedStateSlots: WeaveStateSlotCandidate[] = [];
  const branchCandidates: WeaveBranchCandidate[] = [];
  const crownJewelCandidates: WeaveCrownJewelCandidate[] = [];
  const lines = source.split(/\r?\n/);
  const parsedFns = extractPythonFunctions(source);

  for (const fn of parsedFns) {
    const exported = !fn.name.startsWith("_");
    const role = classifyFunctionRole(fn.name, exported);
    if (entryFunctions.length < 12) {
      entryFunctions.push({
        name: fn.name,
        line: fn.startLine,
        exported,
        paramCount: fn.paramCount,
        role,
      });
    }
    if (role === "gate-or-auth" && crownJewelCandidates.length < 8) {
      crownJewelCandidates.push({
        functionName: fn.name,
        line: fn.startLine,
        vulnerabilityKind: "isolated-verify-oracle",
        riskSummary: `Python auth/policy def \`${fn.name}\` (line ${fn.startLine}) is a high-value verification boundary.`,
        agentRefactorDirective: `Couple \`${fn.name}\` with module state dict and weave 2 domain-plausible helper defs so static slicing cannot isolate the policy check.`,
      });
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i]!;
    const stateMatch = lineText.match(
      /^([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(\{|\[|dict\(|set\(|bytearray\()/,
    );
    if (stateMatch && sharedStateSlots.length < 6) {
      const slotName = stateMatch[1]!;
      sharedStateSlots.push({
        name: slotName,
        kind: "existing-container",
        line: i + 1,
        touchRecipe: `Mutate and read keys on \`${slotName}\` inside both customer defs and woven helper defs.`,
      });
    }
    const boolReturnMatch = lineText.match(/^\s+return\s+(True|False)\b/);
    if (boolReturnMatch && entryFunctions.length > 0 && crownJewelCandidates.length < 8) {
      const currentFn =
        [...entryFunctions].reverse().find((f) => f.line <= i + 1)?.name ??
        entryFunctions[entryFunctions.length - 1]!.name;
      crownJewelCandidates.push({
        functionName: currentFn,
        line: i + 1,
        vulnerabilityKind: "single-point-boolean-gate",
        riskSummary: `Def \`${currentFn}\` (line ${i + 1}) returns raw \`${boolReturnMatch[1]}\` — vulnerable to trivial branch patching.`,
        agentRefactorDirective: `Fold a shared-state digest update before line ${i + 1} in \`${currentFn}\` and couple the return condition to the shared state dict.`,
      });
    }
    const returnMatch = lineText.match(/^\s+return\s+\S+/);
    if (returnMatch && entryFunctions.length > 0 && branchCandidates.length < 10) {
      const currentFn =
        [...entryFunctions].reverse().find((f) => f.line <= i + 1)?.name ??
        entryFunctions[entryFunctions.length - 1]!.name;
      branchCandidates.push({
        functionName: currentFn,
        line: i + 1,
        statementKind: "return-gate",
        rewriteHint: `In \`${currentFn}\` before line ${i + 1}, update the shared state dict and guard with a deterministic invariant.`,
      });
    }
  }

  if (sharedStateSlots.length === 0) {
    sharedStateSlots.push({
      name: "_session_ledger_state",
      kind: "recommended-carrier",
      touchRecipe:
        "Define module dict `_session_ledger_state = {'epoch': 1, 'cursor': 0, 'digest': 0x5F3759DF}` and touch it from customer defs and woven helpers.",
    });
  }

  const primarySlot = sharedStateSlots[0]!.name;
  const primaryEntry = entryFunctions[0]?.name ?? "main";

  if (crownJewelCandidates.length === 0 && entryFunctions.length > 0) {
    crownJewelCandidates.push({
      functionName: primaryEntry,
      line: entryFunctions[0]!.line,
      vulnerabilityKind: "unentangled-export",
      riskSummary: `Public def \`${primaryEntry}\` is not yet coupled with shared state helpers.`,
      agentRefactorDirective: `Mutate and read \`${primarySlot}\` across \`${primaryEntry}\` and 2 woven helper defs.`,
    });
  }

  const dataFlowEntanglementPlan: WeaveDataFlowEntanglementPlan = {
    stateCarrierName: primarySlot,
    antiPatchStrategy: `Entangle \`${primaryEntry}\` with module state dict \`${primarySlot}\` so removing helper calls alters runtime state invariants.`,
    codeTransformSteps: [
      `Step 1: Define or reuse \`${primarySlot}\` in \`${relPath}\`.`,
      `Step 2: Add 2 helper defs with mundane + security stems that update and return values from \`${primarySlot}\`.`,
      `Step 3: Call the helpers from \`${primaryEntry}\` under an opaque-true state guard (e.g. \`if (${primarySlot}["epoch"] & 1) != 0:\`).`,
    ],
  };

  return {
    language: "python",
    entryFunctions,
    sharedStateSlots,
    branchCandidates,
    crownJewelCandidates,
    dataFlowEntanglementPlan,
    suggestedIdentifierStems: {
      mundane: DEFAULT_MUNDANE_STEMS.slice(0, 6),
      security: DEFAULT_SECURITY_STEMS,
    },
    agentRewriteRecipe: [
      `1. Crown-Jewel Refactor: ${crownJewelCandidates[0]?.agentRefactorDirective ?? `Entangle \`${primaryEntry}\` with \`${primarySlot}\`.`}`,
      `2. Shared State Carrier: Use module dict \`${primarySlot}\` in \`${relPath}\` across customer defs and shadow helpers.`,
      `3. Shadow Helpers: Add 2 non-trivial helper defs (using mundane + security stems, never \`pass\` or \`_bla_*\`) that update \`${primarySlot}\`.`,
      `4. Verification Gate: Call the shadow helpers from \`${primaryEntry}\`, run \`bla_verify_weave\` on \`${relPath}\`, then run \`bla_harden\` with \`weave_decoys: true\`.`,
    ],
  };
}

function buildNativeSurgicalWorkorder(
  source: string,
  relPath: string,
  ext: string,
): WeaveSurgicalWorkorder {
  const entryFunctions: WeaveFunctionCandidate[] = [];
  const branchCandidates: WeaveBranchCandidate[] = [];
  const crownJewelCandidates: WeaveCrownJewelCandidate[] = [];
  const lines = source.split(/\r?\n/);
  const headerLang =
    ext === ".rs" ? "rust" : ext === ".go" ? "go" : "c";

  const fnRegex =
    ext === ".rs"
      ? /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)/
      : ext === ".go"
        ? /^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*\(([^)]*)/
        : /^\s*(?:[A-Za-z_][A-Za-z0-9_*\s]*?)(?:\s+|\*\s*)([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)/;

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i]!;
    if (/^\s*(?:#|\/\/|\/\*|\*)/.test(lineText)) continue;
    const m = lineText.match(fnRegex);
    if (m) {
      const fnName = m[1]!;
      if (/^(?:if|for|while|switch|return|sizeof|else|catch)$/.test(fnName)) continue;
      // Ensure it is a definition (has '{' on this line or next few lines, not a ';' prototype)
      const windowText = lines.slice(i, i + 6).join(" ");
      const bracePos = windowText.indexOf("{");
      const semiPos = windowText.indexOf(";");
      if (bracePos === -1 || (semiPos !== -1 && semiPos < bracePos)) continue;
      const exported =
        ext === ".rs"
          ? /\bpub(?:\s*\([^)]*\))?\s+/.test(lineText)
          : ext === ".go"
            ? /^[A-Z]/.test(fnName)
            : !/\bstatic\b/.test(lineText);
      const role = classifyFunctionRole(fnName, exported);
      if (entryFunctions.length < 12) {
        entryFunctions.push({
          name: fnName,
          line: i + 1,
          exported,
          paramCount: m[2]!.trim().length === 0 ? 0 : m[2]!.split(",").length,
          role,
        });
      }
      if (role === "gate-or-auth" && crownJewelCandidates.length < 8) {
        crownJewelCandidates.push({
          functionName: fnName,
          line: i + 1,
          vulnerabilityKind: "isolated-verify-oracle",
          riskSummary: `Native function \`${fnName}\` (line ${i + 1}) is a high-value symbol for Ghidra/IDA/REA decompilation.`,
          agentRefactorDirective: `Call MCP \`bla_emit_headers\` ({ "language": "${headerLang}", "intensity": "bankrupt" }), include the generated shield header in \`${relPath}\`, and weave opaque state macros into \`${fnName}\`.`,
        });
      }
    }
  }

  const primaryEntry = entryFunctions[0]?.name ?? "main";
  const sharedStateSlots: WeaveStateSlotCandidate[] = [
    {
      name: "g_session_ledger_epoch",
      kind: "recommended-carrier",
      touchRecipe: `Maintain a module/static state accumulator in \`${relPath}\` updated by both \`${primaryEntry}\` and native shadow helpers.`,
    },
  ];

  return {
    language: "native-source",
    entryFunctions,
    sharedStateSlots,
    branchCandidates,
    crownJewelCandidates,
    dataFlowEntanglementPlan: {
      stateCarrierName: "g_session_ledger_epoch",
      antiPatchStrategy: `Emit compile-time native shield headers via \`bla_emit_headers\` (${headerLang}) and entangle \`${primaryEntry}\` with opaque arithmetic invariants before compiling.`,
      codeTransformSteps: [
        `Step 1: Call MCP \`bla_emit_headers\` with \`{ "language": "${headerLang}", "intensity": "bankrupt" }\` and write the header next to \`${relPath}\`.`,
        `Step 2: Include/import the header in \`${relPath}\` and wrap critical branches in \`${primaryEntry}\` with opaque invariants and shared state updates.`,
        `Step 3: Compile the native binary and run \`bla_harden\` on the build output.`,
      ],
    },
    suggestedIdentifierStems: {
      mundane: DEFAULT_MUNDANE_STEMS.slice(0, 6),
      security: DEFAULT_SECURITY_STEMS,
    },
    agentRewriteRecipe: [
      `1. Emit Native Shield Header: Call \`bla_emit_headers\` ({ "language": "${headerLang}", "intensity": "bankrupt" }) and include it in \`${relPath}\`.`,
      `2. Entangle Crown Jewels: In \`${primaryEntry}\`, replace isolated boolean checks with state-accumulating opaque guards.`,
      `3. Build & Harden: Compile the binary and run \`bla_harden\` on the output directory.`,
    ],
  };
}

function buildSurgicalWorkorderForFile(
  absPath: string,
  relPath: string,
  format: ArtifactFormat,
): WeaveSurgicalWorkorder | undefined {
  try {
    const st = statSync(absPath);
    if (!st.isFile() || st.size > 512 * 1024) return undefined;
    if (
      format === "javascript" ||
      format === "typescript" ||
      format === "html-bundle"
    ) {
      const src = readFileSync(absPath, "utf8");
      return buildJsSurgicalWorkorder(src, relPath);
    }
    if (format === "python-source") {
      const src = readFileSync(absPath, "utf8");
      return buildPythonSurgicalWorkorder(src, relPath);
    }
    const ext = extname(absPath).toLowerCase();
    if (ext === ".c" || ext === ".cpp" || ext === ".cc" || ext === ".rs" || ext === ".go") {
      const src = readFileSync(absPath, "utf8");
      return buildNativeSurgicalWorkorder(src, relPath, ext);
    }
  } catch {
    return undefined;
  }
  return undefined;
}

const SCAN_SKIP_ALWAYS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  ".bla-hardened",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".next",
  ".turbo",
  "test",
  "tests",
  "__tests__",
]);

const SCAN_SKIP_BUILD_DIRS = new Set([
  "dist",
  "build",
  "out",
  "target",
  "release",
  "Release",
  "Debug",
]);

const EMITTED_SHIELD_HEADER_FILES = new Set([
  "bla_shield.h",
  "bla_shield.rs",
  "bla_shield.go",
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
  ".c",
  ".cpp",
  ".cc",
  ".rs",
  ".go",
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

function walkWeaveCandidateFiles(
  root: string,
  limit: number,
  skipBuildDirs: boolean,
): string[] {
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
      if (SCAN_SKIP_ALWAYS.has(ent.name)) continue;
      if (skipBuildDirs && SCAN_SKIP_BUILD_DIRS.has(ent.name)) continue;
      if (ent.name.startsWith(".") && ent.name !== ".blarc") continue;
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      if (EMITTED_SHIELD_HEADER_FILES.has(ent.name.toLowerCase())) continue;
      if (/\.d\.ts$/i.test(ent.name)) continue;
      if (/\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(ent.name)) continue;
      if (/\.shielded(\.|$)/i.test(ent.name)) continue;
      const ext = extname(ent.name).toLowerCase();
      if (INTERESTING_EXT.has(ext) || ent.name === "global-metadata.dat") {
        // Generic `.db` files may be non-SQLite runtime state (#130); only include
        // them as weave candidates when format detection recognizes them.
        if (ext === ".db" && detectArtifactFormat(full) === "unknown") {
          continue;
        }
        out.push(full);
      }
    }
  }
  return out;
}

function listCandidateFiles(root: string, limit: number): string[] {
  const primary = walkWeaveCandidateFiles(root, limit, true);
  if (primary.length > 0) return primary;
  return walkWeaveCandidateFiles(root, limit, false);
}

function buildTargetEntry(
  absPath: string,
  rootAbs: string,
): WeaveTargetEntry {
  const format = detectArtifactFormat(absPath);
  const rawMaturity = maturityForFormat(format);
  const relPath = relative(rootAbs, absPath) || basename(absPath) || ".";
  const surgicalWorkorder = buildSurgicalWorkorderForFile(
    absPath,
    relPath,
    format,
  );
  const maturity: WeaveMaturity =
    surgicalWorkorder !== undefined && rawMaturity === "not-applicable"
      ? "woven"
      : rawMaturity;
  return {
    path: absPath,
    relativePath: relPath,
    format,
    maturity,
    status: statusForMaturity(maturity),
    notesZh: notesForMaturity(maturity),
    recommendedActions: actionsForMaturity(maturity),
    ...(surgicalWorkorder !== undefined ? { surgicalWorkorder } : {}),
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

function buildSiblingEntanglementCandidates(
  targets: readonly WeaveTargetEntry[],
): readonly string[] {
  if (targets.length < 2) return Object.freeze([]);
  const rels = targets.map((t) => t.relativePath);
  const hints: string[] = [
    `Multi-artifact tree (${targets.length} targets: ${rels.slice(0, 4).join(", ")}${rels.length > 4 ? ", …" : ""}): pass \`self_seal: true\` and \`sidecar_entangle: true\` to \`bla_harden\` so sibling SHA-256 digests are bound at runtime.`,
  ];
  const hasJs = targets.some(
    (t) => t.format === "javascript" || t.format === "typescript",
  );
  const hasWasm = targets.some((t) => t.format === "wasm");
  if (hasJs && hasWasm) {
    hints.push(
      "JS + WASM sibling pair detected: keep unlock/key verification inside WASM and bind the WASM binary SHA-256 into the JS loader via `self_seal: true` + `integrity-coverage.json`.",
    );
  }
  return Object.freeze(hints);
}

/**
 * Read-only weave planner: classify targets, extract AST surgical workorders,
 * and return an executable checklist JSON so an Agent can apply source-level
 * and artifact-level hardening without chat history.
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
      surgicalTargetsCount: 0,
      siblingEntanglementCandidates: [],
      agentPlaybook: WEAVE_AGENT_PLAYBOOK,
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
    targets.push(
      buildTargetEntry(
        abs,
        abs.endsWith(extname(abs)) ? resolve(abs, "..") : abs,
      ),
    );
  }

  const overallStatus = overallFromTargets(targets);
  const surgicalTargetsCount = targets.filter(
    (t) => t.surgicalWorkorder !== undefined,
  ).length;
  const siblingEntanglementCandidates =
    buildSiblingEntanglementCandidates(targets);
  const summaryZh =
    overallStatus === "ready"
      ? `目标以 JS/Python 源码织入成熟度为主（已提取 ${surgicalTargetsCount} 份 AST 级外科手术工单）；Agent 可先按 surgicalWorkorder 织入业务级共享状态诱饵并用 bla_verify_weave 验收，再执行 bla_harden(weave_decoys:true)。`
      : overallStatus === "partial"
        ? "部分格式已织入或仅有 warm-init/sidecar；按 checklist 执行（.py 需 weave_decoys:true 激活客户 def 织入）。"
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
    surgicalTargetsCount,
    siblingEntanglementCandidates,
    agentPlaybook: WEAVE_AGENT_PLAYBOOK,
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
    "weave_decoys=true 时：JS 保持现有 AST 织入；Python `.py` 对客户 FunctionDef 做结构织入；Python `.pyc` 向客户/模块 co_consts 追加未执行 decoy TYPE_CODE（append-only，保 FLAG_REF）。false 时 .py 为 warm-init-only、.pyc 为 trailer honey。报告标注 weaveDecoys。",
  followUpZh:
    "BLA 3.0 已支持 surgicalWorkorder 源码级工单 + bla_verify_weave 结构化验收闭环。",
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

  return `# Weave-decoy directives (BLA Counter-REA 3.0)

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
2. \`bla_weave_plan\` → 只读计划 JSON（\`${WEAVE_DECOY_SCHEMA}\`，含 AST \`surgicalWorkorder\`）
3. \`bla_verify_weave\` → 验证 Agent 织入后的源码/产物是否满足 6 项结构验收（\`${WEAVE_VERIFY_SCHEMA}\`）
4. \`bla_harden\` / \`bla_defend\` / \`bla_protect\` 传 \`weave_decoys: true\`

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
    if (/hash\(\w+\.__name__\)/.test(source) && /\["epoch"\]/.test(source)) {
      hints.push("python-customer-def-weave");
    }
    return {
      maturity: format === "python-source" ? "woven" : "warm-init-only",
      hints,
    };
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

/**
 * Evaluate whether an AST expression is statically constant-true or constant-false.
 * Returns true/false when statically known, or null when dynamic.
 */
function evalStaticTruthiness(node: t.Node | null | undefined): boolean | null {
  if (!node) return null;
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isNumericLiteral(node)) return node.value !== 0 && !Number.isNaN(node.value);
  if (t.isStringLiteral(node)) return node.value.length > 0;
  if (t.isNullLiteral(node)) return false;
  if (t.isIdentifier(node) && node.name === "undefined") return false;
  if (t.isParenthesizedExpression(node)) return evalStaticTruthiness(node.expression);
  if (t.isUnaryExpression(node) && node.operator === "!") {
    const inner = evalStaticTruthiness(node.argument);
    return inner === null ? null : !inner;
  }
  if (t.isLogicalExpression(node)) {
    const left = evalStaticTruthiness(node.left);
    if (node.operator === "&&") {
      if (left === false) return false;
      if (left === true) return evalStaticTruthiness(node.right);
    } else if (node.operator === "||") {
      if (left === true) return true;
      if (left === false) return evalStaticTruthiness(node.right);
    }
    return null;
  }
  if (t.isBinaryExpression(node)) {
    const getPrimitive = (n: t.Node): string | number | boolean | null | undefined => {
      if (t.isStringLiteral(n)) return n.value;
      if (t.isNumericLiteral(n)) return n.value;
      if (t.isBooleanLiteral(n)) return n.value;
      if (t.isNullLiteral(n)) return null;
      return undefined;
    };
    const l = getPrimitive(node.left);
    const r = getPrimitive(node.right);
    if (l !== undefined && r !== undefined) {
      switch (node.operator) {
        case "===":
        case "==":
          return l === r;
        case "!==":
        case "!=":
          return l !== r;
        case "<":
          return typeof l === "number" && typeof r === "number" ? l < r : null;
        case "<=":
          return typeof l === "number" && typeof r === "number" ? l <= r : null;
        case ">":
          return typeof l === "number" && typeof r === "number" ? l > r : null;
        case ">=":
          return typeof l === "number" && typeof r === "number" ? l >= r : null;
      }
    }
  }
  return null;
}

function isInsideDeadBranch(path: { parentPath: any; node: t.Node }): boolean {
  let curr: any = path;
  while (curr && curr.parentPath) {
    const parent = curr.parentPath;
    const pNode: t.Node = parent.node;
    if (t.isIfStatement(pNode) || t.isConditionalExpression(pNode)) {
      const truth = evalStaticTruthiness(pNode.test);
      if (truth === false && curr.node === pNode.consequent) return true;
      if (truth === true && curr.node === pNode.alternate) return true;
    } else if (t.isLogicalExpression(pNode)) {
      const leftTruth = evalStaticTruthiness(pNode.left);
      if (pNode.operator === "&&" && leftTruth === false && curr.node === pNode.right) {
        return true;
      }
      if (pNode.operator === "||" && leftTruth === true && curr.node === pNode.right) {
        return true;
      }
    }
    curr = parent;
  }
  return false;
}

function isModuleScopedStateBinding(idPath: any, name: string): boolean {
  const binding = idPath.scope?.getBinding?.(name);
  if (!binding) return true;
  return binding.scope?.block?.type === "Program";
}

function isPureAssignmentTarget(idPath: any): boolean {
  let curr = idPath;
  while (curr && curr.parentPath) {
    const parent = curr.parentPath;
    if (t.isAssignmentExpression(parent.node) && parent.node.left === curr.node) {
      return parent.node.operator === "=";
    }
    if (t.isUpdateExpression(parent.node) && parent.node.argument === curr.node) {
      return true;
    }
    if (
      t.isMemberExpression(parent.node) &&
      parent.node.object === curr.node
    ) {
      curr = parent;
      continue;
    }
    break;
  }
  return false;
}

function isInsideIfGuardTestOnly(idPath: any): boolean {
  let curr: any = idPath;
  while (curr && curr.parentPath) {
    const parent = curr.parentPath;
    if (t.isIfStatement(parent.node) && parent.node.test === curr.node) {
      return true;
    }
    if (t.isFunction(parent.node)) {
      return false;
    }
    curr = parent;
  }
  return false;
}

function getRootMemberIdentifier(node: t.Node | null | undefined): t.Identifier | null {
  let curr: t.Node | null | undefined = node;
  while (curr && (t.isMemberExpression(curr) || t.isOptionalMemberExpression(curr))) {
    curr = curr.object;
  }
  return curr && t.isIdentifier(curr) ? curr : null;
}

const CONTAINER_MUTATOR_METHODS =
  /^(?:set|add|delete|clear|push|pop|shift|unshift|splice|fill|writeUInt32LE|writeInt32LE)$/;

const BENIGN_COMPARE_STRING_REGEX =
  /^(?:string|number|object|function|boolean|undefined|symbol|bigint|sha256|sha512|utf8|utf-8|hex|base64|ascii|binary|latin1|ucs2|DENIED|UNLOCKED|ERROR|OK)$/i;
const HEX_SHA256_LITERAL_REGEX = /^[0-9a-f]{64}$/i;
const PLAINTEXT_FLAG_LITERAL_REGEX = /^FLAG\{[^}]{4,}\}$/i;

/**
 * Structural weave verifier (`bla_verify_weave` / CLI `bla verify-weave`).
 * Evaluates JS/TS/Python files against WEAVE_ACCEPTANCE_TESTS and returns
 * concrete `agentActions` for any failed check so the host Agent can self-repair.
 */
function verifyJsWeaveFile(
  absPath: string,
  relPath: string,
  format: ArtifactFormat,
  source: string,
): {
  readonly fileReport: WeaveFileVerification;
  readonly actions: readonly WeaveAgentAction[];
} {
  const actions: WeaveAgentAction[] = [];
  const discoveredFunctions: string[] = [];
  const fnParamCounts = new Map<string, number>();
  const fnHasAnyCall = new Set<string>();
  const entryFunctions = new Set<string>();
  const topLevelReferencedFunctions = new Set<string>();
  const callEdges = new Map<string, Set<string>>();
  const emptyOrStubFunctions: string[] = [];
  const moduleStateVars = new Set<string>();
  const functionsMutatingState = new Set<string>();
  const functionsReadingState = new Set<string>();
  const functionsReadingStateOutsideIfTest = new Set<string>();
  const functionsUsingHelperValueOrMixing = new Set<string>();
  const fnMutatesParamIndices = new Map<string, Set<number>>();
  const fnReadsParamIndices = new Map<string, Set<number>>();
  const stateArgCallRecords: Array<{
    readonly caller: string;
    readonly callee: string;
    readonly argIndex: number;
  }> = [];
  const rawBooleanReturnFunctions = new Set<string>();
  const cleartextCompareLiterals: string[] = [];
  const plaintextFlagLiterals: string[] = [];
  let conditionalCount = 0;
  let literalFalseBranchCount = 0;
  let syntaxValid = true;
  let syntaxErrorMessage = "";

  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      plugins: ["typescript", "jsx", "decorators-legacy"],
      errorRecovery: true,
    });
    if (Array.isArray((ast as any).errors) && (ast as any).errors.length > 0) {
      syntaxValid = false;
      syntaxErrorMessage = String((ast as any).errors[0]?.message ?? "SyntaxError");
    }

    traverse(ast, {
      Program(progPath) {
        for (const stmt of progPath.node.body) {
          const varDecl =
            t.isExportNamedDeclaration(stmt) &&
            t.isVariableDeclaration(stmt.declaration)
              ? stmt.declaration
              : t.isVariableDeclaration(stmt)
                ? stmt
                : null;
          if (!varDecl) continue;
          for (const d of varDecl.declarations) {
            if (!t.isIdentifier(d.id)) continue;
            if (
              varDecl.kind === "let" ||
              varDecl.kind === "var" ||
              t.isObjectExpression(d.init) ||
              t.isArrayExpression(d.init) ||
              t.isNewExpression(d.init)
            ) {
              moduleStateVars.add(d.id.name);
            }
          }
        }
      },
      ExportNamedDeclaration(path) {
        const decl = path.node.declaration;
        if (t.isFunctionDeclaration(decl) && decl.id) {
          entryFunctions.add(decl.id.name);
        } else if (t.isClassDeclaration(decl)) {
          for (const item of decl.body.body) {
            if (
              t.isClassMethod(item) &&
              t.isIdentifier(item.key) &&
              item.key.name !== "constructor"
            ) {
              entryFunctions.add(item.key.name);
            }
          }
        } else if (t.isVariableDeclaration(decl)) {
          for (const d of decl.declarations) {
            if (t.isIdentifier(d.id)) entryFunctions.add(d.id.name);
          }
        }
        for (const spec of path.node.specifiers) {
          if (t.isExportSpecifier(spec) && t.isIdentifier(spec.local)) {
            entryFunctions.add(spec.local.name);
          }
        }
      },
      ExportDefaultDeclaration(path) {
        const decl = path.node.declaration;
        if (t.isFunctionDeclaration(decl) && decl.id) {
          entryFunctions.add(decl.id.name);
        } else if (t.isIdentifier(decl)) {
          entryFunctions.add(decl.name);
        } else if (t.isClassDeclaration(decl)) {
          for (const item of decl.body.body) {
            if (
              t.isClassMethod(item) &&
              t.isIdentifier(item.key) &&
              item.key.name !== "constructor"
            ) {
              entryFunctions.add(item.key.name);
            }
          }
        }
      },
      AssignmentExpression(path) {
        const left = path.node.left;
        if (
          t.isMemberExpression(left) &&
          t.isIdentifier(left.object) &&
          (left.object.name === "exports" || left.object.name === "module")
        ) {
          if (t.isIdentifier(left.property) && left.property.name !== "exports") {
            entryFunctions.add(left.property.name);
          }
          if (t.isIdentifier(path.node.right)) {
            entryFunctions.add(path.node.right.name);
          } else if (t.isObjectExpression(path.node.right)) {
            for (const prop of path.node.right.properties) {
              if (
                (t.isObjectProperty(prop) || t.isObjectMethod(prop)) &&
                t.isIdentifier(prop.key)
              ) {
                entryFunctions.add(prop.key.name);
              }
              if (t.isObjectProperty(prop) && t.isIdentifier(prop.value)) {
                entryFunctions.add(prop.value.name);
              }
            }
          }
        }
      },
    });

    // First pass: collect all named top-level / assigned / method functions
    traverse(ast, {
      Function(path) {
        const fnName = extractJsFunctionName(path);
        if (!fnName) return;
        if (!discoveredFunctions.includes(fnName)) {
          discoveredFunctions.push(fnName);
        }
        fnParamCounts.set(fnName, path.node.params.length);
        if (!callEdges.has(fnName)) {
          callEdges.set(fnName, new Set());
        }
      },
    });

    const discoveredSet = new Set(discoveredFunctions);

    // Second pass: inspect function bodies and top-level warm-init references
    traverse(ast, {
      Function(path) {
        const fnName = extractJsFunctionName(path);
        if (!fnName) return;

        const paramIndexByName = new Map<string, number>();
        path.node.params.forEach((paramNode: t.Node, idx: number) => {
          if (t.isIdentifier(paramNode)) {
            paramIndexByName.set(paramNode.name, idx);
          } else if (
            t.isAssignmentPattern(paramNode) &&
            t.isIdentifier(paramNode.left)
          ) {
            paramIndexByName.set(paramNode.left.name, idx);
          }
        });
        if (!fnMutatesParamIndices.has(fnName)) {
          fnMutatesParamIndices.set(fnName, new Set());
        }
        if (!fnReadsParamIndices.has(fnName)) {
          fnReadsParamIndices.set(fnName, new Set());
        }

        if (t.isBlockStatement(path.node.body)) {
          const stmts = path.node.body.body.filter(
            (s) => !t.isEmptyStatement(s),
          );
          if (stmts.length === 0) {
            emptyOrStubFunctions.push(fnName);
          } else if (
            stmts.length === 1 &&
            t.isReturnStatement(stmts[0]) &&
            (!stmts[0].argument ||
              t.isLiteral(stmts[0].argument) ||
              inspectRawBooleanReturnValue(stmts[0].argument).isRawBool)
          ) {
            emptyOrStubFunctions.push(fnName);
          }
        } else if (
          t.isLiteral(path.node.body) ||
          inspectRawBooleanReturnValue(path.node.body).isRawBool
        ) {
          emptyOrStubFunctions.push(fnName);
        }

        const isEntryFn = entryFunctions.has(fnName);
        const fnRole = classifyFunctionRole(fnName, isEntryFn);
        let fnHasTrueLiteralReturn = false;
        let fnHasFalseLiteralReturn = false;
        let fnHasComputedReturn = false;

        if (!t.isBlockStatement(path.node.body)) {
          const b = inspectRawBooleanReturnValue(path.node.body);
          if (b.isRawBool) {
            if (b.isTrueBranch) fnHasTrueLiteralReturn = true;
            else fnHasFalseLiteralReturn = true;
          } else {
            fnHasComputedReturn = true;
          }
        }

        path.traverse({
          Function(innerPath) {
            innerPath.skip();
          },
          CallExpression(callPath) {
            if (isInsideDeadBranch(callPath)) return;
            fnHasAnyCall.add(fnName);
            let calleeName = "";
            if (t.isIdentifier(callPath.node.callee)) {
              calleeName = callPath.node.callee.name;
            } else if (
              t.isMemberExpression(callPath.node.callee) &&
              t.isThisExpression(callPath.node.callee.object) &&
              t.isIdentifier(callPath.node.callee.property)
            ) {
              calleeName = callPath.node.callee.property.name;
            }

            if (calleeName) {
              callEdges.get(fnName)!.add(calleeName);
              callPath.node.arguments.forEach((argNode, argIdx) => {
                if (
                  t.isIdentifier(argNode) &&
                  moduleStateVars.has(argNode.name) &&
                  isModuleScopedStateBinding(callPath, argNode.name)
                ) {
                  stateArgCallRecords.push({
                    caller: fnName,
                    callee: calleeName,
                    argIndex: argIdx,
                  });
                }
              });

              if (discoveredSet.has(calleeName) && !t.isExpressionStatement(callPath.parent)) {
                let valueActuallyUsed = true;
                if (
                  t.isVariableDeclarator(callPath.parent) &&
                  t.isIdentifier(callPath.parent.id)
                ) {
                  const binding = callPath.scope?.getBinding?.(callPath.parent.id.name);
                  if (
                    binding &&
                    !binding.referenced &&
                    binding.constantViolations.length === 0
                  ) {
                    valueActuallyUsed = false;
                  }
                }
                if (valueActuallyUsed) {
                  functionsUsingHelperValueOrMixing.add(fnName);
                }
              }
              if (/^(?:createHash|pbkdf2Sync|scryptSync|createHmac)$/.test(calleeName)) {
                functionsUsingHelperValueOrMixing.add(fnName);
              }
            }

            if (
              t.isMemberExpression(callPath.node.callee) &&
              t.isIdentifier(callPath.node.callee.property)
            ) {
              const methodName = callPath.node.callee.property.name;
              if (
                /^(?:imul|createHash|pbkdf2Sync|scryptSync|digest|instantiate)$/.test(
                  methodName,
                )
              ) {
                functionsUsingHelperValueOrMixing.add(fnName);
              }
              if (CONTAINER_MUTATOR_METHODS.test(methodName)) {
                const rootObj = getRootMemberIdentifier(callPath.node.callee.object);
                if (rootObj) {
                  if (
                    moduleStateVars.has(rootObj.name) &&
                    isModuleScopedStateBinding(callPath, rootObj.name)
                  ) {
                    functionsMutatingState.add(fnName);
                  }
                  const pIdx = paramIndexByName.get(rootObj.name);
                  if (pIdx !== undefined) {
                    fnMutatesParamIndices.get(fnName)!.add(pIdx);
                  }
                }
              }
            }
          },
          ReturnStatement(retPath) {
            if (isInsideDeadBranch(retPath)) return;
            const arg = retPath.node.argument;
            const b = inspectRawBooleanReturnValue(arg);
            if (b.isRawBool) {
              if (b.isTrueBranch) fnHasTrueLiteralReturn = true;
              else fnHasFalseLiteralReturn = true;
            } else if (arg) {
              fnHasComputedReturn = true;
            }
          },
          BinaryExpression(binPath) {
            if (isInsideDeadBranch(binPath)) return;
            if (
              binPath.node.operator === "^" &&
              !(t.isNumericLiteral(binPath.node.left) && t.isNumericLiteral(binPath.node.right))
            ) {
              functionsUsingHelperValueOrMixing.add(fnName);
            }
            if (
              fnRole === "gate-or-auth" &&
              (binPath.node.operator === "===" ||
                binPath.node.operator === "==" ||
                binPath.node.operator === "!==" ||
                binPath.node.operator === "!=")
            ) {
              const isTypeof =
                (t.isUnaryExpression(binPath.node.left) &&
                  binPath.node.left.operator === "typeof") ||
                (t.isUnaryExpression(binPath.node.right) &&
                  binPath.node.right.operator === "typeof");
              if (!isTypeof) {
                const strLit =
                  extractStaticStringOrTemplate(binPath.node.right) ??
                  extractStaticStringOrTemplate(binPath.node.left);
                if (
                  strLit !== null &&
                  strLit.length >= 4 &&
                  !HEX_SHA256_LITERAL_REGEX.test(strLit) &&
                  !BENIGN_COMPARE_STRING_REGEX.test(strLit)
                ) {
                  cleartextCompareLiterals.push(`${fnName}:${strLit}`);
                }
              }
            }
          },
          StringLiteral(strPath) {
            if (isInsideDeadBranch(strPath)) return;
            if (PLAINTEXT_FLAG_LITERAL_REGEX.test(strPath.node.value)) {
              plaintextFlagLiterals.push(`${fnName}:${strPath.node.value}`);
            }
          },
          TemplateLiteral(tplPath) {
            if (isInsideDeadBranch(tplPath)) return;
            const raw = extractStaticStringOrTemplate(tplPath.node);
            if (raw && PLAINTEXT_FLAG_LITERAL_REGEX.test(raw)) {
              plaintextFlagLiterals.push(`${fnName}:${raw}`);
            }
          },
          Identifier(idPath) {
            const name = idPath.node.name;
            if (isInsideDeadBranch(idPath)) return;
            if (
              discoveredSet.has(name) &&
              name !== fnName &&
              !(t.isFunctionDeclaration(idPath.parent) && idPath.parent.id === idPath.node)
            ) {
              callEdges.get(fnName)!.add(name);
            }
            if (
              moduleStateVars.has(name) &&
              isModuleScopedStateBinding(idPath, name) &&
              !isPureAssignmentTarget(idPath)
            ) {
              functionsReadingState.add(fnName);
              if (!isInsideIfGuardTestOnly(idPath)) {
                functionsReadingStateOutsideIfTest.add(fnName);
              }
            }
            const pIdx = paramIndexByName.get(name);
            if (
              pIdx !== undefined &&
              t.isMemberExpression(idPath.parent) &&
              idPath.parent.object === idPath.node &&
              !isPureAssignmentTarget(idPath)
            ) {
              fnReadsParamIndices.get(fnName)!.add(pIdx);
            }
          },
          IfStatement(ifPath) {
            const truth = evalStaticTruthiness(ifPath.node.test);
            if (truth === false) {
              literalFalseBranchCount += 1;
            } else {
              conditionalCount += 1;
            }
          },
          ConditionalExpression(condPath) {
            const truth = evalStaticTruthiness(condPath.node.test);
            if (truth === false) {
              literalFalseBranchCount += 1;
            } else {
              conditionalCount += 1;
            }
          },
          AssignmentExpression(assignPath) {
            if (isInsideDeadBranch(assignPath)) return;
            if (
              assignPath.node.operator === "^=" ||
              assignPath.node.operator === "|="
            ) {
              functionsUsingHelperValueOrMixing.add(fnName);
            }
            const rootId = getRootMemberIdentifier(assignPath.node.left);
            if (rootId) {
              if (
                moduleStateVars.has(rootId.name) &&
                isModuleScopedStateBinding(assignPath, rootId.name)
              ) {
                functionsMutatingState.add(fnName);
              }
              const pIdx = paramIndexByName.get(rootId.name);
              if (pIdx !== undefined && t.isMemberExpression(assignPath.node.left)) {
                fnMutatesParamIndices.get(fnName)!.add(pIdx);
              }
            }
          },
          UpdateExpression(upPath) {
            if (isInsideDeadBranch(upPath)) return;
            const rootId = getRootMemberIdentifier(upPath.node.argument);
            if (rootId) {
              if (
                moduleStateVars.has(rootId.name) &&
                isModuleScopedStateBinding(upPath, rootId.name)
              ) {
                functionsMutatingState.add(fnName);
                functionsReadingState.add(fnName);
              }
              const pIdx = paramIndexByName.get(rootId.name);
              if (pIdx !== undefined && t.isMemberExpression(upPath.node.argument)) {
                fnMutatesParamIndices.get(fnName)!.add(pIdx);
                fnReadsParamIndices.get(fnName)!.add(pIdx);
              }
            }
          },
        });

        const checkGateBool =
          fnRole === "gate-or-auth" &&
          (isEntryFn ||
            ![...entryFunctions].some(
              (ef) => classifyFunctionRole(ef, true) === "gate-or-auth",
            ));
        if (
          checkGateBool &&
          (fnHasTrueLiteralReturn ||
            (fnHasFalseLiteralReturn && !fnHasComputedReturn))
        ) {
          rawBooleanReturnFunctions.add(fnName);
        }
      },
      // Also track top-level module warm-init / IIFE / dispatch table references
      Identifier(idPath) {
        const name = idPath.node.name;
        if (!discoveredSet.has(name)) return;
        if (isInsideDeadBranch(idPath)) return;
        if (
          (t.isFunctionDeclaration(idPath.parent) && idPath.parent.id === idPath.node) ||
          (t.isVariableDeclarator(idPath.parent) && idPath.parent.id === idPath.node) ||
          ((t.isObjectProperty(idPath.parent) || t.isObjectMethod(idPath.parent)) &&
            idPath.parent.key === idPath.node)
        ) {
          return;
        }
        let enclosingNamedFn = "";
        let p: any = idPath.parentPath;
        while (p) {
          if (t.isFunction(p.node)) {
            const candidate = extractJsFunctionName(p);
            if (candidate) {
              enclosingNamedFn = candidate;
              break;
            }
          }
          p = p.parentPath;
        }
        if (!enclosingNamedFn) {
          topLevelReferencedFunctions.add(name);
        }
      },
    });

    // Propagate parameter-passed module state mutations and reads
    for (const rec of stateArgCallRecords) {
      if (fnMutatesParamIndices.get(rec.callee)?.has(rec.argIndex)) {
        functionsMutatingState.add(rec.callee);
      }
      if (fnReadsParamIndices.get(rec.callee)?.has(rec.argIndex)) {
        functionsReadingState.add(rec.callee);
      }
    }
  } catch (err) {
    syntaxValid = false;
    syntaxErrorMessage = err instanceof Error ? err.message : String(err);
  }

  // If no explicit exports, treat first discovered function as entry
  if (entryFunctions.size === 0 && discoveredFunctions.length > 0) {
    entryFunctions.add(discoveredFunctions[0]!);
  }

  // Reachability BFS from entryFunctions + topLevelReferencedFunctions
  const reachable = new Set<string>([
    ...entryFunctions,
    ...topLevelReferencedFunctions,
  ]);
  const queue = [...reachable];
  while (queue.length > 0) {
    const curr = queue.shift()!;
    const callees = callEdges.get(curr);
    if (!callees) continue;
    for (const target of callees) {
      if (discoveredFunctions.includes(target) && !reachable.has(target)) {
        reachable.add(target);
        queue.push(target);
      }
    }
  }

  const unreferencedFunctions = discoveredFunctions.filter(
    (fn) => !reachable.has(fn),
  );

  // Also flag disconnected no-op helpers in customer-scale modules: a non-entry
  // function that takes 0 parameters, neither touches shared state nor makes any call.
  if (discoveredFunctions.length <= 15) {
    for (const fn of discoveredFunctions) {
      if (
        !entryFunctions.has(fn) &&
        (fnParamCounts.get(fn) ?? 0) === 0 &&
        !emptyOrStubFunctions.includes(fn) &&
        !functionsMutatingState.has(fn) &&
        !functionsReadingState.has(fn) &&
        !fnHasAnyCall.has(fn) &&
        (callEdges.get(fn)?.size ?? 0) === 0
      ) {
        emptyOrStubFunctions.push(fn);
      }
    }
  }

  // Check 1: no-forbidden-markers
  const bannerMatch = source.match(FORBIDDEN_BANNER_REGEX);
  const checkNoMarkers: WeaveCheckResult = {
    id: "no-forbidden-markers",
    titleZh: "无禁止标记",
    passed: bannerMatch === null,
    evidence:
      bannerMatch === null
        ? "0 forbidden `_bla_*` / `BLA-SHIELD` markers found"
        : `Found forbidden marker '${bannerMatch[0]}'`,
    ...(bannerMatch !== null
      ? {
          remediation: `Rename '${bannerMatch[0]}' to a domain-plausible business identifier.`,
        }
      : {}),
  };
  if (!checkNoMarkers.passed) {
    actions.push({
      priority: "high",
      file: relPath,
      checkId: "no-forbidden-markers",
      targetSymbol: bannerMatch?.[0],
      instruction: `Remove or rename forbidden marker '${bannerMatch?.[0]}' in ${relPath}; use domain-plausible business identifiers instead.`,
      verifyTool: "bla_verify_weave",
    });
  }

  // Check 2: mixed-stems
  const scareFns = discoveredFunctions.filter((fn) => hasScareStem(fn));
  const scareRatio =
    discoveredFunctions.length > 0
      ? scareFns.length / discoveredFunctions.length
      : 0;
  const checkMixedStems: WeaveCheckResult = {
    id: "mixed-stems",
    titleZh: "词干混用",
    passed: discoveredFunctions.length > 0 && scareRatio <= 0.5,
    evidence: `${discoveredFunctions.length - scareFns.length}/${discoveredFunctions.length} functions use mundane business stems (scare ratio ${(scareRatio * 100).toFixed(0)}%)`,
    ...(scareRatio > 0.5
      ? {
          remediation: `Rename homogeneous TEE/scare functions (${scareFns.join(", ")}) so >= 2/3 use mundane business stems (session, quota, ledger, epoch).`,
        }
      : {}),
  };
  if (!checkMixedStems.passed) {
    actions.push({
      priority: "medium",
      file: relPath,
      checkId: "mixed-stems",
      instruction:
        discoveredFunctions.length === 0
          ? `Add structured entry/helper functions in ${relPath} so weave verification can inspect identifier stems.`
          : `Rename homogeneous TEE/scare functions (${scareFns.join(", ")}) in ${relPath} so at least 2/3 of functions use mundane business stems.`,
      verifyTool: "bla_verify_weave",
    });
  }

  // Check 3: shared-state-mutation
  // Require both mutation (>=1 fn) AND genuine read (>=2 fns or read+write across >=2 reachable fns)
  const reachableMutating = [...functionsMutatingState].filter((f) =>
    reachable.has(f),
  );
  const reachableReading = [...functionsReadingState].filter((f) =>
    reachable.has(f),
  );
  const sharedStateTouchedCount = new Set([
    ...reachableMutating,
    ...reachableReading,
  ]).size;
  const checkSharedState: WeaveCheckResult = {
    id: "shared-state-mutation",
    titleZh: "共享状态变异",
    passed:
      moduleStateVars.size > 0 &&
      reachableMutating.length >= 1 &&
      reachableReading.length >= 2 &&
      sharedStateTouchedCount >= 2,
    evidence:
      moduleStateVars.size > 0
        ? `Shared state slots [${[...moduleStateVars].join(", ")}] mutated by ${reachableMutating.length} reachable fn(s), read by ${reachableReading.length} reachable fn(s) (touched across ${sharedStateTouchedCount} fn(s))`
        : "No module-level shared state slot detected",
    ...(moduleStateVars.size === 0 ||
    reachableMutating.length < 1 ||
    reachableReading.length < 2 ||
    sharedStateTouchedCount < 2
      ? {
          remediation:
            "Introduce or reuse a shared module state carrier (e.g. `sessionLedgerState`) and ensure it is BOTH mutated (>=1 fn) and genuinely read in conditions/returns/expressions across >=2 reachable functions.",
        }
      : {}),
  };
  if (!checkSharedState.passed) {
    actions.push({
      priority: "high",
      file: relPath,
      checkId: "shared-state-mutation",
      instruction: `Couple entry functions and shadow helpers in ${relPath} via a shared module-level state object/Map (mutated in >=1 reachable function and genuinely read across >=2 reachable functions; write-only stores do not pass).`,
      verifyTool: "bla_verify_weave",
    });
  }

  // Check 4: customer-entry-edges
  const hasEntryEdgeToHelper =
    reachable.size >= 2 && unreferencedFunctions.length === 0;
  const checkEntryEdges: WeaveCheckResult = {
    id: "customer-entry-edges",
    titleZh: "客户入口边",
    passed: hasEntryEdgeToHelper,
    evidence: `Reachable functions from entry: ${reachable.size}/${discoveredFunctions.length}${unreferencedFunctions.length > 0 ? ` (unreferenced: ${unreferencedFunctions.join(", ")})` : ""}`,
    ...(!hasEntryEdgeToHelper
      ? {
          remediation:
            unreferencedFunctions.length > 0
              ? `Wire unreferenced function(s) [${unreferencedFunctions.join(", ")}] into the call graph of [${[...entryFunctions].join(", ")}] so static xref cannot prune them as dead code.`
              : `Add at least one shadow helper function and call it from entry function [${[...entryFunctions].join(", ")}].`,
        }
      : {}),
  };
  if (!checkEntryEdges.passed) {
    actions.push({
      priority: "high",
      file: relPath,
      checkId: "customer-entry-edges",
      ...(unreferencedFunctions[0]
        ? { targetSymbol: unreferencedFunctions[0] }
        : {}),
      instruction:
        unreferencedFunctions.length > 0
          ? `Call unreferenced helper(s) [${unreferencedFunctions.join(", ")}] from entry function(s) [${[...entryFunctions].join(", ")}] in ${relPath}.`
          : `Weave at least one helper call from entry function [${[...entryFunctions].join(", ") || "main"}] in ${relPath}.`,
      verifyTool: "bla_verify_weave",
    });
  }

  // Check 5: opaque-true-entanglement
  const checkOpaque: WeaveCheckResult = {
    id: "opaque-true-entanglement",
    titleZh: "不透明真缠绕",
    passed: conditionalCount >= 1 && literalFalseBranchCount === 0,
    evidence: `${conditionalCount} conditional guard(s) active, ${literalFalseBranchCount} literal-false dead branch(es)`,
    ...(conditionalCount === 0 || literalFalseBranchCount > 0
      ? {
          remediation:
            literalFalseBranchCount > 0
              ? "Replace literal `if (false)` / `if (0)` dead branches with state-dependent opaque predicates over the shared state slot."
              : "Guard the happy-path or helper call with a deterministic state invariant (e.g. `(state.epoch & 1) !== 0`).",
        }
      : {}),
  };
  if (!checkOpaque.passed) {
    actions.push({
      priority: "medium",
      file: relPath,
      checkId: "opaque-true-entanglement",
      instruction:
        literalFalseBranchCount > 0
          ? `Replace literal-false dead branch in ${relPath} with a shared-state opaque predicate.`
          : `Add a shared-state conditional invariant in ${relPath} guarding the business happy path and shadow helper call.`,
      verifyTool: "bla_verify_weave",
    });
  }

  // Check 6: filter-resistance
  const filterDefects: string[] = [];
  if (emptyOrStubFunctions.length > 0) {
    filterDefects.push(`trivial/empty stub functions: ${emptyOrStubFunctions.join(", ")}`);
  }
  if (unreferencedFunctions.length > 0) {
    filterDefects.push(`unreferenced dead functions: ${unreferencedFunctions.join(", ")}`);
  }
  if (!checkNoMarkers.passed) {
    filterDefects.push(`forbidden marker '${bannerMatch?.[0]}'`);
  }
  const checkFilterResistance: WeaveCheckResult = {
    id: "filter-resistance",
    titleZh: "抗「独立层」过滤",
    passed: filterDefects.length === 0,
    evidence:
      filterDefects.length === 0
        ? "0 empty/constant-stub decoy functions detected"
        : `Filter-resistance defects: ${filterDefects.join("; ")}`,
    ...(filterDefects.length > 0
      ? {
          remediation:
            emptyOrStubFunctions.length > 0
              ? `Give [${emptyOrStubFunctions.join(", ")}] non-trivial bodies that read and update the shared state carrier.`
              : `Wire unreferenced functions [${unreferencedFunctions.join(", ")}] into live entry paths and remove any forbidden markers.`,
        }
      : {}),
  };
  if (!checkFilterResistance.passed) {
    actions.push({
      priority: "high",
      file: relPath,
      checkId: "filter-resistance",
      ...(emptyOrStubFunctions[0] || unreferencedFunctions[0]
        ? { targetSymbol: emptyOrStubFunctions[0] ?? unreferencedFunctions[0] }
        : {}),
      instruction:
        emptyOrStubFunctions.length > 0
          ? `Replace trivial/empty body in function(s) [${emptyOrStubFunctions.join(", ")}] in ${relPath} with non-trivial state computations over the shared state slot.`
          : `Resolve filter-resistance defects (${filterDefects.join("; ")}) in ${relPath}.`,
      verifyTool: "bla_verify_weave",
    });
  }

  // Check 7: crown-jewel-entanglement (dissolve raw boolean gates, cleartext compares,
  // lane-independent byte loops, plaintext FLAG literals, and cosmetic side-effect-only weaves)
  const isPostHardenLabyrinth = discoveredFunctions.length > 15;
  const laneLint = isPostHardenLabyrinth
    ? { looksLaneIndependent: false, findings: [] as const }
    : lintLaneIndependence(source);
  const cosmeticOnlyGateEntries: string[] = [];
  if (!isPostHardenLabyrinth) {
    for (const fn of entryFunctions) {
      const role = classifyFunctionRole(fn, true);
      if (role !== "gate-or-auth") continue;
      const callees = [...(callEdges.get(fn) ?? [])].filter(
        (c) => c !== fn && discoveredFunctions.includes(c),
      );
      if (
        callees.length === 0 ||
        (!functionsReadingStateOutsideIfTest.has(fn) &&
          !functionsUsingHelperValueOrMixing.has(fn))
      ) {
        cosmeticOnlyGateEntries.push(fn);
      }
    }
  }

  const crownJewelDefects: string[] = [];
  if (!syntaxValid) {
    crownJewelDefects.push(`syntax error (${syntaxErrorMessage})`);
  }
  if (!isPostHardenLabyrinth && rawBooleanReturnFunctions.size > 0) {
    crownJewelDefects.push(
      `raw boolean return in gate function(s) [${[...rawBooleanReturnFunctions].join(", ")}]`,
    );
  }
  if (!isPostHardenLabyrinth && cleartextCompareLiterals.length > 0) {
    crownJewelDefects.push(
      `cleartext secret comparison [${cleartextCompareLiterals.slice(0, 3).join(", ")}]`,
    );
  }
  if (plaintextFlagLiterals.length > 0) {
    crownJewelDefects.push(
      `hardcoded plaintext FLAG literal [${plaintextFlagLiterals.slice(0, 2).join(", ")}]`,
    );
  }
  if (!isPostHardenLabyrinth && laneLint.looksLaneIndependent) {
    crownJewelDefects.push(
      `lane-independent per-byte/per-index oracle (${laneLint.findings.map((f) => f.id).join(", ")})`,
    );
  }
  if (!isPostHardenLabyrinth && cosmeticOnlyGateEntries.length > 0) {
    crownJewelDefects.push(
      `cosmetic/unentangled gate function(s) [${cosmeticOnlyGateEntries.join(", ")}] do not couple helper return values or shared-state digests into the decision/output`,
    );
  }

  const checkCrownJewel: WeaveCheckResult = {
    id: "crown-jewel-entanglement",
    titleZh: "皇冠逻辑消解与抗Patch耦合",
    passed: crownJewelDefects.length === 0,
    evidence:
      crownJewelDefects.length === 0
        ? "0 raw boolean gates, 0 cleartext secret compares, 0 lane-independent byte oracles, and gate outputs are data-coupled to shared state/helpers"
        : `Crown-jewel weaknesses remaining: ${crownJewelDefects.join("; ")}`,
    ...(crownJewelDefects.length > 0
      ? {
          remediation:
            "Replace raw `return true/false` and cleartext `===` checks in gate/auth functions with whole-input key derivation (SHA-256/PBKDF2/rolling accumulator) where helper return values and shared-state slots directly feed the derived digest or decrypted payload.",
        }
      : {}),
  };
  if (!checkCrownJewel.passed) {
    actions.push({
      priority: "high",
      file: relPath,
      checkId: "crown-jewel-entanglement",
      ...(cosmeticOnlyGateEntries[0] || [...rawBooleanReturnFunctions][0]
        ? {
            targetSymbol:
              cosmeticOnlyGateEntries[0] ?? [...rawBooleanReturnFunctions][0],
          }
        : {}),
      instruction: `Resolve crown-jewel entanglement defects in ${relPath}: ${crownJewelDefects.join("; ")}. Ensure helper return values and shared-state slots feed directly into the verification digest or payload derivation rather than side-effect-only calls.`,
      verifyTool: "bla_verify_weave",
    });
  }

  const checks = [
    checkNoMarkers,
    checkMixedStems,
    checkSharedState,
    checkEntryEdges,
    checkOpaque,
    checkFilterResistance,
    checkCrownJewel,
  ];
  const passedCount = checks.filter((c) => c.passed).length;
  const score = Math.round((passedCount / checks.length) * 100);

  return {
    fileReport: {
      path: absPath,
      relativePath: relPath,
      format,
      passed: syntaxValid && passedCount === checks.length,
      score,
      syntaxValid,
      checks,
      discoveredFunctions,
      reachableFunctions: [...reachable],
      unreferencedFunctions,
      sharedStateVars: [...moduleStateVars],
    },
    actions,
  };
}

function stripPythonCommentsAndStrings(pySource: string): string {
  return pySource
    .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, '""')
    .replace(/#.*$/gm, "")
    .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
}

function verifyPythonWeaveFile(
  absPath: string,
  relPath: string,
  source: string,
): {
  readonly fileReport: WeaveFileVerification;
  readonly actions: readonly WeaveAgentAction[];
} {
  const actions: WeaveAgentAction[] = [];
  const fnNames: string[] = [];
  const fnBodies = new Map<string, string>();
  const passOnlyFns: string[] = [];
  const stateVars: string[] = [];

  const strippedSource = stripPythonCommentsAndStrings(source);
  const parsedPyFns = extractPythonFunctions(source);

  for (const fn of parsedPyFns) {
    const name = fn.name;
    const strippedBody = stripPythonCommentsAndStrings(fn.body);
    if (!fnNames.includes(name)) {
      fnNames.push(name);
    }
    fnBodies.set(name, strippedBody);
    const bodyLines = strippedBody
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && l !== '""' && l !== "''");
    if (
      bodyLines.length === 0 ||
      (bodyLines.length === 1 &&
        /^(?:pass|\.\.\.|return(?:\s+(?:None|True|False|0|1|""|''))?)$/.test(bodyLines[0]!))
    ) {
      if (!passOnlyFns.includes(name)) passOnlyFns.push(name);
    }
  }

  const stateRegex =
    /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(?:\{|\[|dict\(|set\(|bytearray\(|[A-Z][A-Za-z0-9_]*\()/gm;
  let sm: RegExpExecArray | null;
  while ((sm = stateRegex.exec(strippedSource)) !== null) {
    const varName = sm[1]!;
    if (!stateVars.includes(varName)) stateVars.push(varName);
  }
  const globalMatchRegex = /\bglobal\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)/g;
  let gm: RegExpExecArray | null;
  while ((gm = globalMatchRegex.exec(strippedSource)) !== null) {
    for (const part of gm[1]!.split(",")) {
      const v = part.trim();
      if (v && !stateVars.includes(v)) stateVars.push(v);
    }
  }

  // Strip dead `if False:` / `if 0:` lines before checking call reachability
  const liveCode = strippedSource.replace(
    /^[ \t]*if\s+(?:False|0|1\s*==\s*2)\s*:\s*\n(?:[ \t]+.*\n?)*/gm,
    "",
  );

  // Build intra-file call graph across defs in liveCode (including self.method(...))
  const calledFns = new Set<string>();
  const callingFns = new Set<string>();
  for (const [caller, body] of fnBodies.entries()) {
    const liveBody = body.replace(
      /^[ \t]*if\s+(?:False|0|1\s*==\s*2)\s*:\s*\n(?:[ \t]+.*\n?)*/gm,
      "",
    );
    for (const callee of fnNames) {
      if (callee === caller) continue;
      if (new RegExp(`(?:\\b|self\\.)${callee}\\s*\\(`).test(liveBody)) {
        calledFns.add(callee);
        callingFns.add(caller);
      }
    }
  }
  // Also check module top-level calls (outside def headers)
  for (const fn of fnNames) {
    const matches = liveCode.match(new RegExp(`(?:\\b|\\.)${fn}\\s*\\(`, "g"));
    if (matches && matches.length >= 2) {
      calledFns.add(fn);
    }
  }

  const reachable = new Set<string>();
  for (const fn of fnNames) {
    if (callingFns.has(fn) || calledFns.has(fn)) {
      reachable.add(fn);
    }
  }
  const unreferenced = fnNames.filter((f) => !reachable.has(f));
  const bannerMatch = source.match(FORBIDDEN_BANNER_REGEX);
  const scareFns = fnNames.filter((f) => hasScareStem(f));
  const scareRatio = fnNames.length > 0 ? scareFns.length / fnNames.length : 0;
  const hasConditional = /\bif\s+/.test(strippedSource);
  const hasLiteralFalse = /\bif\s+(?:False|0|1\s*==\s*2)\s*:/.test(strippedSource);

  // Verify that shared state containers are actually touched inside >= 2 function bodies
  // (or >= 1 customer def when python-customer-def-weave / warm-init is active)
  const fnsTouchingState = new Set<string>();
  for (const [fn, body] of fnBodies.entries()) {
    for (const sv of stateVars) {
      if (new RegExp(`\\b${sv}\\b`).test(body)) {
        fnsTouchingState.add(fn);
      }
    }
    if (/\["epoch"\]|\["warm"\]/.test(body)) {
      fnsTouchingState.add(fn);
    }
  }
  const isPostProtectWeave =
    inspectWeaveHints(source, "python-source").hints.includes(
      "python-customer-def-weave",
    );
  const statePassed =
    (stateVars.length > 0 && fnsTouchingState.size >= 2) ||
    (isPostProtectWeave && fnsTouchingState.size >= 1);

  const pyCrownJewelDefects: string[] = [];
  if (!isPostProtectWeave && fnNames.length <= 15) {
    const publicGateFns = fnNames.filter(
      (f) => !f.startsWith("_") && classifyFunctionRole(f, true) === "gate-or-auth",
    );
    for (const fn of fnNames) {
      const isPublic = !fn.startsWith("_");
      if (classifyFunctionRole(fn, isPublic) !== "gate-or-auth") {
        continue;
      }
      if (!isPublic && publicGateFns.length > 0) {
        continue;
      }
      const strippedBody = fnBodies.get(fn) ?? "";
      const returnMatches = [...strippedBody.matchAll(/\breturn\s+([^\r\n#]+)/g)].map(
        (rm) => rm[1]!.trim(),
      );
      const hasTrueLit = returnMatches.some((r) => /^True\b/.test(r));
      const hasFalseLit = returnMatches.some((r) => /^False\b/.test(r));
      const hasComputedRet = returnMatches.some(
        (r) => !/^(?:True|False|None)\b/.test(r),
      );
      if (hasTrueLit || (hasFalseLit && !hasComputedRet)) {
        pyCrownJewelDefects.push(`raw boolean return in def '${fn}'`);
      }
      if (isPublic && (!calledFns.has(fn) || callingFns.has(fn))) {
        const callsHelper = fnNames.some(
          (other) =>
            other !== fn &&
            new RegExp(`(?:\\b|self\\.)${other}\\s*\\(`).test(strippedBody),
        );
        const touchesStateOrHash =
          fnsTouchingState.has(fn) ||
          /\^|\^=|\|=|sha256|pbkdf2|hmac|digest/.test(strippedBody);
        if (!callsHelper || !touchesStateOrHash) {
          pyCrownJewelDefects.push(
            `gate def '${fn}' is not data-coupled to shared state and helper defs`,
          );
        }
      }
    }
    const eqMatch = source.match(/[!=]=\s*["']([^"'\r\n]{4,})["']/);
    if (
      eqMatch &&
      eqMatch[1] &&
      !HEX_SHA256_LITERAL_REGEX.test(eqMatch[1]) &&
      !BENIGN_COMPARE_STRING_REGEX.test(eqMatch[1]) &&
      eqMatch[1] !== "__main__"
    ) {
      pyCrownJewelDefects.push(`cleartext string comparison '${eqMatch[1]}'`);
    }
    const pyLaneLint = lintLaneIndependence(source);
    if (pyLaneLint.looksLaneIndependent) {
      pyCrownJewelDefects.push(
        `lane-independent per-byte/per-index oracle (${pyLaneLint.findings.map((f) => f.id).join(", ")})`,
      );
    }
  }
  if (/\bFLAG\{[^}]{4,}\}/i.test(source)) {
    pyCrownJewelDefects.push("hardcoded plaintext FLAG literal");
  }

  const pyFilterDefects: string[] = [];
  if (passOnlyFns.length > 0) {
    pyFilterDefects.push(`pass-only stubs: ${passOnlyFns.join(", ")}`);
  }
  if (unreferenced.length > 0) {
    pyFilterDefects.push(`unreferenced defs: ${unreferenced.join(", ")}`);
  }
  if (bannerMatch !== null) {
    pyFilterDefects.push(`forbidden marker '${bannerMatch[0]}'`);
  }

  const checks: WeaveCheckResult[] = [
    {
      id: "no-forbidden-markers",
      titleZh: "无禁止标记",
      passed: bannerMatch === null,
      evidence:
        bannerMatch === null
          ? "0 forbidden markers"
          : `Found '${bannerMatch[0]}'`,
    },
    {
      id: "mixed-stems",
      titleZh: "词干混用",
      passed: fnNames.length > 0 && scareRatio <= 0.5,
      evidence: `${fnNames.length - scareFns.length}/${fnNames.length} mundane defs`,
    },
    {
      id: "shared-state-mutation",
      titleZh: "共享状态变异",
      passed: statePassed,
      evidence:
        statePassed
          ? `Shared state containers [${stateVars.join(", ")}] touched across ${fnsTouchingState.size} def(s)`
          : `Shared state containers [${stateVars.join(", ") || "none"}] touched in only ${fnsTouchingState.size} def(s) (requires >= 2)`,
    },
    {
      id: "customer-entry-edges",
      titleZh: "客户入口边",
      passed: reachable.size >= 2 && unreferenced.length === 0,
      evidence: `Reachable defs: ${reachable.size}/${fnNames.length}`,
    },
    {
      id: "opaque-true-entanglement",
      titleZh: "不透明真缠绕",
      passed: hasConditional && !hasLiteralFalse,
      evidence: hasConditional
        ? "Conditional invariant present"
        : "No conditional guard found",
    },
    {
      id: "filter-resistance",
      titleZh: "抗「独立层」过滤",
      passed: pyFilterDefects.length === 0,
      evidence:
        pyFilterDefects.length === 0
          ? "0 pass-only stubs"
          : pyFilterDefects.join("; "),
    },
    {
      id: "crown-jewel-entanglement",
      titleZh: "皇冠逻辑消解与抗Patch耦合",
      passed: pyCrownJewelDefects.length === 0,
      evidence:
        pyCrownJewelDefects.length === 0
          ? "0 raw boolean gates, 0 cleartext secret compares, 0 plaintext FLAG literals"
          : `Crown-jewel weaknesses remaining: ${pyCrownJewelDefects.join("; ")}`,
    },
  ];

  for (const c of checks) {
    if (!c.passed) {
      actions.push({
        priority: "high",
        file: relPath,
        checkId: c.id,
        instruction: `Fix failed weave check '${c.id}' (${c.evidence}) in ${relPath}, or run bla_harden with weave_decoys:true.`,
        verifyTool: "bla_verify_weave",
      });
    }
  }

  const passedCount = checks.filter((c) => c.passed).length;
  return {
    fileReport: {
      path: absPath,
      relativePath: relPath,
      format: "python-source",
      passed: passedCount === checks.length,
      score: Math.round((passedCount / checks.length) * 100),
      syntaxValid: true,
      checks,
      discoveredFunctions: fnNames,
      reachableFunctions: [...reachable],
      unreferencedFunctions: unreferenced,
      sharedStateVars: stateVars,
    },
    actions,
  };
}

function verifyNativeWeaveFile(
  absPath: string,
  relPath: string,
  source: string,
  ext: string,
): {
  readonly fileReport: WeaveFileVerification;
  readonly actions: readonly WeaveAgentAction[];
} {
  const actions: WeaveAgentAction[] = [];
  const fnNames: string[] = [];
  const fnBodies = new Map<string, string>();
  const emptyFns: string[] = [];
  const stateVars: string[] = [];

  const noComments = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");

  // Extract top-level state declarations (static/global/mut/var, including Go var (...) blocks)
  const stateLines = noComments.split(/\r?\n/);
  let braceDepth = 0;
  let inGoVarBlock = false;
  for (const rawLine of stateLines) {
    if (braceDepth === 0) {
      if (ext === ".go" && /^\s*var\s*\(\s*$/.test(rawLine)) {
        inGoVarBlock = true;
      } else if (inGoVarBlock && /^\s*\)\s*$/.test(rawLine)) {
        inGoVarBlock = false;
      } else if (inGoVarBlock) {
        const goBlockVar = rawLine.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s+/);
        if (goBlockVar?.[1] && !stateVars.includes(goBlockVar[1])) {
          stateVars.push(goBlockVar[1]);
        }
      }
      const cState = rawLine.match(
        /^\s*(?:(?:static|volatile|mut|pub|const)\s+)*(?:uint(?:32|64|16|8)_t|int(?:32|64|16|8)?_t|unsigned(?:\s+int|\s+long|\s+char|\s+short)?|int|long|short|char|bool|_Bool|size_t|uintptr_t|struct\s+\w+|u32|u64|u16|u8|usize|i32|i64|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])*\s*(?::[^=;]+)?(?:=|;)/,
      );
      const rsState = rawLine.match(
        /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:static|const)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:/,
      );
      const goState = rawLine.match(/^\s*var\s+([A-Za-z_][A-Za-z0-9_]*)\s+/);
      const candidate = cState?.[1] ?? rsState?.[1] ?? goState?.[1];
      if (candidate && !stateVars.includes(candidate)) {
        stateVars.push(candidate);
      }
    }
    for (const ch of rawLine) {
      if (ch === "{") braceDepth += 1;
      else if (ch === "}") braceDepth = Math.max(0, braceDepth - 1);
    }
  }

  // Extract function definitions and brace-delimited bodies
  const fnHeaderRegex =
    ext === ".rs"
      ? /(?:^|\n)[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\([^)]*\)[^{;]*\{/g
      : ext === ".go"
        ? /(?:^|\n)[ \t]*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*\([^)]*\)[^{;]*\{/g
        : /(?:^|\n)[ \t]*(?:[A-Za-z_][A-Za-z0-9_* \t]*?)(?:[ \t]+|\*[ \t]*)([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{/g;

  let fm: RegExpExecArray | null;
  while ((fm = fnHeaderRegex.exec(noComments)) !== null) {
    const fnName = fm[1]!;
    if (/^(?:if|for|while|switch|return|sizeof|catch)$/.test(fnName)) continue;
    const openBraceIdx = fm.index + fm[0].lastIndexOf("{");
    let depth = 1;
    let idx = openBraceIdx + 1;
    while (idx < noComments.length && depth > 0) {
      const ch = noComments[idx];
      if (ch === "{") depth += 1;
      else if (ch === "}") depth -= 1;
      idx += 1;
    }
    const body = noComments.slice(openBraceIdx + 1, Math.max(openBraceIdx + 1, idx - 1));
    if (!fnNames.includes(fnName)) {
      fnNames.push(fnName);
      fnBodies.set(fnName, body);
      const trimmedBody = body.replace(/\s+/g, "");
      if (
        trimmedBody.length === 0 ||
        /^return(?:0|1|true|false)?;$/.test(trimmedBody)
      ) {
        emptyFns.push(fnName);
      }
    }
  }

  const calledFns = new Set<string>();
  const callingFns = new Set<string>();
  for (const [caller, body] of fnBodies.entries()) {
    for (const callee of fnNames) {
      if (callee === caller) continue;
      if (new RegExp(`\\b${callee}\\s*\\(`).test(body)) {
        calledFns.add(callee);
        callingFns.add(caller);
      }
    }
  }

  const reachable = new Set<string>();
  for (const fn of fnNames) {
    if (callingFns.has(fn) || calledFns.has(fn)) {
      reachable.add(fn);
    }
  }
  const unreferenced = fnNames.filter((f) => !reachable.has(f));
  const bannerMatch = source.match(FORBIDDEN_BANNER_REGEX);
  const scareFns = fnNames.filter((f) => hasScareStem(f));
  const scareRatio = fnNames.length > 0 ? scareFns.length / fnNames.length : 0;
  const hasConditional = /\bif\s*[\s(]/.test(noComments);
  const hasLiteralFalse = /\bif\s*\(\s*(?:false|0)\s*\)|\bif\s+false\b/.test(
    noComments,
  );

  const fnsTouchingState = new Set<string>();
  for (const [fn, body] of fnBodies.entries()) {
    for (const sv of stateVars) {
      if (new RegExp(`\\b${sv}\\b`).test(body)) {
        fnsTouchingState.add(fn);
      }
    }
  }

  const nativeCrownJewelDefects: string[] = [];
  for (const [fn, body] of fnBodies.entries()) {
    if (classifyFunctionRole(fn, true) !== "gate-or-auth") continue;
    const retMatches = [...body.matchAll(/\breturn\s+([^;\r\n]+)/g)].map((rm) =>
      rm[1]!.trim(),
    );
    const hasTrueLit = retMatches.some((r) => /^true\b/.test(r));
    const hasFalseLit = retMatches.some((r) => /^false\b/.test(r));
    const hasComputedRet = retMatches.some((r) => !/^(?:true|false)\b/.test(r));
    if (hasTrueLit || (hasFalseLit && !hasComputedRet)) {
      nativeCrownJewelDefects.push(`raw boolean return in '${fn}'`);
    }
    const strcmpMatch = body.match(
      /\b(?:strcmp|strncmp|memcmp)\s*\([^,]+,\s*"([^"]{4,})"|==\s*"([^"]{4,})"/,
    );
    const literalSecret = strcmpMatch?.[1] ?? strcmpMatch?.[2];
    if (
      literalSecret &&
      !HEX_SHA256_LITERAL_REGEX.test(literalSecret) &&
      !BENIGN_COMPARE_STRING_REGEX.test(literalSecret)
    ) {
      nativeCrownJewelDefects.push(
        `cleartext secret comparison '${literalSecret}' in '${fn}'`,
      );
    }
    if (!calledFns.has(fn) || callingFns.has(fn)) {
      const callsHelper = fnNames.some(
        (other) => other !== fn && new RegExp(`\\b${other}\\s*\\(`).test(body),
      );
      const usesMixingOrState =
        fnsTouchingState.has(fn) ||
        /\^|\^=|\|=|wrapping_mul|rotate_left/.test(body);
      if (!callsHelper || !usesMixingOrState) {
        nativeCrownJewelDefects.push(
          `gate function '${fn}' is not entangled with shared state and helper computations`,
        );
      }
    }
  }
  if (/\bFLAG\{[^}]{4,}\}/i.test(source)) {
    nativeCrownJewelDefects.push("hardcoded plaintext FLAG literal");
  }

  const nativeFilterDefects: string[] = [];
  if (emptyFns.length > 0) {
    nativeFilterDefects.push(`trivial/empty native stubs: ${emptyFns.join(", ")}`);
  }
  if (unreferenced.length > 0) {
    nativeFilterDefects.push(`unreferenced native functions: ${unreferenced.join(", ")}`);
  }
  if (bannerMatch !== null) {
    nativeFilterDefects.push(`forbidden marker '${bannerMatch[0]}'`);
  }

  const checks: WeaveCheckResult[] = [
    {
      id: "no-forbidden-markers",
      titleZh: "无禁止标记",
      passed: bannerMatch === null,
      evidence:
        bannerMatch === null
          ? "0 forbidden markers"
          : `Found '${bannerMatch[0]}'`,
    },
    {
      id: "mixed-stems",
      titleZh: "词干混用",
      passed: fnNames.length > 0 && scareRatio <= 0.5,
      evidence: `${fnNames.length - scareFns.length}/${fnNames.length} mundane native functions`,
    },
    {
      id: "shared-state-mutation",
      titleZh: "共享状态变异",
      passed: stateVars.length > 0 && fnsTouchingState.size >= 2,
      evidence:
        stateVars.length > 0 && fnsTouchingState.size >= 2
          ? `Shared state [${stateVars.join(", ")}] touched across ${fnsTouchingState.size} function(s)`
          : `Shared state [${stateVars.join(", ") || "none"}] touched in ${fnsTouchingState.size} function(s) (requires >= 2)`,
    },
    {
      id: "customer-entry-edges",
      titleZh: "客户入口边",
      passed: reachable.size >= 2 && unreferenced.length === 0,
      evidence: `Reachable native functions: ${reachable.size}/${fnNames.length}`,
    },
    {
      id: "opaque-true-entanglement",
      titleZh: "不透明真缠绕",
      passed: hasConditional && !hasLiteralFalse,
      evidence: hasConditional
        ? "Conditional invariant present"
        : "No conditional guard found",
    },
    {
      id: "filter-resistance",
      titleZh: "抗「独立层」过滤",
      passed: nativeFilterDefects.length === 0,
      evidence:
        nativeFilterDefects.length === 0
          ? "0 trivial/empty native stubs"
          : nativeFilterDefects.join("; "),
    },
    {
      id: "crown-jewel-entanglement",
      titleZh: "皇冠逻辑消解与抗Patch耦合",
      passed: nativeCrownJewelDefects.length === 0,
      evidence:
        nativeCrownJewelDefects.length === 0
          ? "Native gate functions are coupled with shared state and bitwise/helper mixing with 0 cleartext compares"
          : `Native crown-jewel weaknesses: ${nativeCrownJewelDefects.join("; ")}`,
    },
  ];

  for (const c of checks) {
    if (!c.passed) {
      actions.push({
        priority: "high",
        file: relPath,
        checkId: c.id,
        instruction: `Fix failed native weave check '${c.id}' (${c.evidence}) in ${relPath}. Emit shield headers via bla_emit_headers or weave shared state + mundane helpers into the native entry function.`,
        verifyTool: "bla_verify_weave",
      });
    }
  }

  const passedCount = checks.filter((c) => c.passed).length;
  return {
    fileReport: {
      path: absPath,
      relativePath: relPath,
      format: "native-source",
      passed: passedCount === checks.length,
      score: Math.round((passedCount / checks.length) * 100),
      syntaxValid: true,
      checks,
      discoveredFunctions: fnNames,
      reachableFunctions: [...reachable],
      unreferencedFunctions: unreferenced,
      sharedStateVars: stateVars,
    },
    actions,
  };
}

export function verifyWeaveTarget(
  targetPath: string,
  options: { readonly maxTargets?: number } = {},
): WeaveVerificationReport {
  const abs = resolve(targetPath);
  if (!existsSync(abs)) {
    throw new Error(`verify-weave target not found: ${abs}`);
  }
  const maxTargets = options.maxTargets ?? 48;
  const st = statSync(abs);
  const candidateFiles = st.isDirectory()
    ? listCandidateFiles(abs, maxTargets)
    : [abs];
  const rootAbs = st.isDirectory() ? abs : resolve(abs, "..");

  const fileReports: WeaveFileVerification[] = [];
  const allActions: WeaveAgentAction[] = [];

  for (const file of candidateFiles) {
    const format = detectArtifactFormat(file);
    const ext = extname(file).toLowerCase();
    const relPath = relative(rootAbs, file) || basename(file);
    if (
      format === "javascript" ||
      format === "typescript" ||
      format === "html-bundle"
    ) {
      const src = readFileSync(file, "utf8");
      const { fileReport, actions } = verifyJsWeaveFile(
        file,
        relPath,
        format,
        src,
      );
      fileReports.push(fileReport);
      allActions.push(...actions);
    } else if (format === "python-source") {
      const src = readFileSync(file, "utf8");
      const { fileReport, actions } = verifyPythonWeaveFile(file, relPath, src);
      fileReports.push(fileReport);
      allActions.push(...actions);
    } else if (
      ext === ".c" ||
      ext === ".cpp" ||
      ext === ".cc" ||
      ext === ".rs" ||
      ext === ".go"
    ) {
      const src = readFileSync(file, "utf8");
      const { fileReport, actions } = verifyNativeWeaveFile(
        file,
        relPath,
        src,
        ext,
      );
      fileReports.push(fileReport);
      allActions.push(...actions);
    }
  }

  const overallPassed =
    fileReports.length > 0 && fileReports.every((f) => f.passed);
  const weaveScore =
    fileReports.length > 0
      ? Math.round(
          fileReports.reduce((acc, f) => acc + f.score, 0) / fileReports.length,
        )
      : 0;

  const summary =
    fileReports.length === 0
      ? "No JS/TS/Python source files found to verify weave entanglement."
      : overallPassed
        ? `All ${fileReports.length} file(s) passed structural weave verification (weaveScore: ${weaveScore}/100). Ready for bla_harden.`
        : `${fileReports.filter((f) => !f.passed).length}/${fileReports.length} file(s) need structural weave adjustments (weaveScore: ${weaveScore}/100). Follow the ${allActions.length} agentActions and re-run bla_verify_weave.`;

  return {
    schema: WEAVE_VERIFY_SCHEMA,
    targetPath: abs,
    verifiedAtIso: new Date().toISOString(),
    overallPassed,
    weaveScore,
    files: fileReports,
    agentActions: allActions,
    summary,
  };
}
