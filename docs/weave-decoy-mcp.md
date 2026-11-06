# 织入诱饵（Weave Decoy）理论包 — MCP 可执行

> **防御专用（Counter-REA）**。本文只描述如何把诱饵巧妙织入真实业务路径，提升对 REA / WorkBuddy 类智能体的过滤难度。  
> **禁止**：破解、逆向突破、绕过 PoC、攻击剧本。  
> 给后续 AI 的入口：MCP resource `bla://directives/weave-decoy`、工具 `bla_weave_plan`、harden 旗标 `weave_decoys: true`。

## 1. 背景：为什么「噪声诱饵」失败

在 Python 稠密化（#51）之后，经验仍成立：

| 失败形态 | 智能体如何过滤 | 结果 |
| :--- | :--- | :--- |
| 空 / `pass` 桩、`_bla_*` 同质 honeypot | 未引用 + 空体启发式 | 整层丢弃 |
| 仅 TEE / TPM / Nitro / enclave 词表 | 一次 scare 正则 | 整图丢弃 |
| 与业务无关的 sidecar「防护层」文件 | 「独立层」分类 | 难度不升反降 |
| 可 grep 的 `BLA-SHIELD` 横幅 | 明确「这是防护」证据 | 方便一刀切 |

**目标**：诱饵必须**巧妙织入**客户真实路径，使「丢掉诱饵层」等于破坏业务或验证失败。  
**构建方式必须是结构纠缠，而不是规则引擎**（禁止「匹配业务名 → 注入固定片段」对照表；禁止同质 marker 模板当策略）。

## 2. JS 已织入 vs Python 结构织入（gated）

| 管线 | 现状 | 含义 |
| :--- | :--- | :--- |
| **JavaScript / TypeScript** (`ast-shield.ts`) | **已织入** | opaque-true 包裹快乐路径语句；真实函数体织入步进器与 tarpit 互调；认知装甲与 seed 纠缠 |
| **Python `.py`** (`python-ast-weave.ts` + tarpit) | **woven（需 `weave_decoys: true`）** | #51 稠密异构体 + warm-init 之后，对客户 `FunctionDef` 做结构织入：共享槽 touch + opaque-false 诱饵调用；按 tarpit 名表**身份**跳过已注入 decoy/warm（非业务名规则） |
| **Python `.pyc`** | `weave_decoys:true` → co_consts decoy TYPE_CODE 织入 | false 时仍为 trailer honey |
| 若干二进制 / sidecar 格式 | sidecar / 附加块 | 原则仍适用；完整入口纠缠列为后续 |

`weave_decoys: false` 时 Python 行为与 #51 一致（仅 warm-init，不改客户 `def` 体）。

## 3. 织入原则（执行时必须遵守）

1. **共享状态** — 诱饵与业务读写同一运行时槽位（epoch / peer / digest 等）。  
2. **客户入口可达** — 边必须从入口、路由、导出 API 进入诱饵；仅靠顶层 warm-init 不够对抗「独立层」过滤。  
3. **词干混用** — 约 2/3 平凡业务名 + 约 1/3 安全诱饵名。  
4. **快乐路径不透明真** — 真实语句用 opaque-true 守卫；禁止只把诱饵放进永不执行的死图。  
5. **调用图纠缠** — 在真实函数体内织入步进 / 互调 / 影子堆搅动（结构扫描，非规则表）。  
6. **可选自密封** — 入口与完整字节 / digest 绑定（产品缺口见 issue #40）。

## 4. 明确禁止

- 纯噪声层、可整层剥离的 honeypot 目录/文件  
- 可 grep 的 `BLA-SHIELD` / `_bla_` 横幅（审计短语 `runtime attestation boundary` 可保留）  
- 仅 TEE 词表的同质包  
- 永不调用的 `pass` 桩冒充「加固」  
- 规则式「名字匹配 → 注入」与同质 marker 模板当防护策略  
- 任何进攻性内容

## 5. 后续 AI 执行清单（不依赖聊天记录）

1. `resources/read` → `bla://directives/weave-decoy`（或读本文件）  
2. `bla_weave_plan` → `{ "path": "<project-or-artifact>" }`，读取返回的 JSON 工单及每个目标的 `surgicalWorkorder`（`entryFunctions`、`sharedStateSlots`、`branchCandidates`、`agentRewriteRecipe`）  
3. **Agent 源码级织入（Stage 2）**：按 `surgicalWorkorder` 在源码中编写共享同一运行时状态槽的领域诱饵函数并从真实入口调用，随后调用 **`bla_verify_weave`** 验证 6 项结构验收，确保 `overallPassed: true` 且 `agentActions` 清零  
4. `bla_harden` / `bla_defend` / `bla_protect` 传 **`weave_decoys: true`**  
5. JS：验证现有 AST 织入，**不要**再堆 sidecar 噪声  
6. Python `.py`：确认客户 `def` 体内出现共享槽 touch / 诱饵 xref；**不要**用空 scare 模块填补  
7. 按 §6 验收；失败则回滚噪声改动

## 6. 验收（apply 后必须通过）

1. **无禁止标记** — 无 `_bla_` / `BLA-SHIELD` 横幅  
2. **词干混用** — 诱饵名非 100% TEE/enclave  
3. **共享状态变异** — 诱饵体与织入语句修改同一共享槽  
4. **客户入口边** — 静态 xref 从客户入口到达诱饵（JS；Python 在 `weave_decoys:true` 下经由客户 def 织入）  
5. **opaque 缠绕** — 删除守卫或诱饵调用会改变行为或验证结果  
6. **抗独立层过滤** — 不能仅凭空体 / 同质 scare / 未引用启发式整层丢弃

## 7. MCP 表面

| 表面 | 作用 |
| :--- | :--- |
| Resource `bla://directives/weave-decoy` | 返回本理论的可执行 Markdown |
| Tool `bla_weave_plan` | 只读：分析路径 → `bla-weave-plan/v1` JSON（含 AST 级 `surgicalWorkorder`） |
| Tool `bla_verify_weave` | 只读：校验源码/产物的 6 项织入验收 → `bla-weave-verify/v1` JSON（含 `weaveScore` 与 `agentActions`） |
| `bla_harden` / `bla_defend` / `bla_protect` 参数 `weave_decoys` | **真实管线属性**：激活 Python 客户 def 结构织入（JS 始终 AST 织入）；非仅报告布尔标注 |
| `.blarc` / `bla.config.json` 字段 `weaveDecoys` | 与 CLI `--weave-decoys` / MCP `weave_decoys` 同义；CLI 读取后与旗标做 OR |

实现入口：`src/shields/weave/weave-decoy.ts`、`src/shields/formats/python-ast-weave.ts`、`src/mcp/server.ts`。

## 8. Follow-up

- 更多 sidecar 格式的入口纠缠验收（DESIGN + planner stub 已落地；完整 strip⇒fail rewrite 仍开）  
- self-seal / defenseScore honesty soft-caps 已落地；onefile/peel 更深的分数模型仍开（#40）  
- `bla lint-lanes` / WASM `wasmPreserveExports` 已落地；格式 densify 与更广的模板数值卫生仍开

## 相关文档

- [`counter-rea-deception.md`](./counter-rea-deception.md) — 模型误判诱导总览 + PyInstaller 诚实边界  
- [`cli-and-mcp.md`](./cli-and-mcp.md) — CLI / MCP 参数索引  
