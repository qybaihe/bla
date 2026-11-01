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

## 2. JS 已织入 vs Python 仍 warm-init

| 管线 | 现状 | 含义 |
| :--- | :--- | :--- |
| **JavaScript / TypeScript** (`ast-shield.ts`) | **已织入** | opaque-true 包裹快乐路径语句；真实函数体织入步进器与 tarpit 互调；认知装甲与 seed 纠缠 |
| **Python** (`tarpit-generator.ts` + `python.ts`) | **warm-init-only**（#51） | 稠密异构体、共享状态、词干混用、模块级 warm-init 保 xref；**尚未**把诱饵调用织进客户 `def` |
| 若干二进制 / sidecar 格式 | sidecar / 附加块 | 原则仍适用；完整入口纠缠列为后续 |

本 PR 把理论与 MCP 执行面备齐；**完整 Python（及更多格式）AST 织入客户定义**留给 follow-up PR。

## 3. 织入原则（执行时必须遵守）

1. **共享状态** — 诱饵与业务读写同一运行时槽位（epoch / peer / digest 等）。  
2. **客户入口可达** — 边必须从入口、路由、导出 API 进入诱饵；仅靠顶层 warm-init 不够对抗「独立层」过滤。  
3. **词干混用** — 约 2/3 平凡业务名 + 约 1/3 安全诱饵名。  
4. **快乐路径不透明真** — 真实语句用 opaque-true 守卫；禁止只把诱饵放进永不执行的死图。  
5. **调用图纠缠** — 在真实函数体内织入步进 / 互调 / 影子堆搅动。  
6. **可选自密封** — 入口与完整字节 / digest 绑定（产品缺口见 issue #40）。

## 4. 明确禁止

- 纯噪声层、可整层剥离的 honeypot 目录/文件  
- 可 grep 的 `BLA-SHIELD` / `_bla_` 横幅（审计短语 `runtime attestation boundary` 可保留）  
- 仅 TEE 词表的同质包  
- 永不调用的 `pass` 桩冒充「加固」  
- 任何进攻性内容

## 5. 后续 AI 执行清单（不依赖聊天记录）

1. `resources/read` → `bla://directives/weave-decoy`（或读本文件）  
2. `bla_weave_plan` → `{ "path": "<project-or-artifact>" }`，保存返回的 JSON 工单  
3. `bla_harden` / `bla_defend` / `bla_protect` 传 **`weave_decoys: true`**  
4. JS：验证现有 AST 织入，**不要**再堆 sidecar 噪声  
5. Python：保持稠密 + warm-init；**不要**用空 scare 模块填补缺口；标注 follow-up AST weave  
6. 按 §6 验收；失败则回滚噪声改动

## 6. 验收（apply 后必须通过）

1. **无禁止标记** — 无 `_bla_` / `BLA-SHIELD` 横幅  
2. **词干混用** — 诱饵名非 100% TEE/enclave  
3. **共享状态变异** — 诱饵体修改与业务相关的共享槽  
4. **客户入口边** — 静态 xref 从客户入口到达诱饵（JS 必须；Python warm-init 仅为过渡）  
5. **opaque-true 缠绕** — 删除守卫或诱饵调用会改变行为或验证结果  
6. **抗独立层过滤** — 不能仅凭空体 / 同质 scare / 未引用启发式整层丢弃

## 7. MCP 表面

| 表面 | 作用 |
| :--- | :--- |
| Resource `bla://directives/weave-decoy` | 返回本理论的可执行 Markdown |
| Tool `bla_weave_plan` | 只读：分析路径 → `bla-weave-plan/v1` JSON |
| `bla_harden` / `bla_defend` / `bla_protect` 参数 `weave_decoys` | 标注本次加固并挂接未来 AST 织入钩子 |

实现入口：`src/shields/weave/weave-decoy.ts`、`src/mcp/server.ts`。

## 8. Follow-up PR（本 PR 不做）

- 将诱饵调用 **AST 织入 Python 客户函数体**（超越 warm-init）  
- 扩展更多格式的入口纠缠验收  
- 可选 self-seal 与 `defenseScore` 对 onefile 诚实性（#40）

## 相关文档

- [`counter-rea-deception.md`](./counter-rea-deception.md) — 模型误判诱导总览 + PyInstaller 诚实边界  
- [`cli-and-mcp.md`](./cli-and-mcp.md) — CLI / MCP 参数索引  
