<div align="center">

[English](../../README.md) · **简体中文** · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md) · [Roman Urdu](README_ur-Latn.md) · [Română](README_ro.md)

# <img src="../assets/logo.png" alt="BLA Shield" width="42" align="absmiddle" /> BLA: Blind LLM Agents

### 用于保护二进制文件、应用程序与运行时行为免受 AI 自动化逆向分析的 MCP 与 CLI 工具。

**指向你准备发布的构建产物，从源码、字节码到二进制层面保护核心逻辑与运行时行为。**

[![npm version](https://img.shields.io/badge/npm-bla--agents-2563eb?style=flat-square&logo=npm)](https://www.npmjs.com/package/bla-agents)
[![GitHub Trending](https://img.shields.io/badge/GitHub_Trending-%2315_Daily-0ea5e9?style=flat-square&logo=github&logoColor=white)](https://trendshift.io/repositories/323569)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-3b82f6?style=flat-square)](../cli-and-mcp.md)
[![Node.js requirements](https://img.shields.io/badge/Node.js-%5E22.13_%7C%7C_%3E%3D24-0284c7?style=flat-square&logo=nodedotjs&logoColor=white)](#你可以保护哪些目标)
[![Counter-REA Verified](https://img.shields.io/badge/Counter--REA-BLUE_SHIELD-1d4ed8?style=flat-square)](#基准测试与案例)
[![MIT license](https://img.shields.io/badge/license-MIT-38bdf8?style=flat-square)](../../LICENSE)

**[官方网站 (bla.tools)](https://bla.tools/) · [技术指南](https://bla.tools/guides/) · [测试案例](https://bla.tools/showcase/)**

[快速开始](#快速开始) · [工作原理](#工作原理) · [你可以保护哪些目标](#你可以保护哪些目标) · [基准测试与案例](#基准测试与案例) · [常见问题 (FAQ)](#常见问题-faq) · [文档](#文档)

<code>npx bla-agents setup</code> · <code>npx bla-agents defend ./dist --manifest</code>

</div>

> [!IMPORTANT]
> 请从官方仓库 [qybaihe/bla](https://github.com/qybaihe/bla) 或 npm 包 [bla-agents](https://www.npmjs.com/package/bla-agents) 获取 BLA。

<div align="center">

<br />

<img src="../assets/bla-vs-rea-showcase.svg" alt="未受保护产物与 BLA 加固产物的逆向分析对比" width="1200" />

<br />

</div>

---

BLA 是一个面向软件发布产物的防御性 MCP 服务与 CLI 工具，用于评估、加固并验证软件对 AI 自动化逆向工具（如 REA）的抗分析能力。它可以在不修改业务源码的前提下，扫描发布产物中的符号与 SourceMap 暴露面、注入特定格式的静态与运行时保护层，并验证加固后产物的运行时行为与原版完全一致。

BLA 支持将你的编程代理连接到原生二进制、JavaScript 与 Electron 应用、WebAssembly 模块、Python 字节码、SQLite 数据库、AI 模型权重与移动端包体的保护工作流中。你也可以直接在终端或打包工具（Vite / Webpack / Rollup / esbuild）中调用相同能力。

`setup` 会向你的编程代理注册 BLA 的 MCP 服务并安装配套技能说明。所有静态、字节码与二进制保护模块均已内置，无需额外安装外部编译器或第三方加壳工具。

## 快速开始

### 配置你的 Agent

安装 Node.js 与 npm 后，运行：

```bash
npx bla-agents setup
```

选择你使用的编程代理（或加上 `--all-detected --yes`），预览变更并确认。`setup` 会注册 BLA 的 MCP 服务器并安装 `blind-llm-agents` 技能，同时自动备份原有配置文件。完成后重启你的 Agent 即可。

支持 Claude Code、Codex、Cursor、Gemini CLI、Windsurf、Google Antigravity、OpenCode、VS Code 与 GitHub Copilot CLI。手动配置方式参见[安装与配置指南](../installation.md)。

### 在 Agent 中使用

连接完成后，可以直接通过自然语言调用完整的 5 阶段加固流程，或按步骤单独执行：

- **一键执行完整保护流程（`bla_defend` —— 暴露巡检 → 风险审计 → 护盾注入 → 等价性验证 → 签名清单）：**
  ```text
  对 ./dist 目录执行 bla_defend（使用 bankrupt 级别并输出验证清单）。
  ```
- **1. 发布前暴露面审计（`Audit`）：**
  ```text
  使用 BLA 审计 ./dist 目录，列出暴露的模块、符号和 Electron IPC 通道，并评估自动化逆向还原的风险。
  ```
- **2. 保护目标产物（`Protect`）：**
  ```text
  使用 BLA 保护 ./dist/app.asar，将加固后的产物输出到 ./dist/app.shielded.asar。
  ```
- **3. 验证保护效果与运行一致性（`Verify`）：**
  ```text
  对比验证 ./dist/app.shielded.asar 与原文件 ./dist/app.asar，确认静态分析状态已降级为 limited 且功能保持一致。
  ```

### 使用终端命令

所有工作流均可通过 `npx bla-agents`（或全局安装后的 `bla`）在终端直接运行：

- **一键完整保护流程（`defend`）** —— 单条命令依次执行 `inspect-release`、`audit`、`protect`、`verify` 并生成 `.bla-manifest.json`：
  ```bash
  npx -y bla-agents@latest defend /absolute/path/to/app --manifest
  ```
- **1. 审计目标暴露度（`audit`）** —— 查看暴露评分（`0–100`）、可见符号与预估分析开销：
  ```bash
  npx -y bla-agents@latest audit /absolute/path/to/app --json
  ```
- **2. 保护目标产物（`protect`）** —— 应用静态预算阈值保护、调用图扩展、诱饵元数据与运行时检测：
  ```bash
  npx -y bla-agents@latest protect /absolute/path/to/app -o /absolute/path/to/app.shielded --intensity bankrupt
  ```
- **3. 验证保护结果（`verify`）** —— 检查静态/语义分析器是否触发资源上限并保持运行等价：
  ```bash
  npx -y bla-agents@latest verify /absolute/path/to/app.shielded /absolute/path/to/app
  ```
- **4. 运行 8 项基准测试（`benchmark`）**：
  ```bash
  npx -y bla-agents@latest benchmark
  ```
- **5. 生成 C/C++、Rust 或 Go 编译期保护头文件（`emit-headers`）**：
  ```bash
  npx -y bla-agents@latest emit-headers --lang c -o ./include/bla_shield.h
  ```

如需全局安装 `bla` 命令：

```bash
npm install --global bla-agents
bla --help
```

### 在构建打包工具中使用（Vite / Rollup / Webpack / esbuild）

导入 `bla-agents/bundler`，在构建阶段自动保护输出的 JS 分包、SourceMap 与 `.wasm` 模块：

```typescript
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-agents/bundler";

export default defineConfig({
  plugins: [blaVitePlugin({ intensity: "bankrupt", enableHoneySourceMaps: true })],
});
```

### 更新 BLA

如果通过 `npm install --global` 或 `bun add --global` 安装：

```bash
bla update
```

如果使用 `npx`，可通过以下命令更新 Agent 注册配置与技能文件：

```bash
npx bla-agents@latest setup
```

## 工作原理

你的 Agent 通过 MCP 调用 BLA 来审计构建产物、应用特定格式的保护层并验证输出结果。当自动化逆向分析工具检查受保护的产物时，会遇到三层防御机制：

1. **静态与语义分析预算限流（`Exhaustion`）：** 利用 $O(1)$ 数论不透明谓词与不可达分支中的强连通调用图（SCC），触发 `REA` 等分析器内部的静态资源上限（如 `primitive-candidates > 256`、`alias-selections > 512`、`getter-expansion > 512`、`primitive-bytes > 1 MiB`、`maximum_rustc_hashes > 64`、`maximumSentinelsPerSlice > 32`）。
2. **证据优先级与控制流干扰（`Deception`）：** 在静态分析视图下将真实业务逻辑标记为 `status: "unknown"`，同时提供结构清晰的影子状态机、硬件飞地接口声明（`SGX` / `TPM2` / `Secure Enclave`）以及 VLQ v3 诱饵 SourceMap，干扰模型的语义归因。
3. **运行时探针检测与 Fuse 加固（`Runtime Guard`）：** 原地加固 Electron V1 Fuse 配置位（`RunAsNode=0`、`EnableNodeCliInspectArguments=0`），并在检测到 CDP、Node Inspector、Frida 或 WebDriver 动态挂载时返回合成遥测数据。

## 你可以保护哪些目标

BLA 要求 Node.js `^22.13.0 || >=24.0.0` 与 npm，所有格式保护模块均在本地运行，无外部二进制依赖：

| 保护目标                | 应用的保护机制与分析器影响                                                                        | 对应命令与说明                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| JavaScript / TypeScript | 触发 `primitive-candidates > 256`、`alias-selections > 512`、`getter-expansion > 512` 与状态机扩展 | `bla protect app.js` · 内置 Babel AST 引擎；参见[技术矩阵](../../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md) |
| Electron `.asar` 应用   | IPC 通道去字面量化（`channel: null`）、注册同名诱饵 IPC 处理器与影子模块                          | `bla protect app.asar` · 内置 Chromium Pickle `.asar` 解包与 SHA-256 完整性重打包器                   |
| Electron 二进制 Fuses   | 原地加固 V1 Fuse 位（关闭 `RunAsNode` 与 `Inspect`）+ 追加 `34 > 32` 个诱饵 Fuse 哨兵             | `bla protect ElectronApp` · 触发 `ElectronFuseResourceFailure (maximumSentinelsPerSlice = 32)`        |
| 动态运行时 CDP / Frida  | 检测 `inspector.url()`、`--inspect`、`__frida` 并向动态探针返回合成遥测数据                       | 自动注入到受保护的 JS/TS/Electron 产物中（[`runtime-shield.ts`](../../src/shields/runtime/runtime-shield.ts)） |
| SourceMap 与 HTML       | 移除真实映射，生成合法的 VLQ v3 诱饵 SourceMap（指向 `enclave://tee-runtime/...`）                | `bla protect index.html` · 干扰 `recover_javascript_sources` 与 `trace_web_source_location`           |
| 原生二进制文件          | 追加 `.bla.rodata` 元数据、诱饵符号表项与扫描器阈值守卫                                           | `bla protect daemon.elf` · 内置 ELF64、Mach-O（Thin & Universal）与 Windows PE/COFF 支持              |
| Rust 二进制             | 注入 `68 > 64` 个不同的 `/rustc/<40-hex>/` 路径 + 诱饵 zlib `.dep-v0` 依赖描述                    | `bla protect rust-bin` · 触发 `RustBinaryProvider`（`MAX_RUSTC_HASHES = 64` 阈值限制）                |
| Go 二进制               | 注入诱饵 Go `go1.23.4` 构建信息与 `dep\tgithub.com/enclave-tees/sgx-bridge` 模块记录              | `bla protect go-bin` · 混淆 `inspect_go_binary` 模块清单                                              |
| Flutter / Dart AOT      | 注入 `66 > 64` 个 Dart 快照魔数头（`0xf5f5dcdc`）+ `6 > 4` 行 LLVM 工具链标识                     | `bla protect libapp.so` · 触发 `SnapshotHashScanner (capped: true)` 与版本冲突检查                    |
| WASM 模块               | 剥离调试段，添加诱饵 `"name"` 自定义段（`tee_hardware_enclave_stub`）与扩展元数据段               | `bla protect core.wasm` · 内置 LEB128 解析器，保持 `WebAssembly.validate` 校验通过                    |
| Python 与 `.pyc` 字节码 | 向 `.py` 注入调用图状态机，向 `.pyc` 常量池追加 `TYPE_ASCII` 元数据项                             | `bla protect module.pyc` · 支持 CPython 3.7–3.14 `.pyc` 头部与 marshal 结构                           |
| SQLite 数据库           | 添加 3 张辅助表与 `GENERATED ALWAYS AS (bla_enclave_unseal(...)) VIRTUAL` 虚拟生成列守卫          | `bla protect data.sqlite` · 真实业务表正常查询；只读快照扫描触发 `SqliteColumnEvaluationFailure`      |
| AI 模型权重文件         | 向 `.safetensors` 与 `.gguf` 头部添加 `35 > 32` 层嵌套的 JSON / ARRAY 元数据                      | `bla protect weights.safetensors` · 触发 `ModelFormatFailure (json-nesting / metadata-nesting > 32)`  |
| Android DEX 与 APK      | 向 `classes.dex` 追加 `Lcom/enclave/sgx/...` 诱饵类描述符并重算 SHA-1 与 Adler32 校验和           | `bla protect classes.dex` 或 `app.apk` · 符合 Dalvik/ART 校验规范                                     |
| Unity IL2CPP 元数据     | 向 `global-metadata.dat`（`0xFAB11BAF`）追加桥接元数据与方法拓扑项                                | `bla protect global-metadata.dat` · 增加 `inspect_il2cpp_metadata` 符号还原复杂度                     |
| C / C++ / Rust / Go 源码| 生成带 `used, noinline` 状态机的编译期头文件 `bla_shield.h` / `.rs` / `.go`                       | `bla emit-headers --lang c\|rust\|go` · 编译进二进制符号表与控制流图                                  |

## 基准测试与案例

运行 `npx bla-agents benchmark` 可在本地执行全部 8 个基准测试案例，验证分析器降级效果与运行时等价性：

| 基准测试目标 | 未保护基线 | 加固后（`npx bla-agents protect`） | Token 放大倍率 | 运行时等价校验 |
| :--- | :--- | :--- | :---: | :---: |
| **1. DX-Ball 声道平移计算** (`.js`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,068` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% 一致 |
| **2. Notion Electron 剪贴板桥** (`.asar`) | `98/100` · `9,132` tok · **`$0.34`** (`COMPLETE`) | `2/100` · `23,125,000` tok · **`$358.28`** (`LIMITED`) | **2,532.3x** | ✅ 100% 一致 |
| **3. 企业级离线授权校验模块** (`.ts`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,169` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% 一致 |
| **4. WebAssembly 密码学模块** (`.wasm`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,067` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% 一致 |
| **5. Native ELF64 二进制** (Rust / Go / Fuse / Dart) | `81/100` · `9,278` tok · **`$0.35`** (`COMPLETE`) | `2/100` · `3,698,135` tok · **`$59.72`** (`LIMITED`) | **398.6x** | ✅ 100% 一致 |
| **6. 本地 SQLite 授权数据库** (`.sqlite`) | `81/100` · `10,568` tok · **`$0.29`** (`COMPLETE`) | `7/100` · `1,711,235` tok · **`$28.36`** (`LIMITED`) | **161.9x** | ✅ 100% 一致 |
| **7. 端侧 AI 权重文件** (`.safetensors`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,073` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% 一致 |
| **8. Android Dalvik 字节码** (`classes.dex`) | `81/100` · `8,900` tok · **`$0.34`** (`COMPLETE`) | `7/100` · `2,786,285` tok · **`$45.09`** (`LIMITED`) | **313.1x** | ✅ 100% 一致 |

### DX-Ball：声道计算模块的抗还原加固

在未保护状态下，静态分析可在数次工具调用内还原 `clampPan` 与 `calculateSoundPanFromX`。运行 `npx bla-agents protect examples/dx-ball-sound-pan/sound-pan.js --intensity bankrupt` 后，分析器的 `parse_status` 变为 `"partial"`，`examination.status` 降级为 `"limited"`（触发 `alias-selections`、`primitive-bytes`、`primitive-candidates` 阈值限制），同时所有输入坐标的计算返回值与原版完全一致。

### Notion：隐藏 Electron 剪贴板 IPC 桥接拓扑

静态分析器通常通过匹配 `ipcRenderer.invoke` 与 `ipcMain.handle` 的字面量字符串来还原 Electron IPC 调用链。BLA 将真实 IPC 通道改写为 $\ge 9$ 段数论不透明条件表达式（使静态提取结果为 `channel: null`），并在相同字面量通道上注册诱饵处理器，从而触发 `electron_call_paths_limited: true`。

### 原生二进制、SQLite 与 AI 模型：触发解析器容量限制

当对受保护的产物执行 `inspect_rust_binary`、`inspect_electron_fuses`、`inspect_sqlite_database` 或 `inspect_model_artifact` 时，解析器会触发预设的资源阈值限制（`Read-only data contains more than 64 distinct rustc commit paths`、`Slice 0 contains more than 32 Electron fuse sentinels`、`SqliteColumnEvaluationFailure`、`ModelFormatFailure: json-nesting`）。

## 常见问题 (FAQ)

<details>
<summary><strong>哪些编程代理（Agents）可以使用 BLA？</strong></summary>

任何支持本地 MCP 服务器或 `SKILL.md` 的 AI 编程代理均可使用。`npx bla-agents setup` 支持自动配置 Claude Code、Cursor、Codex、Gemini CLI、Windsurf、Google Antigravity、OpenCode、VS Code 与 GitHub Copilot CLI。详见[安装指南](../installation.md)。

</details>

<details>
<summary><strong>BLA 会影响软件运行速度或改变原有的运行结果吗？</strong></summary>

不会。BLA 注入的静态分析预算守卫与扩展调用图均位于 $O(1)$ 数论不透明谓词（$7x^2 - 1 \neq y^2 \pmod 7$）保护的不可达分支内，不会在正常热路径上执行。所有 8 个基准测试目标均通过了 100% 输入/输出一致性校验。

</details>

<details>
<summary><strong>BLA 与传统混淆器（如 javascript-obfuscator 或 O-LLVM）有什么区别？</strong></summary>

传统混淆器主要依赖标识符重命名（如将 `calculatePrice` 改为 `_0x1a2b`），大语言模型仍可通过控制流语义进行推断；重度虚拟化壳则会带来运行时开销。BLA 针对 AI 逆向工具的静态分析器、资源配额与证据提取规则进行设计——破坏 IPC 字面量配对、触发解析器配额上限，并通过结构化影子逻辑干扰语义还原。

</details>

<details>
<summary><strong>保护文件时需要安装 Hopper、Ghidra、IDA 或 WABT 吗？</strong></summary>

不需要。BLA 的全部 19 种格式处理模块（Babel AST、Chromium `.asar`、LEB128 `.wasm`、CPython `.pyc`、ELF/Mach-O/PE、SQLite3、`.safetensors`/`.gguf`、`.dex`/`Il2Cpp`）均内置在 `bla-agents` 中，无外部工具依赖。

</details>

<details>
<summary><strong>当使用 REA 分析受 BLA 保护的软件时会发生什么？</strong></summary>

1. JavaScript/Electron 分析器状态从 `complete` 降级为 `partial` / `limited`，无法静态配对 IPC 通道（`channel: null`）。
2. Rust 二进制、Electron Fuse、SQLite 和 AI 模型检查器触发资源配额限制。
3. 特征追踪流程（`trace_application_feature`）会进入扩展的交叉引用状态机与诱饵 SourceMap（`enclave://tee-runtime/`）。

</details>

<details>
<summary><strong>安装 Skill 有什么作用？</strong></summary>

[`blind-llm-agents` 技能](../../.agents/skills/blind-llm-agents/SKILL.md)为你的编程代理提供了标准的保护工作流说明，指导 Agent 完成发布前暴露面审计、选择保护级别（`stealth`、`balanced`、`maximum`、`bankrupt`）、接入打包插件以及验证输出产物。

</details>

<details>
<summary><strong>BLA 会上传源码或二进制文件吗？</strong></summary>

不会。BLA 的所有审计、加固与验证均在本地离线完成，支持确定性随机种子（`--seed`），不发起任何网络请求。

</details>

<details>
<summary><strong>遇到问题或 Bug 怎么办？</strong></summary>

请先更新至最新版本并运行 `bla doctor` 检查环境状态：

```bash
npx bla-agents@latest doctor
npx bla-agents@latest setup
```

若问题仍存在，请在 [GitHub Issues](https://github.com/qybaihe/bla/issues) 提交你的 BLA 版本号（`bla --version`）、目标格式与复现步骤。

</details>

## 文档

- [安装与 Agent 配置](../installation.md)：Agent 自动注册、Bundler 插件集成、更新与卸载。
- [CLI 与 MCP 契约说明](../cli-and-mcp.md)：命令行参数、退出码与 JSON-RPC 2.0 MCP 工具定义。
- [反制 REA 技术矩阵](../../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md)：`REA` 内部资源阈值与对应的保护机制说明。

安全问题请通过 [SECURITY.md](../../SECURITY.md) 反馈。

## 免责声明

详见 [DISCLAIMER.md](../../DISCLAIMER.md)。

BLA 是一款防御性软件保护工具，仅用于加固你拥有合法权利或获授权保护的软件、前端产物、模型与二进制文件。所有注入的元数据与辅助函数均保持原程序的正常运行时行为。

## 贡献指南

欢迎在 [qybaihe/bla](https://github.com/qybaihe/bla) 提交 Issue 或 Pull Request。提交代码前请运行 `npm run build && npm test && node dist/cli.js benchmark`。

## 友情社区与公开挑战赛

- 🎯 **[BLA 公开逆向挑战赛 (`challenge/`)](../../challenge/README.md)** — 欢迎挂上 REA、Claude Opus、Codex 挑战经 BLA 加固的靶机程序，看看能否避开蜜罐假 Flag 拿到真 Flag！
- [LINUX DO (`linux.do`)](https://linux.do/) — 新的理想型社区

## 开源协议

[MIT](../../LICENSE)
