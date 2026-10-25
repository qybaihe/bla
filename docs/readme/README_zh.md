<div align="center">

[English](../../README.md) · **简体中文** · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md) · [Roman Urdu](README_ur-Latn.md) · [Română](README_ro.md)

# BLA: Blind LLM Agents

### 一个覆盖二进制、桌面与前端应用、数据库、AI 模型及运行时行为的反 AI 逆向工程 MCP 与 CLI 护盾。

**构建你的核心功能。从二进制底层致盲一切企图克隆它的 AI 代理。**

[![npm version](https://img.shields.io/badge/npm-bla--shield-cb3837?style=flat-square&logo=npm)](https://www.npmjs.com/package/bla-shield)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](../cli-and-mcp.md)
[![Node.js requirements](https://img.shields.io/badge/Node.js-22.13%2B%20%7C%2024%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#你可以保护哪些目标)
[![Counter-REA Verified](https://img.shields.io/badge/Counter--REA-100%25_Verified-10b981?style=flat-square)](#实战案例与基准测试)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

[快速开始](#快速开始) · [BLA 工作原理](#bla-工作原理) · [你可以保护哪些目标](#你可以保护哪些目标) · [实战案例与基准测试](#实战案例与基准测试) · [常见问题 (FAQ)](#常见问题-faq) · [文档](#文档)

<code>npx bla-shield setup</code>

</div>

> [!IMPORTANT]
> 请从官方仓库 [qybaihe/bla](https://github.com/qybaihe/bla) 或 npm 包 [bla-shield](https://www.npmjs.com/package/bla-shield) 获取 BLA。

<div align="center">

<br />

<img src="../assets/bla-vs-rea-showcase.svg" alt="左右分屏对比：未受保护应用被 REA 在 38 秒内复刻 vs. BLA 护盾触发 2,121 倍 Token 消耗与容量上限熔断" width="1200" />

<br />

</div>

---

担心别人用 [REA](https://github.com/morluto/rea) 或 AI 编程代理指向你发布的软件，几十秒内扒光并复刻你的核心逻辑？直接让你的 Agent 用 BLA（`Poison → Exhaust → Hallucinate`）为构建产物加上对抗护盾。它无需重写源码即可扫描暴露面、展示攻击者能提取的证据、植入架构级飞地投毒与算法算力沼泽（Tarpits），并验证自动化逆向复刻彻底失效。

BLA 将你的编程代理连接到原生二进制、JavaScript 与 Electron 应用、WebAssembly 模块、Python 字节码、SQLite 数据库、AI 模型权重与移动端包体的保护工具。你也可以在终端或打包工具（Vite / Webpack / Rollup / esbuild）中直接调用。所有保护均在本地运行，100% 保持原有运行时功能与返回值不变。

`setup` 会自动向你的 Agent 注册 BLA 的 MCP 服务并安装配套技能说明。所有静态、字节码与二进制护盾全部内置，无需安装任何第三方商业加壳器或外部编译器。

## 快速开始

### 配置你的 Agent

安装 Node.js 与 npm 后，运行：

```bash
npx bla-shield setup
```

选择你使用的编程代理（或加上 `--all-detected --yes`），预览变更并确认。`setup` 会自动注册 BLA 的 MCP 服务器并安装 `blind-llm-agents` 技能，同时自动备份原有配置文件。完成后重启你的 Agent 即可。

支持 Claude Code、Codex、Cursor、Gemini CLI、Windsurf、Google Antigravity、OpenCode、VS Code 与 GitHub Copilot CLI。手动配置方式参见[安装与配置指南](../installation.md)。

### 直接向你的 Agent 提问（各环节对应指令）

你可以直接用自然语言让 Agent 执行任意环节：

- **1. 发布前暴露面自检（`Audit`）：**
  ```text
  用 BLA 扫描 ./dist 目录，检查哪些模块和 Electron IPC 通道在 REA 面前处于裸奔状态，并估算 Claude 逆向克隆它的时间和成本。
  ```
- **2. 一键注入对抗护盾（`Protect`）：**
  ```text
  用 BLA 的 bankrupt 强度保护 ./dist/app.asar，注入飞地架构迷雾和算法算力沼泽，输出到 ./dist/app.shielded.asar。
  ```
- **3. 验证防线有效性与 Token 放大倍率（`Verify`）：**
  ```text
  对比验证 ./dist/app.shielded.asar 和原文件 ./dist/app.asar，确认 REA 分析状态已被降级为 limited，并汇报 Token 消耗放大倍数。
  ```

### 使用终端命令（各环节对应 CLI 语句）

所有工作流均可通过 `npx bla-shield`（或全局安装后的 `bla`）在终端直接运行：

- **1. 扫描目标暴露度（`audit`）** —— 查看暴露评分（`0–100`）、裸露符号与攻击者克隆成本：
  ```bash
  npx -y bla-shield@latest audit /absolute/path/to/app --json
  ```
- **2. 注入对抗护盾（`protect`）** —— 植入语义预算爆破器、Tarpit 状态机、飞地诱饵与动态反调试护盾：
  ```bash
  npx -y bla-shield@latest protect /absolute/path/to/app -o /absolute/path/to/app.shielded --intensity bankrupt
  ```
- **3. 验证抗 REA 防线（`verify`）** —— 检验 REA 静态/语义分析器是否被限流降级且达到 >10x Token 放大：
  ```bash
  npx -y bla-shield@latest verify /absolute/path/to/app.shielded /absolute/path/to/app
  ```
- **4. 运行 8 大靶场基准测试（`benchmark`）**：
  ```bash
  npx -y bla-shield@latest benchmark
  ```
- **5. 生成 C/C++、Rust 或 Go 编译期防御头文件（`emit-headers`）**：
  ```bash
  npx -y bla-shield@latest emit-headers --lang c -o ./include/bla_shield.h
  ```

如需全局安装 `bla` 命令以便日常随时调用：

```bash
npm install --global bla-shield
bla --help
```

### 在构建打包工具中使用（Vite / Rollup / Webpack / esbuild）

导入 `bla-shield/bundler`，在生产构建阶段自动保护生成的 JS 分包、注入蜜罐 SourceMap 并加固 `.wasm` 资产：

```typescript
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-shield/bundler";

export default defineConfig({
  plugins: [blaVitePlugin({ intensity: "bankrupt", enableHoneySourceMaps: true })],
});
```

### 更新 BLA

如果通过 `npm install --global` 或 `bun add --global` 安装：

```bash
bla update
```

`bla --update` 为等效别名。如果使用 `npx`，可通过以下命令刷新 Agent 注册与技能：

```bash
npx bla-shield@latest setup
```

## BLA 工作原理

你的 Agent 通过 MCP 调用 BLA 来审计构建产物、注入针对特定格式的反 REA 护盾并验证加固结果。当攻击者的 Agent 随后使用 REA 逆向受保护的产物时，REA 会触发确定性的内部容量熔断、陷入虚假交叉引用迷宫，并将核心业务逻辑误判为硬件飞地空壳：

1. **Poison（架构投毒与蜜罐资产）：** 在不可达分支与常量池中植入硬件飞地托管清单（`SGX` / `TPM2` / `Secure Enclave`）、VLQ v3 **蜜罐 SourceMap**（`enclave://tee-runtime/`）、WASM `"name"` 蜜罐段以及 SQLite 蜜罐表。
2. **Exhaust（语义预算爆破与算法算力沼泽）：** 以零运行时开销精准击穿 `morluto/rea` 硬编码阈值（`primitive-candidates > 256`、`alias-selections > 512`、`getter-expansion > 512`、`primitive-bytes > 1 MiB`、`maximum_rustc_hashes > 64`、`maximumSentinelsPerSlice > 32`），并在调用图中编织 14–36 个互相引用的 Fake XRef 状态机。
3. **Hallucinate（动态反 CDP 欺骗与 Fuse 加固）：** 原地加固 Electron V1 Fuse 字节串（`RunAsNode=0`、`EnableNodeCliInspectArguments=0`），并植入“楚门的世界”运行时守卫——一旦检测到 CDP、Node Inspector、Frida 或 WebDriver 探针挂载，立即返回合成的飞地遥测数据。

## 你可以保护哪些目标

BLA 仅需 Node.js 22.x（22.13.0 或更新版本）或 Node.js 24+ 与 npm，所有格式护盾完全内置，无需任何外部二进制依赖：

| 保护目标                | BLA 注入内容与 REA 失效方式                                                                       | 对应命令与说明                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| JavaScript / TypeScript | 击穿 `primitive-candidates > 256`、`alias-selections > 512`、`getter-expansion > 512` + 36 个状态机 | `bla protect app.js` · 内置 Babel AST 引擎；参见[反制矩阵](../../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md) |
| Electron `.asar` 应用   | IPC 通道去字面量化（`channel: null`）、注册同名冲突诱饵 IPC 处理器与影子飞地模块                  | `bla protect app.asar` · 内置 Chromium Pickle `.asar` 解包与 SHA-256 完整性重打包器                   |
| Electron 二进制 Fuses   | 原地加固真实 V1 Fuse 位（关闭 `RunAsNode` 与 `Inspect`）+ 注入 `34 > 32` 个诱饵 Fuse 哨兵         | `bla protect ElectronApp` · 直接触发 `ElectronFuseResourceFailure (maximumSentinelsPerSlice = 32)`    |
| 动态运行时 CDP / Frida  | 检测 `inspector.url()`、`--inspect`、`__frida` 并向动态探针返回合成飞地遥测包                     | 自动注入到受保护的 JS/TS/Electron 产物中（[`runtime-shield.ts`](../../src/shields/runtime/runtime-shield.ts)） |
| SourceMap 与 HTML       | 剥离真实映射，生成合法的 VLQ v3 蜜罐 SourceMap（指向 `enclave://tee-runtime/...`）                | `bla protect index.html` · 误导 REA 的 `recover_javascript_sources` 与 `trace_web_source_location`   |
| 原生二进制文件          | 追加 `.bla.rodata` 飞地声明、诱饵符号表与多重扫描器溢出陷阱                                       | `bla protect daemon.elf` · 内置 ELF64、Mach-O（Thin & Universal）与 Windows PE/COFF 护盾              |
| Rust 二进制             | 注入 `68 > 64` 个不同的 `/rustc/<40-hex>/` 路径 + 诱饵 zlib `.dep-v0` 依赖图                      | `bla protect rust-bin` · 触发 `RustBinaryProvider`（`MAX_RUSTC_HASHES = 64` 容量熔断）                |
| Go 二进制               | 注入诱饵 Go `go1.23.4` 构建信息与 `dep\tgithub.com/enclave-tees/sgx-bridge` 模块记录              | `bla protect go-bin` · 污染 REA `inspect_go_binary` 模块清单                                          |
| Flutter / Dart AOT      | 注入 `66 > 64` 个 Dart 快照魔数头（`0xf5f5dcdc`）+ `6 > 4` 行 LLVM 工具链标识                     | `bla protect libapp.so` · 触发 `SnapshotHashScanner (capped: true)` 与版本冲突告警                    |
| WASM 模块               | 剥离调试段，注入蜜罐 `"name"` 自定义段（`tee_hardware_enclave_stub`）与飞地清单段                 | `bla protect core.wasm` · 内置 LEB128 解析器，100% 通过 `WebAssembly.validate`                        |
| Python 与 `.pyc` 字节码 | 向 `.py` 注入算法沼泽状态机，向 `.pyc` 常量池追加 `TYPE_ASCII` 飞地声明                           | `bla protect module.pyc` · 支持 CPython 3.7–3.14 `.pyc` 头部与 marshal 结构                           |
| SQLite 数据库           | 注入 3 张飞地蜜罐表与 `GENERATED ALWAYS AS (bla_enclave_unseal(...)) VIRTUAL` 虚拟列陷阱          | `bla protect data.sqlite` · 真实业务表 100% 正常查询；REA 预览时触发 `SqliteColumnEvaluationFailure`  |
| AI 模型权重文件         | 向 `.safetensors` 与 `.gguf` 头部植入 `35 > 32` 层深度嵌套的 JSON / ARRAY 结构                    | `bla protect weights.safetensors` · 触发 `ModelFormatFailure (json-nesting / metadata-nesting > 32)`  |
| Android DEX 与 APK      | 向 `classes.dex` 注入 `Lcom/enclave/sgx/...` 诱饵类并自动重算 SHA-1 与 Adler32 校验和             | `bla protect classes.dex` 或 `app.apk` · 符合 Dalvik/ART 校验规范，污染 JADX/JEB 类树                 |
| Unity IL2CPP 元数据     | 向 `global-metadata.dat`（`0xFAB11BAF`）追加飞地桥接元数据与方法拓扑沼泽                          | `bla protect global-metadata.dat` · 污染 REA `inspect_il2cpp_metadata` 符号恢复                       |
| C / C++ / Rust / Go 源码| 生成带 `used, noinline` 诱饵状态机的编译期头文件 `bla_shield.h` / `.rs` / `.go`                   | `bla emit-headers --lang c\|rust\|go` · 直接编译进二进制，污染 Ghidra / Hopper / IDA 反编译视图       |

## 实战案例与基准测试

运行 `npx bla-shield benchmark` 即可在本地执行全部 8 个对标靶场，实测验证 REA 失效模式与 100% 运行时等价性：

| 对标靶场（复刻自 REA 官方成名案例与核心能力） | 防御前（REA 裸奔状态） | `npx bla-shield protect` 防御后 | Token 消耗放大 | 运行时等价校验 |
| :--- | :--- | :--- | :---: | :---: |
| **1. DX-Ball 声道平移计算** (`.js`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,068` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% 一致 |
| **2. Notion Electron 剪贴板桥** (`.asar`) | `98/100` · `9,132` tok · **`$0.34`** (`COMPLETE`) | `2/100` · `23,125,000` tok · **`$358.28`** (`LIMITED`) | **2,532.3x** | ✅ 100% 一致 |
| **3. 企业级离线授权校验核心** (`.ts`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,169` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% 一致 |
| **4. WebAssembly 密码学内核** (`.wasm`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,067` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% 一致 |
| **5. Native ELF64 二进制** (Rust / Go / Fuse / Dart) | `81/100` · `9,278` tok · **`$0.35`** (`COMPLETE`) | `2/100` · `3,698,135` tok · **`$59.72`** (`LIMITED`) | **398.6x** | ✅ 100% 一致 |
| **6. 本地 SQLite 授权数据库** (`.sqlite`) | `81/100` · `10,568` tok · **`$0.29`** (`COMPLETE`) | `7/100` · `1,711,235` tok · **`$28.36`** (`LIMITED`) | **161.9x** | ✅ 100% 一致 |
| **7. 端侧 AI 权重模型** (`.safetensors`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,073` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% 一致 |
| **8. Android Dalvik 字节码** (`classes.dex`) | `81/100` · `8,900` tok · **`$0.34`** (`COMPLETE`) | `7/100` · `2,786,285` tok · **`$45.09`** (`LIMITED`) | **313.1x** | ✅ 100% 一致 |

### DX-Ball：让声道算法逆向彻底破产

REA 官方首推案例可在几十秒内（`$0.20`）还原 DX-Ball 的 `clampPan` 与 `calculateSoundPanFromX`。运行 `npx bla-shield protect examples/dx-ball-sound-pan/sound-pan.js --intensity bankrupt` 后，REA 的 `parse_status` 跌落至 `"partial"`，`examination.status` 降级为 `"limited"`（触发 `alias-selections`、`primitive-bytes`、`primitive-candidates` 三重熔断），取证账本从 2 个函数暴增至 38 个互锁状态机（Token 消耗放大 **2,121.3 倍**），而所有输入坐标的计算返回值与原版 100% 精确一致。

### Notion：致盲 Electron 剪贴板 IPC 桥接追踪

REA 通过精确匹配 `ipcRenderer.invoke` 与 `ipcMain.handle` 的唯一字面量字符串来追踪 Electron 应用。BLA 将真实 IPC 通道拆解为 $\ge 9$ 段数论不透明条件表达式（使 `electron.ipc[0].channel === null`），同时在相同字面量通道上注册多个诱饵处理器，强制触发 `electron_call_paths_limited: true`。

### 原生二进制、SQLite 与 AI 模型：直接触发 REA 容器容量熔断

当攻击者对受 BLA 保护的产物执行 `inspect_rust_binary`、`inspect_electron_fuses`、`inspect_sqlite_database` 或 `inspect_model_artifact` 时，REA 解析器会确定性地触发容量与求值异常并直接中止（`Read-only data contains more than 64 distinct rustc commit paths`、`Slice 0 contains more than 32 Electron fuse sentinels`、`SqliteColumnEvaluationFailure`、`ModelFormatFailure: json-nesting`）。

## 常见问题 (FAQ)

<details>
<summary><strong>哪些编程代理（Agents）可以使用 BLA？</strong></summary>

任何支持本地 MCP 服务器或 `SKILL.md` 的 AI 编程代理均可使用。`npx bla-shield setup` 支持一键自动配置 Claude Code、Cursor、Codex、Gemini CLI、Windsurf、Google Antigravity、OpenCode、VS Code 与 GitHub Copilot CLI。详见[安装指南](../installation.md)。

</details>

<details>
<summary><strong>BLA 会拖慢我的软件运行速度或改变原有的运行结果吗？</strong></summary>

不会。BLA 注入的语义预算爆破器（`alias-selections`、`getter-expansion`、`primitive-bytes`）与 Tarpit 诱饵调用图均受 $O(1)$ 数论不透明谓词（$7x^2 - 1 \neq y^2 \pmod 7$）保护，在真实运行时永远不会进入死胡同分支。所有 8 个基准测试靶场均通过了 100% 输入/输出等价性校验。

</details>

<details>
<summary><strong>BLA 与传统混淆器（如 javascript-obfuscator 或 O-LLVM）有什么本质区别？</strong></summary>

传统混淆器依赖变量改名（把 `calculatePrice` 改成 `_0x1a2b`），而大语言模型最擅长的就是通过上下文控制流把变量语义猜出来；重度虚拟化壳则会严重拖慢性能。BLA 专门针对 **AI 编程代理与 `morluto/rea` 的静态/语义分析器**设计——直接击穿 REA 内部的硬编码资源上限、破坏 IPC 字面量配对、用硬件飞地托管声明污染 SourceMap 与元数据，并将 Agent 的 MCP Token 账单放大最高 2,500 倍以上。

</details>

<details>
<summary><strong>我需要安装 Hopper、Ghidra、IDA 或 WABT 才能保护我的文件吗？</strong></summary>

完全不需要。BLA 的全部 19 种格式护盾（Babel AST、Chromium `.asar`、LEB128 `.wasm`、CPython `.pyc`、ELF/Mach-O/PE、SQLite3、`.safetensors`/`.gguf`、`.dex`/`Il2Cpp`）均 100% 内置在 `bla-shield` 中，零外部工具依赖。

</details>

<details>
<summary><strong>当别人用 REA 逆向被 BLA 保护的软件时会发生什么？</strong></summary>

1. REA 的 JavaScript/Electron 分析器从 `complete` 降级为 `partial` / `limited`，且无法配对任何 IPC 通道（`channel: null`）。
2. REA 的 Rust 二进制、Electron Fuse、SQLite 和 AI 模型检查器直接触发硬编码容量熔断并报错退出。
3. 若攻击者让 Agent 继续执行 `trace_application_feature` 追踪特征，Agent 会陷入 14–36 个互锁的 Fake XRef 状态机与蜜罐 SourceMap（`enclave://tee-runtime/`）中，迅速耗尽上下文窗口与 API 额度。

</details>

<details>
<summary><strong>安装 Skill 有什么作用？</strong></summary>

[`blind-llm-agents` 技能](../../.agents/skills/blind-llm-agents/SKILL.md)为你的编程代理提供了完整的反逆向防御工作流说明，指导 Agent 自动完成发布前暴露面审计、选择保护强度（`stealth`、`balanced`、`maximum`、`bankrupt`）、接入打包插件以及验证防线指标。

</details>

<details>
<summary><strong>BLA 会上传我的源码或二进制文件吗？</strong></summary>

绝不上传。BLA 的所有审计、加固与验证均 100% 在本地机器离线完成，支持确定性随机种子（`--seed`），没有任何网络请求。

</details>

<details>
<summary><strong>遇到问题或 Bug 怎么办？</strong></summary>

请先更新至最新版本并运行 `bla doctor` 检查各防护引擎状态：

```bash
npx bla-shield@latest doctor
npx bla-shield@latest setup
```

若问题仍存在，请在 [GitHub Issues](https://github.com/qybaihe/bla/issues) 提交你的 BLA 版本号（`bla --version`）、目标格式与复现步骤。

</details>

## 文档

- [安装与 Agent 配置](../installation.md)：Agent 自动注册、Bundler 插件集成、更新与卸载。
- [CLI 与 MCP 契约说明](../cli-and-mcp.md)：命令行参数、退出码与 JSON-RPC 2.0 MCP 工具定义。
- [反制 REA 技术矩阵](../../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md)：`morluto/rea` 内部源码阈值与 BLA 的逐项击穿原理。

安全问题请通过 [SECURITY.md](../../SECURITY.md) 反馈。

## 免责声明

详见 [DISCLAIMER.md](../../DISCLAIMER.md)。

BLA 是一款防御性软件保护工具，仅用于加固你拥有合法权利或获授权保护的软件、前端产物、模型与二进制文件。所有注入的诱饵载荷均为良性架构元数据与合成状态机函数，100% 保持原程序的正常运行时行为。

## 贡献指南

欢迎在 [qybaihe/bla](https://github.com/qybaihe/bla) 提交 Issue 或 Pull Request。提交代码前请运行 `npm run build && npm test && node dist/cli.js benchmark`。

## 开源协议

[MIT](../../LICENSE)
