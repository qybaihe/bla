# 🛡️ BLA CrackMe — 公开 Counter-REA 挑战 / Public Challenge

## 当前：v6 Harden-Native（推荐）

**→ [`v6/README.md`](./v6/README.md)**

v6 的靶机就是 `bla harden` 的真实产物：Node vault + HTML 面板 + WebAssembly 核心组成的多格式小应用，
以 `bankrupt` 强度、固定种子、**关闭高风险 LLM 指令层** 加固后原样发布。明文模板公开，挑战是从加固产物中还原每次构建的常量与逻辑。

```bash
npm run crackme:v6 -- '<16位密钥>'
```

通关证明：`SHA-256(FLAG{...})` 等于 [`v6/SEAL.json`](./v6/SEAL.json) 中的 `flagSha256`（仓库内无明文密钥 / FLAG）。

## 历史归档

- [`archive/v6-tiered-protect/`](./archive/v6-tiered-protect/) — v6 初稿（PR #38）：单文件 L1/L2/L3 protect 档位，已被 harden-native 版取代。
- [`archive/v5/`](./archive/v5/) — v5.2 手写 Cognitive-Armor 海绵，仅供历史参考。
