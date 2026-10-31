# BLA CrackMe

BLA 对外发布的逆向 / 防护挑战。当前主挑战是 **v7 Meridian**。

## v7 — Meridian（当前）

真实小型工程计算器，经 `bla harden`（bankrupt、llm-directives OFF）硬化后发布。
通过 `license activate` 解锁 Meridian Pro，打印激活证书。

```bash
npm run crackme:v7 -- calc "sqrt(2)*sin(pi/4)"
npm run crackme:v7 -- license activate 'XXXXX-XXXXX-XXXXX-XXXXX'
```

设计说明：[`v7/DESIGN.md`](./v7/DESIGN.md) · 承诺摘要：[`v7/SEAL.json`](./v7/SEAL.json)

## 历史

| 版本 | 状态 | 说明 |
|---|---|---|
| v7 Meridian | **当前** | 真实应用 + 整钥链式 ARX + 自完整性 |
| v6 Harden-Native | 快照（1.6.1） | `challenge/v6/`，已被 v7 取代 |
| v6-tiered-protect | 归档 | `challenge/archive/v6-tiered-protect/`（#38） |
| v5.2 | 归档 | `challenge/archive/v5/` |
