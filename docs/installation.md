# Installation & Setup Guide

**BLA (`bla-shield` — Blind LLM Agents / Block Anything)** is distributed as a zero-config Node.js CLI and MCP server requiring Node.js 22.x (22.13.0 or newer) or Node.js 24+, with npm. Node.js 18, 20, older 22.x releases, and 23.x are not supported; Bun is not a supported runtime.

The SQLite integration requires the built-in `node:sqlite` module and `DatabaseSync.function`, available without an opt-in flag starting in [Node.js 22.13.0](https://nodejs.org/download/release/v22.13.0/docs/api/sqlite.html). Do not disable SQLite with `--no-experimental-sqlite`. CI tests the minimum version, latest 22.x, and latest 24.x.

---

## 1. Quick Start (`npx`)

Run BLA directly without installing anything globally:

```bash
# 1. Register BLA MCP Server + Skill into Claude Code, Cursor, Codex, Windsurf, Gemini CLI, etc.
npx bla-shield setup

# 2. Check your environment and configured AI clients
npx bla-shield doctor

# 3. Audit an artifact for REA exposure before release
npx bla-shield audit ./dist/app.js

# 4. Protect the artifact with BLA's three-stage shield
npx bla-shield protect ./dist/app.js --mode bankrupt

# 5. Verify functional preservation and REA analyzer degradation
npx bla-shield verify ./dist/app.js ./dist/app.bla.js
```

---

## 2. Global or Project-Local Installation

### Install as a Dev Dependency (Recommended for CI/CD Release Pipelines)

```bash
npm install --save-dev bla-shield
# or
pnpm add -D bla-shield
# or
bun add -d bla-shield
```

Then add a post-build protection script to your `package.json`:

```json
{
  "scripts": {
    "build": "vite build",
    "postbuild": "bla protect ./dist/assets/index.js --in-place --mode bankrupt --emit-sourcemap"
  }
}
```

### Install Globally

```bash
npm install -g bla-shield

# Both `bla` and `bla-shield` binaries are registered:
bla --version
bla-shield doctor
```

---

## 3. Registering BLA in Coding Agents (`bla setup`)

Just like `npx reverse-engineer-anything setup`, `npx bla-shield setup` auto-discovers installed AI coding agents on your machine and registers:

1. **The `bla` MCP stdio server** (`bla_audit`, `bla_protect`, `bla_verify`, `bla_benchmark`, `bla_emit_headers`, `bla_doctor`)
2. **The `blind-llm-agents` skill** (`SKILL.md` + Counter-REA Matrix)

### Supported Clients

| Client ID | Name | Config Location | Skill Location |
| :--- | :--- | :--- | :--- |
| `claude-code` | Claude Code | `~/.claude.json` | `~/.claude/skills/blind-llm-agents` |
| `cursor` | Cursor | `~/.cursor/mcp.json` | `~/.cursor/skills/blind-llm-agents` |
| `codex` | OpenAI Codex | `~/.codex/config.toml` | `~/.codex/skills/blind-llm-agents` |
| `windsurf` | Windsurf | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/skills/blind-llm-agents` |
| `gemini` | Gemini CLI | `~/.gemini/settings.json` | `~/.gemini/skills/blind-llm-agents` |
| `opencode` | OpenCode | `~/.config/opencode/opencode.json` | `~/.config/opencode/skills/blind-llm-agents` |

### Target Specific Clients

```bash
npx bla-shield setup --client claude-code,cursor
```

### Uninstall

To cleanly remove BLA from all agent configuration files and delete installed skill folders:

```bash
npx bla-shield uninstall
```

---

## 4. Compile-Time Header Integration (C / C++ / Rust / Go)

If you are shipping a native binary compiled with `clang`, `gcc`, `rustc`, or `go build`, you can embed BLA's compile-time counters directly into `.rodata` before linking:

```bash
npx bla-shield emit-headers ./include/shield --seed my-release-v1
```

- **C / C++**: `#include "bla_shield.h"` and call `BLA_ANCHOR_SHIELD();` inside `main()`.
- **Rust**: `mod bla_shield;` and call `bla_shield::anchor_shield();` inside `fn main()`.
- **Go**: Include `bla_shield.go` in your package and call `AnchorBlaShield()` inside `func main()`.
