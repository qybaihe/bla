# Installation & Setup Guide

**BLA (`bla-agents` — Blind LLM Agents)** is distributed as a zero-config Node.js CLI and MCP server that runs anywhere Node.js `^22.23.4 || >=24.0.0` is installed (matches `package.json` `engines`).

---

## 1. Quick Start (`npx`)

Run BLA directly without installing anything globally:

```bash
# 1. Register the BLA MCP server + skill with Claude Code, Cursor, Codex, Windsurf, Gemini CLI, etc.
npx bla-agents setup

# 2. Check the environment and the registered AI clients
npx bla-agents doctor                     # add --verify-handshake to also start each server

# 3. Build your project, then harden everything it produced
npm run build
npx bla-agents harden .                   # writes a partial mirror to .bla-hardened/ and ships nothing
npx bla-agents harden . --apply           # replaces the build output with the hardened files
npx bla-agents harden . --restore         # puts the original build output back
```

`harden` finds the build output itself (`dist/`, `build/`, `out/`, `release/`, root-level
binaries / `.wasm` / models, or the sources of a project with no build step) and leaves
the toolchain alone (`vite.config.*`, test files, the scripts `package.json` runs for
build / test / release, `.d.ts` declarations). Run `npx bla-agents harden . --dry-run` to
see the plan without writing a byte.

Working on one known file instead:

```bash
npx bla-agents audit ./dist/app.js                                             # exposure report
npx bla-agents protect ./dist/app.js -o ./dist/app.bla.js --intensity bankrupt # shield one file
npx bla-agents verify ./dist/app.bla.js ./dist/app.js                          # protected first, original second
```

---

## 2. Global or Project-Local Installation

### Install as a Dev Dependency (Recommended for CI/CD Release Pipelines)

```bash
npm install --save-dev bla-agents
# or
pnpm add -D bla-agents
# or
bun add -d bla-agents
```

Then add a post-build protection script to your `package.json`:

```json
{
  "scripts": {
    "build": "vite build",
    "postbuild": "bla harden . --apply"
  }
}
```

`--apply` overwrites only files inside a build-output directory, keeps the originals in a
per-user state directory outside the project (`BLA_STATE_DIR` overrides the location —
set it to a cached path in CI), and a re-run hardens from those originals again rather
than hardening hardened code. Always run your own tests against the promoted build: BLA
checks structure, not behaviour.

### Install Globally

```bash
npm install -g bla-agents

# Both `bla` and `bla-agents` binaries are registered:
bla --version
bla-agents doctor
```

---

## 3. Registering BLA in Coding Agents (`bla setup`)

Just like `npx reverse-engineer-anything setup`, `npx bla-agents setup` auto-discovers installed AI coding agents on your machine and registers:

1. **The `bla` MCP stdio server** — 31 tools; `bla_harden` is the default verb, and the full
   catalogue is in [`cli-and-mcp.md`](./cli-and-mcp.md). The server also sends a short playbook
   in its `initialize` response (`instructions`), so an agent that never loads the skill still
   knows the sequence: build → `bla_harden` → follow `nextSteps` → `apply` → run the tests.
   The skill bundle is served as MCP resources too (`bla://skill/SKILL.md`), for clients that
   only have the server.
2. **The `blind-llm-agents` skill** (`SKILL.md` + format appendices + Counter-REA matrix)

The registration pins the release that ran `setup` (`npx -y bla-agents@<version> mcp`).
After upgrading, re-run `npx bla-agents@latest setup --yes`; `doctor` reports a client that
still launches an older release as `versionSkew`.

### Supported Clients

| Client ID | Name | Config Location | Skill Location |
| :--- | :--- | :--- | :--- |
| `claude_code` | Claude Code | `~/.claude.json` | `~/.claude/skills/blind-llm-agents` |
| `claude_desktop` | Claude Desktop | `<UserConfig>/Claude/claude_desktop_config.json` | `~/.agents/skills/blind-llm-agents` |
| `cursor` | Cursor | `~/.cursor/mcp.json` | `~/.cursor/skills/blind-llm-agents` |
| `codex` | Codex CLI | `~/.codex/config.toml` | `~/.codex/skills/blind-llm-agents` |
| `gemini_cli` | Gemini CLI | `~/.gemini/settings.json` | `~/.gemini/skills/blind-llm-agents` |
| `antigravity` | Google Antigravity | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/skills/blind-llm-agents` |
| `windsurf` | Windsurf | `~/.codeium/windsurf/mcp_config.json` | `~/.agents/skills/blind-llm-agents` |
| `vscode` | VS Code | `<UserConfig>/Code/User/mcp.json` | `~/.agents/skills/blind-llm-agents` |
| `opencode` | OpenCode | `~/.config/opencode/opencode.json` | `~/.agents/skills/blind-llm-agents` |
| `copilot_cli` | GitHub Copilot CLI | `~/.copilot/mcp-config.json` | `~/.agents/skills/blind-llm-agents` |

### Target Specific Clients

```bash
npx bla-agents setup --client claude_code --client cursor
npx bla-agents setup --all-detected --yes
```

### Check a Registration

```bash
npx bla-agents doctor --verify-handshake
```

`doctor` reads each client's configuration from disk; with `--verify-handshake` it also
starts every registered server and checks that it answers the MCP `initialize` request.
The report ends with a numbered `Next:` list when something needs repair.

Run it inside a project and it also reads that project's own MCP config files —
`.mcp.json` (Claude Code), `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`,
`.codex/config.toml`, `opencode.json` — and lists a BLA entry found there under
"Registered In This Project" (`projectRegistrations` in `--json`). `setup` writes per-user
configs only: a project entry that is broken or pinned to another release has to be edited
by hand, and `doctor` says so.

### Uninstall

To cleanly remove BLA from all agent configuration files and delete installed skill folders:

```bash
npx bla-agents uninstall
```

---

## 4. Compile-Time Header Integration (C / C++ / Rust / Go)

If you are shipping a native binary compiled with `clang`, `gcc`, `rustc`, or `go build`, you can embed BLA's compile-time counters directly into `.rodata` before linking:

```bash
npx bla-agents emit-headers ./include/shield --seed my-release-v1
```

- **C / C++**: `#include "bla_shield.h"` and call `BLA_ANCHOR_SHIELD();` inside `main()`.
- **Rust**: `mod bla_shield;` and call `bla_shield::anchor_shield();` inside `fn main()`.
- **Go**: Include `bla_shield.go` in your package and call `AnchorBlaShield()` inside `func main()`.
