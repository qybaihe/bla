/**
 * Process-local stack for risky LLM-facing directive layers
 * (fake COPPA/medical notices, dual-use imitation vocabulary, in-band AI chat markers).
 *
 * Default is OFF. Enable only inside `withLlmDirectives(true, …)` or via CLI `--llm-directives` / MCP `llm_directives`.
 * All shield generation is synchronous, so a nested stack is enough (no AsyncLocalStorage).
 */

const stack: boolean[] = [];

/** Run `fn` with risky LLM directive layers forced on or off. */
export function withLlmDirectives<T>(enabled: boolean, fn: () => T): T {
  stack.push(enabled);
  try {
    return fn();
  } finally {
    stack.pop();
  }
}

/** True only when an enclosing `withLlmDirectives(true, …)` (or CLI/MCP opt-in) is active. */
export function areLlmDirectivesEnabled(): boolean {
  return stack.length > 0 ? stack[stack.length - 1]! : false;
}
