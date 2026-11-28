import { describe, expect, it } from "vitest";
import { EVM_DISPATCHER_RUNTIME_HEX } from "../src/engine/benchmark.js";

/**
 * The showcase fixture is hand-written bytecode. A JUMPI whose target is not a JUMPDEST makes the
 * runtime abort with BadJumpDestination, so the benchmark would measure a throw instead of the
 * dispatch path. Decode the fixture and check every static jump target.
 */
describe("showcase EVM dispatcher fixture", () => {
  it("lands every JUMP/JUMPI on a JUMPDEST", () => {
    const code = Buffer.from(EVM_DISPATCHER_RUNTIME_HEX, "hex");
    const jumpdests = new Set<number>();
    const jumps: { pc: number; target: number | null }[] = [];

    for (let pc = 0; pc < code.length; ) {
      const op = code[pc]!;
      if (op === 0x5b) jumpdests.add(pc);
      if (op === 0x56 || op === 0x57) {
        // The fixture pushes each target with a PUSH1 immediately before the jump.
        const push = pc - 2;
        jumps.push({ pc, target: code[push] === 0x60 ? code[push + 1]! : null });
      }
      pc += op >= 0x60 && op <= 0x7f ? op - 0x5e : 1;
    }

    expect(jumps.map((jump) => jump.pc)).toEqual([9, 25]);
    for (const jump of jumps) {
      expect(jumpdests.has(jump.target as number)).toBe(true);
    }
  });
});
