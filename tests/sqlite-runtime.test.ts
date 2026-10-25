import { afterEach, describe, expect, it, vi } from "vitest";

const { loadModule } = vi.hoisted(() => ({ loadModule: vi.fn() }));
vi.mock("node:module", () => ({ createRequire: () => loadModule }));

import { getDatabaseSyncClass } from "../src/core/sqlite-runtime.js";

afterEach(() => loadModule.mockReset());

describe("SQLite runtime diagnostics", () => {
  it("returns a compatible constructor without opening a database", () => {
    class DatabaseSync {
      function() {}
    }
    loadModule.mockReturnValue({ DatabaseSync });
    expect(getDatabaseSyncClass()).toBe(DatabaseSync);
    expect(loadModule).toHaveBeenCalledWith("node:sqlite");
  });

  it("explains missing or disabled SQLite and preserves the original error", () => {
    const cause = new Error("No such built-in module: node:sqlite");
    loadModule.mockImplementation(() => {
      throw cause;
    });
    expect(getDatabaseSyncClass).toThrow(/22\.13\.0/);
    expect(getDatabaseSyncClass).toThrow(/remove --no-experimental-sqlite/);
    try {
      getDatabaseSyncClass();
    } catch (error) {
      expect((error as Error).cause).toBe(cause);
    }
  });

  it.each([{}, { DatabaseSync: class {} }])(
    "rejects incomplete SQLite APIs before database work",
    (module) => {
      loadModule.mockReturnValue(module);
      expect(getDatabaseSyncClass).toThrow(/BLA SQLite support requires/);
    },
  );
});
