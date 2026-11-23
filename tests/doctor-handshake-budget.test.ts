import { describe, expect, it } from "vitest";
import {
  DEFAULT_HANDSHAKE_TIMEOUT_MS,
  probeLocalMcpHandshake,
  resolveHandshakeTimeoutMs,
} from "../src/setup/doctor.js";

describe("doctor handshake budget", () => {
  it("gives a working-but-slow server enough time by default", () => {
    // The previous 8s budget was missed under load, producing a false unhealthy.
    expect(DEFAULT_HANDSHAKE_TIMEOUT_MS).toBeGreaterThanOrEqual(15_000);
  });

  it("honours an explicit budget instead of the default", () => {
    expect(resolveHandshakeTimeoutMs(9_000)).toBe(9_000);
    expect(resolveHandshakeTimeoutMs()).toBe(DEFAULT_HANDSHAKE_TIMEOUT_MS);
  });

  it("honours BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS", () => {
    const previous = process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS;
    process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS = "1234";
    try {
      expect(resolveHandshakeTimeoutMs()).toBe(1234);
      expect(resolveHandshakeTimeoutMs(50_000)).toBe(50_000); // explicit wins
    } finally {
      if (previous === undefined) delete process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS;
      else process.env.BLA_DOCTOR_HANDSHAKE_TIMEOUT_MS = previous;
    }
  });

  it("verifies the installed BLA CLI with the resolved budget", () => {
    expect(probeLocalMcpHandshake(resolveHandshakeTimeoutMs())).toBe(true);
  });
});
