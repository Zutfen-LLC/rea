import { describe, expect, it } from "vitest";

import { openBinaryInputSchema } from "./sessionLifecycleInputs.js";

describe("open_binary raw-binary input contract", () => {
  it("accepts header detection without architecture", () => {
    expect(
      openBinaryInputSchema.safeParse({ path: "/tmp/fixture.bin" }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/legacy.com",
        format: "dos-com",
      }).success,
    ).toBe(true);
  });
  it("accepts raw-binary with architecture and entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(true);
  });
  it("rejects raw-binary without architecture or entry", () => {
    const parsed = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      format: "raw-binary",
    });
    expect(parsed.success).toBe(false);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
      }).success,
    ).toBe(false);
  });
  it("rejects architecture without format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(false);
  });
  it("accepts snes-rom without architecture or entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/game.sfc",
        format: "snes-rom",
      }).success,
    ).toBe(true);
  });
  it("rejects mixed raw-binary flags with format=snes-rom", () => {
    const architecture = openBinaryInputSchema.safeParse({
      path: "/tmp/game.sfc",
      format: "snes-rom",
      architecture: "6502",
    });
    expect(architecture.success).toBe(false);
    if (!architecture.success)
      expect(architecture.error.issues[0]?.message).toContain(
        "apply only with format=raw-binary",
      );
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/game.sfc",
        format: "snes-rom",
        entry_point: "0x8000",
      }).success,
    ).toBe(false);
  });
});
