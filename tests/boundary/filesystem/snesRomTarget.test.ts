import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  SNES_HIROM_TITLE_BASE,
  SNES_LOROM_TITLE_BASE,
  snesCartridgeImage,
  snesHeaderBase,
} from "../../fixtures/snesCartridge.js";

// Filesystem-boundary admission: the cartridge checks themselves are owned by
// src/domain/snesRom.test.ts; these cases exercise target resolution from a
// real file, including its digest and pairing refusals.

describe("snes-rom target resolution", () => {
  it("resolves a typed snes-rom executable target with a source digest", async () => {
    const directory = await createTestTempDirectory("rea-snes-target-");
    const path = join(directory, "fixture.sfc");
    const bytes = snesCartridgeImage();
    await writeFile(path, bytes);
    const target = await parseBinaryTarget(path, {
      cwd: directory,
      formatHint: "snes-rom",
    });
    expect(target).toMatchObject({
      ok: true,
      value: {
        path,
        kind: "executable",
        format: "snes-rom",
        architecture: "65816",
        availableArchitectures: ["65816"],
        sha256: createHash("sha256").update(bytes).digest("hex"),
        cartridge: {
          headerOffset: snesHeaderBase(SNES_LOROM_TITLE_BASE),
          declaredMapping: "lorom",
        },
      },
    });
  });

  it("does not expose a raw-binary entry point on the typed target", async () => {
    const directory = await createTestTempDirectory("rea-snes-entry-");
    const path = join(directory, "fixture.sfc");
    await writeFile(path, snesCartridgeImage());
    const target = await parseBinaryTarget(path, {
      cwd: directory,
      formatHint: "snes-rom",
    });
    expect(target.ok && "entryPoint" in target.value).toBe(false);
  });

  it("rejects mixed raw-binary architecture flags with format=snes-rom", async () => {
    const directory = await createTestTempDirectory("rea-snes-mixed-");
    const path = join(directory, "fixture.sfc");
    await writeFile(path, snesCartridgeImage());
    expect(
      await parseBinaryTarget(path, {
        cwd: directory,
        formatHint: "snes-rom",
        architecture: "6502",
        entryPoint: "0x8000",
      }),
    ).toMatchObject({
      ok: false,
      error: {
        reason: expect.stringContaining("raw-binary"),
        constraint: "load_selection_rejected",
      },
    });
  });

  it("rejects a non-executable target kind for format=snes-rom", async () => {
    const directory = await createTestTempDirectory("rea-snes-kind-");
    const path = join(directory, "fixture.sfc");
    await writeFile(path, snesCartridgeImage());
    expect(
      await parseBinaryTarget(path, {
        cwd: directory,
        formatHint: "snes-rom",
        targetKind: "database",
      }),
    ).toMatchObject({
      ok: false,
      error: {
        constraint: "load_selection_rejected",
      },
    });
  });

  it("rejects ambiguous cartridge metadata from the target file", async () => {
    const directory = await createTestTempDirectory("rea-snes-ambig-");
    const path = join(directory, "fixture.sfc");
    await writeFile(
      path,
      snesCartridgeImage({
        headerBases: [SNES_LOROM_TITLE_BASE, SNES_HIROM_TITLE_BASE],
      }),
    );
    expect(
      await parseBinaryTarget(path, {
        cwd: directory,
        formatHint: "snes-rom",
      }),
    ).toMatchObject({
      ok: false,
      error: {
        reason: expect.stringContaining("ambiguous"),
        constraint: "file_format_rejected",
      },
    });
  });
});
