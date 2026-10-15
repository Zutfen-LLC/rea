import { execFile } from "node:child_process";
import {
  mkdir,
  rename,
  rm,
  symlink,
  truncate,
  utimes,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  ghidraSnesExtensionSchema,
  inspectGhidraSnesExtension,
  resolveGhidraSnesExtension,
} from "../../../src/ghidra/GhidraSnesExtension.js";
import { openRegularFile } from "../../../src/filesystem/RegularFile.js";
import type { GhidraInstallationInspection } from "../../../src/ghidra/GhidraInstallation.js";

// Synthetic installation files exercise the filesystem identity boundary only;
// they are independently authored text and prove nothing about SnesRomLoader
// execution, SNES target admission, or real Ghidra interoperability.
// Upstream facts verified against joshleaves/ghidra-snes@d33ce5db installed at
// Ghidra 12.0.4: extension.properties declares name=SNES Loader and
// version=12.0.4, and the language is 65816:LE:24:snes built from
// data/languages/65816.ldefs with 65816.sla, 65816-snes.pspec and 65816.cspec.
const SNES_PROPERTIES =
  "name=SNES Loader\n" +
  "description=Loader for SNES ROMs with LoROM/HiROM mapping and WRAM blocks.\n" +
  "author=red\n" +
  "createdOn=2026-05-01\n" +
  "version=12.0.4\n";
const SNES_CONTENTS: Record<string, string> = {
  "Module.manifest":
    "MODULE NAME: Ghidra-SNES\nMODULE DEPENDENCIES:\n    Ghidra\n",
  "extension.properties": SNES_PROPERTIES,
  "data/languages/65816.ldefs": "synthetic language definition",
  "data/languages/65816.sla": "synthetic compiled processor",
  "data/languages/65816-snes.pspec": "synthetic processor specification",
  "data/languages/65816.cspec": "synthetic compiler specification",
  "lib/ghidra-snes.jar": "synthetic loader artifact",
};

vi.mock("../../../src/filesystem/RegularFile.js", async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import("../../../src/filesystem/RegularFile.js")
    >();
  return { ...actual, openRegularFile: vi.fn(actual.openRegularFile) };
});

async function snesInstallation(options?: {
  readonly properties?: string;
  readonly writeOrder?: readonly string[];
}) {
  const directory = await createTestTempDirectory("rea-snes-extension-");
  const root = join(directory, "Ghidra", "Extensions", "ghidra-snes");
  const contents =
    options?.properties !== undefined
      ? { ...SNES_CONTENTS, "extension.properties": options.properties }
      : SNES_CONTENTS;
  const order = options?.writeOrder ?? Object.keys(contents);
  for (const path of order) {
    const text = contents[path];
    if (text === undefined)
      throw new Error(`Unknown fixture component: ${path}`);
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
  return { directory, root };
}

function installation(
  installDir: string,
  providerVersion: string,
): GhidraInstallationInspection {
  return {
    status: "available",
    installDir,
    analyzeHeadlessPath: join(installDir, "support", "analyzeHeadless"),
    applicationPropertiesPath: join(
      installDir,
      "Ghidra",
      "application.properties",
    ),
    nativeDecompilerPath: null,
    javaCommand: "java",
    javaHome: "/jdk-21",
    javaVersion: "21.0.12",
    providerVersion,
    platform: "linux",
    architecture: "x64",
    checks: [],
  };
}

describe.skipIf(process.platform === "win32")(
  "SNES installed-extension identity",
  () => {
    it("produces a valid typed identity for a complete compatible installation", async () => {
      const { root } = await snesInstallation();
      const extension = await inspectGhidraSnesExtension(root, "12.0.4");
      expect(extension).toEqual({
        id: "ghidra-snes",
        root,
        ghidra_version: "12.0.4",
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/u) as string,
      });
      expect(() => ghidraSnesExtensionSchema.parse(extension)).not.toThrow();
    });

    it("reproduces the same digest for unchanged content", async () => {
      const { root } = await snesInstallation();
      const first = await inspectGhidraSnesExtension(root, "12.0.4");
      const again = await inspectGhidraSnesExtension(root, "12.0.4");
      expect(again.sha256).toBe(first.sha256);
    });

    it("reproduces the same digest across independently created installations", async () => {
      const first = await snesInstallation();
      const second = await snesInstallation();
      const a = await inspectGhidraSnesExtension(first.root, "12.0.4");
      const b = await inspectGhidraSnesExtension(second.root, "12.0.4");
      expect(b.sha256).toBe(a.sha256);
    });

    it("changes the digest when a language definition changes", async () => {
      const { root } = await snesInstallation();
      const first = await inspectGhidraSnesExtension(root, "12.0.4");
      await writeFile(
        join(root, "data/languages/65816.ldefs"),
        "changed language definition",
      );
      const changed = await inspectGhidraSnesExtension(root, "12.0.4");
      expect(changed.sha256).not.toBe(first.sha256);
    });

    it("changes the digest when the loader JAR changes", async () => {
      const { root } = await snesInstallation();
      const first = await inspectGhidraSnesExtension(root, "12.0.4");
      await writeFile(join(root, "lib/ghidra-snes.jar"), "changed loader");
      const changed = await inspectGhidraSnesExtension(root, "12.0.4");
      expect(changed.sha256).not.toBe(first.sha256);
    });

    it("does not change the digest when only mtimes change", async () => {
      const { root } = await snesInstallation();
      const first = await inspectGhidraSnesExtension(root, "12.0.4");
      const stamp = new Date("2020-01-02T03:04:05.678Z");
      for (const path of Object.keys(SNES_CONTENTS))
        await utimes(join(root, path), stamp, stamp);
      const changed = await inspectGhidraSnesExtension(root, "12.0.4");
      expect(changed.sha256).toBe(first.sha256);
    });

    it("does not depend on filesystem enumeration order", async () => {
      const forward = await snesInstallation();
      const reverse = await snesInstallation({
        writeOrder: Object.keys(SNES_CONTENTS).reverse(),
      });
      const a = await inspectGhidraSnesExtension(forward.root, "12.0.4");
      const b = await inspectGhidraSnesExtension(reverse.root, "12.0.4");
      expect(b.sha256).toBe(a.sha256);
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES extension required installed components",
  () => {
    it.each([
      "Module.manifest",
      "extension.properties",
      "data/languages/65816.ldefs",
      "data/languages/65816.sla",
      "data/languages/65816-snes.pspec",
      "data/languages/65816.cspec",
    ])("rejects a missing required component: %s", async (component) => {
      const { root } = await snesInstallation();
      await rm(join(root, component));
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        `Missing installed ghidra-snes component: ${component}`,
      );
    });

    it("does not treat an uninstall marker as an installed manifest", async () => {
      const { root } = await snesInstallation();
      await rename(
        join(root, "Module.manifest"),
        join(root, "Module.manifest.uninstalled"),
      );
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "Module.manifest",
      );
    });

    it("rejects an installation without a loader JAR", async () => {
      const { root } = await snesInstallation();
      await rm(join(root, "lib/ghidra-snes.jar"));
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "no loader JAR",
      );
    });

    it("does not accept an arbitrary JAR elsewhere as the loader", async () => {
      const { root } = await snesInstallation();
      await rm(join(root, "lib/ghidra-snes.jar"));
      await writeFile(join(root, "ghidra-snes.jar"), "stray jar");
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "no loader JAR",
      );
    });

    it("rejects a missing installation with an actionable reason", async () => {
      const { directory } = await snesInstallation();
      const missing = join(directory, "Ghidra", "Extensions", "ghidra-snes");
      await rm(missing, { recursive: true });
      await expect(
        inspectGhidraSnesExtension(missing, "12.0.4"),
      ).rejects.toThrow(/No installed ghidra-snes extension at .+ghidra-snes/u);
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES extension symlink and nonregular entry refusal",
  () => {
    it("rejects a symlinked extension root", async () => {
      const { directory, root } = await snesInstallation();
      const linked = join(directory, "ghidra-snes-link");
      await symlink(root, linked);
      await expect(
        inspectGhidraSnesExtension(linked, "12.0.4"),
      ).rejects.toThrow("canonical non-symlink path");
    });

    it("rejects a symlinked component instead of hashing an external producer", async () => {
      const { directory, root } = await snesInstallation();
      const path = join(root, "lib/ghidra-snes.jar");
      await rename(path, join(directory, "external.jar"));
      await symlink(join(directory, "external.jar"), path);
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "regular files or directories",
      );
    });

    it("rejects nonregular filesystem entries", async () => {
      const { root } = await snesInstallation();
      const path = join(root, "data/languages/65816.sla");
      await rm(path);
      await promisify(execFile)("mkfifo", [path]);
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "regular files or directories",
      );
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES extension resource bounds",
  () => {
    it("rejects an individual component above the byte budget", async () => {
      const { root } = await snesInstallation();
      await truncate(join(root, "lib/ghidra-snes.jar"), 64 * 1024 * 1024 + 1);
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "bytes exceed the inspection limit",
      );
    });

    it("rejects components whose cumulative bytes exceed the budget", async () => {
      const { root } = await snesInstallation();
      await truncate(join(root, "data/languages/65816.sla"), 33 * 1024 * 1024);
      await truncate(join(root, "lib/ghidra-snes.jar"), 33 * 1024 * 1024 + 1);
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "bytes exceed the inspection limit",
      );
    });

    it("rejects extension properties above the 64 KiB limit", async () => {
      const { root } = await snesInstallation();
      await writeFile(
        join(root, "extension.properties"),
        `# ${"p".repeat(64 * 1024 + 1)}`,
      );
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "properties exceed the inspection limit",
      );
    });

    it("rejects inventories above 1,024 entries", async () => {
      const { root } = await snesInstallation();
      const inventory = join(root, "inventory");
      await mkdir(inventory);
      await Promise.all(
        Array.from({ length: 1020 }, (_, index) =>
          writeFile(join(inventory, `entry-${index}`), ""),
        ),
      );
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "inventory exceeds the inspection limit",
      );
    });

    it("rejects nesting beyond 16 directory levels", async () => {
      const { root } = await snesInstallation();
      let path = join(root, "data", "languages");
      for (let level = 0; level < 17; level += 1) {
        path = join(path, `nested-${level}`);
        await mkdir(path);
      }
      await writeFile(join(path, "deep"), "excessively nested");
      await expect(inspectGhidraSnesExtension(root, "12.0.4")).rejects.toThrow(
        "nesting exceeds the inspection limit",
      );
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES extension metadata binding",
  () => {
    it.each([
      ["name=SNES Loader\nversion=12.0.5\n", "does not match"],
      ["name=SNES Loader\n", "does not match"],
      ["name=Other Loader\nversion=12.0.4\n", "does not match"],
      ["name=SNES Loader\nversion=12.0.\\uZZZZ\n", "extension properties"],
      ["", "does not match"],
    ])(
      "rejects invalid or conflicting metadata %j",
      async (properties, reason) => {
        const { root } = await snesInstallation({ properties });
        await expect(
          inspectGhidraSnesExtension(root, "12.0.4"),
        ).rejects.toThrow(reason);
      },
    );

    it("cannot represent a Ghidra 12.0.4 extension as 12.1.x compatible", async () => {
      const { root } = await snesInstallation();
      await expect(inspectGhidraSnesExtension(root, "12.1.4")).rejects.toThrow(
        "does not match the selected Ghidra 12.1.4",
      );
    });

    it.each([
      {
        form: "escaped key and value with colon separator",
        properties: "n\\u0061me : SNES Loader\nver\\u0073ion=12.0.4\n",
      },
      {
        form: "continued key and value lines",
        properties: "name=SNES \\\n Loader\nversion=12.0.\\\n 4\n",
      },
      {
        form: "duplicate keys use the last value",
        properties:
          "name=wrong\nname=SNES Loader\nversion=12.0.5\nversion=12.0.4\n",
      },
    ])(
      "accepts Java Properties $form and hashes raw bytes",
      async ({ properties }) => {
        const { root } = await snesInstallation();
        const canonical = await inspectGhidraSnesExtension(root, "12.0.4");
        const latin1Properties = Buffer.from(
          `${properties}author=caf\u00e9\n`,
          "latin1",
        );
        await writeFile(join(root, "extension.properties"), latin1Properties);
        const extension = await inspectGhidraSnesExtension(root, "12.0.4");
        expect(extension.id).toBe("ghidra-snes");
        expect(extension.sha256).not.toBe(canonical.sha256);
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES extension cancellation and mutation safety",
  () => {
    it("preserves cancellation over missing-prerequisite reporting", async () => {
      const { directory } = await snesInstallation();
      const missing = join(directory, "Ghidra", "Extensions", "ghidra-snes");
      await rm(missing, { recursive: true });
      await expect(
        inspectGhidraSnesExtension(missing, "12.0.4", AbortSignal.abort()),
      ).rejects.toMatchObject({ name: "AbortError" });
    });

    it("cancels during inspection from within file reads", async () => {
      const { root } = await snesInstallation();
      const mocked = vi.mocked(openRegularFile);
      const original = mocked.getMockImplementation();
      if (!original) throw new Error("openRegularFile mock not initialized");
      const controller = new AbortController();
      mocked.mockImplementation(async (path, options) => {
        const handle = await original(path, options);
        controller.abort();
        return handle;
      });
      try {
        await expect(
          inspectGhidraSnesExtension(root, "12.0.4", controller.signal),
        ).rejects.toMatchObject({ name: "AbortError" });
      } finally {
        mocked.mockImplementation(original);
      }
    });

    it("fails closed when a component is replaced during inspection", async () => {
      const { root } = await snesInstallation();
      const mocked = vi.mocked(openRegularFile);
      const original = mocked.getMockImplementation();
      if (!original) throw new Error("openRegularFile mock not initialized");
      mocked.mockImplementation(async (path, options) => {
        const handle = await original(path, options);
        await rename(path, `${path}.replaced`);
        await writeFile(path, "replacement content");
        return handle;
      });
      try {
        await expect(
          inspectGhidraSnesExtension(root, "12.0.4"),
        ).rejects.toThrow("changed during inspection");
      } finally {
        mocked.mockImplementation(original);
      }
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "SNES extension resolver boundaries",
  () => {
    it("resolves prerequisites from explicit caller installation coordinates", async () => {
      const { directory } = await snesInstallation();
      const resolved = await resolveGhidraSnesExtension(
        installation(directory, "12.0.4"),
      );
      expect(resolved.ok).toBe(true);
      if (!resolved.ok) throw resolved.error;
      expect(resolved.value.id).toBe("ghidra-snes");
      expect(resolved.value.ghidra_version).toBe("12.0.4");
      expect(resolved.value.root).toBe(
        join(directory, "Ghidra", "Extensions", "ghidra-snes"),
      );
    });

    it("reports a missing extension as unavailable without scanning elsewhere", async () => {
      const { directory, root } = await snesInstallation();
      await rm(root, { recursive: true });
      const resolved = await resolveGhidraSnesExtension(
        installation(directory, "12.0.4"),
      );
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Missing installation was accepted");
      expect(resolved.error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect(resolved.error.message).toContain("SNES_EXTENSION_UNAVAILABLE");
    });

    it("refuses a 12.0.4 extension for a selected Ghidra 12.1.x installation", async () => {
      const { directory } = await snesInstallation();
      const resolved = await resolveGhidraSnesExtension(
        installation(directory, "12.1.4"),
      );
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Version mismatch was accepted");
      expect(resolved.error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect(resolved.error.message).toContain("does not match");
    });

    it("requires an available Ghidra installation", async () => {
      const unavailable = {
        status: "unavailable",
        installDir: null,
        analyzeHeadlessPath: null,
        applicationPropertiesPath: null,
        nativeDecompilerPath: null,
        javaCommand: "java",
        javaHome: null,
        javaVersion: null,
        providerVersion: null,
        platform: "linux",
        architecture: "x64",
        checks: [],
        rejection: { code: "GHIDRA_UNAVAILABLE", reason: "test" },
      } as unknown as GhidraInstallationInspection;
      const resolved = await resolveGhidraSnesExtension(unavailable);
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Unavailable installation was accepted");
      expect(resolved.error.message).toContain("SNES_EXTENSION_UNAVAILABLE");
    });

    it("preserves cancellation before prerequisite inspection", async () => {
      const { directory } = await snesInstallation();
      const resolved = await resolveGhidraSnesExtension(
        installation(directory, "12.0.4"),
        AbortSignal.abort(),
      );
      expect(resolved.ok).toBe(false);
      if (resolved.ok) throw new Error("Cancellation was ignored");
      expect(resolved.error._tag).toBe("AnalysisCancelledError");
    });
  },
);
