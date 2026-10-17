import { execFile } from "node:child_process";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const exec = promisify(execFile);

// Executes the bridge's actual pre-service Java gate with a detached program
// double. This is a gate regression, NOT real-provider qualification.
describe("SNES bridge preparation gate", () => {
  it("refuses skipped or failed preparation before serving any request", async ({
    skip,
  }) => {
    const source = await readFile("bridge/ghidra/ReaGhidraBridge.java", "utf8");
    const start = source.indexOf(
      '        if (currentProgram.getExecutableFormat().equals("Raw Binary"))',
    );
    const end = source.indexOf(
      "        if (!Application.getApplicationVersion()",
      start,
    );
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    expect(end).toBeLessThan(source.indexOf("            serve(descriptor);"));
    const root = await createTestTempDirectory("rea-snes-bridge-gate-");
    const packageRoot = join(root, "ghidra", "program", "model", "listing");
    await mkdir(packageRoot, { recursive: true });
    await writeFile(
      join(packageRoot, "Program.java"),
      'package ghidra.program.model.listing; public class Program { public static final String PROGRAM_INFO = "info"; }',
    );
    await writeFile(
      join(root, "Gate.java"),
      `
public class Gate {
  static class Language { public String getIdAsString() { return "65816:LE:24:snes"; } }
  static class Options {
    boolean prepared;
    public boolean getBoolean(String name, boolean fallback) {
      if (!name.equals("REA SNES ROM prepared")) throw new AssertionError(name);
      return prepared;
    }
  }
  static class Program {
    String format; Options options = new Options();
    public String getExecutableFormat() { return format; }
    public Language getLanguageID() { return new Language(); }
    public Options getOptions(String name) { return options; }
  }
  static Program currentProgram = new Program();
  static void gate() {
${source.slice(start, end)}
  }
  public static void main(String[] args) {
    currentProgram.format = "SNES ROM Loader";
    for (String failure : new String[] { "skipped pre-script", "failed pre-script", "unmappable reset vector", "failed entry preparation" }) {
      currentProgram.options.prepared = false;
      try { gate(); throw new AssertionError("served after " + failure); }
      catch (IllegalStateException expected) {
        if (!expected.getMessage().contains("SNES")) throw expected;
      }
    }
    currentProgram.options.prepared = true;
    gate();
    currentProgram.format = "Executable and Linking Format (ELF)";
    currentProgram.options.prepared = false;
    gate();
    System.out.println("SNES marker negatives and prepared/non-SNES controls passed");
  }
}
`,
    );
    const javaHome = process.env.JAVA_HOME;
    const javac = javaHome ? join(javaHome, "bin", "javac") : "javac";
    const java = javaHome ? join(javaHome, "bin", "java") : "java";
    try {
      await exec(javac, ["-version"]);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT")
        skip("JDK javac unavailable: detached Java gate is unverified");
      throw error;
    }
    await exec(javac, [
      join(packageRoot, "Program.java"),
      join(root, "Gate.java"),
    ]);
    const result = await exec(java, ["-cp", root, "Gate"]);
    expect(result.stdout).toContain(
      "SNES marker negatives and prepared/non-SNES controls passed",
    );
  });

  it("only publishes preparation success after complete vector read and entry creation", async () => {
    const source = await readFile(
      "bridge/ghidra/ReaGhidraPrepareSnes.java",
      "utf8",
    );
    const cleared = source.indexOf(
      'setBoolean("REA SNES ROM prepared", false)',
    );
    const read = source.indexOf("getBytes(vector, word)");
    const checked = source.indexOf("!= word.length");
    const entry = source.indexOf("addEntryPoint(entry)");
    const decoded = source.indexOf("!disassemble(entry)");
    const success = source.indexOf('setBoolean("REA SNES ROM prepared", true)');
    expect(cleared).toBeGreaterThan(0);
    expect(cleared).toBeLessThan(read);
    expect(checked).toBeGreaterThan(read);
    expect(checked).toBeLessThan(entry);
    expect(success).toBeGreaterThan(decoded);
    expect(source.slice(decoded, success)).toContain("createFunction(entry");
    expect(source.slice(decoded, success)).toContain(
      "throw new IllegalStateException",
    );
  });
});
