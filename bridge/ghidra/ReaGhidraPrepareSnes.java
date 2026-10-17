import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

/**
 * Seed the loader-resolved reset-vector entry before default auto-analysis.
 *
 * The pinned SnesRomLoader maps canonical file-backed banks but creates no
 * entry points, so this script resolves the cartridge's reset vector from the
 * committed canonical header bank, verifies its file-backed source offset,
 * and refuses to continue when the resolved entry is not file-backed ROM.
 */
public final class ReaGhidraPrepareSnes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3) {
            throw new IllegalArgumentException(
                "SNES preparation requires the declared mapping, reset-vector address, and file offset"
            );
        }
        String mapping = arguments[0];
        if (!mapping.equals("lorom") && !mapping.equals("hirom")) {
            throw new IllegalArgumentException(
                "SNES preparation requires the admitted lorom or hirom mapping, not " + mapping
            );
        }
        if (!currentProgram.getLanguageID().getIdAsString().equals("65816:LE:24:snes") ||
            !currentProgram.getExecutableFormat().equals("SNES ROM Loader")) {
            throw new IllegalArgumentException(
                "SNES preparation requires the pinned 65816 language and SnesRomLoader import"
            );
        }
        Address vector = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(arguments[1]);
        long expectedFileOffset = Long.parseUnsignedLong(arguments[2], 10);
        MemoryBlockSourceInfo source = fileBackedSourceContaining(vector);
        // A source info reports its own start's file offset; the vector's
        // offset adds its distance from that start.
        long observedFileOffset = source == null ? -1
            : source.getFileBytesOffset() + vector.subtract(source.getMinAddress());
        if (source == null || observedFileOffset != expectedFileOffset) {
            throw new IllegalArgumentException(
                "The reset vector must be file-backed at offset " + expectedFileOffset +
                    " in the canonical " + mapping + " bank, not " + observedFileOffset
            );
        }
        byte[] word = new byte[2];
        currentProgram.getMemory().getBytes(vector, word);
        int value = (word[0] & 0xff) | ((word[1] & 0xff) << 8);
        long entryBank = vector.getOffset() >>> 16;
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress((entryBank << 16) | value);
        if (fileBackedSourceContaining(entry) == null) {
            throw new IllegalArgumentException(
                "The reset vector value 0x" + Integer.toHexString(value) +
                    " resolves to " + entry + ", which is not file-backed canonical ROM"
            );
        }
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, "entry") == null) {
            throw new IllegalStateException("SNES reset entry cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA SNES ROM prepared", true);
    }

    private MemoryBlockSourceInfo fileBackedSourceContaining(Address address) {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block == null || !block.isInitialized()) {
            return null;
        }
        for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            if (source.contains(address) && source.getFileBytes().isPresent()) {
                return source;
            }
        }
        return null;
    }
}
