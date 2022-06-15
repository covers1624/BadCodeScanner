package net.covers1624.bcs.scanners;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import it.unimi.dsi.fastutil.ints.IntArraySet;
import it.unimi.dsi.fastutil.ints.IntSet;
import net.covers1624.bcs.util.OpcodeLookup;
import net.covers1624.quack.collection.StreamableIterable;
import org.jetbrains.annotations.Nullable;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Collection;

/**
 * Created by covers1624 on 15/6/22.
 */
public class OpcodeUseScanner implements Scanner {

    private final IntSet opcodes;

    public OpcodeUseScanner(Collection<Integer> opcodes) {
        this.opcodes = new IntArraySet(opcodes);
    }

    public OpcodeUseScanner(JsonElement jsonElement) {
        if (!jsonElement.isJsonArray()) throw new JsonParseException("Expected Json array.");

        opcodes = new IntArraySet(StreamableIterable.of(jsonElement.getAsJsonArray())
                .filterNot(JsonElement::isJsonNull)
                .map(e -> e.getAsJsonPrimitive().getAsString())
                .map(OpcodeLookup::lookupOpcode)
                .toList()
        );
    }

    @Nullable
    @Override
    public ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode) {
        if (!opcodes.contains(insn.getOpcode())) return null;

        return Scanner.simpleResult(insn, mNode, "");
    }
}
