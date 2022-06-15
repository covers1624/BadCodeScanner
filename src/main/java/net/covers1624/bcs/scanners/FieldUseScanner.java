package net.covers1624.bcs.scanners;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import net.covers1624.quack.collection.StreamableIterable;
import org.jetbrains.annotations.Nullable;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.function.Predicate;

/**
 * Created by covers1624 on 15/6/22.
 */
public class FieldUseScanner implements Scanner {

    private final List<FieldPredicate> predicates;

    public FieldUseScanner(List<FieldPredicate> predicates) {
        this.predicates = List.copyOf(predicates);
    }

    public FieldUseScanner(JsonElement jsonElement) {
        if (!jsonElement.isJsonArray()) throw new JsonParseException("Expected Json array.");

        predicates = StreamableIterable.of(jsonElement.getAsJsonArray())
                .filterNot(JsonElement::isJsonNull)
                .map(e -> e.getAsJsonPrimitive().getAsString())
                .map(FieldUseScanner::parsePredicate)
                .toImmutableList();
    }

    @Nullable
    @Override
    public ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode) {
        if (Scanner.noneMatch(predicates, insn)) return null;

        return Scanner.simpleResult(insn, mNode, "usage of field: " + Scanner.describeSimple(insn));
    }

    private static FieldPredicate parsePredicate(String s) {
        String[] segs = s.split(" ");
        if (segs.length != 2) throw new JsonParseException("Expected 2 segments. Got: '" + s + "'");

        return new FieldPredicate(segs[0].replace('.', '/'), segs[1]);
    }

    public record FieldPredicate(String owner, String name) implements Predicate<AbstractInsnNode> {

        @Override
        public boolean test(AbstractInsnNode insn) {
            if (insn.getType() != AbstractInsnNode.FIELD_INSN) return false;

            FieldInsnNode fInsn = (FieldInsnNode) insn;
            if (!fInsn.owner.equals(owner)) return false;

            if (name.equals("*")) return true;

            return fInsn.name.equals(name);
        }
    }
}
