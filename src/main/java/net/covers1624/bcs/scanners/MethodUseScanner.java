package net.covers1624.bcs.scanners;

import com.google.common.collect.ImmutableList;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import net.covers1624.quack.collection.StreamableIterable;
import org.jetbrains.annotations.Nullable;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.function.Predicate;

/**
 * Created by covers1624 on 13/6/22.
 */
public class MethodUseScanner implements Scanner {

    private final List<MethodPredicate> predicates;

    public MethodUseScanner(List<MethodPredicate> predicates) {
        this.predicates = List.copyOf(predicates);
    }

    public MethodUseScanner(JsonElement jsonElement) {
        if (!jsonElement.isJsonArray()) throw new JsonParseException("Expected Json array.");

        predicates = StreamableIterable.of(jsonElement.getAsJsonArray())
                .filterNot(JsonElement::isJsonNull)
                .map(e -> e.getAsJsonPrimitive().getAsString())
                .map(MethodUseScanner::parsePredicate)
                .toImmutableList();
    }

    @Override
    public ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode) {
        if (Scanner.noneMatch(predicates, insn)) return null;

        return Scanner.simpleResult(insn, mNode, "usage of method: " + Scanner.describeSimple(insn));
    }

    private static MethodPredicate parsePredicate(String s) {
        String[] segs = s.split(" ");
        if (segs.length != 2) throw new JsonParseException("Expected 2 segments. Got: '" + s + "'");

        String name = segs[1];
        String desc = null;
        int brace = name.indexOf('(');
        if (brace != -1) {
            desc = name.substring(brace);
            name = name.substring(0, brace);
        }

        return new MethodPredicate(segs[0].replace(".", "/"), name, desc);
    }

    public record MethodPredicate(String owner, String name, @Nullable String desc) implements Predicate<AbstractInsnNode> {

        @Override
        public boolean test(AbstractInsnNode insn) {
            if (insn.getType() != AbstractInsnNode.METHOD_INSN) return false;

            MethodInsnNode mInsn = (MethodInsnNode) insn;
            if (!mInsn.owner.equals(owner)) return false;

            if (name.equals("*")) return true;

            if (!mInsn.name.equals(name)) return false;

            return desc == null || desc.equals(mInsn.desc);
        }
    }
}
