package net.covers1624.bcs.scanners;

import net.covers1624.bcs.util.OpcodeLookup;
import org.jetbrains.annotations.Nullable;
import org.objectweb.asm.tree.*;

import java.util.List;
import java.util.function.Predicate;

/**
 * Created by covers1624 on 13/6/22.
 */
public interface Scanner {

    @Nullable
    ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode);

    static boolean noneMatch(List<? extends Predicate<AbstractInsnNode>> predicates, AbstractInsnNode node) {
        for (Predicate<AbstractInsnNode> predicate : predicates) {
            if (predicate.test(node)) {
                return false;
            }
        }
        return true;
    }

    static Location getLoc(MethodNode mNode, AbstractInsnNode insn) {
        AbstractInsnNode ln = insn;
        while (ln != null && ln.getType() != AbstractInsnNode.LINE) {
            ln = ln.getPrevious();
        }

        return new Location(ln != null ? ((LineNumberNode) ln).line : -1, mNode.instructions.indexOf(insn));
    }

    static ScanResult simpleResult(AbstractInsnNode insn, MethodNode mNode, String message) {
        String tail = !message.isEmpty() ? " " + message : "";
        return new ScanResult(getLoc(mNode, insn), OpcodeLookup.getName(insn.getOpcode()) + tail);
    }

    static String describeSimple(AbstractInsnNode insn) {
        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
            MethodInsnNode mInsn = (MethodInsnNode) insn;
            return mInsn.owner + " " + mInsn.name + mInsn.desc;
        }
        if (insn.getType() == AbstractInsnNode.FIELD_INSN) {
            FieldInsnNode fInsn = (FieldInsnNode) insn;
            return fInsn.owner + " " + fInsn.name + " : " + fInsn.desc;
        }
        return "Unknown Instruction";
    }

    record ScanResult(Location ctx, String problem) {
    }

    record Location(int lineNumber, int insnIndex) {

        public String describe() {
            return lineNumber != -1 ? "line " + lineNumber : "insn index " + insnIndex;
        }
    }
}
