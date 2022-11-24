package net.covers1624.bcs.scanners;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import net.covers1624.quack.collection.StreamableIterable;
import org.jetbrains.annotations.Nullable;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.List;

/**
 * Created by covers1624 on 23/11/22.
 */
public class TypeUseScanner implements Scanner {

    private final List<String> types;

    public TypeUseScanner(JsonElement jsonElement) {
        if (!jsonElement.isJsonArray()) throw new JsonParseException("Expected Json array.");

        types = StreamableIterable.of(jsonElement.getAsJsonArray())
                .filterNot(JsonElement::isJsonNull)
                .map(e -> e.getAsJsonPrimitive().getAsString())
                .toImmutableList();
    }

    @Nullable
    @Override
    public ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode) {
        if (matches(insn)) {
            return Scanner.simpleResult(insn, mNode, "");
        }
        return null;
    }

    private boolean matches(AbstractInsnNode insn) {
        if (insn.getType() == AbstractInsnNode.TYPE_INSN) {
            TypeInsnNode typeInsn = (TypeInsnNode) insn;
            return matches(typeInsn.desc);
        } else if (insn.getType() == AbstractInsnNode.FIELD_INSN) {
            FieldInsnNode fieldInsn = (FieldInsnNode) insn;
            if (matches(fieldInsn.owner)) {
                return true;
            }
            return matches(Type.getType(fieldInsn.desc));
        } else if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            if (matches(methodInsn.owner)) {
                return true;
            }
            return matches(Type.getType(methodInsn.desc));
        }
        return false;
    }

    private boolean matches(Type type) {
        if (type.getSort() == Type.ARRAY) {
            return matches(type.getElementType());
        } else if (type.getSort() == Type.OBJECT) {
            return matches(type.getInternalName());
        } else if (type.getSort() == Type.METHOD) {
            if (matches(type.getReturnType())) {
                return true;
            }
            for (Type arg : type.getArgumentTypes()) {
                if (matches(arg)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean matches(String type) {
        for (String s : types) {
            if (type.startsWith(s)) {
                return true;
            }
        }
        return false;
    }
}
