/*
 * MIT License
 *
 * Copyright (c) 2018-2021 covers1624
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package net.covers1624.scanner.scanners;

import codechicken.asm.ObfMapping;
import com.google.common.collect.ImmutableList;
import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.ints.IntList;
import net.covers1624.scanner.ScanResult;
import net.covers1624.scanner.json.Exclusion;
import org.objectweb.asm.Handle;
import org.objectweb.asm.tree.*;

import java.util.Collections;
import java.util.List;

import static org.objectweb.asm.Opcodes.*;

/**
 * Created by covers1624 on 23/12/20.
 */
public class MethodAccessScanner extends FilteredScanner {

    public static final String IDENTIFIER = "method_access";

    private static final List<String> NAMES = ImmutableList.of(
            "INVOKEVIRTUAL",
            "INVOKESPECIAL",
            "INVOKESTATIC",
            "INVOKEINTERFACE"
    );
    // Handle tag -> Insn
    public static final int[] HANDLE_LOOKUP = {
            -1,
            GETFIELD,
            GETSTATIC,
            PUTFIELD,
            PUTSTATIC,
            INVOKEVIRTUAL,
            INVOKESTATIC,
            INVOKESPECIAL,
            INVOKESPECIAL,
            INVOKEINTERFACE
    };

    private final ObfMapping methodMapping;
    private final IntList opcodes;

    public MethodAccessScanner(ObfMapping methodMapping, int... opcodes) {
        this(methodMapping, Collections.emptyList(), opcodes);
    }

    public MethodAccessScanner(ObfMapping methodMapping, List<Exclusion> exclusions, int... opcodes) {
        super(exclusions);
        this.methodMapping = methodMapping;

        if (opcodes.length == 0) {
            throw new IllegalArgumentException("Opcodes not specified.");
        }
        for (int opcode : opcodes) {
            if (!(INVOKEVIRTUAL <= opcode && opcode <= INVOKEINTERFACE)) {
                throw new IllegalArgumentException("Expected: " + String.join(", ", NAMES));
            }
        }
        this.opcodes = new IntArrayList(opcodes);
    }

    @Override
    public ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode) {
        if (filter(mNode)) return null;

        int opcode = insn.getOpcode();

        if (insn instanceof MethodInsnNode) {
            if (!opcodes.contains(insn.getOpcode())) return null;

            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            boolean matches = methodInsn.owner.equals(methodMapping.s_owner) && nameDescMatch(methodInsn.name, methodInsn.desc);
            if (matches) {
                String problem = NAMES.get(opcode - INVOKEVIRTUAL) + " Usage of method: '" + methodInsn.owner + "." + methodInsn.name + methodInsn.desc;
                return new ScanResult(IDENTIFIER, findLineOrIndex(insn, mNode), problem);
            }
        } else if (insn instanceof InvokeDynamicInsnNode) {
            InvokeDynamicInsnNode mInsn = (InvokeDynamicInsnNode) insn;
            for (Object bsmArg : mInsn.bsmArgs) {
                if (!(bsmArg instanceof Handle)) continue;

                Handle handle = (Handle) bsmArg;
                if (!opcodes.contains(HANDLE_LOOKUP[handle.getTag()])) continue;

                if (handle.getOwner().equals(methodMapping.s_owner) && nameDescMatch(handle.getName(), handle.getDesc())) {
                    String problem = "INVOKEDYNAMIC(" + NAMES.get(HANDLE_LOOKUP[handle.getTag()] - INVOKEVIRTUAL) + ") Usage of method: '" + handle.getOwner() + "." + handle.getName() + handle.getDesc();
                    return new ScanResult(IDENTIFIER, findLineOrIndex(insn, mNode), problem);
                }

            }
        }
        return null;
    }

    private boolean nameDescMatch(String name, String desc) {
        return (methodMapping.s_name.equals("*") || name.equals(methodMapping.s_name))
                && (methodMapping.s_desc.equals("*") || desc.equals(methodMapping.s_desc));
    }
}
