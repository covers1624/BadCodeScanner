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
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Collections;
import java.util.List;

/**
 * Created by covers1624 on 23/12/20.
 */
public class FieldAccessScanner extends FilteredScanner {

    public static final String IDENTIFIER = "field_access";

    private static final List<String> NAMES = ImmutableList.of(
            "GETSTATIC",
            "PUTSTATIC",
            "GETFIELD",
            "PUTFIELD"
    );

    private final ObfMapping fieldMapping;
    private final IntList opcodes;

    public FieldAccessScanner(ObfMapping fieldMapping, int... opcodes) {
        this(fieldMapping, Collections.emptyList(), opcodes);
    }

    public FieldAccessScanner(ObfMapping fieldMapping, List<Exclusion> exclusions, int... opcodes) {
        super(exclusions);
        this.fieldMapping = fieldMapping;
        if (opcodes.length == 0) {
            throw new IllegalArgumentException("Opcodes not specified.");
        }
        for (int opcode : opcodes) {
            if (!(Opcodes.GETSTATIC <= opcode && opcode <= Opcodes.PUTFIELD)) {
                throw new IllegalArgumentException("Expected: " + String.join(", ", NAMES));
            }
        }
        this.opcodes = new IntArrayList(opcodes);
    }

    @Override
    public ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode) {
        if (filter(mNode)) return null;

        if (insn instanceof FieldInsnNode) {
            FieldInsnNode fieldInsn = (FieldInsnNode) insn;
            boolean matches = fieldInsn.owner.equals(fieldMapping.s_owner) && fieldInsn.name.equals(fieldMapping.s_name);
            if (matches && opcodes.contains(fieldInsn.getOpcode())) {
                String problem = NAMES.get(fieldInsn.getOpcode() - Opcodes.GETSTATIC) + " Access of field: '" + fieldMapping.s_owner + "." + fieldMapping.s_name + "'";
                return new ScanResult(IDENTIFIER, findLineOrIndex(insn, mNode), problem);
            }
        }
        return null;
    }
}
