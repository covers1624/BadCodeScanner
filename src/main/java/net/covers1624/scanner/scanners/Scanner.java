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

import com.mojang.datafixers.util.Either;
import net.covers1624.scanner.ScanResult;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Created by covers1624 on 23/12/20.
 */
public interface Scanner {

    ScanResult scan(AbstractInsnNode insn, MethodNode mNode, ClassNode cNode);

    default Either<LineNumberNode, Integer> findLineOrIndex(AbstractInsnNode insn, MethodNode node) {
        LineNumberNode lineNumber = null;
        AbstractInsnNode prev = insn;
        do {
            if (prev instanceof LineNumberNode) {
                lineNumber = (LineNumberNode) prev;
                break;
            }
            prev = prev.getPrevious();
        }
        while (prev != null);
        if (lineNumber != null) {
            return Either.left(lineNumber);
        }
        return Either.right(node.instructions.indexOf(insn));
    }

}
