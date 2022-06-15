package net.covers1624.bcs.util;

import it.unimi.dsi.fastutil.ints.Int2ObjectArrayMap;
import it.unimi.dsi.fastutil.ints.Int2ObjectMap;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import it.unimi.dsi.fastutil.objects.Object2IntOpenHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Set;

/**
 * Created by covers1624 on 1/3/21.
 */
public class OpcodeLookup {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final Object2IntMap<String> OPCODES = new Object2IntOpenHashMap<>();
    private static final Int2ObjectMap<String> OPCODES_LOOKUP = new Int2ObjectArrayMap<>();

    static {
        OPCODES.defaultReturnValue(-1);
        boolean foundNop = false;
        for (Field field : Opcodes.class.getDeclaredFields()) {
            String name = field.getName();

            if (name.equals("NOP")) {
                foundNop = true;
            }

            if (!foundNop) continue;

            try {
                int i = field.getInt(null);
                OPCODES.put(name, i);
                OPCODES_LOOKUP.put(i, name);
            } catch (IllegalAccessException e) {
                throw new ExceptionInInitializerError(e);
            }
        }
    }

    public static int lookupOpcode(String name) {
        return OPCODES.getInt(name);
    }

    public static String getName(int opcode) {
        return OPCODES_LOOKUP.get(opcode);
    }

    public static Set<String> getOpcodeNames() {
        return Collections.unmodifiableSet(OPCODES.keySet());
    }
}
