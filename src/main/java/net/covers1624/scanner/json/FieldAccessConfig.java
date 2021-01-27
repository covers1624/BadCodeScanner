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

package net.covers1624.scanner.json;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.ints.IntList;
import it.unimi.dsi.fastutil.objects.Object2IntArrayMap;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import net.covers1624.quack.util.SneakyUtils;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Type;
import java.util.Collections;
import java.util.List;

/**
 * Created by covers1624 on 26/1/21.
 */
public class FieldAccessConfig {

    private static final Type EXCLUSION_LIST = new TypeToken<List<Exclusion>>() {}.getType();
    private static final Object2IntMap<String> OPCODE_LOOKUP = SneakyUtils.sneaky(() -> {
        Object2IntMap<String> map = new Object2IntArrayMap<>();
        map.put("GETSTATIC", Opcodes.GETSTATIC);
        map.put("PUTSTATIC", Opcodes.PUTSTATIC);
        map.put("GETFIELD", Opcodes.GETFIELD);
        map.put("PUTFIELD", Opcodes.PUTFIELD);
        return map;
    });

    public String name;
    public int[] opcodes;
    public List<Exclusion> exclusions;

    public static class Serializer implements JsonDeserializer<FieldAccessConfig> {

        @Override
        public FieldAccessConfig deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            FieldAccessConfig fConfig = new FieldAccessConfig();
            JsonObject obj = json.getAsJsonObject();
            fConfig.name = context.deserialize(obj.get("name"), String.class);
            IntList opcodes = new IntArrayList();

            JsonElement opcode = obj.get("opcode");
            if (opcode.isJsonPrimitive()) {
                opcodes.add(OPCODE_LOOKUP.getInt(opcode.getAsString()));
            } else {
                JsonArray array = opcode.getAsJsonArray();
                for (JsonElement e : array) {
                    opcodes.add(OPCODE_LOOKUP.getInt(e.getAsString()));
                }
            }
            fConfig.opcodes = opcodes.toIntArray();

            List<Exclusion> exclusions = context.deserialize(obj.get("exclusions"), EXCLUSION_LIST);
            if (exclusions == null) {
                exclusions = Collections.emptyList();
            }
            fConfig.exclusions = exclusions;

            return fConfig;
        }
    }
}
