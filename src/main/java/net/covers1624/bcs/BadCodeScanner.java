package net.covers1624.bcs;

import com.google.common.collect.ImmutableSet;
import com.google.gson.*;
import net.covers1624.bcs.scanners.FieldUseScanner;
import net.covers1624.bcs.scanners.MethodUseScanner;
import net.covers1624.bcs.scanners.OpcodeUseScanner;
import net.covers1624.bcs.scanners.Scanner;
import net.covers1624.bcs.scanners.Scanner.ScanResult;
import net.covers1624.quack.collection.StreamableIterable;
import net.covers1624.quack.gson.JsonUtils;
import net.covers1624.quack.io.IOUtils;
import net.covers1624.quack.util.SneakyUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Stream;

import static net.covers1624.quack.util.SneakyUtils.unsafeCast;

/**
 * Created by covers1624 on 13/6/22.
 */
public class BadCodeScanner {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson GSON = new GsonBuilder().setLenient().create();

    private final Map<String, Function<JsonElement, Scanner>> scannerFactories;

    private final Set<String> ignoreAnnotations = new HashSet<>();
    private final Map<String, List<Scanner>> scanners = new HashMap<>();
    private final Map<String, Map<String, List<ScanResult>>> scanResults = new ConcurrentHashMap<>();

    public BadCodeScanner(Map<String, Function<JsonElement, Scanner>> scannerFactories) {
        this.scannerFactories = scannerFactories;
    }

    public static void main(String[] args) throws IOException {
        BadCodeScanner scanner = new BadCodeScanner(Map.of(
                "method_use", MethodUseScanner::new,
                "field_use", FieldUseScanner::new,
                "opcode_use", OpcodeUseScanner::new
        ));

        scanner.setup(Path.of("./config.json"));
        scanner.operate(Path.of(args[0]));
        scanner.printResults();
    }

    public void setup(Path config) throws IOException {
        JsonObject obj = JsonUtils.parse(GSON, config, JsonObject.class);

        if (obj.has("settings")) {
            JsonObject settings = obj.getAsJsonObject("settings");
            if (settings.has("ignore_annotations")) {
                for (JsonElement element : settings.getAsJsonArray("ignore_annotations")) {
                    ignoreAnnotations.add(element.getAsString());
                }
            }
        }

        if (!obj.has("groups")) throw new JsonSyntaxException("Expected 'groups' object.");
        for (Map.Entry<String, JsonElement> groupEntry : obj.getAsJsonObject("groups").entrySet()) {
            String groupName = groupEntry.getKey();
            List<Scanner> scanners = new LinkedList<>();

            for (Map.Entry<String, JsonElement> scannerEntry : groupEntry.getValue().getAsJsonObject().entrySet()) {
                String scannerType = scannerEntry.getKey();
                Function<JsonElement, Scanner> factory = scannerFactories.get(scannerType);
                if (factory == null) {
                    LOGGER.warn("Unknown scanner type: " + scannerType);
                    continue;
                }

                scanners.add(factory.apply(scannerEntry.getValue()));
            }

            this.scanners.put(groupName, scanners);
        }
    }

    public void operate(Path location) throws IOException {
        if (Files.isDirectory(location)) {
            scanRootDir(location);
        } else if (location.getFileName().toString().endsWith(".jar")) {
            try (FileSystem fs = IOUtils.getJarFileSystem(location, true)) {
                scanRootDir(fs.getPath("/"));
            }
        }
    }

    public void printResults() {
        if (!scanResults.isEmpty()) {
            LOGGER.error("Errors detected:");
            for (Map.Entry<String, Map<String, List<ScanResult>>> classEntry : scanResults.entrySet()) {
                LOGGER.error(classEntry.getKey());
                for (Map.Entry<String, List<ScanResult>> methodEntry : classEntry.getValue().entrySet()) {
                    LOGGER.error(" {}", methodEntry.getKey());
                    for (ScanResult scanResult : methodEntry.getValue()) {
                        LOGGER.error("  {}, {}", scanResult.problem(), scanResult.ctx().describe());
                    }
                }
            }
        }
    }

    public Map<String, Map<String, List<ScanResult>>> getScanResults() {
        return scanResults;
    }

    private void scanRootDir(Path root) throws IOException {
        try (Stream<Path> stream = Files.walk(root)) {
            stream.parallel()
                    .filter(Files::isRegularFile)
                    .filter(e -> e.getFileName().toString().endsWith(".class"))
                    .forEach(SneakyUtils.sneak(this::scanClass));
        }
    }

    private void scanClass(Path file) throws IOException {
        Map<String, List<ScanResult>> methodResults = new HashMap<>();

        ClassNode cNode = toNode(file);
        Set<String> excludedGroupsByClass = getExcludedGroups(cNode.visibleAnnotations);
        for (MethodNode mNode : cNode.methods) {
            if (excludedGroupsByClass.contains("*")) continue;
            Set<String> excludedGroupsByMethod = getExcludedGroups(mNode.visibleAnnotations);
            List<ScanResult> results = new LinkedList<>();
            for (AbstractInsnNode insn : mNode.instructions) {
                if (excludedGroupsByMethod.contains("*")) continue;
                for (Scanner scanner : getApplicableScanners(excludedGroupsByClass, excludedGroupsByMethod)) {
                    ScanResult result = scanner.scan(insn, mNode, cNode);
                    if (result != null) {
                        results.add(result);
                    }
                }
            }
            if (!results.isEmpty()) {
                methodResults.put(mNode.name + mNode.desc, results);
            }
        }
        if (!methodResults.isEmpty()) {
            scanResults.put(cNode.name, methodResults);
        }
    }

    private StreamableIterable<Scanner> getApplicableScanners(Set<String> classExcludes, Set<String> methodExcludes) {
        return StreamableIterable.of(scanners.entrySet())
                .filterNot(e -> classExcludes.contains(e.getKey()) || methodExcludes.contains(e.getKey()))
                .flatMap(Map.Entry::getValue);
    }

    private static ClassNode toNode(Path file) throws IOException {
        try (InputStream is = Files.newInputStream(file)) {
            ClassReader reader = new ClassReader(is);
            ClassNode cNode = new ClassNode();
            reader.accept(cNode, ClassReader.EXPAND_FRAMES);
            return cNode;
        }
    }

    private Set<String> getExcludedGroups(List<AnnotationNode> annotations) {
        if (annotations == null || annotations.isEmpty()) return ImmutableSet.of();

        Set<String> ignored = new HashSet<>();
        for (AnnotationNode annotation : annotations) {
            if (ignoreAnnotations.contains(annotation.desc)) {
                if (annotation.values == null) {
                    ignored.add("*");
                } else if (annotation.values.size() != 2) {
                    LOGGER.warn("Failed to parse ignore annotation. Expected 2 values. Got :" + annotation.values);
                } else {
                    addValues(ignored, annotation.values.get(1));
                }
                ignored.addAll(unsafeCast(annotation.values.get(1)));
            }
        }
        return ignored;
    }

    private void addValues(Set<String> ignored, Object obj) {
        if (obj instanceof String s) {
            ignored.add(s);
        } else if (obj instanceof List<?> list) {
            for (Object o : list) {
                addValues(ignored, o);
            }
        } else {
            LOGGER.info("Unknown value type in ignore annotation: {}:{}", obj.getClass(), obj);
        }
    }
}
