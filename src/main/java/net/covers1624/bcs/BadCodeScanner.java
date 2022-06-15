package net.covers1624.bcs;

import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.covers1624.bcs.api.IgnoreBadCode;
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

    private static final String IGNORE_BAD_CODE_DESC = IgnoreBadCode.class.getName().replace(".", "/");

    private final Map<String, Function<JsonElement, Scanner>> scannerFactories;

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
        for (Map.Entry<String, JsonElement> groupEntry : obj.entrySet()) {
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
            Set<String> excludedGroupsByMethod = getExcludedGroups(mNode.visibleAnnotations);
            List<ScanResult> results = new LinkedList<>();
            for (AbstractInsnNode insn : mNode.instructions) {
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

    private static Set<String> getExcludedGroups(List<AnnotationNode> annotations) {
        if (annotations == null || annotations.isEmpty()) return ImmutableSet.of();

        Set<String> ignored = new HashSet<>();
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc.equals(IGNORE_BAD_CODE_DESC)) {
                ignored.addAll(unsafeCast(annotation.values.get(1)));
            }
        }
        return ignored;
    }
}
