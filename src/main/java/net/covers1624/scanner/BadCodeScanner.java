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

package net.covers1624.scanner;

import codechicken.asm.InsnListSection;
import codechicken.asm.ObfMapping;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.PathConverter;
import net.covers1624.quack.io.IOUtils;
import net.covers1624.scanner.json.Config;
import net.covers1624.scanner.json.FieldAccessConfig;
import net.covers1624.scanner.json.MethodAccessConfig;
import net.covers1624.scanner.json.OpcodeUseConfig;
import net.covers1624.scanner.scanners.FieldAccessScanner;
import net.covers1624.scanner.scanners.MethodAccessScanner;
import net.covers1624.scanner.scanners.OpcodeUseScanner;
import net.covers1624.scanner.scanners.Scanner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Arrays.asList;
import static net.covers1624.quack.util.SneakyUtils.sneak;

/**
 * Created by covers1624 on 23/12/20.
 */
public class BadCodeScanner {

    private static final Logger logger = LogManager.getLogger();

    public static List<Scanner> scanners = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        System.exit(mainI(args));
    }

    private static int mainI(String[] args) throws IOException {
        OptionParser parser = new OptionParser();

        OptionSpec<Void> helpOpt = parser.acceptsAll(asList("h", "help"), "Prints this help.").forHelp();
        OptionSpec<Path> configOpt = parser.acceptsAll(asList("c", "config"), "The config file to use.")
                .withRequiredArg()
                .withValuesConvertedBy(new PathConverter());

        OptionSpec<Path> targetOpt = parser.acceptsAll(asList("t", "target"), "The target to scan.")
                .withRequiredArg()
                .withValuesConvertedBy(new PathConverter());

        OptionSet optSet = parser.parse(args);
        if (optSet.has(helpOpt)) {
            parser.printHelpOn(System.err);
            return -1;
        }

        if (!optSet.has(configOpt)) {
            System.err.println("Requires config opt.");
            parser.printHelpOn(System.err);
            return -1;
        }

        if (!optSet.has(targetOpt)) {
            System.err.println("Requires target opt.");
            parser.printHelpOn(System.err);
            return -1;
        }
        Path configFile = optSet.valueOf(configOpt);
        Path targetFile = optSet.valueOf(targetOpt);

        if (Files.notExists(configFile)) {
            System.err.println("Config file does not exist.");
            parser.printHelpOn(System.err);
            return -1;
        }

        if (Files.notExists(targetFile)) {
            System.err.println("Target file does not exist.");
            parser.printHelpOn(System.err);
            return -1;
        }

        Config config;
        try (BufferedReader reader = Files.newBufferedReader(configFile)) {
            config = Config.GSON.fromJson(reader, Config.class);
        }

        for (Map.Entry<String, List<FieldAccessConfig>> entry : config.fieldAccesses.entrySet()) {
            String name = entry.getKey().replace(".", "/");
            for (FieldAccessConfig fConfig : entry.getValue()) {
                ObfMapping mapping = new ObfMapping(name, fConfig.name);
                scanners.add(new FieldAccessScanner(mapping, fConfig.exclusions, fConfig.opcodes));
            }
        }

        for (Map.Entry<String, List<MethodAccessConfig>> entry : config.methodAccesses.entrySet()) {
            String name = entry.getKey().replace(".", "/");
            for (MethodAccessConfig mConfig : entry.getValue()) {
                ObfMapping mapping = new ObfMapping(name, mConfig.name, mConfig.desc);
                scanners.add(new MethodAccessScanner(mapping, mConfig.exclusions, mConfig.opcodes));
            }
        }

        for (OpcodeUseConfig opcodeUse : config.opcodeUses) {
            scanners.add(new OpcodeUseScanner(opcodeUse.opcodes));
        }

        if (Files.isDirectory(targetFile)) {
            scan(targetFile);
        } else if (targetFile.getFileName().toString().endsWith(".jar")) {
            try (FileSystem fs = IOUtils.getJarFileSystem(targetFile, true)) {
                scan(fs.getPath("/"));
            }
        } else {
            System.err.println("Expected Folder or Jar file. Got: " + targetFile);
        }
        return 0;
    }

    private static void scan(Path root) throws IOException {
        Map<String, Map<ObfMapping, List<ScanResult>>> classScanResults = new ConcurrentHashMap<>();
        Files.walk(root)
                .parallel()
                .filter(Files::isRegularFile)
                .filter(e -> e.getFileName().toString().endsWith(".class"))
                .forEach(sneak(path -> {
                    try (InputStream is = Files.newInputStream(path)) {
                        ClassReader reader = new ClassReader(is);
                        ClassNode cNode = new ClassNode();
                        reader.accept(cNode, ClassReader.EXPAND_FRAMES);
                        Map<ObfMapping, List<ScanResult>> scanResults = new HashMap<>();
                        for (MethodNode mNode : cNode.methods) {
                            List<ScanResult> methodResults = new ArrayList<>();
                            for (AbstractInsnNode insn : new InsnListSection(mNode.instructions)) {
                                for (Scanner scanner : scanners) {
                                    ScanResult result = scanner.scan(insn, mNode, cNode);
                                    if (result != null) {
                                        methodResults.add(result);
                                    }
                                }
                            }
                            if (!methodResults.isEmpty()) {
                                ObfMapping method = new ObfMapping(cNode.name, mNode.name, mNode.desc);
                                scanResults.put(method, methodResults);
                            }
                        }
                        if (!scanResults.isEmpty()) {
                            Object existing = classScanResults.put(cNode.name, scanResults);
                            if (existing != null) {
                                throw new RuntimeException("Duplicate class detected: " + cNode.name);
                            }
                        }
                    }
                }));

        if (!classScanResults.isEmpty()) {
            logger.info("Errors detected:");
            for (Map.Entry<String, Map<ObfMapping, List<ScanResult>>> entry : classScanResults.entrySet()) {
                logger.info(entry.getKey());
                for (Map.Entry<ObfMapping, List<ScanResult>> methodEntry : entry.getValue().entrySet()) {
                    ObfMapping method = methodEntry.getKey();
                    logger.info(" {}{}", method.s_name, method.s_desc);
                    for (ScanResult scanResult : methodEntry.getValue()) {
                        String at = scanResult.lineOrIndex.map(
                                e -> "on line " + e.line,
                                e -> "at insn index:" + e
                        );
                        logger.info("  {}, {}", scanResult.problem, at);
                    }
                }
            }
            System.exit(2);
        } else {
            logger.info("All good.");
        }
    }
}
