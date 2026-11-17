package com.github.isaacadams135.secretscanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Walks files and directories, applies the rule catalog line by line, and
 * returns every match with the secret masked. Skips dependency/build/vcs
 * directories, obvious binaries, oversized files, and absurdly long lines.
 */
public final class SecretScanner {

    private static final Set<String> SKIP_DIRS = Set.of(
            ".git", "node_modules", "target", "build", "dist", ".gradle", ".idea",
            "__pycache__", "venv"
    );

    private static final Set<String> BINARY_EXTENSIONS = Set.of(
            "png", "jpg", "jpeg", "gif", "webp", "pdf", "zip", "gz", "jar", "class",
            "exe", "dll", "so", "dylib", "o", "woff", "woff2", "ttf", "ico", "bmp", "mp4"
    );

    private static final long MAX_FILE_BYTES = 5L * 1024 * 1024;
    private static final int MAX_LINE_CHARS = 10000;
    private static final int SNIFF_BYTES = 1024;

    private final List<Rule> rules;

    public SecretScanner() {
        this(Rules.all());
    }

    public SecretScanner(List<Rule> rules) {
        this.rules = rules;
    }

    public List<Finding> scan(List<Path> paths) throws IOException {
        List<Finding> findings = new ArrayList<>();
        for (Path path : paths) {
            if (Files.isDirectory(path)) {
                scanTree(path, findings);
            } else {
                scanFile(path, findings);
            }
        }
        return findings;
    }

    private void scanTree(Path root, List<Finding> findings) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                Path name = dir.getFileName();
                if (name != null && SKIP_DIRS.contains(name.toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isRegularFile()) {
                    scanFile(file, findings);
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void scanFile(Path file, List<Finding> findings) {
        try {
            if (Files.size(file) > MAX_FILE_BYTES || hasBinaryExtension(file) || hasNulByte(file)) {
                return;
            }
        } catch (IOException e) {
            System.err.println("warning: skipping " + file + " (" + e.getMessage() + ")");
            return;
        }

        // latin1 never fails on weird bytes, unlike utf-8
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.ISO_8859_1)) {
            String line;
            int lineNo = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                if (line.length() > MAX_LINE_CHARS) {
                    continue;
                }
                for (Rule rule : rules) {
                    Matcher match = rule.pattern().matcher(line);
                    if (match.find()) {
                        findings.add(new Finding(file.toString(), lineNo, rule.id(),
                                rule.severity(), Finding.mask(match.group())));
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("warning: cannot read " + file + " (" + e.getMessage() + ")");
        }
    }

    private static boolean hasBinaryExtension(Path file) {
        Path name = file.getFileName();
        if (name == null) {
            return false;
        }
        String fileName = name.toString();
        int dot = fileName.lastIndexOf('.');
        if (dot < 0) {
            return false;
        }
        return BINARY_EXTENSIONS.contains(fileName.substring(dot + 1).toLowerCase());
    }

    private static boolean hasNulByte(Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            byte[] head = in.readNBytes(SNIFF_BYTES);
            for (byte b : head) {
                if (b == 0) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return true; // unreadable counts as unscannable
        }
    }
}
