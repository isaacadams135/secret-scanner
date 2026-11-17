package com.github.isaacadams135.secretscanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class Main {

    private static final String USAGE = """
        usage: secret-scanner [options] <path...>

        Scans files and directories for hardcoded credentials.
        Exit codes: 0 = clean, 1 = findings (CI-friendly), 2 = usage error.

        options:
          -h, --help    show this help
        """;

    private Main() {
    }

    public static void main(String[] args) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println(USAGE);
            System.exit(2);
            return;
        }

        if (opts.help()) {
            System.out.println(USAGE);
            return;
        }

        List<Finding> findings;
        try {
            findings = new SecretScanner().scan(opts.paths());
        } catch (IOException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
            return;
        }

        for (Finding finding : findings) {
            System.out.println(finding);
        }

        if (findings.isEmpty()) {
            System.out.println("no secrets found");
            System.exit(0);
            return;
        }

        Set<Path> files = new LinkedHashSet<>();
        int high = 0;
        int medium = 0;
        for (Finding finding : findings) {
            files.add(Path.of(finding.path()));
            if (finding.severity() == Rule.Severity.HIGH) {
                high++;
            } else {
                medium++;
            }
        }
        System.out.printf("%n%d findings in %d files (%d high, %d medium)%n",
                findings.size(), files.size(), high, medium);
        System.exit(1);
    }

    record Options(List<Path> paths, boolean help) {

        static Options parse(String[] args) {
            List<Path> paths = new ArrayList<>();
            boolean help = false;

            for (String arg : args) {
                switch (arg) {
                    case "-h", "--help" -> help = true;
                    default -> {
                        if (arg.startsWith("-")) {
                            throw new IllegalArgumentException("unknown option: " + arg);
                        }
                        Path path = Path.of(arg);
                        if (!Files.exists(path)) {
                            throw new IllegalArgumentException("no such path: " + arg);
                        }
                        paths.add(path);
                    }
                }
            }

            if (help) {
                return new Options(List.of(), true);
            }
            if (paths.isEmpty()) {
                throw new IllegalArgumentException("missing path");
            }
            return new Options(paths, false);
        }
    }
}
