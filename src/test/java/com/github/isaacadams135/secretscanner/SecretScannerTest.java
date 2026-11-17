package com.github.isaacadams135.secretscanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecretScannerTest {

    @TempDir
    Path dir;

    @Test
    void findsAwsAccessKeyWithCorrectRuleAndLine() throws IOException {
        Path file = dir.resolve("settings.gradle");
        Files.writeString(file, """
            // fake demo file
            // fake demo file
            accessKey = "AKIAIOSFODNN7EXAMPLE"
            """);

        List<Finding> findings = new SecretScanner().scan(List.of(file));

        assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        assertEquals("aws-access-key", finding.ruleId());
        assertEquals(Rule.Severity.HIGH, finding.severity());
        assertEquals(3, finding.line());
        assertEquals("AKIA...MPLE", finding.masked());
    }

    @Test
    void findsGithubToken() throws IOException {
        Path file = dir.resolve("ci.yml");
        Files.writeString(file, "Authorization: Bearer ghp_1234567890abcdefghij1234567890abcdef\n");

        List<Finding> findings = new SecretScanner().scan(List.of(file));

        assertEquals(1, findings.size());
        assertEquals("github-token", findings.get(0).ruleId());
        assertEquals("ghp_...cdef", findings.get(0).masked());
    }

    @Test
    void findsPrivateKeyBlock() throws IOException {
        Path file = dir.resolve("server.pem");
        Files.writeString(file, """
            some notes
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA0fakefakefake
            -----END RSA PRIVATE KEY-----
            """);

        List<Finding> findings = new SecretScanner().scan(List.of(file));

        assertEquals(1, findings.size());
        assertEquals("private-key", findings.get(0).ruleId());
        assertEquals(2, findings.get(0).line());
        assertEquals(Rule.Severity.HIGH, findings.get(0).severity());
    }

    @Test
    void genericSecretCatchesPasswordAssignment() throws IOException {
        Path file = dir.resolve("config.json");
        Files.writeString(file, "\"myPassword\": \"hunter2hunter2\"\n");

        List<Finding> findings = new SecretScanner().scan(List.of(file));

        assertEquals(1, findings.size());
        assertEquals("generic-secret", findings.get(0).ruleId());
        assertEquals(Rule.Severity.MEDIUM, findings.get(0).severity());
    }

    @Test
    void masksLongAndShortMatches() {
        assertEquals("****", Finding.mask("short"));
        assertEquals("****", Finding.mask("12345678"));
        assertEquals("1234...6789", Finding.mask("123456789"));
        assertEquals("AKIA...MPLE", Finding.mask("AKIAIOSFODNN7EXAMPLE"));
    }

    @Test
    void cleanFileHasNoFindings() throws IOException {
        Path file = dir.resolve("Main.java");
        Files.writeString(file, """
            public class Main {
                public static void main(String[] args) {
                    System.out.println("hello");
                }
            }
            """);

        assertTrue(new SecretScanner().scan(List.of(file)).isEmpty());
    }

    @Test
    void skipsGitDirectory() throws IOException {
        Path gitDir = Files.createDirectories(dir.resolve(".git"));
        Files.writeString(gitDir.resolve("config"), "url = AKIAIOSFODNN7EXAMPLE\n");
        Path clean = dir.resolve("README.md");
        Files.writeString(clean, "just a readme\n");

        assertTrue(new SecretScanner().scan(List.of(dir)).isEmpty());
    }

    @Test
    void skipsBinaryFileWithNulByte() throws IOException {
        byte[] fakeImage = new byte[] {
            'A', 'K', 'I', 'A', 'I', 'O', 'S', 'F', 'O', 'D', 'N', 'N', '7', 'E', 'X', 'A', 'M', 'P', 'L', 'E',
            0, 1, 2, 3
        };
        Path file = dir.resolve("logo.dat");
        Files.write(file, fakeImage);

        assertTrue(new SecretScanner().scan(List.of(file)).isEmpty());
    }
}
