package com.github.isaacadams135.secretscanner;

import java.util.List;
import java.util.regex.Pattern;

/** The built-in rule catalog. Kept small on purpose — expand as needed. */
public final class Rules {

    private static final List<Rule> ALL = List.of(
        new Rule("aws-access-key",
                Pattern.compile("AKIA[0-9A-Z]{16}"),
                Rule.Severity.HIGH),
        new Rule("github-token",
                Pattern.compile("ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}"),
                Rule.Severity.HIGH),
        new Rule("slack-token",
                Pattern.compile("xox[baprs]-[A-Za-z-]{10,}"),
                Rule.Severity.HIGH),
        new Rule("private-key",
                Pattern.compile("-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
                Rule.Severity.HIGH),
        new Rule("jwt",
                Pattern.compile("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\."),
                Rule.Severity.MEDIUM),
        new Rule("stripe-key",
                Pattern.compile("sk_live_[0-9a-zA-Z]{24,}"),
                Rule.Severity.HIGH),
        new Rule("google-api-key",
                Pattern.compile("AIza[0-9A-Za-z_-]{35}"),
                Rule.Severity.HIGH),
        new Rule("url-credentials",
                Pattern.compile("(ftp|https?)://[^\\s:/@]+:[^\\s:/@]+@"),
                Rule.Severity.HIGH),
        // quotes around the value are optional so both JSON ("token": "abc...") and
        // .properties (token = abc...) assignments match; value stops at whitespace
        new Rule("generic-secret",
                Pattern.compile("(?i)(password|passwd|secret|api[_-]?key|token|auth[_-]?key)"
                        + "[\"']?\\s*[:=]\\s*[\"']?[^\"'\\s]{8,}[\"']?"),
                Rule.Severity.MEDIUM)
    );

    private Rules() {
    }

    public static List<Rule> all() {
        return ALL;
    }
}
