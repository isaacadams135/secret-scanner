package com.github.isaacadams135.secretscanner;

/** One match in one file. The secret itself is never kept — only a masked form. */
public record Finding(String path, int line, String ruleId, Rule.Severity severity, String masked) {

    /**
     * Never print a full secret. Anything short enough to guess from prints as
     * "****"; longer secrets keep first and last 4 chars, e.g. "AKIA...MPLE".
     */
    public static String mask(String secret) {
        if (secret.length() <= 8) {
            return "****";
        }
        return secret.substring(0, 4) + "..." + secret.substring(secret.length() - 4);
    }

    @Override
    public String toString() {
        return path + ":" + line + " [" + severity + "] " + ruleId + " " + masked;
    }
}
