package com.github.isaacadams135.secretscanner;

import java.util.regex.Pattern;

/** One detection rule: a named regex plus how bad a hit is. */
public record Rule(String id, Pattern pattern, Severity severity) {

    public enum Severity {
        HIGH, MEDIUM
    }
}
