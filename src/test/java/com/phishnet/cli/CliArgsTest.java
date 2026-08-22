package com.phishnet.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliArgsTest {

    @Test
    void parsesUrlMode() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com"});
        assertEquals("https://example.com", args.url());
        assertFalse(args.json());
    }

    @Test
    void parsesEmailModeWithJsonFlag() {
        CliArgs args = CliArgs.parse(new String[]{"--email", "message.eml", "--json"});
        assertEquals("message.eml", args.emailPath());
        assertTrue(args.json());
    }

    @Test
    void parsesBatchModeWithConfig() {
        CliArgs args = CliArgs.parse(new String[]{"--batch", "urls.txt", "--config", "custom.yaml"});
        assertEquals("urls.txt", args.batchPath());
        assertEquals("custom.yaml", args.configPath());
    }

    @Test
    void helpFlagBypassesModeRequirement() {
        CliArgs args = CliArgs.parse(new String[]{"--help"});
        assertTrue(args.help());
    }

    @Test
    void shortHelpFlagAlsoWorks() {
        CliArgs args = CliArgs.parse(new String[]{"-h"});
        assertTrue(args.help());
    }

    @Test
    void noModeFlagThrows() {
        assertThrows(IllegalArgumentException.class, () -> CliArgs.parse(new String[]{"--json"}));
    }

    @Test
    void multipleModeFlagsThrow() {
        assertThrows(IllegalArgumentException.class,
                () -> CliArgs.parse(new String[]{"--url", "https://example.com", "--email", "x.eml"}));
    }

    @Test
    void unknownFlagThrows() {
        assertThrows(IllegalArgumentException.class, () -> CliArgs.parse(new String[]{"--bogus"}));
    }

    @Test
    void flagMissingValueThrows() {
        assertThrows(IllegalArgumentException.class, () -> CliArgs.parse(new String[]{"--url"}));
    }

    @Test
    void emptyArgsThrows() {
        assertThrows(IllegalArgumentException.class, () -> CliArgs.parse(new String[]{}));
    }
}
