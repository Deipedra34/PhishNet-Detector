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

    @Test
    void parsesVerboseFlag() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com", "--verbose"});
        assertTrue(args.verbose());
        assertFalse(args.quiet());
        assertEquals(OutputLevel.VERBOSE, args.outputLevel());
    }

    @Test
    void shortVerboseFlagAlsoWorks() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com", "-v"});
        assertTrue(args.verbose());
    }

    @Test
    void parsesQuietFlag() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com", "--quiet"});
        assertTrue(args.quiet());
        assertFalse(args.verbose());
        assertEquals(OutputLevel.QUIET, args.outputLevel());
    }

    @Test
    void shortQuietFlagAlsoWorks() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com", "-q"});
        assertTrue(args.quiet());
    }

    @Test
    void neitherVerboseNorQuietMeansNormalLevel() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com"});
        assertFalse(args.verbose());
        assertFalse(args.quiet());
        assertEquals(OutputLevel.NORMAL, args.outputLevel());
    }

    @Test
    void verboseAndQuietTogetherThrows() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CliArgs.parse(new String[]{"--url", "https://example.com", "--verbose", "--quiet"}));
        assertTrue(e.getMessage().contains("--verbose") && e.getMessage().contains("--quiet"));
    }

    @Test
    void shortVerboseAndQuietTogetherThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> CliArgs.parse(new String[]{"--url", "https://example.com", "-v", "-q"}));
    }

    @Test
    void parsesNoColorFlag() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com", "--no-color"});
        assertTrue(args.noColor());
    }

    @Test
    void noColorDefaultsToFalse() {
        CliArgs args = CliArgs.parse(new String[]{"--url", "https://example.com"});
        assertFalse(args.noColor());
    }
}
