package com.phishnet.util;

import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigLoaderTest {

    @Test
    void loadsBundledDefaultConfig() {
        PhishNetConfig config = ConfigLoader.loadDefault();
        assertTrue(config.brands().contains("paypal"));
        assertTrue(config.suspiciousTlds().contains("tk"));
        assertTrue(config.urlShorteners().contains("bit.ly"));
        assertTrue(config.urgencyKeywords().containsKey("en"));
        assertTrue(config.urgencyKeywords().containsKey("tr"));
        assertTrue(config.scoring().weightOf("homograph") > 0);
    }

    @Test
    void parsesCustomYamlFromStream() {
        String yaml = "brands:\n"
                + "  - testbrand\n"
                + "suspiciousTlds:\n"
                + "  - zz\n"
                + "urlShorteners:\n"
                + "  - short.example\n"
                + "urgencyKeywords:\n"
                + "  en:\n"
                + "    - \"act now\"\n"
                + "scoring:\n"
                + "  weights:\n"
                + "    typosquatting: 42\n"
                + "  mediumThreshold: 20\n"
                + "  highThreshold: 50\n"
                + "  typosquattingMaxDistance: 3\n"
                + "  longUrlThreshold: 100\n"
                + "  maxQueryParams: 5\n";

        try (InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))) {
            PhishNetConfig config = ConfigLoader.load(in);

            assertEquals(List.of("testbrand"), config.brands());
            assertEquals(List.of("zz"), config.suspiciousTlds());
            assertEquals(List.of("short.example"), config.urlShorteners());
            assertEquals(Map.of("en", List.of("act now")), config.urgencyKeywords());
            assertEquals(42, config.scoring().weightOf("typosquatting"));
            assertEquals(20, config.scoring().mediumThreshold());
            assertEquals(50, config.scoring().highThreshold());
            assertEquals(3, config.scoring().typosquattingMaxDistance());
            assertEquals(100, config.scoring().longUrlThreshold());
            assertEquals(5, config.scoring().maxQueryParams());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void missingWeightFallsBackToDefaultOfTen() {
        PhishNetConfig config = ConfigLoader.loadDefault();
        assertEquals(10, config.scoring().weightOf("someSignalNotInConfig"));
    }

    @Test
    void nonMappingRootThrows() {
        String yaml = "- just\n- a\n- list\n";
        InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(in));
    }
}
