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

    @Test
    void emptyDocumentThrowsClearError() {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(in));
        assertTrue(e.getMessage().toLowerCase(java.util.Locale.ROOT).contains("mapping"));
    }

    @Test
    void whitespaceOnlyDocumentThrowsClearError() {
        InputStream in = new ByteArrayInputStream("   \n   \n".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(in));
    }

    @Test
    void completelyEmptyMappingFallsBackToDefaultsEverywhere() {
        InputStream in = new ByteArrayInputStream("{}\n".getBytes(StandardCharsets.UTF_8));
        PhishNetConfig config = ConfigLoader.load(in);

        assertTrue(config.brands().isEmpty());
        assertTrue(config.suspiciousTlds().isEmpty());
        assertTrue(config.urlShorteners().isEmpty());
        assertTrue(config.urgencyKeywords().isEmpty());
        assertEquals(30, config.scoring().mediumThreshold());
        assertEquals(60, config.scoring().highThreshold());
        assertEquals(2, config.scoring().typosquattingMaxDistance());
        assertEquals(75, config.scoring().longUrlThreshold());
        assertEquals(8, config.scoring().maxQueryParams());
        assertEquals(5, config.scoring().encodedCharThreshold());
        assertEquals(10, config.scoring().weightOf("anySignal"));
    }

    @Test
    void missingBrandListDefaultsToEmptyNotNull() {
        String yaml = "suspiciousTlds:\n  - tk\n";
        InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        PhishNetConfig config = ConfigLoader.load(in);

        assertTrue(config.brands().isEmpty());
        assertEquals(List.of("tk"), config.suspiciousTlds());
    }

    @Test
    void missingTldListDefaultsToEmptyNotNull() {
        String yaml = "brands:\n  - acme\n";
        InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        PhishNetConfig config = ConfigLoader.load(in);

        assertEquals(List.of("acme"), config.brands());
        assertTrue(config.suspiciousTlds().isEmpty());
        assertTrue(config.urlShorteners().isEmpty());
    }

    @Test
    void missingScoringSectionUsesDefaultThresholdsAndWeights() {
        String yaml = "brands:\n  - acme\n";
        InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        PhishNetConfig config = ConfigLoader.load(in);

        assertEquals(30, config.scoring().mediumThreshold());
        assertEquals(60, config.scoring().highThreshold());
        assertEquals(10, config.scoring().weightOf("homograph"));
    }

    @Test
    void missingWeightsMapUnderScoringUsesDefaultWeightForEveryId() {
        String yaml = "scoring:\n  mediumThreshold: 20\n  highThreshold: 50\n";
        InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        PhishNetConfig config = ConfigLoader.load(in);

        assertEquals(20, config.scoring().mediumThreshold());
        assertEquals(50, config.scoring().highThreshold());
        assertEquals(10, config.scoring().weightOf("typosquatting"));
        assertTrue(config.scoring().weights().isEmpty());
    }

    @Test
    void missingUrgencyKeywordsSectionDefaultsToEmptyMap() {
        String yaml = "brands:\n  - acme\n";
        InputStream in = new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8));
        PhishNetConfig config = ConfigLoader.load(in);

        assertTrue(config.urgencyKeywords().isEmpty());
    }
}
