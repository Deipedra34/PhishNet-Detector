package com.phishnet.util;

import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The {@code threatFeeds} section of the YAML config. */
class ThreatFeedConfigTest {

    private static PhishNetConfig yaml(String text) {
        return ConfigLoader.load(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void bundledConfigUsesTheDocumentedDefaults() {
        ThreatFeedSettings feeds = ConfigLoader.loadDefault().threatFeeds();

        assertEquals(Duration.ofHours(1), feeds.refreshInterval());
        assertEquals(Duration.ofSeconds(3), feeds.scanWait());
        assertEquals(Duration.ofSeconds(60), feeds.downloadTimeout());
        assertTrue(feeds.openPhishEnabled());
        assertEquals(URI.create("https://openphish.com/feed.txt"), feeds.openPhishUrl());
        assertTrue(feeds.phishTankEnabled());
        assertNull(feeds.phishTankApiKey());
        assertEquals(ThreatFeedSettings.DEFAULT_PHISHTANK_URL, feeds.phishTankUrl());
        assertTrue(feeds.sharedHostingDomains().contains("sites.google.com"));
        // URL shorteners are shared hosts automatically.
        assertTrue(feeds.sharedHostingDomains().contains("bit.ly"));
    }

    @Test
    void configWithoutAThreatFeedsSectionGetsTheDefaults() {
        ThreatFeedSettings feeds = yaml("brands: [paypal]\n").threatFeeds();
        ThreatFeedSettings defaults = ThreatFeedSettings.defaults();

        assertEquals(defaults.refreshInterval(), feeds.refreshInterval());
        assertEquals(defaults.scanWait(), feeds.scanWait());
        assertEquals(defaults.openPhishUrl(), feeds.openPhishUrl());
        assertTrue(feeds.openPhishEnabled());
        assertTrue(feeds.sharedHostingDomains().isEmpty());
    }

    @Test
    void everySettingCanBeConfigured() {
        ThreatFeedSettings feeds = yaml("""
                urlShorteners: [Short.Example]
                threatFeeds:
                  refreshIntervalMinutes: 15
                  scanWaitSeconds: 0
                  downloadTimeoutSeconds: 20
                  openPhish:
                    enabled: false
                    url: https://mirror.example/openphish.txt
                  phishTank:
                    enabled: true
                    apiKey: abc123
                    username: analyst
                    url: https://mirror.example/{apiKey}/phishtank.json
                  sharedHostingDomains:
                    - WWW.Pages.Example
                    - .ipfs.example
                    - "   "
                """).threatFeeds();

        assertEquals(Duration.ofMinutes(15), feeds.refreshInterval());
        assertEquals(Duration.ZERO, feeds.scanWait());
        assertEquals(Duration.ofSeconds(20), feeds.downloadTimeout());
        assertFalse(feeds.openPhishEnabled());
        assertEquals(URI.create("https://mirror.example/openphish.txt"), feeds.openPhishUrl());
        assertEquals("abc123", feeds.phishTankApiKey());
        assertEquals("analyst", feeds.phishTankUsername());
        assertEquals("https://mirror.example/{apiKey}/phishtank.json", feeds.phishTankUrl());
        assertEquals(java.util.Set.of("pages.example", ".ipfs.example", "short.example"),
                feeds.sharedHostingDomains());
    }

    @Test
    void environmentKeyBeatsTheConfigFileKey() {
        ThreatFeedSettings feeds = yaml("""
                threatFeeds:
                  phishTank:
                    apiKey: from-config
                """).threatFeeds();

        assertEquals("from-env", feeds.withEnvironment(
                Map.of(ThreatFeedSettings.PHISHTANK_API_KEY_ENV, "from-env")).phishTankApiKey());
        assertEquals("from-config", feeds.withEnvironment(Map.of()).phishTankApiKey());
    }

    @Test
    void negativeDurationsAreClamped() {
        ThreatFeedSettings feeds = yaml("""
                threatFeeds:
                  refreshIntervalMinutes: -5
                  scanWaitSeconds: -1
                  downloadTimeoutSeconds: 0
                """).threatFeeds();

        assertEquals(Duration.ZERO, feeds.refreshInterval());
        assertEquals(Duration.ZERO, feeds.scanWait());
        assertEquals(Duration.ofSeconds(1), feeds.downloadTimeout());
    }

    @Test
    void existingConfigConstructorKeepsDefaultFeedSettings() {
        PhishNetConfig config = new PhishNetConfig(List.of(), List.of(), List.of(), Map.of(), null);

        assertEquals(ThreatFeedSettings.defaults(), config.threatFeeds());
    }
}
