package com.phishnet.feeds;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * How threat feeds are downloaded and refreshed.
 *
 * @param refreshInterval     a cached feed older than this is refreshed before (or during) a scan
 * @param scanWait            how long a scan waits for a stale or missing feed to download before
 *                            carrying on with whatever is cached; the download itself keeps going
 *                            in the background
 * @param downloadTimeout     how long a download may take to start responding
 *                            ({@code phishnet feeds update}, and background refreshes)
 * @param openPhishEnabled    whether the OpenPhish feed is used at all
 * @param openPhishUrl        where the OpenPhish feed is downloaded from
 * @param userAgent           User-Agent sent with every download
 * @param sharedHostingDomains hosts that never produce a domain-level match (see {@link ThreatFeedIndex})
 * @param phishTankEnabled    whether the PhishTank feed is used (it still needs an API key)
 * @param phishTankApiKey     PhishTank application key, or {@code null}; without one PhishTank is skipped
 * @param phishTankUsername   PhishTank username, or {@code null}; sent as the {@code phishtank/<username>}
 *                            User-Agent PhishTank asks for
 * @param phishTankUrl        download URL, with {@code {apiKey}} where the key goes
 */
public record ThreatFeedSettings(Duration refreshInterval, Duration scanWait, Duration downloadTimeout,
                                 boolean openPhishEnabled, URI openPhishUrl, String userAgent,
                                 Set<String> sharedHostingDomains, boolean phishTankEnabled, String phishTankApiKey,
                                 String phishTankUsername, String phishTankUrl) {

    public static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofHours(1);
    public static final Duration DEFAULT_SCAN_WAIT = Duration.ofSeconds(3);
    public static final Duration DEFAULT_DOWNLOAD_TIMEOUT = Duration.ofSeconds(60);
    public static final URI DEFAULT_OPENPHISH_URL = URI.create("https://openphish.com/feed.txt");
    public static final String DEFAULT_USER_AGENT = "PhishNet-Detector (+https://github.com/Deipedra34/PhishNet-Detector)";
    public static final String DEFAULT_PHISHTANK_URL = "https://data.phishtank.com/data/{apiKey}/online-valid.json.gz";

    /** Environment variable holding the PhishTank API key; takes precedence over the config file. */
    public static final String PHISHTANK_API_KEY_ENV = "PHISHNET_PHISHTANK_API_KEY";

    /** Environment variable holding the PhishTank username; takes precedence over the config file. */
    public static final String PHISHTANK_USERNAME_ENV = "PHISHNET_PHISHTANK_USERNAME";

    public ThreatFeedSettings {
        Objects.requireNonNull(refreshInterval, "refreshInterval");
        Objects.requireNonNull(scanWait, "scanWait");
        Objects.requireNonNull(downloadTimeout, "downloadTimeout");
        Objects.requireNonNull(openPhishUrl, "openPhishUrl");
        Objects.requireNonNull(userAgent, "userAgent");
        Objects.requireNonNull(phishTankUrl, "phishTankUrl");
        sharedHostingDomains = Set.copyOf(sharedHostingDomains);
        phishTankApiKey = blankToNull(phishTankApiKey);
        phishTankUsername = blankToNull(phishTankUsername);
    }

    /** The built-in defaults: hourly refresh, a 3-second scan wait, OpenPhish on, PhishTank on but keyless. */
    public static ThreatFeedSettings defaults() {
        return new ThreatFeedSettings(DEFAULT_REFRESH_INTERVAL, DEFAULT_SCAN_WAIT, DEFAULT_DOWNLOAD_TIMEOUT,
                true, DEFAULT_OPENPHISH_URL, DEFAULT_USER_AGENT, Set.of(), true, null, null, DEFAULT_PHISHTANK_URL);
    }

    /**
     * These settings with the PhishTank API key and username taken from
     * {@link #PHISHTANK_API_KEY_ENV} / {@link #PHISHTANK_USERNAME_ENV} where those
     * are set, so a key never has to be written into a config file.
     */
    public ThreatFeedSettings withEnvironment(Map<String, String> environment) {
        String apiKey = blankToNull(environment.get(PHISHTANK_API_KEY_ENV));
        String username = blankToNull(environment.get(PHISHTANK_USERNAME_ENV));
        return new ThreatFeedSettings(refreshInterval, scanWait, downloadTimeout, openPhishEnabled, openPhishUrl,
                userAgent, sharedHostingDomains, phishTankEnabled, apiKey != null ? apiKey : phishTankApiKey,
                username != null ? username : phishTankUsername, phishTankUrl);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }
}
