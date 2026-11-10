package com.phishnet.feeds;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

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
 */
public record ThreatFeedSettings(Duration refreshInterval, Duration scanWait, Duration downloadTimeout,
                                 boolean openPhishEnabled, URI openPhishUrl, String userAgent) {

    public static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofHours(1);
    public static final Duration DEFAULT_SCAN_WAIT = Duration.ofSeconds(3);
    public static final Duration DEFAULT_DOWNLOAD_TIMEOUT = Duration.ofSeconds(60);
    public static final URI DEFAULT_OPENPHISH_URL = URI.create("https://openphish.com/feed.txt");
    public static final String DEFAULT_USER_AGENT = "PhishNet-Detector (+https://github.com/Deipedra34/PhishNet-Detector)";

    public ThreatFeedSettings {
        Objects.requireNonNull(refreshInterval, "refreshInterval");
        Objects.requireNonNull(scanWait, "scanWait");
        Objects.requireNonNull(downloadTimeout, "downloadTimeout");
        Objects.requireNonNull(openPhishUrl, "openPhishUrl");
        Objects.requireNonNull(userAgent, "userAgent");
    }

    /** The built-in defaults: hourly refresh, a 3-second scan wait, OpenPhish on. */
    public static ThreatFeedSettings defaults() {
        return new ThreatFeedSettings(DEFAULT_REFRESH_INTERVAL, DEFAULT_SCAN_WAIT, DEFAULT_DOWNLOAD_TIMEOUT,
                true, DEFAULT_OPENPHISH_URL, DEFAULT_USER_AGENT);
    }
}
