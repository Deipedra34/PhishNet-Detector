package com.phishnet.feeds;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Downloads, caches, and serves threat intelligence feeds of known phishing
 * URLs, as an extra high-confidence signal next to the heuristic analyzers.
 *
 * <b>A scan never fails or stalls on a feed.</b> {@link #loadForScan()} uses
 * each feed's cached copy if it's fresh. If it's stale or missing, a refresh
 * starts, and the scan waits for it for at most {@link ThreatFeedSettings#scanWait()}
 * (all feeds in parallel). If the download isn't done by then or fails, the
 * scan carries on with the stale copy, or without that feed if there's none.
 * A slow download keeps running in the background and lands in the cache
 * whenever it completes; cache writes are atomic, so a process exiting
 * mid-download can't leave a broken file. {@link #refreshAll()} (behind
 * {@code phishnet feeds update}) is the synchronous, full-timeout version.
 *
 * PhishTank needs an API key: without one ({@link ThreatFeedSettings#phishTankApiKey()})
 * it's reported as not configured and skipped, and everything else carries on.
 *
 * The network sits behind {@link FeedFetcher} and time behind {@link Clock},
 * so tests drive this with canned feeds and a fixed clock.
 */
public final class ThreatFeedService {

    /** Where feeds are cached by default: {@code ~/.phishnet/feeds}. */
    public static Path defaultDirectory() {
        return FeedCache.defaultDirectory();
    }

    /** Background refreshes run on daemon threads, so an unfinished one never keeps the JVM alive. */
    private static final ExecutorService REFRESHER = Executors.newCachedThreadPool(task -> {
        Thread thread = new Thread(task, "phishnet-feed-refresh");
        thread.setDaemon(true);
        return thread;
    });

    private final ThreatFeedSettings settings;
    private final FeedCache cache;
    private final FeedFetcher fetcher;
    private final Clock clock;
    private final boolean offline;

    public ThreatFeedService(ThreatFeedSettings settings, FeedCache cache, FeedFetcher fetcher, Clock clock) {
        this(settings, cache, fetcher, clock, false);
    }

    private ThreatFeedService(ThreatFeedSettings settings, FeedCache cache, FeedFetcher fetcher, Clock clock,
                              boolean offline) {
        this.settings = settings;
        this.cache = cache;
        this.fetcher = fetcher;
        this.clock = clock;
        this.offline = offline;
    }

    /** The real thing: HTTP downloads into {@link #defaultDirectory()}. */
    public static ThreatFeedService live(ThreatFeedSettings settings) {
        return new ThreatFeedService(settings, new FeedCache(defaultDirectory()), new HttpFeedFetcher(),
                Clock.systemUTC());
    }

    /**
     * A service that never downloads or reads anything: every scan gets an
     * empty index. What {@code --no-threat-feeds} amounts to, and what tests use
     * when they shouldn't depend on the network or the user's home directory.
     */
    public static ThreatFeedService offline(ThreatFeedSettings settings) {
        return new ThreatFeedService(settings, new FeedCache(defaultDirectory()), (uri, headers, timeout) -> {
            throw new IOException("threat feeds are offline");
        }, Clock.systemUTC(), true);
    }

    public ThreatFeedSettings settings() {
        return settings;
    }

    public FeedCache cache() {
        return cache;
    }

    public boolean isOffline() {
        return offline;
    }

    /** Whether {@code source} is switched on in the config. */
    public boolean isEnabled(FeedSource source) {
        return switch (source) {
            case OPENPHISH -> settings.openPhishEnabled();
            case PHISHTANK -> settings.phishTankEnabled();
        };
    }

    /** Why {@code source} can't be downloaded yet even though it's enabled, if anything. */
    public Optional<String> missingConfiguration(FeedSource source) {
        if (source == FeedSource.PHISHTANK && settings.phishTankApiKey() == null) {
            return Optional.of("no API key configured (set " + ThreatFeedSettings.PHISHTANK_API_KEY_ENV
                    + " or threatFeeds.phishTank.apiKey)");
        }
        return Optional.empty();
    }

    // --- refreshing ---------------------------------------------------------

    /** Downloads every enabled, configured feed now, one after another, with the full download timeout. */
    public List<FeedRefreshResult> refreshAll() {
        List<FeedRefreshResult> results = new ArrayList<>();
        for (FeedSource source : FeedSource.values()) {
            results.add(refresh(source));
        }
        return results;
    }

    /** Downloads {@code source} now and caches it. Never throws: failures come back as {@link FeedRefreshResult.Outcome#FAILED}. */
    public FeedRefreshResult refresh(FeedSource source) {
        Optional<String> skipReason = skipReason(source);
        if (skipReason.isPresent()) {
            return FeedRefreshResult.skipped(source, skipReason.get());
        }
        Instant started = clock.instant();
        try (InputStream in = fetcher.open(downloadUri(source), headers(source), settings.downloadTimeout())) {
            FeedEntries entries = parse(source, in);
            if (entries.size() == 0) {
                // Treated as a failure, not as "the feed is now empty": an error page or
                // truncated response must not wipe out a good cached copy.
                throw new IOException("the download contained no feed entries");
            }
            cache.write(source, entries, started);
            return FeedRefreshResult.updated(source, entries.size());
        } catch (IOException | RuntimeException e) {
            String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            cache.recordFailure(source, message, started);
            return FeedRefreshResult.failed(source, message);
        }
    }

    private Optional<String> skipReason(FeedSource source) {
        if (offline) {
            return Optional.of("threat feeds are turned off for this run");
        }
        if (!isEnabled(source)) {
            return Optional.of("disabled in the config");
        }
        return missingConfiguration(source);
    }

    URI downloadUri(FeedSource source) {
        return switch (source) {
            case OPENPHISH -> settings.openPhishUrl();
            case PHISHTANK -> URI.create(settings.phishTankUrl().replace("{apiKey}",
                    URLEncoder.encode(settings.phishTankApiKey() == null ? "" : settings.phishTankApiKey(),
                            StandardCharsets.UTF_8)));
        };
    }

    Map<String, String> headers(FeedSource source) {
        // PhishTank asks every client to identify itself as "phishtank/<username>".
        if (source == FeedSource.PHISHTANK && settings.phishTankUsername() != null) {
            return Map.of("User-Agent", "phishtank/" + settings.phishTankUsername());
        }
        return Map.of("User-Agent", settings.userAgent());
    }

    private static FeedEntries parse(FeedSource source, InputStream in) throws IOException {
        return switch (source) {
            case OPENPHISH -> FeedParser.parseOpenPhish(new InputStreamReader(in, StandardCharsets.UTF_8));
            case PHISHTANK -> FeedParser.parsePhishTank(in);
        };
    }

    // --- scanning -----------------------------------------------------------

    /**
     * The feeds for one run, refreshing stale or missing ones within the scan
     * wait (see the class comment). Never throws, and never waits longer than
     * {@link ThreatFeedSettings#scanWait()}.
     */
    public ThreatFeedIndex loadForScan() {
        if (offline) {
            return ThreatFeedIndex.empty(status());
        }
        Instant now = clock.instant();
        Map<FeedSource, Optional<FeedSnapshot>> cached = new EnumMap<>(FeedSource.class);
        Map<FeedSource, CompletableFuture<FeedRefreshResult>> refreshing = new EnumMap<>(FeedSource.class);
        List<FeedStatus> statuses = new ArrayList<>();

        for (FeedSource source : FeedSource.values()) {
            if (skipReason(source).isPresent()) {
                continue;
            }
            Optional<FeedSnapshot> snapshot = cache.read(source);
            cached.put(source, snapshot);
            Instant refreshedAt = snapshot.map(FeedSnapshot::refreshedAt).orElse(null);
            if (FeedFreshness.of(refreshedAt, settings.refreshInterval(), now) != FeedFreshness.FRESH) {
                refreshing.put(source, CompletableFuture.supplyAsync(() -> refresh(source), REFRESHER));
            }
        }

        long deadline = System.nanoTime() + settings.scanWait().toNanos();
        Map<FeedSource, String> notes = new EnumMap<>(FeedSource.class);
        for (Map.Entry<FeedSource, CompletableFuture<FeedRefreshResult>> entry : refreshing.entrySet()) {
            FeedSource source = entry.getKey();
            try {
                long remaining = Math.max(0, deadline - System.nanoTime());
                FeedRefreshResult result = entry.getValue().get(remaining, TimeUnit.NANOSECONDS);
                if (result.outcome() == FeedRefreshResult.Outcome.UPDATED) {
                    cached.put(source, cache.read(source));
                } else {
                    notes.put(source, "refresh failed: " + result.message());
                }
            } catch (TimeoutException e) {
                notes.put(source, "refresh still downloading in the background");
            } catch (ExecutionException e) {
                notes.put(source, "refresh failed: " + e.getCause());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                notes.put(source, "refresh interrupted");
            }
        }

        List<FeedSnapshot> snapshots = new ArrayList<>();
        for (FeedSource source : FeedSource.values()) {
            Optional<String> skipReason = skipReason(source);
            if (skipReason.isPresent()) {
                statuses.add(skippedStatus(source, skipReason.get()));
                continue;
            }
            Optional<FeedSnapshot> snapshot = cached.getOrDefault(source, Optional.empty());
            snapshot.ifPresent(snapshots::add);
            Instant refreshedAt = snapshot.map(FeedSnapshot::refreshedAt).orElse(null);
            FeedStatus.State state = switch (FeedFreshness.of(refreshedAt, settings.refreshInterval(), clock.instant())) {
                case FRESH -> FeedStatus.State.FRESH;
                case STALE -> FeedStatus.State.STALE;
                case MISSING -> FeedStatus.State.MISSING;
            };
            statuses.add(new FeedStatus(source, state, refreshedAt, snapshot.map(s -> s.entries().size()).orElse(0),
                    cache.metadata(source).lastError(), notes.getOrDefault(source, "")));
        }
        return new ThreatFeedIndex(snapshots, statuses, settings.sharedHostingDomains());
    }

    // --- status -------------------------------------------------------------

    /** Every feed's current state, from the cache alone (no downloads). */
    public List<FeedStatus> status() {
        List<FeedStatus> statuses = new ArrayList<>();
        Instant now = clock.instant();
        for (FeedSource source : FeedSource.values()) {
            Optional<String> skipReason = skipReason(source);
            if (skipReason.isPresent()) {
                statuses.add(skippedStatus(source, skipReason.get()));
                continue;
            }
            FeedCache.Metadata metadata = cache.metadata(source);
            FeedStatus.State state = switch (FeedFreshness.of(metadata.refreshedAt(), settings.refreshInterval(), now)) {
                case FRESH -> FeedStatus.State.FRESH;
                case STALE -> FeedStatus.State.STALE;
                case MISSING -> FeedStatus.State.MISSING;
            };
            statuses.add(new FeedStatus(source, state, metadata.refreshedAt(), metadata.entries(),
                    metadata.lastError(), ""));
        }
        return statuses;
    }

    private FeedStatus skippedStatus(FeedSource source, String reason) {
        FeedStatus.State state;
        if (offline) {
            state = FeedStatus.State.OFF;
        } else if (!isEnabled(source)) {
            state = FeedStatus.State.DISABLED;
        } else {
            state = FeedStatus.State.NOT_CONFIGURED;
        }
        return new FeedStatus(source, state, null, 0, null, reason);
    }
}
