package com.phishnet.api;

import com.phishnet.feeds.FeedStatus;
import com.phishnet.feeds.ThreatFeedService;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code GET /api/feeds/status}: the threat feed cache state {@code phishnet feeds status}
 * prints, as JSON. Built on the same {@link ThreatFeedService#status()} call, so it
 * reads the cache only and never starts a download.
 */
final class FeedsApi {

    private final ThreatFeedService service;

    FeedsApi(ThreatFeedService service) {
        this.service = service;
    }

    Map<String, Object> status() {
        Instant now = service.clock().instant();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cacheDirectory", service.cache().directory().toString());
        body.put("refreshIntervalSeconds", service.settings().refreshInterval().toSeconds());
        body.put("offline", service.isOffline());
        body.put("checkedAt", now.toString());

        List<Map<String, Object>> feeds = new ArrayList<>();
        for (FeedStatus status : service.status()) {
            Map<String, Object> feed = new LinkedHashMap<>();
            feed.put("source", status.source().id());
            feed.put("name", status.source().displayName());
            feed.put("state", status.state().name());
            feed.put("available", status.state().available());
            feed.put("refreshedAt", status.refreshedAt() == null ? null : status.refreshedAt().toString());
            feed.put("ageSeconds", status.refreshedAt() == null ? null
                    : Math.max(0, Duration.between(status.refreshedAt(), now).toSeconds()));
            feed.put("entries", status.entries());
            feed.put("lastError", status.lastError());
            feed.put("detail", status.detail() == null || status.detail().isEmpty() ? null : status.detail());
            feeds.add(feed);
        }
        body.put("feeds", feeds);
        return body;
    }
}
