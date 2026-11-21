package com.phishnet.model;

/**
 * Settings for the REST API ({@code phishnet serve}), from the config's {@code api} section.
 *
 * @param rateLimitPerMinute scan requests each client may make per minute; 0 turns rate limiting off
 */
public record ApiSettings(int rateLimitPerMinute) {

    public static final int DEFAULT_RATE_LIMIT_PER_MINUTE = 60;

    public ApiSettings {
        if (rateLimitPerMinute < 0) {
            throw new IllegalArgumentException("api.rateLimitPerMinute must be 0 or more, got " + rateLimitPerMinute);
        }
    }

    public static ApiSettings defaults() {
        return new ApiSettings(DEFAULT_RATE_LIMIT_PER_MINUTE);
    }
}
