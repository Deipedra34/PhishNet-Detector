package com.phishnet.queue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.UUID;

/**
 * One job on the queue: a URL to scan. Stored as a small JSON object,
 * {@code {"id":"...","target":"https://...","enqueuedAt":"2026-11-04T09:00:00Z"}}.
 * A job pushed by hand as a bare URL (e.g. {@code redis-cli LPUSH phishnet:jobs https://example.com})
 * is accepted too.
 */
public record ScanJob(String id, String target, Instant enqueuedAt) {

    /** Same limit as the REST API's {@code /api/scan/url}. */
    public static final int MAX_TARGET_LENGTH = 8192;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A job that doesn't describe anything scannable. */
    public static final class InvalidJobException extends Exception {
        public InvalidJobException(String message) {
            super(message);
        }
    }

    public static ScanJob create(String target, Instant now) {
        return new ScanJob(UUID.randomUUID().toString(), target, now);
    }

    public String toJson() {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("id", id);
        node.put("target", target);
        node.put("enqueuedAt", enqueuedAt.toString());
        return node.toString();
    }

    /**
     * Reads a job: a JSON object with a {@code target} string, or a bare URL.
     *
     * @throws InvalidJobException if there's nothing usable to scan
     */
    public static ScanJob parse(String payload) throws InvalidJobException {
        String text = payload == null ? "" : payload.strip();
        if (text.isEmpty()) {
            throw new InvalidJobException("empty job");
        }
        if (!text.startsWith("{")) {
            return new ScanJob("", checkTarget(text), null);
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(text);
        } catch (JsonProcessingException e) {
            throw new InvalidJobException("not valid JSON");
        }
        JsonNode target = node.get("target");
        if (target == null || !target.isTextual()) {
            throw new InvalidJobException("no \"target\" string");
        }
        JsonNode id = node.get("id");
        Instant enqueuedAt = null;
        JsonNode at = node.get("enqueuedAt");
        if (at != null && at.isTextual()) {
            try {
                enqueuedAt = Instant.parse(at.asText());
            } catch (RuntimeException ignored) {
                // optional metadata; a bad value doesn't make the job unusable
            }
        }
        return new ScanJob(id != null && id.isTextual() ? id.asText() : "", checkTarget(target.asText().strip()),
                enqueuedAt);
    }

    private static String checkTarget(String target) throws InvalidJobException {
        if (target.isEmpty()) {
            throw new InvalidJobException("empty target");
        }
        if (target.length() > MAX_TARGET_LENGTH) {
            throw new InvalidJobException("target longer than " + MAX_TARGET_LENGTH + " characters");
        }
        return target;
    }
}
