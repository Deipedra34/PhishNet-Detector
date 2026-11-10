package com.phishnet.feeds;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A {@link FeedFetcher} serving canned responses by host, so feed tests never
 * touch the network. Hosts without a canned response fail like an unreachable
 * server. Every request is recorded for assertions.
 */
public final class FakeFeedFetcher implements FeedFetcher {

    /** One request the service made. */
    public record Call(URI uri, Map<String, String> headers, Duration timeout) {
    }

    @FunctionalInterface
    private interface Response {
        InputStream open() throws IOException;
    }

    private final Map<String, Response> responses = new ConcurrentHashMap<>();
    private final List<Call> calls = new CopyOnWriteArrayList<>();

    /** {@code host} answers with {@code body}. */
    public FakeFeedFetcher respond(String host, String body) {
        return respond(host, body.getBytes(StandardCharsets.UTF_8));
    }

    public FakeFeedFetcher respond(String host, byte[] body) {
        responses.put(host, () -> new ByteArrayInputStream(body));
        return this;
    }

    /** {@code host} fails with {@code message}, like a timeout or an HTTP error. */
    public FakeFeedFetcher fail(String host, String message) {
        responses.put(host, () -> {
            throw new IOException(message);
        });
        return this;
    }

    /** {@code host} answers with {@code body}, but only once {@code release} is counted down. */
    public FakeFeedFetcher blockUntil(String host, CountDownLatch release, String body) {
        responses.put(host, () -> {
            try {
                if (!release.await(30, TimeUnit.SECONDS)) {
                    throw new IOException("test download never released");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
            return new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        });
        return this;
    }

    @Override
    public InputStream open(URI uri, Map<String, String> headers, Duration timeout) throws IOException {
        calls.add(new Call(uri, headers, timeout));
        Response response = responses.get(uri.getHost());
        if (response == null) {
            throw new IOException("no route to " + uri.getHost() + " (test fetcher)");
        }
        return response.open();
    }

    public List<Call> calls() {
        return List.copyOf(calls);
    }

    /** Requests made to {@code host}. */
    public long callsTo(String host) {
        return calls.stream().filter(call -> host.equals(call.uri().getHost())).count();
    }
}
