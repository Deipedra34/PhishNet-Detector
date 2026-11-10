package com.phishnet.feeds;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * {@link FeedFetcher} over {@link HttpClient}. Follows redirects, and
 * transparently un-gzips responses that are gzip-encoded or whose URL ends in
 * {@code .gz}.
 */
public final class HttpFeedFetcher implements FeedFetcher {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient client;

    public HttpFeedFetcher() {
        this.client = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    @Override
    public InputStream open(URI uri, Map<String, String> headers, Duration timeout) throws IOException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(timeout).GET();
        headers.forEach(request::header);
        HttpResponse<InputStream> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("download interrupted", e);
        }
        InputStream body = response.body();
        if (response.statusCode() != 200) {
            body.close();
            throw new IOException("HTTP " + response.statusCode() + " from " + uri.getHost());
        }
        boolean gzipped = response.headers().firstValue("Content-Encoding")
                .map(value -> value.toLowerCase(Locale.ROOT).contains("gzip"))
                .orElse(false)
                || uri.getPath() != null && uri.getPath().endsWith(".gz");
        return gzipped ? new GZIPInputStream(body) : body;
    }
}
