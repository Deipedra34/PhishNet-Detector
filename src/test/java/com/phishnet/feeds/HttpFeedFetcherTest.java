package com.phishnet.feeds;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The real HTTP fetcher against an in-process server on the loopback interface: no outside network. */
class HttpFeedFetcherTest {

    private HttpServer server;
    private final AtomicReference<String> userAgent = new AtomicReference<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/feed.txt", exchange -> {
            userAgent.set(exchange.getRequestHeaders().getFirst("User-Agent"));
            byte[] body = "https://evil.example/login\n".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/online-valid.json.gz", exchange -> {
            byte[] body = gzip("[{\"url\": \"https://tank.example/x\"}]");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/missing", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    @Test
    void downloadsThePlainBodyAndSendsTheHeaders() throws IOException {
        try (InputStream in = new HttpFeedFetcher().open(uri("/feed.txt"),
                Map.of("User-Agent", "PhishNet-Test"), Duration.ofSeconds(5))) {
            assertEquals("https://evil.example/login\n", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        assertEquals("PhishNet-Test", userAgent.get());
    }

    @Test
    void gzippedDownloadIsDecompressed() throws IOException {
        try (InputStream in = new HttpFeedFetcher().open(uri("/online-valid.json.gz"), Map.of(),
                Duration.ofSeconds(5))) {
            FeedEntries entries = FeedParser.parsePhishTank(in);
            assertTrue(entries.containsUrl("tank.example/x"));
        }
    }

    @Test
    void nonOkStatusIsAnError() {
        IOException error = assertThrows(IOException.class,
                () -> new HttpFeedFetcher().open(uri("/missing"), Map.of(), Duration.ofSeconds(5)));
        assertTrue(error.getMessage().contains("404"), error.getMessage());
    }

    private static byte[] gzip(String text) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(bytes)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return bytes.toByteArray();
    }
}
