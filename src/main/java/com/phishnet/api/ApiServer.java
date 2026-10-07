package com.phishnet.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.config.JavalinConfig;
import io.javalin.config.SizeUnit;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.ContentType;
import io.javalin.http.Context;
import io.javalin.http.HttpResponseException;
import io.javalin.http.HttpStatus;
import io.javalin.http.UploadedFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The optional REST API ({@code phishnet serve}): a thin HTTP layer over
 * {@link ScanService}, built on an embedded Javalin/Jetty server.
 *
 * <ul>
 *   <li>{@code GET  /api/health}     - {@code {"status":"ok"}}</li>
 *   <li>{@code POST /api/scan/url}   - JSON {@code {"url":"..."}}</li>
 *   <li>{@code POST /api/scan/email} - multipart upload (form field {@value #EMAIL_UPLOAD_FIELD}),
 *       or JSON {@code {"raw":"<full .eml text>"}}</li>
 * </ul>
 *
 * Every error - bad input, unknown route, oversized body, or an unexpected
 * failure - is answered with a JSON {@code {"error":"..."}} body; stack traces
 * go to the server's log stream only, never to the client.
 */
public final class ApiServer {

    public static final int DEFAULT_PORT = 8080;

    /** Largest request body accepted on any endpoint (JSON or multipart), in MB. */
    static final int MAX_REQUEST_MB = 5;
    static final long MAX_REQUEST_BYTES = MAX_REQUEST_MB * 1024L * 1024L;
    private static final String TOO_LARGE_MESSAGE = "Request body too large (max " + MAX_REQUEST_MB + " MB)";

    /** Longest URL accepted by /api/scan/url - far beyond any real link, but rules out abuse. */
    static final int MAX_URL_LENGTH = 8192;

    /** Multipart form field the .eml file must be uploaded under. */
    static final String EMAIL_UPLOAD_FIELD = "file";

    private final ScanService scanner;
    private final PrintStream log;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Javalin app;

    /**
     * @param log where unexpected (500) errors are reported, with their stack trace
     */
    public ApiServer(ScanService scanner, PrintStream log) {
        this.scanner = scanner;
        this.log = log;
        this.app = Javalin.create(this::configure);
    }

    /** Starts listening; port 0 picks a free port (see {@link #port()}). Returns once the server is up. */
    public ApiServer start(int port) {
        app.start(port);
        return this;
    }

    public void stop() {
        app.stop();
    }

    /** The port actually being listened on. */
    public int port() {
        return app.port();
    }

    private void configure(JavalinConfig config) {
        config.startup.showJavalinBanner = false;
        config.startup.showOldJavalinVersionWarning = false;
        // e.g. GET /api/scan/url answers 405 Method Not Allowed rather than 404.
        config.http.prefer405over404 = true;

        // Applies to ctx.body()/bodyAsBytes(), which stop reading and fail with 413
        // as soon as a body crosses the limit, even with no Content-Length header.
        config.http.maxRequestSize = MAX_REQUEST_BYTES;
        // Multipart uploads bypass maxRequestSize, so cap them separately. Keeping the
        // whole (capped) upload in memory means nothing is ever spooled to disk.
        config.jetty.multipartConfig.maxFileSize(MAX_REQUEST_MB, SizeUnit.MB);
        config.jetty.multipartConfig.maxTotalRequestSize(MAX_REQUEST_MB, SizeUnit.MB);
        config.jetty.multipartConfig.maxInMemoryFileSize(MAX_REQUEST_MB, SizeUnit.MB);

        // Reject a declared-oversized body up front, before reading any of it.
        config.routes.before("/api/*", ctx -> {
            if (ctx.req().getContentLengthLong() > MAX_REQUEST_BYTES) {
                throw tooLarge();
            }
        });

        config.routes.get("/api/health", ctx -> respond(ctx, HttpStatus.OK, Map.of("status", "ok")));
        config.routes.post("/api/scan/url", this::scanUrl);
        config.routes.post("/api/scan/email", this::scanEmail);

        // Overrides Javalin's built-in handler, so its own 404/405/413 responses use our JSON error shape too.
        config.routes.exception(HttpResponseException.class, (e, ctx) -> {
            HttpStatus status = HttpStatus.forStatus(e.getStatus());
            // Javalin's own body-limit 413 just says "Content Too Large"; say what the limit is.
            String message = status == HttpStatus.CONTENT_TOO_LARGE ? TOO_LARGE_MESSAGE : e.getMessage();
            respondError(ctx, status, message);
        });
        config.routes.exception(Exception.class, (e, ctx) -> {
            log.println("Error: unexpected failure handling " + ctx.method() + " " + ctx.path());
            e.printStackTrace(log);
            respondError(ctx, HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
        });
    }

    // --- endpoints -------------------------------------------------------------

    private void scanUrl(Context ctx) {
        JsonNode body = readJsonObject(ctx);
        String url = requiredText(body, "url");
        if (url.length() > MAX_URL_LENGTH) {
            throw new BadRequestResponse("Field 'url' is too long (max " + MAX_URL_LENGTH + " characters)");
        }
        respond(ctx, HttpStatus.OK, scanner.scanUrl(url));
    }

    private void scanEmail(Context ctx) throws IOException {
        if (ctx.isMultipartFormData()) {
            UploadedFile file = uploadedEmail(ctx);
            String label = file.filename() == null || file.filename().isBlank() ? "upload.eml" : file.filename();
            try (InputStream in = file.content()) {
                respond(ctx, HttpStatus.OK, scanner.scanEmail(label, in));
            }
            return;
        }
        String raw = requiredText(readJsonObject(ctx), "raw");
        respond(ctx, HttpStatus.OK,
                scanner.scanEmail("raw email", new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8))));
    }

    // --- input parsing / validation --------------------------------------------

    private UploadedFile uploadedEmail(Context ctx) {
        UploadedFile file;
        try {
            file = ctx.uploadedFile(EMAIL_UPLOAD_FIELD);
        } catch (Exception e) {
            // Jetty rejects a multipart body that is malformed or exceeds the configured
            // limits by throwing (a checked ServletException, despite no throws clause
            // on the Kotlin side) while parsing it; neither is a server-side fault.
            throw new BadRequestResponse("Could not read multipart upload (malformed, or larger than "
                    + MAX_REQUEST_MB + " MB)");
        }
        if (file == null) {
            throw new BadRequestResponse("Multipart request must include the .eml file in a form field named '"
                    + EMAIL_UPLOAD_FIELD + "'");
        }
        if (file.size() == 0) {
            throw new BadRequestResponse("Uploaded email file is empty");
        }
        return file;
    }

    private JsonNode readJsonObject(Context ctx) {
        String body = ctx.body();
        if (body.isBlank()) {
            throw new BadRequestResponse("Request body is empty; expected a JSON object");
        }
        JsonNode node;
        try {
            node = mapper.readTree(body);
        } catch (JsonProcessingException e) {
            throw new BadRequestResponse("Request body is not valid JSON");
        }
        if (node == null || !node.isObject()) {
            throw new BadRequestResponse("Request body must be a JSON object");
        }
        return node;
    }

    private static String requiredText(JsonNode body, String field) {
        JsonNode value = body.get(field);
        if (value == null || value.isNull()) {
            throw new BadRequestResponse("Missing required field '" + field + "'");
        }
        if (!value.isTextual()) {
            throw new BadRequestResponse("Field '" + field + "' must be a string");
        }
        String text = value.asText().trim();
        if (text.isEmpty()) {
            throw new BadRequestResponse("Field '" + field + "' must not be empty");
        }
        return text;
    }

    private static HttpResponseException tooLarge() {
        return new HttpResponseException(HttpStatus.CONTENT_TOO_LARGE.getCode(), TOO_LARGE_MESSAGE);
    }

    // --- responses -------------------------------------------------------------

    private void respondError(Context ctx, HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message == null || message.isBlank() ? status.getMessage() : message);
        respond(ctx, status, body);
    }

    private void respond(Context ctx, HttpStatus status, Object body) {
        String json;
        try {
            json = mapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize response to JSON", e);
        }
        ctx.status(status).contentType(ContentType.APPLICATION_JSON).result(json);
    }
}
