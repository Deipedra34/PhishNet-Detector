package com.phishnet.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.history.HistoryDatabase;
import io.javalin.Javalin;
import io.javalin.config.JavalinConfig;
import io.javalin.config.SizeUnit;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.ContentType;
import io.javalin.http.Context;
import io.javalin.http.HttpResponseException;
import io.javalin.http.HttpStatus;
import io.javalin.http.UploadedFile;
import io.javalin.http.staticfiles.Location;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The optional REST API ({@code phishnet serve}): a thin HTTP layer over
 * {@link ScanService}, built on an embedded Javalin/Jetty server.
 *
 * <ul>
 *   <li>{@code GET  /api/health}     - {@code {"status":"ok"}}</li>
 *   <li>{@code POST /api/scan/url}   - JSON {@code {"url":"..."}}</li>
 *   <li>{@code POST /api/scan/email} - multipart upload (form field {@value #EMAIL_UPLOAD_FIELD}),
 *       or JSON {@code {"raw":"<full .eml text>"}}</li>
 *   <li>{@code GET  /api/history}    - one page of scans from the SQLite scan history, filterable (read-only)</li>
 *   <li>{@code GET  /api/history/stats} - the aggregate figures of {@code phishnet history stats}</li>
 *   <li>{@code GET  /api/feeds/status} - threat feed cache state, as {@code phishnet feeds status}</li>
 *   <li>{@code GET  /api/auth/check} - {@code {"status":"ok"}} when the request's API key is accepted</li>
 * </ul>
 *
 * <p>With an API key set ({@link #withApiKey}), every endpoint except {@code GET /api/health}
 * requires it in the {@value #API_KEY_HEADER} header and answers 401 without it. A missing
 * key and a wrong one get the same answer, and keys are compared in constant time.
 *
 * Every error - bad input, unknown route, oversized body, or an unexpected
 * failure - is answered with a JSON {@code {"error":"..."}} body; stack traces
 * go to the server's log stream only, never to the client.
 *
 * <p>Cross-origin (CORS) access is granted to browser-extension pages only - that's
 * how the PhishNet browser extension's popup calls the API. Ordinary websites get
 * no CORS headers, so a page you happen to visit can't read results from (or send
 * JSON scans to) a server running on your machine.
 */
public final class ApiServer {

    public static final int DEFAULT_PORT = 8080;

    /** Largest request body accepted on any endpoint (JSON or multipart) by default: 5 MB. */
    static final long MAX_REQUEST_BYTES = 5L * 1024 * 1024;

    /** Longest URL accepted by /api/scan/url - far beyond any real link, but rules out abuse. */
    static final int MAX_URL_LENGTH = 8192;

    /** Multipart form field the .eml file must be uploaded under. */
    static final String EMAIL_UPLOAD_FIELD = "file";

    /**
     * Origins allowed cross-origin access: Chrome/Edge ({@code chrome-extension://<id>})
     * and Firefox ({@code moz-extension://<uuid>}) extension pages.
     */
    private static final Pattern EXTENSION_ORIGIN = Pattern.compile("(chrome|moz)-extension://[A-Za-z0-9-]+");

    /** Every endpoint path, for CORS preflights and the dashboard's 404/405 fallback. */
    static final List<String> API_PATHS = List.of("/api/health", "/api/scan/url", "/api/scan/email",
            "/api/history", "/api/history/stats", "/api/feeds/status", "/api/auth/check");

    /** Request header carrying the API key. */
    public static final String API_KEY_HEADER = "X-API-Key";

    /** The only endpoint open without an API key, for uptime checks. */
    static final String HEALTH_PATH = "/api/health";

    /** The 401 message - identical for a missing and a wrong key. */
    static final String UNAUTHORIZED_MESSAGE = "Missing or invalid API key. Send the key that 'phishnet serve' "
            + "printed in the " + API_KEY_HEADER + " header (by default it is stored in ~/.phishnet/api-key).";

    /** The dashboard's entry page, served for every client-side route. */
    static final String DASHBOARD_INDEX = "index.html";

    /** How long a browser may cache a preflight answer, in seconds. */
    static final String CORS_MAX_AGE_SECONDS = "600";

    private final ScanService scanner;
    private final PrintStream log;
    private final long maxRequestBytes;
    private final String tooLargeMessage;
    private final ObjectMapper mapper = new ObjectMapper();
    /** Created by {@link #start}, once the optional read-side components below are set. */
    private Javalin app;
    /** Read-only history endpoints, or {@code null} when no history database was given. */
    private HistoryApi historyApi;
    /** Threat feed status endpoint, or {@code null} when no feed service was given. */
    private FeedsApi feedsApi;
    /** Built web dashboard to serve at "/", or {@code null} to serve the API only. */
    private Path dashboardDirectory;
    /** SHA-256 of the required API key, or {@code null} when no key is required. */
    private byte[] apiKeyDigest;
    /** Limits scan requests per client, or {@code null} for no limit. */
    private RateLimiter rateLimiter;

    /**
     * @param log where unexpected (500) errors are reported, with their stack trace
     */
    public ApiServer(ScanService scanner, PrintStream log) {
        this(scanner, log, MAX_REQUEST_BYTES);
    }

    /** Same, with a custom request-size limit (lets tests exercise the limit with small bodies). */
    ApiServer(ScanService scanner, PrintStream log, long maxRequestBytes) {
        this.scanner = scanner;
        this.log = log;
        this.maxRequestBytes = maxRequestBytes;
        this.tooLargeMessage = "Request body too large (max " + describeSize(maxRequestBytes) + ")";
    }

    /**
     * Serves the read-only scan history endpoints ({@code GET /api/history...}) from
     * {@code database}. Only reads are made through it, so a database with writes
     * disabled is fine. Must be called before {@link #start}; without it those
     * endpoints answer 503.
     */
    public ApiServer withHistory(HistoryDatabase database) {
        requireNotStarted();
        this.historyApi = database == null ? null : new HistoryApi(database);
        return this;
    }

    /**
     * Serves {@code GET /api/feeds/status} from {@code service}'s cache (no downloads).
     * Must be called before {@link #start}; without it that endpoint answers 503.
     */
    public ApiServer withFeeds(ThreatFeedService service) {
        requireNotStarted();
        this.feedsApi = service == null ? null : new FeedsApi(service);
        return this;
    }

    /**
     * Also serves the built web dashboard (the output of {@code npm run build} in
     * {@code dashboard/}) from {@code directory} at "/", on the same port as the API.
     * Paths that aren't a file and don't start with {@code /api/} get its
     * {@code index.html}, so the dashboard's client-side routes ({@code /history}, ...)
     * survive a reload. Must be called before {@link #start}.
     *
     * @throws IllegalArgumentException if {@code directory} has no {@code index.html}
     */
    public ApiServer withDashboard(Path directory) {
        requireNotStarted();
        if (directory != null && !isDashboardDirectory(directory)) {
            throw new IllegalArgumentException("No " + DASHBOARD_INDEX + " in " + directory);
        }
        this.dashboardDirectory = directory == null ? null : directory.toAbsolutePath().normalize();
        return this;
    }

    /**
     * Requires {@code apiKey} in the {@value #API_KEY_HEADER} header on every endpoint except
     * {@code GET /api/health}; {@code null} requires none. Must be called before {@link #start}.
     */
    public ApiServer withApiKey(String apiKey) {
        requireNotStarted();
        this.apiKeyDigest = apiKey == null ? null : sha256(apiKey);
        return this;
    }

    /**
     * Limits each client (by IP address) to {@code requestsPerMinute} scan requests
     * ({@code POST /api/scan/url}, {@code POST /api/scan/email}); 0 means no limit. Other
     * endpoints are never limited. Must be called before {@link #start}.
     */
    public ApiServer withRateLimit(int requestsPerMinute) {
        return withRateLimiter(requestsPerMinute > 0 ? new RateLimiter(requestsPerMinute) : null);
    }

    /** Same, with a ready-made limiter (lets tests control its clock); {@code null} for no limit. */
    ApiServer withRateLimiter(RateLimiter limiter) {
        requireNotStarted();
        this.rateLimiter = limiter;
        return this;
    }

    /** Whether {@code directory} looks like a built dashboard (it has an index.html). */
    public static boolean isDashboardDirectory(Path directory) {
        return directory != null && Files.isRegularFile(directory.resolve(DASHBOARD_INDEX));
    }

    /** Starts listening; port 0 picks a free port (see {@link #port()}). Returns once the server is up. */
    public ApiServer start(int port) {
        requireNotStarted();
        app = Javalin.create(this::configure);
        app.start(port);
        return this;
    }

    public void stop() {
        if (app != null) {
            app.stop();
        }
    }

    private void requireNotStarted() {
        if (app != null) {
            throw new IllegalStateException("The API server has already been started");
        }
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
        config.http.maxRequestSize = maxRequestBytes;
        // Multipart uploads bypass maxRequestSize, so cap them separately. Keeping the
        // whole (capped) upload in memory means nothing is ever spooled to disk.
        config.jetty.multipartConfig.maxFileSize(maxRequestBytes, SizeUnit.BYTES);
        config.jetty.multipartConfig.maxTotalRequestSize(maxRequestBytes, SizeUnit.BYTES);
        config.jetty.multipartConfig.maxInMemoryFileSize((int) maxRequestBytes, SizeUnit.BYTES);

        config.routes.before("/api/*", ctx -> {
            // First, so every response to an extension - errors included - carries it.
            allowExtensionOrigin(ctx);
            // Reject a declared-oversized body up front, before reading any of it.
            if (ctx.req().getContentLengthLong() > maxRequestBytes) {
                throw tooLarge();
            }
            requireApiKey(ctx);
            // After the key check, so requests with a bad key don't use up a client's allowance.
            enforceRateLimit(ctx);
        });
        config.routes.get("/api/health", ctx -> respond(ctx, HttpStatus.OK, Map.of("status", "ok")));
        config.routes.post("/api/scan/url", this::scanUrl);
        config.routes.post("/api/scan/email", this::scanEmail);
        config.routes.get("/api/history", ctx -> respond(ctx, HttpStatus.OK, history().list(ctx)));
        config.routes.get("/api/history/stats", ctx -> respond(ctx, HttpStatus.OK, history().stats(ctx)));
        config.routes.get("/api/feeds/status", ctx -> respond(ctx, HttpStatus.OK, feeds().status()));
        // Reaching this handler means the key (if one is required) was accepted.
        config.routes.get("/api/auth/check", ctx -> respond(ctx, HttpStatus.OK, Map.of("status", "ok")));
        // Per endpoint rather than "/api/*", so an unknown path still answers 404, not 405.
        for (String path : API_PATHS) {
            config.routes.options(path, this::preflight);
        }

        if (dashboardDirectory != null) {
            configureDashboard(config, dashboardDirectory);
        }

        // Overrides Javalin's built-in handler, so its own 404/405/413 responses use our JSON error shape too.
        config.routes.exception(HttpResponseException.class, (e, ctx) -> {
            HttpStatus status = HttpStatus.forStatus(e.getStatus());
            // Javalin's own body-limit 413 just says "Content Too Large"; say what the limit is.
            String message = status == HttpStatus.CONTENT_TOO_LARGE ? tooLargeMessage : e.getMessage();
            respondError(ctx, status, message);
        });
        config.routes.exception(SQLException.class, (e, ctx) -> {
            log.println("Error: could not read the scan history database for " + ctx.method() + " " + ctx.path()
                    + ": " + e.getMessage());
            respondError(ctx, HttpStatus.INTERNAL_SERVER_ERROR, "Could not read the scan history database");
        });
        config.routes.exception(Exception.class, (e, ctx) -> {
            log.println("Error: unexpected failure handling " + ctx.method() + " " + ctx.path());
            e.printStackTrace(log);
            respondError(ctx, HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
        });
    }

    /** Static files from the built dashboard, with index.html for client-side routes. */
    private static void configureDashboard(JavalinConfig config, Path directory) {
        config.staticFiles.add(files -> {
            files.hostedPath = "/";
            files.directory = directory.toString();
            files.location = Location.EXTERNAL;
        });
        Path index = directory.resolve(DASHBOARD_INDEX);
        config.spaRoot.addHandler("/", ctx -> {
            String path = ctx.path();
            // The fallback is reached before Javalin's own 404/405 handling, so give API
            // paths the answers they'd get without a dashboard: 405 for a known endpoint
            // called with the wrong method, otherwise a JSON 404.
            boolean apiPath = path.equals("/api") || path.startsWith("/api/");
            if (apiPath && API_PATHS.contains(path)) {
                throw new HttpResponseException(HttpStatus.METHOD_NOT_ALLOWED.getCode(),
                        HttpStatus.METHOD_NOT_ALLOWED.getMessage());
            }
            // A missing file (e.g. an old hashed asset) is a 404 too, not the app's HTML.
            if (apiPath || path.substring(path.lastIndexOf('/') + 1).contains(".")) {
                throw new HttpResponseException(HttpStatus.NOT_FOUND.getCode(),
                        "Endpoint " + ctx.method() + " " + path + " not found");
            }
            ctx.header("Cache-Control", "no-cache");
            ctx.contentType(ContentType.TEXT_HTML).result(Files.newInputStream(index));
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

    private HistoryApi history() {
        if (historyApi == null) {
            throw new HttpResponseException(HttpStatus.SERVICE_UNAVAILABLE.getCode(),
                    "Scan history is not available on this server");
        }
        return historyApi;
    }

    private FeedsApi feeds() {
        if (feedsApi == null) {
            throw new HttpResponseException(HttpStatus.SERVICE_UNAVAILABLE.getCode(),
                    "Threat feed status is not available on this server");
        }
        return feedsApi;
    }

    // --- API key ----------------------------------------------------------------------

    private void requireApiKey(Context ctx) {
        if (apiKeyDigest == null || ctx.path().equals(HEALTH_PATH) || ctx.method().name().equals("OPTIONS")) {
            // Browsers send CORS preflights without custom headers, so they can't carry the key.
            return;
        }
        String provided = ctx.header(API_KEY_HEADER);
        // Digests are compared rather than the keys, so the comparison takes the same time
        // whatever the provided key's length or how much of it matches.
        if (provided == null || !MessageDigest.isEqual(sha256(provided), apiKeyDigest)) {
            throw new HttpResponseException(HttpStatus.UNAUTHORIZED.getCode(), UNAUTHORIZED_MESSAGE);
        }
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is missing from this Java runtime", e);
        }
    }

    // --- rate limiting ----------------------------------------------------------------

    /** The endpoints that are rate limited: the scans, which do the real work (WHOIS, parsing). */
    static boolean isRateLimited(Context ctx) {
        return ctx.method().name().equals("POST")
                && (ctx.path().equals("/api/scan/url") || ctx.path().equals("/api/scan/email"));
    }

    private void enforceRateLimit(Context ctx) {
        if (rateLimiter == null || !isRateLimited(ctx)) {
            return;
        }
        if (!rateLimiter.tryAcquire(ctx.ip()).allowed()) {
            throw new HttpResponseException(HttpStatus.TOO_MANY_REQUESTS.getCode(),
                    HttpStatus.TOO_MANY_REQUESTS.getMessage());
        }
    }

    // --- CORS (browser extensions only) -------------------------------------------

    static boolean isExtensionOrigin(String origin) {
        return origin != null && EXTENSION_ORIGIN.matcher(origin).matches();
    }

    private static void allowExtensionOrigin(Context ctx) {
        String origin = ctx.header("Origin");
        if (isExtensionOrigin(origin)) {
            ctx.header("Access-Control-Allow-Origin", origin);
            ctx.header("Vary", "Origin");
        }
    }

    /**
     * Answers an extension's CORS preflight (sent before its JSON POST). For anyone
     * else OPTIONS stays exactly what it was before CORS support: 405.
     */
    private void preflight(Context ctx) {
        if (!isExtensionOrigin(ctx.header("Origin"))) {
            throw new HttpResponseException(HttpStatus.METHOD_NOT_ALLOWED.getCode(),
                    HttpStatus.METHOD_NOT_ALLOWED.getMessage());
        }
        ctx.header("Access-Control-Allow-Methods", "GET, POST");
        ctx.header("Access-Control-Allow-Headers", "Content-Type, " + API_KEY_HEADER);
        ctx.header("Access-Control-Max-Age", CORS_MAX_AGE_SECONDS);
        ctx.status(HttpStatus.NO_CONTENT);
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
                    + describeSize(maxRequestBytes) + ")");
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

    private HttpResponseException tooLarge() {
        return new HttpResponseException(HttpStatus.CONTENT_TOO_LARGE.getCode(), tooLargeMessage);
    }

    /** "5 MB" for whole megabytes, otherwise an exact byte count. */
    private static String describeSize(long bytes) {
        long mb = 1024L * 1024L;
        return bytes % mb == 0 ? (bytes / mb) + " MB" : bytes + " bytes";
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
