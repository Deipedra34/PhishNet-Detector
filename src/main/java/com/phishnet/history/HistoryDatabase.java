package com.phishnet.history;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishnet.cli.HistoryWriter.TargetType;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlComponents;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * SQLite-backed scan history: one row per scan, queryable by target, risk level,
 * type, and date range. Lives alongside the CSV history ({@link com.phishnet.cli.HistoryWriter})
 * rather than replacing it.
 *
 * <p>Writing follows the same rules as the CSV history: it's a side effect of
 * scanning, so a failure (unwritable directory, locked or corrupt file, ...) is
 * reported to stderr once and swallowed - it never aborts a scan. Reads, used by
 * {@code phishnet history}, throw {@link SQLException} so the command can report it.
 *
 * <p>The database file and schema are created on the first write. A connection is
 * opened per operation (like the CSV writer opening the file per row), so an
 * interrupted batch keeps everything recorded so far, and separate processes - a CLI
 * scan and a running {@code serve} - can share one file; SQLite's own locking (with a
 * busy timeout) serializes their writes. Every value reaches SQL through a
 * {@link PreparedStatement} parameter, never by string concatenation.
 */
public final class HistoryDatabase {

    /** Default location: {@code ~/.phishnet/phishnet-history.db}. */
    public static final String DEFAULT_DIRECTORY = ".phishnet";
    public static final String DEFAULT_FILE_NAME = "phishnet-history.db";

    /** Bumped (with a migration) whenever the schema below changes shape. */
    static final int SCHEMA_VERSION = 1;

    private static final String[] SCHEMA = {
            """
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                type            TEXT    NOT NULL CHECK (type IN ('URL', 'EMAIL')),
                target          TEXT    NOT NULL,
                domain          TEXT,
                subject         TEXT,
                risk_score      INTEGER NOT NULL,
                risk_level      TEXT    NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
                signals         TEXT    NOT NULL,
                domain_age_days INTEGER
            )""",
            "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans (risk_level)",
            "CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans (domain)"
    };

    private static final String COLUMNS =
            "id, timestamp, type, target, domain, subject, risk_score, risk_level, signals, domain_age_days";

    /**
     * Timestamps are stored as UTC ISO-8601 text with fixed millisecond precision, so
     * they read naturally in any SQLite tool and sort (and range-compare) correctly as
     * plain strings. {@link Instant#toString()} drops trailing zero fractions, which
     * would break that ordering.
     */
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);

    /** How long a connection waits for another process's write lock before giving up. */
    private static final int BUSY_TIMEOUT_MILLIS = 5_000;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<HistoryEntry.Reason>> REASONS_TYPE = new TypeReference<>() {
    };

    private final Path file;
    private final boolean writesEnabled;
    private final PrintStream err;
    private final Clock clock;

    /** Guarded by {@code this}: the schema has been ensured on this file. */
    private boolean schemaReady;
    /** Guarded by {@code this}: a write failure has already been reported. */
    private boolean warned;

    /**
     * @param file          the SQLite database file (created, with its parent directories, on first write)
     * @param writesEnabled when false, the {@code record*} methods do nothing ({@code --no-history-db});
     *                      reads are unaffected
     * @param err           stream that write failures are reported to
     */
    public HistoryDatabase(Path file, boolean writesEnabled, PrintStream err) {
        this(file, writesEnabled, err, Clock.systemUTC());
    }

    /** Same, with the clock that stamps new rows swapped out (for tests). */
    public HistoryDatabase(Path file, boolean writesEnabled, PrintStream err, Clock clock) {
        this.file = file;
        this.writesEnabled = writesEnabled;
        this.err = err;
        this.clock = clock;
    }

    /**
     * {@code ~/.phishnet/phishnet-history.db}, so every scan lands in one place no
     * matter which directory it was run from. Falls back to {@code ./.phishnet/} when
     * there is no usable home directory (e.g. a container run under an arbitrary UID,
     * where the JVM reports the home directory as {@code ?}).
     */
    public static Path defaultPath() {
        String home = System.getProperty("user.home");
        Path base = home == null || home.isBlank() || home.equals("?") ? Path.of("") : Path.of(home);
        return base.resolve(DEFAULT_DIRECTORY).resolve(DEFAULT_FILE_NAME);
    }

    public Path file() {
        return file;
    }

    public boolean writesEnabled() {
        return writesEnabled;
    }

    // --- writes -----------------------------------------------------------------

    /** Records a URL scan. The domain column is the registrable domain, or the host for IP URLs. */
    public void recordUrl(String url, UrlComponents components, RiskScore score, DomainAgeResult domainAge) {
        record(TargetType.URL, url, domainOf(components), null, score, domainAge);
    }

    /** Records an email scan. The domain column is the sender's domain (after the {@code @}). */
    public void recordEmail(String label, String senderAddress, String subject, RiskScore score) {
        record(TargetType.EMAIL, label, senderDomainOf(senderAddress), blankToNull(subject), score,
                DomainAgeResult.skipped());
    }

    private synchronized void record(TargetType type, String target, String domain, String subject,
                                     RiskScore score, DomainAgeResult domainAge) {
        if (!writesEnabled) {
            return;
        }
        String sql = "INSERT INTO scans (timestamp, type, target, domain, subject, risk_score, risk_level, "
                + "signals, domain_age_days) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (Connection conn = connect();
                 PreparedStatement insert = conn.prepareStatement(sql)) {
                insert.setString(1, TIMESTAMP_FORMAT.format(clock.instant()));
                insert.setString(2, type.name());
                insert.setString(3, target == null ? "" : target);
                insert.setString(4, domain);
                insert.setString(5, subject);
                insert.setInt(6, score.score());
                insert.setString(7, score.level().name());
                insert.setString(8, reasonsJson(score.signals()));
                if (domainAge != null && domainAge.isKnown()) {
                    insert.setLong(9, domainAge.ageDays());
                } else {
                    insert.setNull(9, Types.INTEGER);
                }
                insert.executeUpdate();
            }
        } catch (SQLException | IOException | RuntimeException e) {
            if (!warned) {
                err.println("Warning: could not write scan history database " + file + ": " + e.getMessage());
                warned = true;
            }
        }
    }

    // --- reads ------------------------------------------------------------------

    /**
     * Scans matching {@code filter}, newest first. Returns an empty list - without
     * creating anything - when the database file doesn't exist yet.
     */
    public List<HistoryEntry> search(HistoryFilter filter) throws SQLException {
        if (!Files.exists(file)) {
            return List.of();
        }
        List<String> conditions = new ArrayList<>();
        List<Object> params = new ArrayList<>();
        if (filter.targetContains() != null) {
            conditions.add("(target LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\')");
            String pattern = "%" + escapeLike(filter.targetContains()) + "%";
            params.add(pattern);
            params.add(pattern);
            params.add(pattern);
        }
        if (filter.riskLevel() != null) {
            conditions.add("risk_level = ?");
            params.add(filter.riskLevel().name());
        }
        if (filter.type() != null) {
            conditions.add("type = ?");
            params.add(filter.type().name());
        }
        if (filter.since() != null) {
            conditions.add("timestamp >= ?");
            params.add(TIMESTAMP_FORMAT.format(filter.since()));
        }
        if (filter.until() != null) {
            conditions.add("timestamp < ?");
            params.add(TIMESTAMP_FORMAT.format(filter.until()));
        }

        // Only fixed SQL fragments are concatenated here; every value is a bound parameter.
        StringBuilder sql = new StringBuilder("SELECT ").append(COLUMNS).append(" FROM scans");
        if (!conditions.isEmpty()) {
            sql.append(" WHERE ").append(String.join(" AND ", conditions));
        }
        sql.append(" ORDER BY timestamp DESC, id DESC");
        if (filter.limit() > 0) {
            sql.append(" LIMIT ?");
            params.add(filter.limit());
        }

        try (Connection conn = connect();
             PreparedStatement query = conn.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                query.setObject(i + 1, params.get(i));
            }
            List<HistoryEntry> entries = new ArrayList<>();
            try (ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    entries.add(toEntry(rows));
                }
            }
            return entries;
        }
    }

    /**
     * Totals, per-level and per-type counts, and the {@code topDomains} domains with
     * the most MEDIUM/HIGH scans. {@link HistoryStats#empty()} when the database file
     * doesn't exist yet.
     */
    public HistoryStats stats(int topDomains) throws SQLException {
        if (!Files.exists(file)) {
            return HistoryStats.empty();
        }
        try (Connection conn = connect()) {
            long total;
            Instant first = null;
            Instant last = null;
            try (PreparedStatement query = conn.prepareStatement(
                    "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM scans");
                 ResultSet rows = query.executeQuery()) {
                rows.next();
                total = rows.getLong(1);
                if (total > 0) {
                    first = Instant.parse(rows.getString(2));
                    last = Instant.parse(rows.getString(3));
                }
            }

            Map<RiskLevel, Long> byLevel = new EnumMap<>(RiskLevel.class);
            try (PreparedStatement query = conn.prepareStatement(
                    "SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level");
                 ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    byLevel.put(RiskLevel.valueOf(rows.getString(1)), rows.getLong(2));
                }
            }

            Map<TargetType, Long> byType = new EnumMap<>(TargetType.class);
            try (PreparedStatement query = conn.prepareStatement(
                    "SELECT type, COUNT(*) FROM scans GROUP BY type");
                 ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    byType.put(TargetType.valueOf(rows.getString(1)), rows.getLong(2));
                }
            }

            List<HistoryStats.DomainCount> topFlagged = new ArrayList<>();
            try (PreparedStatement query = conn.prepareStatement(
                    "SELECT domain, COUNT(*) AS flagged FROM scans "
                            + "WHERE risk_level IN (?, ?) AND domain IS NOT NULL "
                            + "GROUP BY domain ORDER BY flagged DESC, domain ASC LIMIT ?")) {
                query.setString(1, RiskLevel.MEDIUM.name());
                query.setString(2, RiskLevel.HIGH.name());
                query.setInt(3, Math.max(0, topDomains));
                try (ResultSet rows = query.executeQuery()) {
                    while (rows.next()) {
                        topFlagged.add(new HistoryStats.DomainCount(rows.getString(1), rows.getLong(2)));
                    }
                }
            }
            return new HistoryStats(total, byLevel, byType, first, last, topFlagged);
        }
    }

    // --- internals --------------------------------------------------------------

    /** Opens a connection and makes sure the schema exists (once per instance). */
    private Connection connect() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + file.toAbsolutePath());
        try {
            try (Statement statement = conn.createStatement()) {
                statement.execute("PRAGMA busy_timeout = " + BUSY_TIMEOUT_MILLIS);
            }
            ensureSchema(conn);
            return conn;
        } catch (SQLException | RuntimeException e) {
            conn.close();
            throw e;
        }
    }

    private synchronized void ensureSchema(Connection conn) throws SQLException {
        if (schemaReady) {
            return;
        }
        try (Statement statement = conn.createStatement()) {
            for (String ddl : SCHEMA) {
                statement.execute(ddl);
            }
            try (ResultSet version = statement.executeQuery("PRAGMA user_version")) {
                if (version.next() && version.getInt(1) == 0) {
                    statement.execute("PRAGMA user_version = " + SCHEMA_VERSION);
                }
            }
        }
        schemaReady = true;
    }

    private static HistoryEntry toEntry(ResultSet rows) throws SQLException {
        long ageDays = rows.getLong("domain_age_days");
        Long domainAgeDays = rows.wasNull() ? null : ageDays;
        return new HistoryEntry(
                rows.getLong("id"),
                Instant.parse(rows.getString("timestamp")),
                TargetType.valueOf(rows.getString("type")),
                rows.getString("target"),
                rows.getString("domain"),
                rows.getString("subject"),
                rows.getInt("risk_score"),
                RiskLevel.valueOf(rows.getString("risk_level")),
                parseReasons(rows.getString("signals")),
                domainAgeDays);
    }

    private static String reasonsJson(List<Signal> signals) {
        List<HistoryEntry.Reason> reasons = new ArrayList<>();
        for (Signal signal : signals) {
            reasons.add(new HistoryEntry.Reason(signal.id(), signal.description()));
        }
        try {
            return MAPPER.writeValueAsString(reasons);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize signals to JSON", e);
        }
    }

    /** Tolerates hand-edited or damaged rows: unreadable JSON just means no reasons shown. */
    private static List<HistoryEntry.Reason> parseReasons(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return MAPPER.readValue(json, REASONS_TYPE);
        } catch (JsonProcessingException e) {
            return List.of();
        }
    }

    /** Escapes LIKE wildcards so a search for {@code "50%_off"} matches that text literally. */
    static String escapeLike(String text) {
        return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    static String domainOf(UrlComponents components) {
        if (components == null) {
            return null;
        }
        String domain = components.isIpHost() ? components.host() : components.registrableDomain();
        return blankToNull(domain == null ? null : domain.toLowerCase(Locale.ROOT));
    }

    static String senderDomainOf(String senderAddress) {
        if (senderAddress == null) {
            return null;
        }
        int at = senderAddress.lastIndexOf('@');
        return at < 0 ? null : blankToNull(senderAddress.substring(at + 1).trim().toLowerCase(Locale.ROOT));
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
