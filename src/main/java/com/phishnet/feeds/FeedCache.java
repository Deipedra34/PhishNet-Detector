package com.phishnet.feeds;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

/**
 * The on-disk copy of each feed, under {@code ~/.phishnet/feeds} by default:
 * {@code <feed>.txt} holds one normalized URL key per line, and
 * {@code <feed>.properties} records when it was last refreshed, how many
 * entries it has, and the last failed attempt (if any).
 *
 * Every file is written to a temporary file first and then moved into place,
 * so a download cut short - including one still running in the background
 * when a one-off scan exits - never leaves a half-written feed behind. A
 * missing or unreadable cache simply reads as "no cached copy".
 */
public final class FeedCache {

    private static final String REFRESHED_AT = "refreshedAt";
    private static final String ENTRIES = "entries";
    private static final String LAST_ATTEMPT = "lastAttempt";
    private static final String LAST_ERROR = "lastError";

    /** What {@code <feed>.properties} says about a feed. Any field may be absent. */
    public record Metadata(Instant refreshedAt, int entries, Instant lastAttempt, String lastError) {

        static final Metadata NONE = new Metadata(null, 0, null, null);
    }

    private final Path directory;

    /** Where feeds are cached by default: {@code ~/.phishnet/feeds}, next to the scan history and ML model. */
    public static Path defaultDirectory() {
        return Path.of(System.getProperty("user.home"), ".phishnet", "feeds");
    }

    public FeedCache(Path directory) {
        this.directory = directory;
    }

    public Path directory() {
        return directory;
    }

    /** The cached copy of {@code source}, or empty if it was never downloaded or can't be read. */
    public Optional<FeedSnapshot> read(FeedSource source) {
        Metadata metadata = metadata(source);
        Path data = dataFile(source);
        if (metadata.refreshedAt() == null || !Files.isRegularFile(data)) {
            return Optional.empty();
        }
        try {
            List<String> keys = Files.readAllLines(data, StandardCharsets.UTF_8);
            keys.removeIf(String::isBlank);
            return Optional.of(new FeedSnapshot(source, FeedEntries.ofKeys(keys), metadata.refreshedAt()));
        } catch (IOException | UncheckedIOException e) {
            return Optional.empty();
        }
    }

    /** Replaces the cached copy of {@code source} after a successful download. */
    public void write(FeedSource source, FeedEntries entries, Instant refreshedAt) throws IOException {
        Files.createDirectories(directory);
        Path temp = Files.createTempFile(directory, source.id(), ".tmp");
        try {
            Files.write(temp, entries.urls(), StandardCharsets.UTF_8);
            moveIntoPlace(temp, dataFile(source));
        } finally {
            Files.deleteIfExists(temp);
        }
        writeMetadata(source, new Metadata(refreshedAt, entries.size(), refreshedAt, null));
    }

    /**
     * Notes a failed download without touching the cached entries, so
     * {@code phishnet feeds status} can say why a feed is going stale. Never
     * throws: failing to record a failure must not turn into a scan error.
     */
    public void recordFailure(FeedSource source, String error, Instant attemptedAt) {
        Metadata previous = metadata(source);
        try {
            writeMetadata(source, new Metadata(previous.refreshedAt(), previous.entries(), attemptedAt, error));
        } catch (IOException | RuntimeException e) {
            // Best effort only.
        }
    }

    /** The metadata recorded for {@code source}, or all-absent if there's none. */
    public Metadata metadata(FeedSource source) {
        Path file = metadataFile(source);
        if (!Files.isRegularFile(file)) {
            return Metadata.NONE;
        }
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            props.load(in);
        } catch (IOException e) {
            return Metadata.NONE;
        }
        int entries;
        try {
            entries = Integer.parseInt(props.getProperty(ENTRIES, "0"));
        } catch (NumberFormatException e) {
            entries = 0;
        }
        String error = props.getProperty(LAST_ERROR);
        return new Metadata(instant(props.getProperty(REFRESHED_AT)), entries,
                instant(props.getProperty(LAST_ATTEMPT)), error == null || error.isEmpty() ? null : error);
    }

    private void writeMetadata(FeedSource source, Metadata metadata) throws IOException {
        Properties props = new Properties();
        if (metadata.refreshedAt() != null) {
            props.setProperty(REFRESHED_AT, metadata.refreshedAt().toString());
        }
        props.setProperty(ENTRIES, Integer.toString(metadata.entries()));
        if (metadata.lastAttempt() != null) {
            props.setProperty(LAST_ATTEMPT, metadata.lastAttempt().toString());
        }
        if (metadata.lastError() != null) {
            props.setProperty(LAST_ERROR, metadata.lastError());
        }
        Files.createDirectories(directory);
        Path temp = Files.createTempFile(directory, source.id(), ".tmp");
        try {
            try (OutputStream out = Files.newOutputStream(temp)) {
                props.store(out, source.displayName() + " feed cache");
            }
            moveIntoPlace(temp, metadataFile(source));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private Path dataFile(FeedSource source) {
        return directory.resolve(source.id() + ".txt");
    }

    private Path metadataFile(FeedSource source) {
        return directory.resolve(source.id() + ".properties");
    }

    private static void moveIntoPlace(Path temp, Path target) throws IOException {
        try {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static Instant instant(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
