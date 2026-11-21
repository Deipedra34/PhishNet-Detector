package com.phishnet.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The API key that {@code phishnet serve} requires clients to send. On the first run
 * a random key is generated and saved to {@code ~/.phishnet/api-key}; later runs load
 * it from there. The {@value #KEY_ENV} environment variable, when set, is used instead
 * and nothing is written (handy for containers).
 *
 * <p>The key file holds just the key, on one line. It's written atomically, and where
 * the file system has POSIX permissions it's readable by its owner only.
 */
public final class ApiKeyStore {

    /** Environment variable that supplies the key directly, instead of the key file. */
    public static final String KEY_ENV = "PHISHNET_API_KEY";

    public static final String DEFAULT_DIRECTORY = ".phishnet";
    public static final String DEFAULT_FILE_NAME = "api-key";

    /** 32 random bytes: a 256-bit key, 43 characters in URL-safe base64. */
    static final int KEY_BYTES = 32;

    static final int MIN_KEY_LENGTH = 16;
    static final int MAX_KEY_LENGTH = 256;

    /** Characters a key may use: safe in an HTTP header and easy to copy. */
    private static final Pattern KEY_CHARACTERS = Pattern.compile("[A-Za-z0-9._~+/=-]+");

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Where a loaded key came from. */
    public enum Source {
        /** Read from an existing key file. */
        FILE,
        /** Just generated and saved, because there was no key file yet. */
        CREATED,
        /** Taken from {@value #KEY_ENV}. */
        ENVIRONMENT
    }

    /** The key in effect, and where it came from. {@link #toString()} never shows the key. */
    public record LoadedKey(String key, Source source, Path file) {
        @Override
        public String toString() {
            return "LoadedKey[key=<redacted>, source=" + source + ", file=" + file + "]";
        }
    }

    private ApiKeyStore() {
    }

    /** {@code ~/.phishnet/api-key}, next to the scan history database. */
    public static Path defaultPath() {
        String home = System.getProperty("user.home");
        Path base = home == null || home.isBlank() || home.equals("?") ? Path.of("") : Path.of(home);
        return base.resolve(DEFAULT_DIRECTORY).resolve(DEFAULT_FILE_NAME);
    }

    /** A new random key. */
    public static String generate() {
        byte[] bytes = new byte[KEY_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * The key from {@code envValue} if set, else from {@code file}, else a new key saved to {@code file}.
     *
     * @throws IOException              if the key file can't be read or written
     * @throws IllegalArgumentException if the environment variable or the key file holds an unusable key
     */
    public static LoadedKey loadOrCreate(Path file, String envValue) throws IOException {
        if (envValue != null && !envValue.isBlank()) {
            return new LoadedKey(validate(envValue.strip(), KEY_ENV), Source.ENVIRONMENT, null);
        }
        try {
            String stored = Files.readString(file, StandardCharsets.UTF_8).strip();
            return new LoadedKey(validate(stored, "API key file " + file), Source.FILE, file);
        } catch (NoSuchFileException e) {
            String key = generate();
            write(file, key);
            return new LoadedKey(key, Source.CREATED, file);
        }
    }

    /** Replaces the key in {@code file} with a new one and returns it. */
    public static String regenerate(Path file) throws IOException {
        String key = generate();
        write(file, key);
        return key;
    }

    /**
     * @throws IllegalArgumentException naming {@code source} if {@code key} is empty, too short or long,
     *                                  or contains characters that don't belong in an HTTP header
     */
    static String validate(String key, String source) {
        if (key.isEmpty()) {
            throw new IllegalArgumentException(source + " is empty");
        }
        if (key.length() < MIN_KEY_LENGTH || key.length() > MAX_KEY_LENGTH) {
            throw new IllegalArgumentException(source + " must hold a key of " + MIN_KEY_LENGTH + "-"
                    + MAX_KEY_LENGTH + " characters");
        }
        if (!KEY_CHARACTERS.matcher(key).matches()) {
            throw new IllegalArgumentException(source + " holds characters that can't be sent in an HTTP header");
        }
        return key;
    }

    /** Writes via a temporary file and a rename, so a reader never sees a half-written key. */
    private static void write(Path file, String key) throws IOException {
        Path directory = file.toAbsolutePath().getParent();
        Files.createDirectories(directory);
        boolean posix = directory.getFileSystem().supportedFileAttributeViews().contains("posix");
        FileAttribute<?>[] ownerOnly = posix
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(
                        Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))}
                : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(directory, file.getFileName().toString(), ".tmp", ownerOnly);
        try {
            Files.writeString(temp, key + "\n", StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
