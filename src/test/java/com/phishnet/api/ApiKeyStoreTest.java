package com.phishnet.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ApiKeyStoreTest {

    @TempDir
    Path tempDir;

    private Path keyFile() {
        return tempDir.resolve("nested").resolve("api-key");
    }

    @Test
    void generatedKeysAreLongRandomAndHeaderSafe() {
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            String key = ApiKeyStore.generate();
            assertEquals(43, key.length(), "32 random bytes in URL-safe base64");
            assertTrue(key.matches("[A-Za-z0-9_-]+"), key);
            keys.add(key);
        }
        assertEquals(100, keys.size());
    }

    @Test
    void firstRunCreatesTheKeyFileAndLaterRunsReuseIt() throws IOException {
        ApiKeyStore.LoadedKey first = ApiKeyStore.loadOrCreate(keyFile(), null);
        ApiKeyStore.LoadedKey second = ApiKeyStore.loadOrCreate(keyFile(), null);

        assertEquals(ApiKeyStore.Source.CREATED, first.source());
        assertEquals(ApiKeyStore.Source.FILE, second.source());
        assertEquals(first.key(), second.key());
        assertEquals(first.key() + "\n", Files.readString(keyFile()));
        try (var files = Files.list(keyFile().getParent())) {
            assertEquals(1, files.count(), "no temporary file left behind");
        }
    }

    @Test
    void keyFileIsReadableByItsOwnerOnly() throws IOException {
        assumeTrue(tempDir.getFileSystem().supportedFileAttributeViews().contains("posix"),
                "POSIX permissions only exist on Linux/macOS");

        ApiKeyStore.loadOrCreate(keyFile(), null);

        assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(keyFile()));
    }

    @Test
    void environmentVariableWinsAndNothingIsWritten() throws IOException {
        ApiKeyStore.LoadedKey loaded = ApiKeyStore.loadOrCreate(keyFile(), "  from-the-environment-123  ");

        assertEquals("from-the-environment-123", loaded.key());
        assertEquals(ApiKeyStore.Source.ENVIRONMENT, loaded.source());
        assertNull(loaded.file());
        assertFalse(Files.exists(keyFile()));
    }

    @Test
    void blankEnvironmentVariableFallsBackToTheFile() throws IOException {
        assertEquals(ApiKeyStore.Source.CREATED, ApiKeyStore.loadOrCreate(keyFile(), "   ").source());
    }

    @Test
    void unusableKeysAreRejectedWithTheirSource() throws IOException {
        Files.createDirectories(keyFile().getParent());
        for (String content : new String[] {"", "   \n", "short", "has spaces in the middle of it", "x".repeat(300)}) {
            Files.writeString(keyFile(), content);
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> ApiKeyStore.loadOrCreate(keyFile(), null), content);
            assertTrue(error.getMessage().startsWith("API key file " + keyFile()), error.getMessage());
        }
        IllegalArgumentException fromEnv = assertThrows(IllegalArgumentException.class,
                () -> ApiKeyStore.loadOrCreate(keyFile(), "short"));
        assertTrue(fromEnv.getMessage().startsWith(ApiKeyStore.KEY_ENV), fromEnv.getMessage());
    }

    @Test
    void hexOrBase64KeysFromElsewhereAreAccepted() throws IOException {
        Files.createDirectories(keyFile().getParent());
        Files.writeString(keyFile(), "0123456789abcdef0123456789abcdef\r\n");
        assertEquals("0123456789abcdef0123456789abcdef", ApiKeyStore.loadOrCreate(keyFile(), null).key());

        Files.writeString(keyFile(), "c29tZSBiYXNlNjQgc2VjcmV0Kys=");
        assertEquals("c29tZSBiYXNlNjQgc2VjcmV0Kys=", ApiKeyStore.loadOrCreate(keyFile(), null).key());
    }

    @Test
    void regenerateReplacesTheKey() throws IOException {
        String old = ApiKeyStore.loadOrCreate(keyFile(), null).key();

        ApiKeyStore.LoadedKey fresh = ApiKeyStore.regenerate(keyFile());

        assertEquals(ApiKeyStore.Source.REGENERATED, fresh.source());
        assertNotEquals(old, fresh.key());
        assertEquals(fresh.key(), ApiKeyStore.loadOrCreate(keyFile(), null).key());
    }

    @Test
    void toStringNeverShowsTheKey() throws IOException {
        ApiKeyStore.LoadedKey loaded = ApiKeyStore.loadOrCreate(keyFile(), null);

        assertFalse(loaded.toString().contains(loaded.key()));
        assertTrue(loaded.toString().contains("key=<redacted>"));
    }

    @Test
    void defaultLocationIsNextToTheHistoryDatabase() {
        Path path = ApiKeyStore.defaultPath();

        assertEquals("api-key", path.getFileName().toString());
        assertEquals(".phishnet", path.getParent().getFileName().toString());
    }
}
