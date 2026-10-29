package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;
import com.phishnet.mail.FakeMailSource;
import com.phishnet.mail.MailProtocol;
import com.phishnet.mail.MailServerSettings;
import com.phishnet.mail.MailServerSettings.Security;
import com.phishnet.mail.MonitorActions;
import com.phishnet.model.RiskLevel;
import jakarta.mail.AuthenticationFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.phishnet.mail.FakeMailSource.HIGH_RISK_EML;
import static com.phishnet.mail.FakeMailSource.LOW_RISK_EML;
import static com.phishnet.mail.FakeMailSource.arrives;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code phishnet monitor} end to end, against {@link FakeMailSource} instead of a
 * mail server: the environment, the password prompt, and the clock are injected,
 * and history goes to a JUnit temp directory.
 */
class MonitorCommandTest {

    private record Captured(int exitCode, String stdout, String stderr) {
        String all() {
            return stdout + stderr;
        }
    }

    private static final String PASSWORD = "hunter2-app-password";

    @TempDir
    Path tempDir;

    private final Map<String, String> env = new HashMap<>();
    private final List<MailServerSettings> connectedWith = new ArrayList<>();
    private final List<MonitorActions> actionsUsed = new ArrayList<>();
    private FakeMailSource source;
    private char[] promptAnswer;
    private String promptShown;
    private Path csv;
    private Path db;

    @BeforeEach
    void setUp() {
        source = new FakeMailSource();
        csv = tempDir.resolve("history.csv");
        db = tempDir.resolve("history.db");
        env.put(MonitorCommand.PASSWORD_ENV, PASSWORD);
    }

    private Captured monitor(String... args) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            MonitorCommand command = new MonitorCommand(out, err, env,
                    prompt -> {
                        promptShown = prompt;
                        return promptAnswer == null ? null : promptAnswer.clone();
                    },
                    (settings, actions) -> {
                        connectedWith.add(settings);
                        actionsUsed.add(actions);
                        return source;
                    },
                    Clock.fixed(Instant.parse("2026-10-29T12:00:00Z"), ZoneOffset.UTC), false);
            CommandLine cmd = Main.monitorCommandLine(command);
            cmd.setOut(new PrintWriter(out, true, StandardCharsets.UTF_8));
            cmd.setErr(new PrintWriter(err, true, StandardCharsets.UTF_8));
            int code = cmd.execute(args);
            return new Captured(code, outBytes.toString(StandardCharsets.UTF_8), errBytes.toString(StandardCharsets.UTF_8));
        }
    }

    /** The usual options (IMAP over TLS, history in the temp dir, no colors) plus {@code extra}. */
    private String[] args(String... extra) {
        List<String> all = new ArrayList<>(List.of("--host", "imap.example.com", "--username", "alice@example.com",
                "--ssl", "--history-file", csv.toString(), "--history-db", db.toString(), "--no-color"));
        all.addAll(Arrays.asList(extra));
        return all.toArray(String[]::new);
    }

    private List<HistoryEntry> dbEntries() throws Exception {
        return new HistoryDatabase(db, false, new PrintStream(new ByteArrayOutputStream()))
                .search(HistoryFilter.recent(0));
    }

    // --- scanning ------------------------------------------------------------------------

    @Test
    void scansNewMailAndRecordsSuspiciousMessages() throws Exception {
        source.existing(HIGH_RISK_EML).then(arrives(LOW_RISK_EML, HIGH_RISK_EML));

        Captured result = monitor(args());

        assertEquals(0, result.exitCode(), result.stderr());
        String out = result.stdout();
        assertTrue(out.contains("PhishNet is monitoring INBOX on imap.example.com:993 (IMAP over TLS) as alice@example.com"), out);
        assertTrue(out.contains("Read-only: the mailbox is never changed."), out);
        assertTrue(out.contains("[12:00:00] Connected. Waiting for new mail (IMAP IDLE - near real time)."), out);
        assertTrue(out.contains("From: Alice <alice@example.com>  Subject: Lunch on Friday?"), out);
        assertTrue(out.contains("✗ HIGH 85/100  From: PayPal <alert@random-mailer.info>  Subject: Verify immediately"), out);
        assertTrue(out.contains("[senderMismatch]"), out);
        assertTrue(out.contains("Actions: recorded in scan history"), out);
        assertTrue(out.contains("Monitoring stopped. Scanned 2 message(s), 1 suspicious."), out);

        // Only the suspicious message is recorded, in both histories, labelled by mailbox and UID.
        List<String> rows = Files.readAllLines(csv);
        assertEquals(2, rows.size(), rows.toString());
        assertTrue(rows.get(1).contains("fake://INBOX;UID=3,EMAIL,85,HIGH"), rows.get(1));
        List<HistoryEntry> entries = dbEntries();
        assertEquals(1, entries.size());
        assertEquals("Verify immediately", entries.get(0).subject());
        assertEquals(HistoryWriter.TargetType.EMAIL, entries.get(0).type());
    }

    @Test
    void connectsWithTheRequestedSettings() {
        monitor(args("--folder", "Work", "--poll-interval", "30"));

        MailServerSettings settings = connectedWith.get(0);
        assertEquals(MailProtocol.IMAP, settings.protocol());
        assertEquals("imap.example.com", settings.host());
        assertEquals(993, settings.port());
        assertEquals("alice@example.com", settings.username());
        assertEquals(PASSWORD, settings.password());
        assertEquals(Security.SSL, settings.security());
        assertEquals("Work", settings.folder());
        assertFalse(actionsUsed.get(0).mutatesMailbox(), "read-only unless opted in");
    }

    @Test
    void passwordIsNeverPrintedOrRecorded() throws Exception {
        source.then(arrives(HIGH_RISK_EML, LOW_RISK_EML));

        Captured result = monitor(args("--verbose", "--record-all"));

        assertEquals(0, result.exitCode());
        assertFalse(result.all().contains(PASSWORD));
        assertFalse(Files.readString(csv).contains(PASSWORD));
        assertFalse(new String(Files.readAllBytes(db), StandardCharsets.ISO_8859_1).contains(PASSWORD));
    }

    @Test
    void optInActionsFlagAndMoveSuspiciousMail() {
        source.then(arrives(LOW_RISK_EML, HIGH_RISK_EML));

        Captured result = monitor(args("--flag-suspicious", "--move-to-folder", "Suspicious"));

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(actionsUsed.get(0).mutatesMailbox());
        assertTrue(result.stdout().contains(
                "Suspicious mail (MEDIUM and HIGH risk) is flagged and moved to \"Suspicious\"."), result.stdout());
        assertEquals(List.of("2"), source.flagged);
        assertEquals(List.of("2->Suspicious"), source.moved);
        assertTrue(result.stdout().contains("Actions: recorded in scan history, flagged, moved to \"Suspicious\""));
    }

    @Test
    void actOnHighLeavesMediumAlone() {
        monitor(args("--act-on", "high", "--flag-suspicious"));

        assertEquals(RiskLevel.HIGH, actionsUsed.get(0).minLevel());
    }

    @Test
    void quietPrintsOneLinePerMessageAndNothingElse() {
        source.then(arrives(LOW_RISK_EML, HIGH_RISK_EML));

        Captured result = monitor(args("--quiet"));

        List<String> lines = result.stdout().lines().toList();
        assertEquals(2, lines.size(), result.stdout());
        assertTrue(lines.get(0).matches("LOW \\d+ fake://INBOX;UID=1"), lines.get(0));
        assertEquals("HIGH 85 fake://INBOX;UID=2", lines.get(1));
    }

    @Test
    void verboseShowsConnectionAttemptsAndEveryMessagesDetails() {
        source.then(arrives(LOW_RISK_EML));

        String out = monitor(args("-v")).stdout();

        assertTrue(out.contains("Connecting to INBOX on fake.example.com..."), out);
        assertTrue(out.contains("Message: fake://INBOX;UID=1, links inspected: 0"), out);
    }

    @Test
    void controlCharactersInHeadersAreNotEchoedToTheTerminal() {
        source.then(arrives(LOW_RISK_EML.replace("Lunch on Friday?", "Hi\u001b[2J\u001b[31mthere")));

        String out = monitor(args()).stdout();

        assertFalse(out.contains("\u001b"), "escape sequences from a mail header must be stripped");
        assertTrue(out.contains("Subject: Hi [2J [31mthere"), out);
    }

    @Test
    void noHistoryOptionsWriteNothing() {
        source.then(arrives(HIGH_RISK_EML));

        Captured result = monitor("--host", "imap.example.com", "--username", "alice", "--ssl",
                "--no-history", "--no-history-db", "--history-file", csv.toString(), "--history-db", db.toString());

        assertEquals(0, result.exitCode());
        assertFalse(Files.exists(csv));
        assertFalse(Files.exists(db));
        assertFalse(result.stdout().contains("Recording"));
    }

    // --- credentials -------------------------------------------------------------------

    @Test
    void promptsForThePasswordWhenTheEnvironmentHasNone() {
        env.remove(MonitorCommand.PASSWORD_ENV);
        promptAnswer = "typed-secret".toCharArray();

        Captured result = monitor(args());

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals("typed-secret", connectedWith.get(0).password());
        assertTrue(promptShown.contains("alice@example.com on imap.example.com:993"), promptShown);
        assertFalse(result.all().contains("typed-secret"));
    }

    @Test
    void missingPasswordWithoutATerminalIsAUsageError() {
        env.remove(MonitorCommand.PASSWORD_ENV);

        Captured result = monitor(args());

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("No password: set PHISHNET_MAIL_PASSWORD"), result.stderr());
        assertTrue(connectedWith.isEmpty(), "never connects without credentials");
    }

    @Test
    void passwordCannotBeGivenAsAPlainArgumentAndIsNeverEchoed() {
        Captured parsed = monitor(args("--password=hunter2"));
        assertEquals(2, parsed.exitCode());
        assertTrue(connectedWith.isEmpty());

        // Through Main, both spellings are caught before picocli could echo the value.
        for (String[] typed : List.of(
                new String[] {"monitor", "--host", "h", "--username", "u", "--ssl", "--password=hunter2-typed"},
                new String[] {"monitor", "--host", "h", "--username", "u", "--ssl", "--password", "hunter2-typed"})) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (PrintStream stream = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
                assertEquals(2, Main.run(typed, stream, stream, (server, query, timeout) -> {
                    throw new IOException("offline");
                }));
            }
            String output = bytes.toString(StandardCharsets.UTF_8);
            assertTrue(output.contains("--password doesn't take a value"), output);
            assertFalse(output.contains("hunter2-typed"), output);
        }
        assertEquals(null, MonitorCommand.passwordValueError(new String[] {"--password", "--ssl"}));
    }

    @Test
    void usernameCanComeFromTheEnvironment() {
        env.put(MonitorCommand.USERNAME_ENV, "bob@example.com");

        monitor("--host", "imap.example.com", "--ssl", "--no-history", "--no-history-db");

        assertEquals("bob@example.com", connectedWith.get(0).username());
    }

    @Test
    void missingUsernameIsAUsageError() {
        Captured result = monitor("--host", "imap.example.com", "--ssl");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Missing username"), result.stderr());
    }

    @Test
    void rejectedLoginExitsWithAnAppPasswordHint() {
        source.failNextConnect(new AuthenticationFailedException("[AUTHENTICATIONFAILED] Invalid credentials"));

        Captured result = monitor(args());

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("the mail server rejected the login"), result.stderr());
        assertTrue(result.stderr().contains("app password"), result.stderr());
        assertFalse(result.all().contains(PASSWORD));
    }

    // --- options -----------------------------------------------------------------------

    @Test
    void defaultPortsFollowProtocolAndEncryption() {
        monitor("--host", "h", "--username", "u", "--starttls", "--no-history", "--no-history-db");
        monitor("--host", "h", "--username", "u", "--ssl", "--protocol", "pop3", "--no-history", "--no-history-db");
        monitor("--host", "h", "--username", "u", "--ssl", "--port", "1993", "--no-history", "--no-history-db");

        assertEquals(143, connectedWith.get(0).port());
        assertEquals(Security.STARTTLS, connectedWith.get(0).security());
        assertEquals(995, connectedWith.get(1).port());
        assertEquals(MailProtocol.POP3, connectedWith.get(1).protocol());
        assertEquals(1993, connectedWith.get(2).port());
    }

    @Test
    void plaintextNeedsAnExplicitOptInAndWarns() {
        Captured withoutEncryption = monitor("--host", "h", "--username", "u");
        Captured plaintext = monitor("--host", "localhost", "--username", "u", "--allow-plaintext",
                "--no-history", "--no-history-db");

        assertEquals(2, withoutEncryption.exitCode());
        assertTrue(withoutEncryption.stderr().contains("--ssl | --starttls | --allow-plaintext"));
        assertEquals(0, plaintext.exitCode());
        assertTrue(plaintext.stderr().contains("unencrypted"), plaintext.stderr());
        assertTrue(plaintext.stdout().contains("UNENCRYPTED"));
    }

    @Test
    void invalidOptionCombinationsAreUsageErrors() {
        List<String[]> invalid = List.of(
                args("--protocol", "pop3", "--flag-suspicious"),
                args("--protocol", "pop3", "--move-to-folder", "Junk"),
                args("--protocol", "pop3", "--folder", "Work"),
                args("--act-on", "LOW"),
                args("--poll-interval", "4"),
                args("--move-to-folder", "inbox"),
                args("--move-to-folder", " "),
                args("--port", "70000"),
                args("--ssl", "--starttls"));
        for (String[] arguments : invalid) {
            Captured result = monitor(arguments);
            assertEquals(2, result.exitCode(), String.join(" ", arguments) + "\n" + result.stderr());
        }
        assertTrue(connectedWith.isEmpty(), "nothing connects with invalid options");
    }

    @Test
    void mainDispatchesTheMonitorCommand() {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        WhoisClient offline = (server, query, timeout) -> {
            throw new IOException("offline");
        };
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8)) {
            int code = Main.run(new String[] {"monitor", "--help"}, out, out, offline);
            assertEquals(0, code);
        }
        String help = outBytes.toString(StandardCharsets.UTF_8);
        assertTrue(help.contains("phishnet monitor"), help);
        assertTrue(help.contains("--flag-suspicious"));
    }

    // --- reporter formatting ----------------------------------------------------------------

    @Test
    void reporterFormatsConnectionProblems() {
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        MonitorReporter reporter = new MonitorReporter(new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(errBytes, true, StandardCharsets.UTF_8), OutputLevel.NORMAL, false,
                Clock.fixed(Instant.parse("2026-10-29T08:30:15Z"), ZoneOffset.UTC), "polling");

        reporter.connectionLost(new jakarta.mail.MessagingException("Connection reset"), Duration.ofSeconds(8), 3);

        assertEquals("[08:30:15] Connection problem: Connection reset. Reconnecting in 8s (attempt 3)...",
                errBytes.toString(StandardCharsets.UTF_8).strip());
        assertEquals("5m", MonitorReporter.formatDuration(Duration.ofMinutes(5)));
        assertEquals("1m 30s", MonitorReporter.formatDuration(Duration.ofSeconds(90)));
        assertEquals("(none)", MonitorReporter.clean(" \r\n ", "(none)"));
        assertEquals(120, MonitorReporter.clean("x".repeat(500), "").length());
        assertEquals("MessagingException", MonitorReporter.describe(new jakarta.mail.MessagingException()));
    }
}
