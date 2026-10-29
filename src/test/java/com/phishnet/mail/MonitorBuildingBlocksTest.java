package com.phishnet.mail;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.mail.MailServerSettings.Security;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.Signal;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.time.Duration;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Message conversion, the action policy, backoff, and connection settings - all without a mail server. */
class MonitorBuildingBlocksTest {

    private static final PhishNetConfig CONFIG = PhishNetConfig.defaultConfig();
    private static final EmailAnalyzer ANALYZER = new EmailAnalyzer(CONFIG, new UrlAnalyzer(CONFIG));

    // --- message -> EmailAnalyzer conversion -------------------------------------------

    private static List<String> signalIds(EmailAnalysisResult result) {
        return result.allSignals().stream().map(Signal::id).toList();
    }

    @Test
    void fetchedMessageIsAnalyzedExactlyLikeTheSameEmlFile() throws Exception {
        for (String fixture : List.of("phishing_ip_link.eml", "phishing_html_shortener.eml", "legitimate.eml")) {
            byte[] eml;
            try (InputStream in = getClass().getResourceAsStream("/emails/" + fixture)) {
                eml = in.readAllBytes();
            }
            MimeMessage fetched = FakeMailSource.mime(new String(eml, java.nio.charset.StandardCharsets.UTF_8));

            EmailAnalysisResult fromMailbox = ANALYZER.analyze(
                    MessageConverter.toRaw(fetched, MessageConverter.DEFAULT_MAX_BYTES).stream());
            EmailAnalysisResult fromFile = ANALYZER.analyze(new java.io.ByteArrayInputStream(eml));

            assertEquals(fromFile.senderAddress(), fromMailbox.senderAddress(), fixture);
            assertEquals(fromFile.subject(), fromMailbox.subject(), fixture);
            assertEquals(signalIds(fromFile), signalIds(fromMailbox), fixture);
        }
    }

    @Test
    void programmaticallyBuiltMultipartMessageKeepsSenderSubjectAndLinks() throws Exception {
        Properties props = new Properties();
        props.setProperty("mail.host", "localhost"); // saveChanges() would otherwise resolve this machine's name
        MimeMessage message = new MimeMessage(Session.getInstance(props));
        message.setFrom(new InternetAddress("alert@random-mailer.info", "PayPal Security"));
        message.setRecipients(Message.RecipientType.TO, "victim@example.com");
        message.setSubject("Your account is suspended");
        MimeBodyPart text = new MimeBodyPart();
        text.setText("Verify immediately at http://192.168.1.1/login");
        MimeBodyPart html = new MimeBodyPart();
        html.setContent("<a href=\"http://paypa1-secure.tk/x\">Log in</a>", "text/html; charset=UTF-8");
        message.setContent(new MimeMultipart("alternative", text, html));
        message.saveChanges();

        MessageConverter.RawMessage raw = MessageConverter.toRaw(message, MessageConverter.DEFAULT_MAX_BYTES);
        EmailAnalysisResult result = ANALYZER.analyze(raw.stream());

        assertFalse(raw.truncated());
        assertEquals("alert@random-mailer.info", result.senderAddress());
        assertEquals("PayPal Security", result.displayName());
        assertEquals("Your account is suspended", result.subject());
        assertEquals(2, result.linkResults().size());
        assertTrue(signalIds(result).contains("senderMismatch"), signalIds(result).toString());
    }

    @Test
    void oversizedMessageIsTruncatedButHeadersSurvive() throws Exception {
        MimeMessage message = FakeMailSource.mime(FakeMailSource.HIGH_RISK_EML + "x".repeat(5000));

        MessageConverter.RawMessage raw = MessageConverter.toRaw(message, 1000);

        assertTrue(raw.truncated());
        assertEquals(1000, raw.bytes().length);
        assertEquals("Verify immediately", ANALYZER.analyze(raw.stream()).subject());
    }

    // --- action policy ------------------------------------------------------------------

    @Test
    void readOnlyPolicyRecordsSuspiciousMailAndNeverMutates() {
        MonitorActions actions = MonitorActions.readOnly();

        assertFalse(actions.mutatesMailbox());
        assertEquals(new MonitorActions.Plan(false, false, false, null), actions.decide(RiskLevel.LOW));
        assertEquals(new MonitorActions.Plan(true, true, false, null), actions.decide(RiskLevel.MEDIUM));
        assertEquals(new MonitorActions.Plan(true, true, false, null), actions.decide(RiskLevel.HIGH));
    }

    @Test
    void optedInPolicyFlagsAndMovesAtOrAboveTheThreshold() {
        MonitorActions highOnly = new MonitorActions(RiskLevel.HIGH, true, "Suspicious", false);

        assertTrue(highOnly.mutatesMailbox());
        assertFalse(highOnly.decide(RiskLevel.MEDIUM).mutatesMailbox());
        assertFalse(highOnly.decide(RiskLevel.MEDIUM).record());
        MonitorActions.Plan high = highOnly.decide(RiskLevel.HIGH);
        assertTrue(high.flag());
        assertEquals("Suspicious", high.moveTo());
        assertTrue(high.mutatesMailbox());

        MonitorActions flagOnly = new MonitorActions(RiskLevel.MEDIUM, true, null, false);
        assertTrue(flagOnly.decide(RiskLevel.MEDIUM).flag());
        assertNull(flagOnly.decide(RiskLevel.MEDIUM).moveTo());
    }

    @Test
    void recordAllRecordsLowRiskWithoutOtherActions() {
        MonitorActions.Plan low = new MonitorActions(RiskLevel.MEDIUM, true, "Junk", true).decide(RiskLevel.LOW);

        assertEquals(new MonitorActions.Plan(false, true, false, null), low);
    }

    @Test
    void policyRejectsLowThresholdAndBlankFolder() {
        assertThrows(IllegalArgumentException.class, () -> new MonitorActions(RiskLevel.LOW, false, null, false));
        assertThrows(IllegalArgumentException.class, () -> new MonitorActions(RiskLevel.MEDIUM, false, " ", false));
    }

    // --- backoff ------------------------------------------------------------------------

    @Test
    void backoffDoublesUpToTheCapAndResets() {
        Backoff backoff = new Backoff(Duration.ofSeconds(2), Duration.ofSeconds(20));

        assertEquals(List.of(2L, 4L, 8L, 16L, 20L, 20L),
                java.util.stream.Stream.generate(backoff::nextDelay).limit(6).map(Duration::toSeconds).toList());
        assertEquals(6, backoff.attempts());

        backoff.reset();
        assertEquals(0, backoff.attempts());
        assertEquals(Duration.ofSeconds(2), backoff.nextDelay());
    }

    @Test
    void defaultBackoffCapsAtFiveMinutes() {
        Backoff backoff = new Backoff();
        Duration last = Duration.ZERO;
        for (int i = 0; i < 20; i++) {
            last = backoff.nextDelay();
        }
        assertEquals(Duration.ofMinutes(5), last);
    }

    @Test
    void backoffRejectsNonsenseBounds() {
        assertThrows(IllegalArgumentException.class, () -> new Backoff(Duration.ZERO, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new Backoff(Duration.ofSeconds(5), Duration.ofSeconds(1)));
    }

    // --- connection settings ------------------------------------------------------------

    private static MailServerSettings settings(MailProtocol protocol, Security security, boolean oauth2) {
        return new MailServerSettings(protocol, "imap.example.com",
                MailServerSettings.defaultPort(protocol, security), "alice@example.com", "hunter2-secret",
                security, null, oauth2);
    }

    @Test
    void passwordNeverAppearsInToStringOrSessionProperties() {
        for (Security security : Security.values()) {
            MailServerSettings s = settings(MailProtocol.IMAP, security, false);

            assertFalse(s.toString().contains("hunter2-secret"));
            assertTrue(s.toString().contains("password=<redacted>"));
            assertFalse(s.sessionProperties().toString().contains("hunter2-secret"));
            assertFalse(s.describe().contains("hunter2-secret"));
        }
    }

    @Test
    void defaultPortsMatchProtocolAndEncryption() {
        assertEquals(993, MailServerSettings.defaultPort(MailProtocol.IMAP, Security.SSL));
        assertEquals(143, MailServerSettings.defaultPort(MailProtocol.IMAP, Security.STARTTLS));
        assertEquals(995, MailServerSettings.defaultPort(MailProtocol.POP3, Security.SSL));
        assertEquals(110, MailServerSettings.defaultPort(MailProtocol.POP3, Security.NONE));
    }

    @Test
    void sslSettingsCheckTheServerCertificateAndNeverMarkMailRead() {
        Properties props = settings(MailProtocol.IMAP, Security.SSL, false).sessionProperties();

        assertEquals("imaps", settings(MailProtocol.IMAP, Security.SSL, false).storeProtocol());
        assertEquals("true", props.getProperty("mail.imaps.ssl.checkserveridentity"));
        assertEquals("true", props.getProperty("mail.imaps.peek"));
        assertEquals("30000", props.getProperty("mail.imaps.connectiontimeout"));
        assertTrue(Integer.parseInt(props.getProperty("mail.imaps.timeout")) > ImapMailSource.IDLE_REFRESH.toMillis(),
                "the read timeout must outlast one IDLE period");
    }

    @Test
    void starttlsIsRequiredNotJustAttempted() {
        Properties props = settings(MailProtocol.IMAP, Security.STARTTLS, false).sessionProperties();

        assertEquals("imap", settings(MailProtocol.IMAP, Security.STARTTLS, false).storeProtocol());
        assertEquals("true", props.getProperty("mail.imap.starttls.enable"));
        assertEquals("true", props.getProperty("mail.imap.starttls.required"));
    }

    @Test
    void oauth2SelectsXoauth2Only() {
        Properties props = settings(MailProtocol.IMAP, Security.SSL, true).sessionProperties();

        assertEquals("XOAUTH2", props.getProperty("mail.imaps.auth.mechanisms"));
        assertEquals("true", props.getProperty("mail.imaps.auth.plain.disable"));
    }

    @Test
    void pop3SettingsUsePop3Properties() {
        MailServerSettings pop3 = settings(MailProtocol.POP3, Security.SSL, false);

        assertEquals("pop3s", pop3.storeProtocol());
        assertEquals("true", pop3.sessionProperties().getProperty("mail.pop3s.ssl.checkserveridentity"));
        assertNull(pop3.sessionProperties().getProperty("mail.pop3s.peek"));
    }

    @Test
    void settingsValidation() {
        assertEquals("INBOX", settings(MailProtocol.IMAP, Security.SSL, false).folder());
        assertThrows(IllegalArgumentException.class, () -> new MailServerSettings(MailProtocol.IMAP, "h", 0,
                "u", "p", Security.SSL, null, false));
        assertTrue(settings(MailProtocol.IMAP, Security.NONE, false).describe().contains("UNENCRYPTED"));
    }

    @Test
    void sourcesRejectTheWrongProtocol() {
        assertThrows(IllegalArgumentException.class,
                () -> new ImapMailSource(settings(MailProtocol.POP3, Security.SSL, false), MonitorActions.readOnly()));
        assertThrows(IllegalArgumentException.class,
                () -> new Pop3MailSource(settings(MailProtocol.IMAP, Security.SSL, false)));
    }
}
