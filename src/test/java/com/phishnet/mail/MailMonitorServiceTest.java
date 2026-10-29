package com.phishnet.mail;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.mail.MailMonitorService.Exit;
import com.phishnet.mail.MailMonitorService.ScanResult;
import com.phishnet.mail.MailSource.IncomingMail;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.scoring.RiskScorer;
import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.FolderClosedException;
import jakarta.mail.FolderNotFoundException;
import jakarta.mail.MessageRemovedException;
import jakarta.mail.MessagingException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.phishnet.mail.FakeMailSource.HIGH_RISK_EML;
import static com.phishnet.mail.FakeMailSource.LOW_RISK_EML;
import static com.phishnet.mail.FakeMailSource.arrives;
import static com.phishnet.mail.FakeMailSource.arrivesBroken;
import static com.phishnet.mail.FakeMailSource.arrivesFlaky;
import static com.phishnet.mail.FakeMailSource.connectionDrops;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The monitor loop, driven by {@link FakeMailSource} - no mail server or network involved. */
class MailMonitorServiceTest {

    private static final PhishNetConfig CONFIG = PhishNetConfig.defaultConfig();

    /** Records every listener callback and recorder call, in order. */
    private static final class Events implements MailMonitorService.Listener, MailMonitorService.Recorder {
        final List<String> log = new ArrayList<>();
        final List<ScanResult> scans = new ArrayList<>();
        final List<String> recorded = new ArrayList<>();
        final List<Duration> retryDelays = new ArrayList<>();
        Exception fatal;

        @Override
        public void connecting(String mailbox, int attempt) {
            log.add("connecting#" + attempt);
        }

        @Override
        public void connected(String mailbox, boolean idle) {
            log.add("connected");
        }

        @Override
        public void notice(String message) {
            log.add("notice:" + message);
        }

        @Override
        public void scanned(ScanResult result) {
            scans.add(result);
            log.add("scanned:" + result.mail().id() + ":" + result.score().level());
        }

        @Override
        public void messageFailed(IncomingMail mail, Exception error, boolean skipped) {
            log.add("failed:" + mail.id() + (skipped ? ":skipped" : ":retry"));
        }

        @Override
        public void connectionLost(Exception error, Duration retryIn, int attempt) {
            retryDelays.add(retryIn);
            log.add("lost#" + attempt);
        }

        @Override
        public void fatal(Exception error) {
            fatal = error;
            log.add("fatal");
        }

        @Override
        public void stopped() {
            log.add("stopped");
        }

        @Override
        public void record(IncomingMail mail, com.phishnet.model.EmailAnalysisResult analysis,
                           com.phishnet.model.RiskScore score) {
            recorded.add(mail.id());
        }
    }

    @AfterEach
    void clearInterruptFlag() {
        // run() restores the interrupt that ends a fake script, as it should; don't leak it into the next test.
        Thread.interrupted();
    }

    private final Events events = new Events();
    private final List<Duration> slept = new ArrayList<>();

    private MailMonitorService service(FakeMailSource source, MonitorActions actions) {
        UrlAnalyzer urls = new UrlAnalyzer(CONFIG);
        return new MailMonitorService(source, new EmailAnalyzer(CONFIG, urls), new RiskScorer(CONFIG), actions,
                events, events, Duration.ofSeconds(60), new Backoff(), slept::add, MessageConverter.DEFAULT_MAX_BYTES);
    }

    @Test
    void scansOnlyMailArrivingAfterStartup() {
        FakeMailSource source = new FakeMailSource()
                .existing(HIGH_RISK_EML)
                .then(arrives(LOW_RISK_EML, HIGH_RISK_EML));

        Exit exit = service(source, MonitorActions.readOnly()).run();

        assertEquals(Exit.STOPPED, exit);
        assertEquals(List.of("connecting#1", "connected", "scanned:2:LOW", "scanned:3:HIGH", "stopped"), events.log);
        assertEquals(3, source.acknowledgedUid());
    }

    @Test
    void readOnlyDefaultRecordsSuspiciousMailButNeverTouchesTheMailbox() {
        FakeMailSource source = new FakeMailSource().then(arrives(LOW_RISK_EML, HIGH_RISK_EML));

        service(source, MonitorActions.readOnly()).run();

        assertEquals(List.of("2"), events.recorded, "only the HIGH message is recorded");
        assertTrue(source.flagged.isEmpty());
        assertTrue(source.moved.isEmpty());
        ScanResult high = events.scans.get(1);
        assertTrue(high.plan().suspicious());
        assertEquals(List.of("recorded in scan history"), high.actionsTaken());
        assertFalse(events.scans.get(0).plan().suspicious());
    }

    @Test
    void optedInActionsApplyToSuspiciousMailOnly() {
        FakeMailSource source = new FakeMailSource().then(arrives(LOW_RISK_EML, HIGH_RISK_EML));
        MonitorActions actions = new MonitorActions(RiskLevel.MEDIUM, true, "Suspicious", false);

        service(source, actions).run();

        assertEquals(List.of("2"), source.flagged);
        assertEquals(List.of("2->Suspicious"), source.moved);
        assertEquals(List.of("recorded in scan history", "flagged", "moved to \"Suspicious\""),
                events.scans.get(1).actionsTaken());
        assertTrue(events.scans.get(0).actionsTaken().isEmpty());
    }

    @Test
    void recordAllRecordsLowRiskMailToo() {
        FakeMailSource source = new FakeMailSource().then(arrives(LOW_RISK_EML));

        service(source, new MonitorActions(RiskLevel.MEDIUM, false, null, true)).run();

        assertEquals(List.of("1"), events.recorded);
    }

    @Test
    void copyOnlyMoveIsReportedHonestly() {
        FakeMailSource source = new FakeMailSource().then(arrives(HIGH_RISK_EML));
        source.moveOutcome = MailSource.MoveOutcome.COPIED_ONLY;

        service(source, new MonitorActions(RiskLevel.MEDIUM, false, "Junk", false)).run();

        String action = events.scans.get(0).actionsTaken().get(1);
        assertTrue(action.startsWith("copied to \"Junk\""), action);
    }

    @Test
    void failedActionIsReportedAndMonitoringContinues() {
        FakeMailSource source = new FakeMailSource()
                .then(arrives(HIGH_RISK_EML))
                .then(arrives(LOW_RISK_EML));
        source.flagFailure = new MessagingException("PERMANENTFLAGS doesn't allow it");

        service(source, new MonitorActions(RiskLevel.MEDIUM, true, null, false)).run();

        assertEquals(List.of("flag: PERMANENTFLAGS doesn't allow it"), events.scans.get(0).actionFailures());
        assertEquals("scanned:2:LOW", events.log.get(events.log.size() - 2));
    }

    @Test
    void retriesFailedConnectionsWithGrowingDelays() {
        FakeMailSource source = new FakeMailSource()
                .failNextConnect(new MessagingException("Connection refused"))
                .failNextConnect(new MessagingException("Connection refused"))
                .then(arrives(HIGH_RISK_EML));

        Exit exit = service(source, MonitorActions.readOnly()).run();

        assertEquals(Exit.STOPPED, exit);
        assertEquals(List.of(Duration.ofSeconds(2), Duration.ofSeconds(4)), slept);
        assertEquals(List.of("connecting#1", "lost#1", "connecting#2", "lost#2", "connecting#3", "connected",
                "scanned:1:HIGH", "stopped"), events.log);
    }

    @Test
    void reconnectsAfterADropAndScansMailThatArrivedMeanwhile() {
        FakeMailSource source = new FakeMailSource()
                .then(arrives(LOW_RISK_EML))
                .then(src -> {
                    src.deliver(HIGH_RISK_EML); // arrives just as the connection breaks
                    connectionDrops().run(src);
                });

        service(source, MonitorActions.readOnly()).run();

        assertEquals(List.of("connecting#1", "connected", "scanned:1:LOW", "lost#1", "connecting#2", "connected",
                "scanned:2:HIGH", "stopped"), events.log);
        assertEquals(2, source.connects);
        assertEquals(List.of(Duration.ofSeconds(2)), slept);
    }

    @Test
    void backoffResetsAfterASuccessfulConnection() {
        FakeMailSource source = new FakeMailSource()
                .failNextConnect(new MessagingException("down"))
                .then(connectionDrops());

        service(source, MonitorActions.readOnly()).run();

        // 2s for the failed connect; after connecting, the next drop starts again at 2s, not 4s.
        assertEquals(List.of(Duration.ofSeconds(2), Duration.ofSeconds(2)), slept);
    }

    @Test
    void rejectedLoginStopsWithoutRetrying() {
        FakeMailSource source = new FakeMailSource()
                .failNextConnect(new AuthenticationFailedException("[AUTHENTICATIONFAILED] Invalid credentials"));

        Exit exit = service(source, MonitorActions.readOnly()).run();

        assertEquals(Exit.FATAL_ERROR, exit);
        assertTrue(events.fatal instanceof AuthenticationFailedException);
        assertEquals(1, source.connects);
        assertTrue(slept.isEmpty(), "no retry - repeated failed logins can lock the account");
        assertEquals(List.of("connecting#1", "fatal", "stopped"), events.log);
    }

    @Test
    void missingFolderStopsWithoutRetrying() {
        FakeMailSource source = new FakeMailSource()
                .failNextConnect(new FolderNotFoundException(null, "Folder \"Archive\" doesn't exist"));

        assertEquals(Exit.FATAL_ERROR, service(source, MonitorActions.readOnly()).run());
        assertEquals(1, source.connects);
    }

    @Test
    void messageDeletedBeforeItCouldBeReadIsSkippedQuietly() {
        FakeMailSource source = new FakeMailSource()
                .then(arrivesBroken(new MessageRemovedException("gone")))
                .then(arrives(LOW_RISK_EML));

        service(source, MonitorActions.readOnly()).run();

        assertEquals(List.of("connecting#1", "connected", "scanned:2:LOW", "stopped"), events.log);
    }

    @Test
    void unreadableMessageIsSkippedAfterRepeatedFailures() {
        FakeMailSource source = new FakeMailSource()
                .then(arrivesBroken(new MessagingException("BAD fetch failed")))
                .then(src -> { })
                .then(src -> { })
                .then(arrives(LOW_RISK_EML));

        service(source, MonitorActions.readOnly()).run();

        assertEquals(List.of("connecting#1", "connected", "failed:1:retry", "failed:1:retry", "failed:1:skipped",
                "scanned:2:LOW", "stopped"), events.log);
    }

    @Test
    void connectionLostWhileReadingAMessageTriggersAReconnectAndARetry() {
        // How Angus Mail reports a connection lost mid-download: an IOException wrapping FolderClosedException.
        FakeMailSource source = new FakeMailSource()
                .then(arrivesFlaky(new IOException(new FolderClosedException(null, "lost")), HIGH_RISK_EML));

        service(source, MonitorActions.readOnly()).run();

        assertEquals(List.of("connecting#1", "connected", "lost#1", "connecting#2", "connected", "scanned:1:HIGH",
                "stopped"), events.log);
        assertEquals(List.of("1"), events.recorded, "scanned and recorded exactly once");
    }

    @Test
    void sourceNoticesAreReported() {
        FakeMailSource source = new FakeMailSource();
        source.setNotice("UIDVALIDITY changed");

        service(source, MonitorActions.readOnly()).run();

        assertTrue(events.log.contains("notice:UIDVALIDITY changed"), events.log.toString());
    }

    @Test
    void stopFromAnotherThreadEndsTheLoop() throws Exception {
        CountDownLatch waiting = new CountDownLatch(1);
        FakeMailSource source = new FakeMailSource().then(src -> {
            waiting.countDown();
            Thread.sleep(30_000); // stands in for a long IDLE; stop() interrupts it
        });
        MailMonitorService service = service(source, MonitorActions.readOnly());
        AtomicReference<Exit> exit = new AtomicReference<>();
        Thread thread = new Thread(() -> exit.set(service.run()));
        thread.start();

        assertTrue(waiting.await(5, TimeUnit.SECONDS));
        service.stop();

        assertTrue(service.awaitFinished(Duration.ofSeconds(5)));
        thread.join(5_000);
        assertEquals(Exit.STOPPED, exit.get());
        assertTrue(source.wokenUp);
        assertFalse(service.isRunning());
        assertEquals("stopped", events.log.get(events.log.size() - 1));
    }

    @Test
    void classifiesErrors() {
        assertTrue(MailMonitorService.isFatal(new AuthenticationFailedException("no")));
        assertTrue(MailMonitorService.isFatal(new FolderNotFoundException()));
        assertFalse(MailMonitorService.isFatal(new MessagingException("timeout")));

        assertTrue(MailMonitorService.isConnectionLoss(new IOException(new FolderClosedException(null))));
        assertTrue(MailMonitorService.isConnectionLoss(new MessagingException("x", new java.net.SocketException())));
        assertFalse(MailMonitorService.isConnectionLoss(new MessagingException("BAD command")));

        assertTrue(MailMonitorService.isRemovedMessage(new MessageRemovedException()));
        assertTrue(MailMonitorService.isRemovedMessage(
                new IOException(new MessagingException("No content for expunged message"))));
        assertFalse(MailMonitorService.isRemovedMessage(new IOException("disk full")));
    }
}
