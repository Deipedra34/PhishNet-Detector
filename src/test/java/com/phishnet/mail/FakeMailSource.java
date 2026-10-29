package com.phishnet.mail;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Properties;

/**
 * An in-memory mailbox standing in for an IMAP server, scripted by tests: messages
 * "arrive" when {@link #awaitNewMail} runs a scripted step, connections can be made to
 * fail, and every flag/move/connect call is recorded. When the script runs out,
 * {@code awaitNewMail} throws {@link InterruptedException}, which ends the monitor
 * like Ctrl+C would - so a test's run always terminates.
 */
public final class FakeMailSource implements MailSource {

    /** One scripted step of {@link #awaitNewMail}. */
    public interface Step {
        void run(FakeMailSource source) throws MessagingException, InterruptedException;
    }

    public static final String HIGH_RISK_EML = """
            From: "PayPal" <alert@random-mailer.info>\r
            To: victim@example.com\r
            Subject: Verify immediately\r
            Content-Type: text/plain; charset=UTF-8\r
            \r
            Your account will be suspended. Verify immediately: http://192.168.1.1/login\r
            """;

    public static final String LOW_RISK_EML = """
            From: Alice <alice@example.com>\r
            To: bob@example.com\r
            Subject: Lunch on Friday?\r
            Content-Type: text/plain; charset=UTF-8\r
            \r
            Want to grab lunch on Friday? The usual place at noon.\r
            """;

    private final List<IncomingMail> mailbox = new ArrayList<>();
    private final Deque<Exception> connectFailures = new ArrayDeque<>();
    private final Deque<Step> steps = new ArrayDeque<>();
    private long nextUid = 1;
    private long acknowledged;
    private boolean connected;
    private boolean everConnected;
    private String notice;

    public final List<String> flagged = new ArrayList<>();
    public final List<String> moved = new ArrayList<>();
    public int connects;
    public int closes;
    public boolean wokenUp;
    public MessagingException flagFailure;
    public MoveOutcome moveOutcome = MoveOutcome.MOVED;

    // --- scripting ------------------------------------------------------------------

    /** Mail already in the mailbox before monitoring starts (must not be scanned). */
    public FakeMailSource existing(String eml) {
        deliver(eml);
        return this;
    }

    public FakeMailSource failNextConnect(Exception error) {
        connectFailures.add(error);
        return this;
    }

    public FakeMailSource then(Step step) {
        steps.add(step);
        return this;
    }

    /** A step that delivers new mail. */
    public static Step arrives(String... emls) {
        return source -> {
            for (String eml : emls) {
                source.deliver(eml);
            }
        };
    }

    /** A step that delivers a message whose content can't be read with this error. */
    public static Step arrivesBroken(Exception readError) {
        return source -> source.add(new BrokenMessage(readError));
    }

    /** A step that delivers a message whose first read fails with {@code firstReadError}, later reads work. */
    public static Step arrivesFlaky(Exception firstReadError, String eml) {
        return source -> source.add(new FlakyMessage(firstReadError, eml));
    }

    /** A step where the connection drops. */
    public static Step connectionDrops() {
        return source -> {
            source.connected = false;
            throw new jakarta.mail.StoreClosedException(null, "connection reset");
        };
    }

    public void setNotice(String notice) {
        this.notice = notice;
    }

    public void deliver(String eml) {
        add(mime(eml));
    }

    private void add(Message message) {
        long uid = nextUid++;
        mailbox.add(new IncomingMail(Long.toString(uid), "fake://INBOX;UID=" + uid, message));
    }

    public static MimeMessage mime(String eml) {
        try {
            return new MimeMessage(Session.getInstance(new Properties()),
                    new ByteArrayInputStream(eml.getBytes(StandardCharsets.UTF_8)));
        } catch (MessagingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // --- MailSource ---------------------------------------------------------------------

    @Override
    public void connect() throws MessagingException {
        connects++;
        Exception failure = connectFailures.poll();
        if (failure instanceof MessagingException me) {
            throw me;
        }
        if (failure instanceof RuntimeException re) {
            throw re;
        }
        if (!everConnected) {
            acknowledged = nextUid - 1; // baseline: existing mail counts as seen
            everConnected = true;
        }
        connected = true;
    }

    @Override
    public List<IncomingMail> fetchNew() throws MessagingException {
        requireConnected();
        List<IncomingMail> fresh = new ArrayList<>();
        for (IncomingMail mail : mailbox) {
            if (Long.parseLong(mail.id()) > acknowledged) {
                fresh.add(mail);
            }
        }
        return fresh;
    }

    @Override
    public void acknowledge(IncomingMail mail) {
        acknowledged = Math.max(acknowledged, Long.parseLong(mail.id()));
    }

    @Override
    public void awaitNewMail(Duration pollInterval) throws MessagingException, InterruptedException {
        requireConnected();
        Step step = steps.poll();
        if (step == null) {
            throw new InterruptedException("script finished");
        }
        step.run(this);
    }

    @Override
    public boolean supportsIdle() {
        return true;
    }

    @Override
    public void flagSuspicious(IncomingMail mail) throws MessagingException {
        if (flagFailure != null) {
            throw flagFailure;
        }
        flagged.add(mail.id());
    }

    @Override
    public MoveOutcome move(IncomingMail mail, String folder) {
        moved.add(mail.id() + "->" + folder);
        return moveOutcome;
    }

    @Override
    public void wakeUp() {
        wokenUp = true;
    }

    @Override
    public void close() {
        closes++;
        connected = false;
    }

    @Override
    public String describe() {
        return "INBOX on fake.example.com";
    }

    @Override
    public String takeNotice() {
        String current = notice;
        notice = null;
        return current;
    }

    public long acknowledgedUid() {
        return acknowledged;
    }

    private void requireConnected() throws MessagingException {
        if (!connected) {
            throw new jakarta.mail.StoreClosedException(null, "not connected");
        }
    }

    /** A message that fails to be read once, then reads normally. */
    private static final class FlakyMessage extends MimeMessage {
        private Exception firstReadError;

        FlakyMessage(Exception firstReadError, String eml) throws MessagingException {
            super(Session.getInstance(new Properties()), new ByteArrayInputStream(eml.getBytes(StandardCharsets.UTF_8)));
            this.firstReadError = firstReadError;
        }

        @Override
        public void writeTo(java.io.OutputStream os) throws IOException, MessagingException {
            Exception error = firstReadError;
            firstReadError = null;
            if (error instanceof IOException io) {
                throw io;
            }
            if (error instanceof MessagingException me) {
                throw me;
            }
            super.writeTo(os);
        }
    }

    /** A message whose content can't be read. */
    private static final class BrokenMessage extends MimeMessage {
        private final Exception readError;

        BrokenMessage(Exception readError) {
            super(Session.getInstance(new Properties()));
            this.readError = readError;
        }

        @Override
        public void writeTo(java.io.OutputStream os) throws IOException, MessagingException {
            if (readError instanceof IOException io) {
                throw io;
            }
            if (readError instanceof MessagingException me) {
                throw me;
            }
            throw (RuntimeException) readError;
        }

        @Override
        public InputStream getInputStream() throws MessagingException {
            throw new MessagingException("unreadable");
        }
    }
}
