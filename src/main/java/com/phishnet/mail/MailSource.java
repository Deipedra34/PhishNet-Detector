package com.phishnet.mail;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;

import java.time.Duration;
import java.util.List;

/**
 * A mailbox the monitor watches for new mail - IMAP ({@link ImapMailSource}) or
 * POP3 ({@link Pop3MailSource}) in practice, a fake in tests. {@link MailMonitorService}
 * drives it in a loop:
 *
 * <pre>
 * connect()
 * loop: fetchNew() -> scan each -> acknowledge(each) ; awaitNewMail()
 * </pre>
 *
 * Any {@link MessagingException} means the connection is unusable; the service then
 * calls {@link #close()} and, after a backoff delay, {@link #connect()} again. The
 * source keeps its "already seen" position across reconnects, so mail that arrives
 * while disconnected is still picked up, and nothing is scanned twice.
 */
public interface MailSource {

    /** One new message: a stable id, a label for output and history, and the message itself. */
    record IncomingMail(String id, String label, Message message) {
    }

    /** What a move request actually did, since servers differ in what they support. */
    enum MoveOutcome {
        /** Moved with the IMAP MOVE command. */
        MOVED,
        /** Copied, then the original deleted with UID EXPUNGE (servers without MOVE). */
        COPIED_AND_DELETED,
        /**
         * Copied only: the server supports neither MOVE nor UIDPLUS, and a plain EXPUNGE
         * could also remove other messages the user had marked deleted.
         */
        COPIED_ONLY
    }

    /** Connects and logs in (again). On the very first connect, everything already in the mailbox counts as seen. */
    void connect() throws MessagingException;

    /** New messages since the last acknowledged one, oldest first. */
    List<IncomingMail> fetchNew() throws MessagingException;

    /** Marks a message as handled, so it isn't returned by {@link #fetchNew()} again. */
    void acknowledge(IncomingMail mail);

    /**
     * Blocks until new mail may have arrived: with IMAP IDLE until the server reports a
     * change (or a periodic refresh), otherwise for {@code pollInterval}.
     */
    void awaitNewMail(Duration pollInterval) throws MessagingException, InterruptedException;

    /** True once connected to a server that supports IMAP IDLE. */
    boolean supportsIdle();

    /** Adds the \Flagged flag (and the $Phishing keyword where the server allows keywords). */
    void flagSuspicious(IncomingMail mail) throws MessagingException;

    /** Moves the message to {@code folder}, creating the folder if needed. */
    MoveOutcome move(IncomingMail mail, String folder) throws MessagingException;

    /** Interrupts a blocking {@link #awaitNewMail} from another thread (used on shutdown). */
    void wakeUp();

    /** Disconnects; safe to call at any time, repeatedly, and when not connected. */
    void close();

    /** e.g. "INBOX on imap.example.com:993 (IMAP over TLS)". */
    String describe();

    /** Something the user should know that isn't an error, e.g. a mailbox reset; null if none. Cleared on read. */
    default String takeNotice() {
        return null;
    }
}
