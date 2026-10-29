package com.phishnet.mail;

/** Mailbox access protocols the monitor supports. */
public enum MailProtocol {
    /** Near-real-time with IDLE, polling otherwise; supports flagging and moving messages. */
    IMAP,
    /** Polling only, read-only: POP3 has no IDLE, no flags, and no folders. */
    POP3
}
