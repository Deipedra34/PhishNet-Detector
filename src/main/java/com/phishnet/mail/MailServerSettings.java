package com.phishnet.mail;

import java.util.Locale;
import java.util.Objects;
import java.util.Properties;

/**
 * Where and how to log in to the monitored mailbox.
 *
 * <p>The password (or OAuth2 access token) is only ever handed to the mail
 * server: {@link #toString()} redacts it, and it is not part of
 * {@link #sessionProperties()}, so it can't end up in a log line, an exception
 * message, or the scan history.
 *
 * @param protocol IMAP or POP3
 * @param host     mail server host name
 * @param port     server port
 * @param username login name
 * @param password password, app password, or (with {@code oauth2}) access token
 * @param security how the connection is encrypted
 * @param folder   folder to watch (IMAP only; POP3 only has INBOX)
 * @param oauth2   authenticate with SASL XOAUTH2, using {@code password} as the access token
 */
public record MailServerSettings(MailProtocol protocol, String host, int port, String username, String password,
                                 Security security, String folder, boolean oauth2) {

    /** Connection encryption. */
    public enum Security {
        /** TLS from the first byte (IMAPS / POP3S, usually ports 993 / 995). */
        SSL,
        /** Plain connection upgraded with STARTTLS before logging in; refuses to continue without it. */
        STARTTLS,
        /** No encryption at all - only for a local test server. */
        NONE
    }

    public static final String DEFAULT_FOLDER = "INBOX";

    /** Socket connect timeout. */
    static final int CONNECT_TIMEOUT_MILLIS = 30_000;

    /**
     * Socket read timeout. Kept longer than {@link ImapMailSource#IDLE_REFRESH} so a quiet
     * IDLE isn't mistaken for a dead connection, while a dead one is still noticed.
     */
    static final int READ_TIMEOUT_MILLIS = 5 * 60_000 + 60_000;

    public MailServerSettings {
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(security, "security");
        folder = folder == null || folder.isBlank() ? DEFAULT_FOLDER : folder;
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("port must be 1-65535, got " + port);
        }
    }

    /** The usual port for this protocol and encryption: 993/143 for IMAP, 995/110 for POP3. */
    public static int defaultPort(MailProtocol protocol, Security security) {
        boolean ssl = security == Security.SSL;
        return switch (protocol) {
            case IMAP -> ssl ? 993 : 143;
            case POP3 -> ssl ? 995 : 110;
        };
    }

    /** Jakarta Mail store protocol name: imap, imaps, pop3, or pop3s. */
    String storeProtocol() {
        String base = protocol.name().toLowerCase(Locale.ROOT);
        return security == Security.SSL ? base + "s" : base;
    }

    /**
     * Jakarta Mail session properties for this server: timeouts, certificate host-name
     * checking, STARTTLS enforcement, and XOAUTH2 when requested. Contains no credentials.
     */
    public Properties sessionProperties() {
        String p = "mail." + storeProtocol() + ".";
        Properties props = new Properties();
        props.setProperty(p + "connectiontimeout", String.valueOf(CONNECT_TIMEOUT_MILLIS));
        props.setProperty(p + "timeout", String.valueOf(READ_TIMEOUT_MILLIS));
        if (security == Security.SSL) {
            props.setProperty(p + "ssl.checkserveridentity", "true");
        }
        if (security == Security.STARTTLS) {
            props.setProperty(p + "starttls.enable", "true");
            props.setProperty(p + "starttls.required", "true");
            props.setProperty(p + "ssl.checkserveridentity", "true");
        }
        if (protocol == MailProtocol.IMAP) {
            // Read messages without setting \Seen: the monitor must not change what the
            // user sees as unread, whether or not the folder is opened read-write.
            props.setProperty(p + "peek", "true");
        }
        if (oauth2) {
            props.setProperty(p + "auth.mechanisms", "XOAUTH2");
            props.setProperty(p + "auth.login.disable", "true");
            props.setProperty(p + "auth.plain.disable", "true");
        }
        return props;
    }

    /** "imap.example.com:993 (IMAP over TLS)" - for status lines. */
    public String describe() {
        String transport = switch (security) {
            case SSL -> "over TLS";
            case STARTTLS -> "with STARTTLS";
            case NONE -> "UNENCRYPTED";
        };
        return host + ":" + port + " (" + protocol + " " + transport + ")";
    }

    @Override
    public String toString() {
        return "MailServerSettings[protocol=" + protocol + ", host=" + host + ", port=" + port
                + ", username=" + username + ", password=<redacted>, security=" + security
                + ", folder=" + folder + ", oauth2=" + oauth2 + "]";
    }
}
