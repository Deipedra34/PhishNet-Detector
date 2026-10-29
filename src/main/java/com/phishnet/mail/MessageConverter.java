package com.phishnet.mail;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Turns a message fetched from a mailbox into the raw RFC 822 bytes that the
 * existing {@link com.phishnet.analyzer.EmailAnalyzer} reads from {@code .eml} files,
 * so monitored mail goes through exactly the same parsing as a scanned file.
 */
public final class MessageConverter {

    /** Messages are analyzed from at most this many bytes; the rest (usually attachments) is skipped. */
    public static final int DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

    /** The message's raw bytes, and whether they were cut off at the size limit. */
    public record RawMessage(byte[] bytes, boolean truncated) {
        public InputStream stream() {
            return new ByteArrayInputStream(bytes);
        }
    }

    private MessageConverter() {
    }

    /**
     * Writes {@code message} out as RFC 822 text, keeping at most {@code maxBytes}.
     * Headers and text parts come first in a message, so a cut-off message still
     * gives the analyzer its sender, subject, and body links.
     *
     * @throws MessagingException if the message can't be read (e.g. the connection dropped)
     * @throws IOException        if reading its content fails
     */
    public static RawMessage toRaw(Message message, int maxBytes) throws MessagingException, IOException {
        BoundedOutputStream out = new BoundedOutputStream(maxBytes);
        message.writeTo(out);
        return new RawMessage(out.toByteArray(), out.truncated);
    }

    /** Keeps the first {@code limit} bytes written and silently drops the rest. */
    private static final class BoundedOutputStream extends OutputStream {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final int limit;
        private boolean truncated;

        BoundedOutputStream(int limit) {
            this.limit = limit;
        }

        @Override
        public void write(int b) {
            if (buffer.size() < limit) {
                buffer.write(b);
            } else {
                truncated = true;
            }
        }

        @Override
        public void write(byte[] b, int off, int len) {
            int room = limit - buffer.size();
            if (len > room) {
                truncated = true;
            }
            if (room > 0) {
                buffer.write(b, off, Math.min(len, room));
            }
        }

        byte[] toByteArray() {
            return buffer.toByteArray();
        }
    }
}
