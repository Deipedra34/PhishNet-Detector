package com.phishnet.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/**
 * Minimal RFC 3912 WHOIS client: open a TCP connection to port 43, send the
 * query terminated by CRLF, read until the server closes the connection.
 *
 * The timeout is a single deadline covering connect plus the entire read,
 * not a per-read idle timeout - a server that trickles bytes slowly still
 * gets cut off, so one slow lookup can't stall a batch scan.
 */
public final class SocketWhoisClient implements WhoisClient {

    static final int WHOIS_PORT = 43;

    /** Real WHOIS replies are a few KB; anything past this is ignored rather than buffered. */
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    @Override
    public String query(String server, String query, int timeoutMillis) throws IOException {
        long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(server, WHOIS_PORT), timeoutMillis);

            OutputStream out = socket.getOutputStream();
            out.write((query + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();

            InputStream in = socket.getInputStream();
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            while (response.size() < MAX_RESPONSE_BYTES) {
                socket.setSoTimeout(remainingMillis(deadline, server, timeoutMillis));
                int n = in.read(chunk);
                if (n == -1) {
                    break;
                }
                response.write(chunk, 0, n);
            }
            return response.toString(StandardCharsets.UTF_8);
        }
    }

    private static int remainingMillis(long deadline, String server, int timeoutMillis) throws SocketTimeoutException {
        long remaining = (deadline - System.nanoTime()) / 1_000_000L;
        if (remaining <= 0) {
            throw new SocketTimeoutException("no complete reply from " + server + " within " + timeoutMillis + " ms");
        }
        return (int) remaining;
    }
}
