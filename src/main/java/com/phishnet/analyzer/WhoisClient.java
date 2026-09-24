package com.phishnet.analyzer;

import java.io.IOException;

/**
 * Sends one WHOIS query to one server and returns the raw plain-text reply.
 *
 * Exists as an interface purely so {@link DomainAgeChecker} can be tested
 * with canned responses instead of real port-43 sockets - see
 * {@link SocketWhoisClient} for the real implementation.
 */
@FunctionalInterface
public interface WhoisClient {

    /**
     * @param server        WHOIS server hostname, e.g. {@code "whois.verisign-grs.com"}
     * @param query         the query line (normally just the domain name)
     * @param timeoutMillis upper bound for the whole exchange (connect + read)
     * @throws IOException on any network failure, including a timeout
     */
    String query(String server, String query, int timeoutMillis) throws IOException;
}
