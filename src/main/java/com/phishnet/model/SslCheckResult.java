package com.phishnet.model;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * The output of {@code SslChecker}: whether a certificate was found for a
 * host and, if so, what's suspicious about it.
 */
public final class SslCheckResult {

    private final String host;
    private final boolean certificatePresent;
    private final boolean expired;
    private final boolean selfSigned;
    private final boolean trustedCa;
    private final Instant notAfter;
    private final List<Signal> signals;

    public SslCheckResult(String host, boolean certificatePresent, boolean expired, boolean selfSigned,
                           boolean trustedCa, Instant notAfter, List<Signal> signals) {
        this.host = host;
        this.certificatePresent = certificatePresent;
        this.expired = expired;
        this.selfSigned = selfSigned;
        this.trustedCa = trustedCa;
        this.notAfter = notAfter;
        this.signals = Collections.unmodifiableList(signals);
    }

    public String host() {
        return host;
    }

    public boolean isCertificatePresent() {
        return certificatePresent;
    }

    public boolean isExpired() {
        return expired;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public boolean isTrustedCa() {
        return trustedCa;
    }

    public Instant notAfter() {
        return notAfter;
    }

    public List<Signal> signals() {
        return signals;
    }
}
