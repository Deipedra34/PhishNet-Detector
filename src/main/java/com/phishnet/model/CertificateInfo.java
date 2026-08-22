package com.phishnet.model;

import java.time.Instant;

/**
 * The facts we care about from a TLS certificate, pulled out of a live
 * connection by SslChecker. Kept as a plain holder so tests can build one
 * by hand instead of standing up a real socket or a fake X.509 cert.
 */
public final class CertificateInfo {

    private final String subjectDn;
    private final String issuerDn;
    private final Instant notBefore;
    private final Instant notAfter;
    private final boolean selfSigned;
    private final boolean trustedByDefaultCa;

    public CertificateInfo(String subjectDn, String issuerDn, Instant notBefore, Instant notAfter,
                            boolean selfSigned, boolean trustedByDefaultCa) {
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.selfSigned = selfSigned;
        this.trustedByDefaultCa = trustedByDefaultCa;
    }

    public String subjectDn() {
        return subjectDn;
    }

    public String issuerDn() {
        return issuerDn;
    }

    public Instant notBefore() {
        return notBefore;
    }

    public Instant notAfter() {
        return notAfter;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public boolean isTrustedByDefaultCa() {
        return trustedByDefaultCa;
    }
}
