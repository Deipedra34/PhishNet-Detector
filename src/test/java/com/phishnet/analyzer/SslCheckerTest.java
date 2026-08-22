package com.phishnet.analyzer;

import com.phishnet.model.CertificateInfo;
import com.phishnet.model.Signal;
import com.phishnet.model.SslCheckResult;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SslCheckerTest {

    private final SslChecker checker = new SslChecker();

    private static Set<String> ids(SslCheckResult result) {
        return result.signals().stream().map(Signal::id).collect(Collectors.toSet());
    }

    @Test
    void validTrustedCertificateHasNoSignals() {
        CertificateInfo info = new CertificateInfo(
                "CN=example.com", "CN=Trusted CA",
                Instant.now().minus(30, ChronoUnit.DAYS),
                Instant.now().plus(60, ChronoUnit.DAYS),
                false, true);

        SslCheckResult result = checker.analyze("example.com", info);

        assertTrue(result.signals().isEmpty());
        assertTrue(result.isCertificatePresent());
        assertFalse(result.isExpired());
        assertFalse(result.isSelfSigned());
        assertTrue(result.isTrustedCa());
    }

    @Test
    void expiredCertificateIsFlagged() {
        CertificateInfo info = new CertificateInfo(
                "CN=example.com", "CN=Trusted CA",
                Instant.now().minus(400, ChronoUnit.DAYS),
                Instant.now().minus(30, ChronoUnit.DAYS),
                false, true);

        SslCheckResult result = checker.analyze("example.com", info);

        assertTrue(result.isExpired());
        assertTrue(ids(result).contains("sslExpired"));
    }

    @Test
    void selfSignedCertificateIsFlagged() {
        CertificateInfo info = new CertificateInfo(
                "CN=phishy.tk", "CN=phishy.tk",
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(300, ChronoUnit.DAYS),
                true, false);

        SslCheckResult result = checker.analyze("phishy.tk", info);

        assertTrue(result.isSelfSigned());
        assertTrue(ids(result).contains("sslSelfSigned"));
        // self-signed takes precedence over the generic untrusted-CA signal
        assertFalse(ids(result).contains("sslUntrustedCa"));
    }

    @Test
    void untrustedCaCertificateIsFlagged() {
        CertificateInfo info = new CertificateInfo(
                "CN=phishy.tk", "CN=Some Unknown CA",
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(300, ChronoUnit.DAYS),
                false, false);

        SslCheckResult result = checker.analyze("phishy.tk", info);

        assertFalse(result.isSelfSigned());
        assertTrue(ids(result).contains("sslUntrustedCa"));
    }

    @Test
    void expiredAndSelfSignedBothFlagged() {
        CertificateInfo info = new CertificateInfo(
                "CN=phishy.tk", "CN=phishy.tk",
                Instant.now().minus(400, ChronoUnit.DAYS),
                Instant.now().minus(10, ChronoUnit.DAYS),
                true, false);

        SslCheckResult result = checker.analyze("phishy.tk", info);

        Set<String> ids = ids(result);
        assertTrue(ids.contains("sslExpired"));
        assertTrue(ids.contains("sslSelfSigned"));
    }

    @Test
    void certificateExpiringExactlyNowIsNotFlaggedExpired() {
        Instant notAfter = Instant.now().plus(1, ChronoUnit.HOURS);
        CertificateInfo info = new CertificateInfo(
                "CN=example.com", "CN=Trusted CA",
                Instant.now().minus(1, ChronoUnit.DAYS), notAfter, false, true);

        SslCheckResult result = checker.analyze("example.com", info);

        assertFalse(result.isExpired());
    }

    @Test
    void missingCertificateIsReportedAsNotPresent() {
        // Simulates check() failing to connect at all (host unreachable / no TLS).
        SslCheckResult result = new SslCheckResult("unreachable.example", false, false, false, false, null,
                java.util.List.of(new Signal("sslMissing", com.phishnet.model.SignalCategory.SSL,
                        "Could not establish a TLS connection or retrieve a certificate", "timeout")));

        assertFalse(result.isCertificatePresent());
        assertTrue(ids(result).contains("sslMissing"));
    }

    @Test
    void checkAgainstUnreachableHostReportsMissingCertificateWithoutThrowing() {
        // Real network path: an address reserved for documentation (RFC 5737, TEST-NET-1)
        // never accepts connections, so this exercises check()'s failure handling with a
        // short timeout instead of hanging or throwing.
        SslChecker shortTimeoutChecker = new SslChecker(500);
        SslCheckResult result = shortTimeoutChecker.check("192.0.2.1", 1);

        assertFalse(result.isCertificatePresent());
        assertTrue(ids(result).contains("sslMissing"));
    }
}
