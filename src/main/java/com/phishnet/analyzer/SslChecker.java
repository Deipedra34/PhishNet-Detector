package com.phishnet.analyzer;

import com.phishnet.model.CertificateInfo;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.model.SslCheckResult;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Checks a host's TLS certificate: does it have one, is it expired, is it
 * self-signed or otherwise not trusted by the platform's CA store.
 *
 * check() does the actual socket work, then hands off to analyze() for the
 * real decision-making. analyze() only takes a plain CertificateInfo, so it
 * can be tested with made-up data without touching a real socket or cert.
 */
public final class SslChecker {

    private final int connectTimeoutMillis;

    public SslChecker() {
        this(5000);
    }

    public SslChecker(int connectTimeoutMillis) {
        this.connectTimeoutMillis = connectTimeoutMillis;
    }

    /**
     * Connects to {@code host:port} over TLS, extracts the leaf certificate's
     * facts, and evaluates them. Returns a result with
     * {@code certificatePresent = false} if no TLS connection could be
     * established at all (host unreachable, connection refused, timeout).
     */
    public SslCheckResult check(String host, int port) {
        try {
            CertificateInfo info = fetchCertificateInfo(host, port);
            return analyze(host, info);
        } catch (IOException | GeneralSecurityException e) {
            List<Signal> signals = new ArrayList<>();
            signals.add(new Signal("sslMissing", SignalCategory.SSL,
                    "Could not establish a TLS connection or retrieve a certificate",
                    e.getMessage()));
            return new SslCheckResult(host, false, false, false, false, null, signals);
        }
    }

    /** Given the cert facts, works out which signals apply. No I/O, easy to test. */
    public SslCheckResult analyze(String host, CertificateInfo info) {
        List<Signal> signals = new ArrayList<>();

        boolean expired = info.notAfter() != null && Instant.now().isAfter(info.notAfter());
        if (expired) {
            signals.add(new Signal("sslExpired", SignalCategory.SSL,
                    "TLS certificate has expired", "notAfter=" + info.notAfter()));
        }

        if (info.isSelfSigned()) {
            signals.add(new Signal("sslSelfSigned", SignalCategory.SSL,
                    "TLS certificate is self-signed", info.subjectDn()));
        } else if (!info.isTrustedByDefaultCa()) {
            signals.add(new Signal("sslUntrustedCa", SignalCategory.SSL,
                    "TLS certificate was not issued by a trusted certificate authority",
                    info.issuerDn()));
        }

        return new SslCheckResult(host, true, expired, info.isSelfSigned(), info.isTrustedByDefaultCa(),
                info.notAfter(), signals);
    }

    // --- network I/O (excluded from unit tests) -----------------------------

    private CertificateInfo fetchCertificateInfo(String host, int port) throws IOException, GeneralSecurityException {
        X509Certificate leaf = fetchLeafCertificate(host, port);
        boolean trusted = isTrustedByDefaultCa(leaf);
        boolean selfSigned = leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal());
        return new CertificateInfo(
                leaf.getSubjectX500Principal().getName(),
                leaf.getIssuerX500Principal().getName(),
                leaf.getNotBefore().toInstant(),
                leaf.getNotAfter().toInstant(),
                selfSigned,
                trusted);
    }

    private X509Certificate fetchLeafCertificate(String host, int port) throws IOException, GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new TrustEverythingManager()}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), connectTimeoutMillis);
            socket.setSoTimeout(connectTimeoutMillis);
            socket.startHandshake();
            SSLSession session = socket.getSession();
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
                throw new SSLPeerUnverifiedException("No X.509 certificate presented by " + host);
            }
            return (X509Certificate) chain[0];
        }
    }

    private boolean isTrustedByDefaultCa(X509Certificate leaf) {
        try {
            SSLContext defaultContext = SSLContext.getInstance("TLS");
            defaultContext.init(null, null, null); // platform default trust manager
            javax.net.ssl.TrustManagerFactory tmf =
                    javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((java.security.KeyStore) null);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    ((X509TrustManager) tm).checkServerTrusted(new X509Certificate[]{leaf}, "RSA");
                    return true;
                }
            }
            return false;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Accepts any certificate chain so we can inspect it ourselves; trust is evaluated separately. */
    private static final class TrustEverythingManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
