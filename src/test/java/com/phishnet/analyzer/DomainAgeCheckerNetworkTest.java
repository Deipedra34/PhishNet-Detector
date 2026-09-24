package com.phishnet.analyzer;

import com.phishnet.model.DomainAgeResult;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-network smoke tests: these open actual port-43 connections to public
 * WHOIS servers, so they're tagged "network" and excluded from the default
 * {@code mvn test} run (see the surefire excludedGroups setting in pom.xml).
 * Run them explicitly with:
 *
 * <pre>mvn test -Dgroups=network -DexcludedGroups=none</pre>
 */
@Tag("network")
class DomainAgeCheckerNetworkTest {

    @Test
    void looksUpARealLongEstablishedComDomain() {
        DomainAgeResult result = new DomainAgeChecker().check("example.com");

        assertTrue(result.isKnown(), result.toString());
        assertTrue(result.ageDays() > 365 * 20, result.toString());
    }

    @Test
    void resolvesAnUncommonTldThroughIana() {
        // .fr isn't in the built-in server table, so this exercises the whois.iana.org referral path
        DomainAgeResult result = new DomainAgeChecker().check("google.fr");

        assertTrue(result.isKnown(), result.toString());
    }
}
