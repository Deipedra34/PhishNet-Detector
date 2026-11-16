package com.phishnet.queue;

import org.junit.jupiter.api.Test;
import redis.clients.jedis.JedisClientConfig;
import redis.clients.jedis.SslVerifyMode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The Jedis connection settings built from {@link RedisSettings}. */
class RedisSettingsTest {

    private static RedisSettings settings(boolean ssl) {
        return new RedisSettings("redis.example", 6380, null, null, ssl, RedisSettings.DEFAULT_QUEUE);
    }

    @Test
    void tlsIsEnabledThroughSslOptionsWithCertificateChainVerification() {
        JedisClientConfig config = settings(true).clientConfig();

        assertNotNull(config.getSslOptions(), "TLS must be on");
        assertEquals(SslVerifyMode.CA, config.getSslOptions().getSslVerifyMode());
    }

    @Test
    void plainConnectionsHaveNoTls() {
        JedisClientConfig config = settings(false).clientConfig();

        assertNull(config.getSslOptions());
        assertEquals(false, config.isSsl());
    }
}
