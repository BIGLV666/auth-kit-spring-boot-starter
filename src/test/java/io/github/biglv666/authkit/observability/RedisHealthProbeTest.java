package io.github.biglv666.authkit.observability;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisHealthProbeTest {

    @Test
    void pingUp() {
        RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        RedisConnection connection = mock(RedisConnection.class);
        when(factory.getConnection()).thenReturn(connection);
        when(connection.ping()).thenReturn("PONG");

        Health health = new RedisHealthProbe(factory).get();

        assertEquals(Status.UP, health.getStatus());
        assertEquals("redis", health.getDetails().get("store"));
        verify(connection).close();
    }

    @Test
    void failureIsDownAndDoesNotLeakDetails() {
        RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        RedisConnection connection = mock(RedisConnection.class);
        when(factory.getConnection()).thenReturn(connection);
        when(connection.ping()).thenThrow(new IllegalStateException("redis://user:secret@host unreachable"));

        Health health = new RedisHealthProbe(factory).get();

        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("redis", health.getDetails().get("store"));
        assertFalse(health.getDetails().toString().contains("secret"),
                "健康详情不得回显连接串/凭证");
    }
}
