package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthKitHealthIndicatorTest {

    @Test
    void redisPingUp() {
        RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        RedisConnection connection = mock(RedisConnection.class);
        when(factory.getConnection()).thenReturn(connection);
        when(connection.ping()).thenReturn("PONG");

        Health health = new AuthKitHealthIndicator(factory, mock(SessionDao.class), true).health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals("redis", health.getDetails().get("store"));
        verify(connection).close();
    }

    @Test
    void redisFailureIsDownAndDoesNotLeakDetails() {
        RedisConnectionFactory factory = mock(RedisConnectionFactory.class);
        RedisConnection connection = mock(RedisConnection.class);
        when(factory.getConnection()).thenReturn(connection);
        when(connection.ping()).thenThrow(new IllegalStateException("redis://user:secret@host unreachable"));

        Health health = new AuthKitHealthIndicator(factory, mock(SessionDao.class), true).health();

        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("redis", health.getDetails().get("store"));
        assertFalse(health.getDetails().toString().contains("secret"),
                "健康详情不得回显连接串/凭证");
    }

    @Test
    void memoryStoreRespectsConfiguration() {
        Health up = new AuthKitHealthIndicator(null, new InMemorySessionDao(), true).health();
        assertEquals(Status.UP, up.getStatus());
        assertEquals("memory", up.getDetails().get("store"));
        assertTrue(up.getDetails().containsKey("warning"));

        Health down = new AuthKitHealthIndicator(null, new InMemorySessionDao(), false).health();
        assertEquals(Status.DOWN, down.getStatus());
    }

    @Test
    void customStoreIsUpWithoutProbe() {
        Health health = new AuthKitHealthIndicator(null, mock(SessionDao.class), false).health();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("custom", health.getDetails().get("store"));
    }
}
