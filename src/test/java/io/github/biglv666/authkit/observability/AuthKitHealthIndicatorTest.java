package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class AuthKitHealthIndicatorTest {

    @Test
    void remoteProbeTakesPrecedence() {
        Health health = new AuthKitHealthIndicator(
                new InMemorySessionDao(), true,
                () -> Health.up().withDetail("store", "redis").build()).health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals("redis", health.getDetails().get("store"));
    }

    @Test
    void memoryStoreRespectsConfiguration() {
        Health up = new AuthKitHealthIndicator(new InMemorySessionDao(), true, null).health();
        assertEquals(Status.UP, up.getStatus());
        assertEquals("memory", up.getDetails().get("store"));
        assertTrue(up.getDetails().containsKey("warning"));

        Health down = new AuthKitHealthIndicator(new InMemorySessionDao(), false, null).health();
        assertEquals(Status.DOWN, down.getStatus());
    }

    @Test
    void customStoreIsUpWithoutProbe() {
        Health health = new AuthKitHealthIndicator(mock(SessionDao.class), false, null).health();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("custom", health.getDetails().get("store"));
    }
}
