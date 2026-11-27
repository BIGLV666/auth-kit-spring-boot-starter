package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.event.AuthKitSessionEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthKitMetricsTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final AuthKitMetrics metrics = new AuthKitMetrics(registry);

    @Test
    void loginOutcomesAreCountedByBoundedTags() {
        metrics.onAudit(new AuthKitAuditEvent(AuthKitAuditEvent.Action.LOGIN_SUCCESS, "u1", "PC", null));
        metrics.onAudit(new AuthKitAuditEvent(AuthKitAuditEvent.Action.LOGIN_SUCCESS, "u2", "APP", null));
        metrics.onAudit(new AuthKitAuditEvent(AuthKitAuditEvent.Action.LOGIN_FAILURE, "u3", null, null));
        metrics.onAudit(new AuthKitAuditEvent(AuthKitAuditEvent.Action.LOCKED_OUT, "u4", null, "60000"));

        assertEquals(2.0, registry.get(AuthKitMetrics.LOGIN_METRIC)
                .tag("outcome", "success").counter().count());
        assertEquals(1.0, registry.get(AuthKitMetrics.LOGIN_METRIC)
                .tag("outcome", "failure").counter().count());
        assertEquals(1.0, registry.get(AuthKitMetrics.LOGIN_METRIC)
                .tag("outcome", "locked_out").counter().count());
        assertEquals(1.0, registry.get(AuthKitMetrics.LOCKOUT_METRIC).counter().count());
        // 用户标识不得成为指标标签（防止基数爆炸）
        assertTrue(registry.getMeters().stream()
                .flatMap(meter -> meter.getId().getTags().stream())
                .noneMatch(tag -> "userId".equals(tag.getKey())));
    }

    @Test
    void sessionEventsAreCountedByAction() {
        metrics.onSession(new AuthKitSessionEvent("u1", "cred-1", AuthKitSessionEvent.Action.KICKED_OUT));
        metrics.onSession(new AuthKitSessionEvent("u2", "cred-2", AuthKitSessionEvent.Action.KICKED_OUT));
        metrics.onSession(new AuthKitSessionEvent("u3", "cred-3", AuthKitSessionEvent.Action.LOGOUT));

        assertEquals(2.0, registry.get(AuthKitMetrics.SESSION_EVENT_METRIC)
                .tag("action", "kicked_out").counter().count());
        assertEquals(1.0, registry.get(AuthKitMetrics.SESSION_EVENT_METRIC)
                .tag("action", "logout").counter().count());
    }
}
