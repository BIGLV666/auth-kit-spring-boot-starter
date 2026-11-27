package io.github.biglv666.authkit.guard;

import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.exception.LoginLockedException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LoginAttemptGuardAuditTest {

    private final List<AuthKitAuditEvent> events = new CopyOnWriteArrayList<>();

    @Test
    void counterModeAuditsFailureAndLockout() {
        LoginAttemptGuard guard = new LoginAttemptGuard(new InMemoryAttemptStore(), 2, 60_000, "test");
        guard.setAuditListener(events::add);

        guard.recordFailure("alice");
        assertEquals(AuthKitAuditEvent.Action.LOGIN_FAILURE, events.get(0).getAction());
        assertEquals("alice", events.get(0).getIdentifier());

        guard.recordFailure("alice");
        assertThrows(LoginLockedException.class, () -> guard.check("alice"));
        assertEquals(AuthKitAuditEvent.Action.LOCKED_OUT, events.get(events.size() - 1).getAction());
    }

    @Test
    void riskControlModeAuditsFailureEvenThoughCounterIsConsumedInCheck() {
        RiskControlPolicy policy = new RiskControlPolicy(
                60_000, 1, List.of(60_000L), 3_600_000, 7_200_000, true);
        LoginAttemptGuard guard = new LoginAttemptGuard(
                new InMemoryRiskControlStore(), policy, "test", true);
        guard.setAuditListener(events::add);

        guard.check("bob");
        guard.recordFailure("bob");
        assertEquals(AuthKitAuditEvent.Action.LOGIN_FAILURE, events.get(events.size() - 1).getAction());

        assertThrows(LoginLockedException.class, () -> guard.check("bob"));
        assertEquals(AuthKitAuditEvent.Action.LOCKED_OUT, events.get(events.size() - 1).getAction());
    }
}
