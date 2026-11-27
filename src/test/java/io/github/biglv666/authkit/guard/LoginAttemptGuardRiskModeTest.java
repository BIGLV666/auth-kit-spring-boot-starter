package io.github.biglv666.authkit.guard;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.exception.LoginLockedException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * risk-control 模式守卫：check 占用尝试额度、recordFailure no-op、成功清窗口、风控升级。
 */
class LoginAttemptGuardRiskModeTest {

    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60L * MINUTE;
    private static final long DAY = 24L * HOUR;

    private final AtomicLong now = new AtomicLong(0);
    private final InMemoryRiskControlStore store = new InMemoryRiskControlStore();

    private LoginAttemptGuard guard(String prefix, boolean enabled) {
        return new LoginAttemptGuard(store, policy(), prefix, enabled, now::get);
    }

    private static RiskControlPolicy policy() {
        return new RiskControlPolicy(5 * MINUTE, 5,
                List.of(5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY),
                6 * HOUR, 7 * DAY, true);
    }

    private static void pass(LoginAttemptGuard guard, String user, int times) {
        for (int i = 0; i < times; i++) {
            guard.check(user);
        }
    }

    @Test
    void allowsMaxAttemptsThenLocks() {
        LoginAttemptGuard guard = guard("test", true);
        pass(guard, "u", 5);

        LoginLockedException e = assertThrows(LoginLockedException.class, () -> guard.check("u"));
        assertEquals(5 * MINUTE, e.getRemainingMillis());
        assertTrue(e.getMessage().contains("风控"));
    }

    @Test
    void recordFailureDoesNotConsumeExtraAttempts() {
        LoginAttemptGuard guard = guard("test", true);
        pass(guard, "u", 3);
        for (int i = 0; i < 10; i++) {
            guard.recordFailure("u");
        }
        pass(guard, "u", 2);
        assertThrows(LoginLockedException.class, () -> guard.check("u"),
                "recordFailure 在 risk-control 模式下不应额外占用额度");
    }

    @Test
    void recordSuccessClearsAttemptWindow() {
        LoginAttemptGuard guard = guard("test", true);
        pass(guard, "u", 4);
        guard.recordSuccess("u");
        pass(guard, "u", 5);
        assertThrows(LoginLockedException.class, () -> guard.check("u"));
    }

    @Test
    void disabledGuardNeverLocks() {
        LoginAttemptGuard guard = guard("test", false);
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> guard.check("u"));
        }
    }

    @Test
    void keyPrefixIsolatesAttempts() {
        LoginAttemptGuard prod = guard("prod", true);
        LoginAttemptGuard dev = guard("dev", true);
        pass(prod, "u", 5);
        assertThrows(LoginLockedException.class, () -> prod.check("u"));
        pass(dev, "u", 5);
        assertThrows(LoginLockedException.class, () -> dev.check("u"));
    }

    @Test
    void lockoutEscalatesAfterExpiry() {
        LoginAttemptGuard guard = guard("test", true);
        pass(guard, "u", 5);
        assertThrows(LoginLockedException.class, () -> guard.check("u"));

        now.set(5 * MINUTE);
        pass(guard, "u", 5);
        LoginLockedException second = assertThrows(LoginLockedException.class, () -> guard.check("u"));
        assertEquals(15 * MINUTE, second.getRemainingMillis());
    }

    @Test
    void usesSeparateKeyNamespaces() {
        RiskControlStore riskStore = mock(RiskControlStore.class);
        when(riskStore.check(anyString(), any(), anyLong())).thenReturn(RiskDecision.allowed(1, 0));
        LoginAttemptGuard riskGuard = new LoginAttemptGuard(riskStore, policy(), "test", true, () -> 0L);
        riskGuard.check("u");
        verify(riskStore).check(eq("test:risk:u"), any(), eq(0L));

        AttemptStore attemptStore = mock(AttemptStore.class);
        when(attemptStore.get(anyString())).thenReturn(0L);
        LoginAttemptGuard counterGuard = new LoginAttemptGuard(attemptStore, 5, 60_000, "test");
        counterGuard.check("u");
        verify(attemptStore).get("test:attempt:u");
    }

    @Test
    void zeroOrNegativeMaxAttemptsDisablesGuard() {
        RiskControlPolicy zero = new RiskControlPolicy(5 * MINUTE, 0,
                List.of(5 * MINUTE), 6 * HOUR, 31 * HOUR, true);
        LoginAttemptGuard zeroGuard = new LoginAttemptGuard(store, zero, "test", true, now::get);
        assertFalse(zeroGuard.isEnabled());
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> zeroGuard.check("u"));
        }

        RiskControlPolicy negative = new RiskControlPolicy(5 * MINUTE, -1,
                List.of(5 * MINUTE), 6 * HOUR, 31 * HOUR, true);
        LoginAttemptGuard negativeGuard = new LoginAttemptGuard(store, negative, "test", true, now::get);
        assertFalse(negativeGuard.isEnabled());
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> negativeGuard.check("u"));
        }
    }
}
