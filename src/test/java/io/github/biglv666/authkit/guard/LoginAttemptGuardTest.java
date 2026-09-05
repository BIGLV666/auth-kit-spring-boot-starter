package io.github.biglv666.authkit.guard;

import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.exception.LoginLockedException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 登录防爆破守卫单测。
 */
class LoginAttemptGuardTest {

    private final LoginAttemptGuard guard = new LoginAttemptGuard(new InMemoryAttemptStore(), 3, 60_000);

    @Test
    void locksAfterMaxFailures() {
        assertDoesNotThrow(() -> guard.check("alice"));
        guard.recordFailure("alice");
        guard.recordFailure("alice");
        assertDoesNotThrow(() -> guard.check("alice"), "未达阈值不应锁定");
        guard.recordFailure("alice");
        assertThrows(LoginLockedException.class, () -> guard.check("alice"), "达到阈值应锁定");
    }

    @Test
    void recordSuccessClearsCounter() {
        guard.recordFailure("bob");
        guard.recordFailure("bob");
        guard.recordSuccess("bob");
        assertDoesNotThrow(() -> guard.check("bob"), "成功登录应清除失败计数");
    }

    @Test
    void identifiersAreIsolated() {
        guard.recordFailure("carol");
        guard.recordFailure("carol");
        guard.recordFailure("carol");
        assertDoesNotThrow(() -> guard.check("dave"), "不同标识的计数应相互隔离");
    }

    @Test
    void disabledWhenMaxAttemptsZero() {
        LoginAttemptGuard disabled = new LoginAttemptGuard(new InMemoryAttemptStore(), 0, 60_000);
        disabled.recordFailure("erin");
        disabled.recordFailure("erin");
        assertDoesNotThrow(() -> disabled.check("erin"), "阈值 <=0 时应完全不启用");
    }
}
