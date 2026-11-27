package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.exception.LoginLockedException;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import io.github.biglv666.authkit.guard.RiskControlStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 默认配置必须保持 counter 模式与既有固定窗口行为。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class})
class AuthKitDefaultModeIntegrationTest {

    @Autowired
    private LoginAttemptGuard guard;
    @Autowired
    private AttemptStore attemptStore;
    @Autowired
    private RiskControlStore riskControlStore;

    @Test
    void defaultModeKeepsCounterBehavior() {
        assertTrue(attemptStore instanceof InMemoryAttemptStore);
        assertTrue(riskControlStore instanceof InMemoryRiskControlStore);
        assertTrue(guard.isEnabled());

        String user = "counter-" + UUID.randomUUID();
        for (int i = 0; i < 5; i++) {
            guard.check(user);
            guard.recordFailure(user);
        }

        LoginLockedException e = assertThrows(LoginLockedException.class, () -> guard.check(user));
        assertTrue(e.getMessage().contains("登录失败"), "默认模式文案不应改变：" + e.getMessage());
        assertTrue(e.getRemainingMillis() == 15 * 60_000L, "默认锁定时长应保持 15 分钟");
    }
}
