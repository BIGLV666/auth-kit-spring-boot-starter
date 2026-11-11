package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * risk-control 模式下 fail-max-attempts=0 必须停用（与 counter 模式 <=0 语义一致）。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = {"auth-kit.guard.mode=risk-control", "auth-kit.guard.fail-max-attempts=0"})
class AuthKitRiskControlZeroAttemptsTest {

    @Autowired
    private LoginAttemptGuard guard;

    @Test
    void zeroAttemptsDisablesGuard() {
        assertFalse(guard.isEnabled());
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> guard.check("zero-attempts-user"));
        }
    }
}
