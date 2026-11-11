package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * risk-control 模式下 guard.enabled=false 必须真正停用。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = {"auth-kit.guard.mode=risk-control", "auth-kit.guard.enabled=false"})
class AuthKitRiskControlDisabledTest {

    @Autowired
    private LoginAttemptGuard guard;

    @Test
    void guardIsDisabledByConfig() {
        assertFalse(guard.isEnabled());
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> guard.check("disabled-user"));
        }
    }
}
