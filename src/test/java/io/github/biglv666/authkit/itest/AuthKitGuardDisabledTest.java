package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * guard.enabled=false 必须真正让守卫停用（而不是仅存在于配置项里）。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = "auth-kit.guard.enabled=false")
class AuthKitGuardDisabledTest {

    @Autowired
    private LoginAttemptGuard guard;

    @Test
    void guardIsDisabledByConfig() {
        assertFalse(guard.isEnabled());
    }
}
