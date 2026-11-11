package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.exception.LoginLockedException;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import io.github.biglv666.authkit.guard.RiskControlStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

/**
 * risk-control 模式自动装配与接口层冒烟。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class, RiskAttemptController.class},
        properties = {
                "auth-kit.guard.mode=risk-control",
                "auth-kit.guard.fail-max-attempts=3",
                "auth-kit.guard.attempt-window=10m",
                "auth-kit.guard.lockout-durations[0]=30s",
                "auth-kit.guard.lockout-durations[1]=5m",
                "auth-kit.guard.lockout-reset-interval=1h"
        })
@AutoConfigureMockMvc
class AuthKitRiskControlIntegrationTest {

    @Autowired
    private LoginAttemptGuard guard;
    @Autowired
    private RiskControlStore riskControlStore;
    @Autowired
    private AttemptStore attemptStore;
    @Autowired
    private MockMvc mockMvc;

    @Test
    void selectsRiskModeAndLocksAfterMaxAttempts() {
        assertTrue(riskControlStore instanceof InMemoryRiskControlStore);
        assertTrue(attemptStore instanceof InMemoryAttemptStore);
        assertTrue(guard.isEnabled());

        String user = "risk-" + UUID.randomUUID();
        for (int i = 0; i < 3; i++) {
            guard.check(user);
        }
        LoginLockedException e = assertThrows(LoginLockedException.class, () -> guard.check(user));
        assertTrue(e.getRemainingMillis() >= 29_000, "第一档风控应为 30 秒，实际 " + e.getRemainingMillis());
    }

    @Test
    void endpointReturnsRiskControlCode() throws Exception {
        String user = "risk-http-" + UUID.randomUUID();
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/test/risk/attempt").param("user", user)).andReturn();
        }
        mockMvc.perform(post("/test/risk/attempt").param("user", user))
                .andExpect(jsonPath("$.code").value(40100))
                .andExpect(jsonPath("$.message", containsString("风控")));
    }
}

/** 测试专用接口：让 LoginLockedException 走统一异常映射。 */
@RestController
class RiskAttemptController {

    private final LoginAttemptGuard guard;

    RiskAttemptController(LoginAttemptGuard guard) {
        this.guard = guard;
    }

    @PostMapping("/test/risk/attempt")
    public String attempt(@RequestParam("user") String user) {
        guard.check(user);
        return "ok";
    }
}
