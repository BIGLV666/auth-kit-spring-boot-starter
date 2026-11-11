package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskControlStore;
import io.github.biglv666.authkit.guard.RiskDecision;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务方注册自定义 RiskControlStore 时必须覆盖默认实现。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = "auth-kit.guard.mode=risk-control")
@Import(AuthKitCustomRiskStoreIntegrationTest.CustomStoreConfig.class)
class AuthKitCustomRiskStoreIntegrationTest {

    @Autowired
    private RiskControlStore riskControlStore;
    @Autowired
    private LoginAttemptGuard guard;

    @Test
    void customStoreWins() {
        assertTrue(riskControlStore instanceof CustomRiskControlStore);
        guard.check("custom-user");
        assertTrue(((CustomRiskControlStore) riskControlStore).isChecked(),
                "守卫必须调用业务自定义的 RiskControlStore");
    }

    @TestConfiguration
    static class CustomStoreConfig {
        @Bean
        RiskControlStore customRiskControlStore() {
            return new CustomRiskControlStore();
        }
    }

    static class CustomRiskControlStore implements RiskControlStore {
        private final InMemoryRiskControlStore delegate = new InMemoryRiskControlStore();
        private volatile boolean checked;

        boolean isChecked() {
            return checked;
        }

        @Override
        public RiskDecision check(String key, RiskControlPolicy policy, long nowMillis) {
            checked = true;
            return delegate.check(key, policy, nowMillis);
        }

        @Override
        public void recordSuccess(String key, RiskControlPolicy policy, long nowMillis) {
            delegate.recordSuccess(key, policy, nowMillis);
        }

        @Override
        public void clear(String key) {
            delegate.clear(key);
        }
    }
}
