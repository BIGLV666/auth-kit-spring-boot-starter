package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemorySafeStore;
import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SafeStore;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 回归：counter 模式下业务自定义全部旧存储 Bean、且 store=redis 但无 Redis 时，
 * 未使用的 RiskControlStore 不能把应用启动打挂。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = {"auth-kit.session.store=redis", "auth-kit.guard.mode=counter"})
@Import(AuthKitCounterModeNoRedisCustomStoresTest.CustomStoresConfig.class)
class AuthKitCounterModeNoRedisCustomStoresTest {

    @Autowired
    private LoginAttemptGuard guard;
    @Autowired
    private AttemptStore attemptStore;

    @Test
    void startsWithoutRedisWhenAllUsedStoresAreCustom() {
        assertNotNull(guard);
        assertTrue(guard.isEnabled());
        assertTrue(attemptStore instanceof InMemoryAttemptStore);
    }

    @TestConfiguration
    static class CustomStoresConfig {
        @Bean
        SessionDao sessionDao() {
            return new InMemorySessionDao();
        }

        @Bean
        AttemptStore attemptStore() {
            return new InMemoryAttemptStore();
        }

        @Bean
        SafeStore safeStore() {
            return new InMemorySafeStore();
        }
    }
}
