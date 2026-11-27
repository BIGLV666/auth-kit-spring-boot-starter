package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.dao.InMemorySafeStore;
import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SafeStore;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.guard.RiskControlStore;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * spring-data-redis 不在类路径时，自动装配必须能正常启动并降级内存；
 * store=redis 时必须 fail-fast，而不是启动后才发现会话不可用。
 */
class NoRedisClasspathTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthKitAutoConfiguration.class))
            .withClassLoader(new FilteredClassLoader("org.springframework.data.redis"));

    @Test
    void startsWithMemoryStoresWhenRedisMissing() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(SessionDao.class)).isInstanceOf(InMemorySessionDao.class);
            assertThat(context.getBean(AttemptStore.class)).isInstanceOf(InMemoryAttemptStore.class);
            assertThat(context.getBean(SafeStore.class)).isInstanceOf(InMemorySafeStore.class);
            assertThat(context.getBean(RiskControlStore.class)).isInstanceOf(InMemoryRiskControlStore.class);
        });
    }

    @Test
    void failsFastWhenRedisStoreRequestedWithoutRedis() {
        runner.withPropertyValues("auth-kit.session.store=redis").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("spring-data-redis");
        });
    }
}
