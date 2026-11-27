package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.observability.AuthKitAuditLogger;
import io.github.biglv666.authkit.observability.AuthKitMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 可观测性自动装配：指标 Bean 不得依赖自动配置顺序；事件必须真正到达指标/审计监听器。
 */
class ObservabilityAutoConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthKitAutoConfiguration.class));

    @Test
    void registersMetricsHealthAndAuditWhenAvailable() {
        runner.withBean(MeterRegistry.class, SimpleMeterRegistry::new).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(AuthKitMetrics.class);
            assertThat(context).hasSingleBean(HealthIndicator.class);
            assertThat(context).hasSingleBean(AuthKitAuditLogger.class);

            // spring-data-redis 在类路径、但没有 RedisConnectionFactory：auto 会静默降级内存，
            // 健康检查必须报 DOWN，而不是一片绿。
            HealthIndicator health = context.getBean(HealthIndicator.class);
            assertThat(health.health().getStatus()).isEqualTo(Status.DOWN);
        });
    }

    @Test
    void loginEventReachesMetricsThroughBridge() {
        runner.withBean(MeterRegistry.class, SimpleMeterRegistry::new).run(context -> {
            AuthManager manager = context.getBean(AuthManager.class);
            manager.login("u-metric", "PC");

            MeterRegistry registry = context.getBean(MeterRegistry.class);
            assertThat(registry.get("authkit.login")
                    .tag("outcome", "success")
                    .counter()
                    .count()).isEqualTo(1.0);
        });
    }

    @Test
    void startsWithoutMeterRegistry() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            // 没有 MeterRegistry 时仍注册 no-op 指标 Bean，但不得影响启动
            assertThat(context).hasSingleBean(AuthKitMetrics.class);
            assertThat(context).hasSingleBean(AuthKitAuditLogger.class);
        });
    }
}
