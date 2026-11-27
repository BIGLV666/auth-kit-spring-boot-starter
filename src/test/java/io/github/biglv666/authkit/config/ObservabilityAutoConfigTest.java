package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.observability.AuthKitAuditLogger;
import io.github.biglv666.authkit.observability.AuthKitMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 可观测性自动装配：类路径有 Micrometer/Actuator 时注册指标与健康检查；
 * 未提供 MeterRegistry 时不得因指标 Bean 缺依赖而启动失败。
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
        });
    }

    @Test
    void startsWithoutMeterRegistry() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(AuthKitMetrics.class);
            assertThat(context).hasSingleBean(AuthKitAuditLogger.class);
        });
    }
}
