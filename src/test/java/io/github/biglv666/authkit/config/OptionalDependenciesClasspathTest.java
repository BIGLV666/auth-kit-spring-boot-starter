package io.github.biglv666.authkit.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 所有可选依赖同时缺失（spring-data-redis / Micrometer / Actuator）时，
 * 自动装配仍必须能启动——这是“optional 依赖不传递”的核心承诺。
 */
class OptionalDependenciesClasspathTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthKitAutoConfiguration.class))
            .withClassLoader(new FilteredClassLoader(
                    "org.springframework.data.redis",
                    "io.micrometer",
                    "org.springframework.boot.actuate"));

    @Test
    void startsWithoutAnyOptionalDependency() {
        runner.run(context -> assertThat(context).hasNotFailed());
    }
}
