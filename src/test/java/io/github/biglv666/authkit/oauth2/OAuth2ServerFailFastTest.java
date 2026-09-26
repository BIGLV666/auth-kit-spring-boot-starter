package io.github.biglv666.authkit.oauth2;

import io.github.biglv666.authkit.config.AuthKitAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 授权服务器 fail-fast 校验：启用 server 却未正确注册客户端时必须启动失败，
 * 而不是带着一个所有授权请求都会 invalid_client 的残缺服务上线（对齐管理端 fail-fast 惯例）。
 */
class OAuth2ServerFailFastTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthKitAutoConfiguration.class));

    @Test
    void serverDisabledStartsNormally() {
        // 默认全关：V1 用户零感知，上下文正常启动
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void serverEnabledWithoutClientsFailsFast() {
        runner.withPropertyValues("auth-kit.oauth2.server.enabled=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("auth-kit.oauth2.server.clients");
                });
    }

    @Test
    void clientWithoutSecretFailsFast() {
        runner.withPropertyValues(
                        "auth-kit.oauth2.server.enabled=true",
                        "auth-kit.oauth2.server.clients.app1.redirect-uris[0]=https://app1.example/cb")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("client-secret");
                });
    }

    @Test
    void clientWithoutRedirectUrisFailsFast() {
        runner.withPropertyValues(
                        "auth-kit.oauth2.server.enabled=true",
                        "auth-kit.oauth2.server.clients.app1.client-secret=secret-app1")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("redirect-uris");
                });
    }

    @Test
    void serverEnabledWithValidClientStarts() {
        runner.withPropertyValues(
                        "auth-kit.oauth2.server.enabled=true",
                        "auth-kit.oauth2.server.clients.app1.client-secret=secret-app1",
                        "auth-kit.oauth2.server.clients.app1.redirect-uris[0]=https://app1.example/cb")
                .run(context -> assertThat(context).hasNotFailed());
    }
}
