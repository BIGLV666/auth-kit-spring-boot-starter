package io.github.biglv666.authkit.management;

import io.github.biglv666.authkit.config.AuthKitProperties;

import java.util.Collection;
import java.util.List;

/**
 * 基于配置的管理令牌来源：合并 {@code auth-token} 与 {@code auth-tokens}。
 * <p>每次调用重新读取配置对象，配合 Spring 配置刷新即可实现不重启轮换。</p>
 */
public class ConfigManagementTokenProvider implements ManagementTokenProvider {

    private final AuthKitProperties.Management properties;

    public ConfigManagementTokenProvider(AuthKitProperties.Management properties) {
        this.properties = properties;
    }

    @Override
    public Collection<String> tokens() {
        List<String> tokens = properties.effectiveTokens();
        return tokens == null ? List.of() : tokens;
    }
}
