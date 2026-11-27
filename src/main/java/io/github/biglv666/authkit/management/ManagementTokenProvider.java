package io.github.biglv666.authkit.management;

import java.util.Collection;

/**
 * 管理端点令牌来源 SPI。
 *
 * <p>默认实现读取 {@code auth-kit.management.auth-token(s)} 配置；业务可注册自己的 Bean
 * 实现动态/热轮换（例如从配置中心或数据库读取），无需重启应用。
 * 过滤器每次请求都会调用 {@link #tokens()}，实现方应保证低开销并做好缓存。</p>
 */
public interface ManagementTokenProvider {

    /** 当前有效的管理令牌集合；返回 null 视同空集合 */
    Collection<String> tokens();
}
