package io.github.biglv666.authkit.itest;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration;
import org.springframework.context.annotation.Bean;
import io.github.biglv666.authkit.spi.PermissionProvider;

import java.util.Set;

/**
 * 集成测试应用：排除 Redis 自动装配，强制走内存会话实现（本地开发降级路径）。
 * Redis 实现的行为由 {@code RedisSessionDaoIT} 直连本机 Redis 单独覆盖。
 */
@SpringBootConfiguration
@EnableAutoConfiguration(exclude = {RedisAutoConfiguration.class, RedisRepositoriesAutoConfiguration.class})
public class TestApp {

    /** 测试权限数据源：10001 有 order:delete/order:view + admin 角色 */
    @Bean
    public PermissionProvider testPermissionProvider() {
        return new PermissionProvider() {
            @Override
            public Set<String> getPermissions(String userId) {
                return "10001".equals(userId) ? Set.of("order:delete", "order:view") : Set.of();
            }

            @Override
            public Set<String> getRoles(String userId) {
                return "10001".equals(userId) ? Set.of("admin") : Set.of();
            }
        };
    }
}
