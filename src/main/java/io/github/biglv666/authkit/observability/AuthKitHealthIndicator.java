package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

import java.util.function.Supplier;

/**
 * auth-kit 健康检查（Spring Boot Actuator，可选依赖）。
 *
 * <p>有 Redis 时由 {@link RedisHealthProbe} 提供远程探测；没有 Redis（或类路径无 spring-data-redis）
 * 时按内存存储配置报告 UP/DOWN。本类刻意不直接引用 Redis 类型，保证无 Redis 依赖时也能加载。</p>
 */
public class AuthKitHealthIndicator implements HealthIndicator {

    private final SessionDao sessionDao;
    private final boolean memoryStoreUp;
    private final Supplier<Health> remoteProbe;

    public AuthKitHealthIndicator(SessionDao sessionDao, boolean memoryStoreUp,
                                  Supplier<Health> remoteProbe) {
        this.sessionDao = sessionDao;
        this.memoryStoreUp = memoryStoreUp;
        this.remoteProbe = remoteProbe;
    }

    @Override
    public Health health() {
        if (remoteProbe != null) {
            return remoteProbe.get();
        }
        if (sessionDao instanceof InMemorySessionDao) {
            Health.Builder builder = memoryStoreUp ? Health.up() : Health.down();
            return builder
                    .withDetail("store", "memory")
                    .withDetail("warning", "内存会话仅适合本地开发/单实例，生产必须使用 Redis")
                    .build();
        }
        return Health.up()
                .withDetail("store", "custom")
                .build();
    }
}
