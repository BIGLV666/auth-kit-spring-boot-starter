package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

/**
 * auth-kit 健康检查（Spring Boot Actuator，可选依赖）。
 *
 * <p>有 Redis 会话存储时实际 ping 一次；内存降级时按配置报告 UP 或 DOWN。
 * 错误详情只暴露异常类型，不回显连接串/密钥。</p>
 */
public class AuthKitHealthIndicator implements HealthIndicator {

    private final RedisConnectionFactory redisConnectionFactory;
    private final SessionDao sessionDao;
    private final boolean memoryStoreUp;

    public AuthKitHealthIndicator(RedisConnectionFactory redisConnectionFactory,
                                  SessionDao sessionDao,
                                  boolean memoryStoreUp) {
        this.redisConnectionFactory = redisConnectionFactory;
        this.sessionDao = sessionDao;
        this.memoryStoreUp = memoryStoreUp;
    }

    @Override
    public Health health() {
        if (redisConnectionFactory != null) {
            try (RedisConnection connection = redisConnectionFactory.getConnection()) {
                connection.ping();
                return Health.up()
                        .withDetail("store", "redis")
                        .build();
            } catch (Exception e) {
                return Health.down()
                        .withDetail("store", "redis")
                        .withDetail("error", e.getClass().getSimpleName())
                        .build();
            }
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
