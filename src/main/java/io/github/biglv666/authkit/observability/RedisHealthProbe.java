package io.github.biglv666.authkit.observability;

import org.springframework.boot.actuate.health.Health;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import java.util.function.Supplier;

/**
 * Redis 健康探测：真实 ping 一次；错误只暴露异常类型，不回显连接串/凭证。
 * <p>仅在类路径存在 spring-data-redis 时由自动装配实例化。</p>
 */
public class RedisHealthProbe implements Supplier<Health> {

    private final RedisConnectionFactory factory;

    public RedisHealthProbe(RedisConnectionFactory factory) {
        this.factory = factory;
    }

    @Override
    public Health get() {
        try (RedisConnection connection = factory.getConnection()) {
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
}
