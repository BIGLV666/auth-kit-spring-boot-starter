package io.github.biglv666.authkit.dao;

import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

/**
 * 基于 Redis 的二级认证状态实现（生产默认）。
 */
public class RedisSafeStore implements SafeStore {

    private final StringRedisTemplate redis;
    private final String prefix;

    public RedisSafeStore(StringRedisTemplate redis, String keyPrefix) {
        this.redis = redis;
        this.prefix = keyPrefix;
    }

    @Override
    public void mark(String userId, long ttlMillis) {
        redis.opsForValue().set(prefix + ":safe:" + userId, "1", Duration.ofMillis(ttlMillis));
    }

    @Override
    public boolean exists(String userId) {
        return Boolean.TRUE.equals(redis.hasKey(prefix + ":safe:" + userId));
    }

    @Override
    public void clear(String userId) {
        redis.delete(prefix + ":safe:" + userId);
    }
}
