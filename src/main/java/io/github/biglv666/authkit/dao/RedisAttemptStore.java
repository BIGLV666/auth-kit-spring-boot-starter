package io.github.biglv666.authkit.dao;

import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

/**
 * 基于 Redis 的登录失败计数实现（生产默认）。
 * <p>固定窗口计数：首次自增时设置 TTL，窗口内累加，窗口过后自动归零。</p>
 */
public class RedisAttemptStore implements AttemptStore {

    private final StringRedisTemplate redis;

    public RedisAttemptStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public long incr(String key, long ttlMillis) {
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redis.expire(key, Duration.ofMillis(ttlMillis));
        }
        return count == null ? 0 : count;
    }

    @Override
    public long get(String key) {
        String value = redis.opsForValue().get(key);
        return value == null ? 0 : Long.parseLong(value);
    }

    @Override
    public void clear(String key) {
        redis.delete(key);
    }
}
