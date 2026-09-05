package io.github.biglv666.authkit.oauth2.store;

import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

/**
 * 基于 Redis 的 OAuth2 键值存储（生产默认）。
 */
public class RedisOAuth2KeyValueStore implements OAuth2KeyValueStore {

    private final StringRedisTemplate redis;
    private final String prefix;

    public RedisOAuth2KeyValueStore(StringRedisTemplate redis, String keyPrefix) {
        this.redis = redis;
        this.prefix = keyPrefix;
    }

    @Override
    public void put(String key, String value, long ttlMillis) {
        redis.opsForValue().set(prefix + ":oauth2:" + key, value, Duration.ofMillis(ttlMillis));
    }

    @Override
    public String get(String key) {
        return redis.opsForValue().get(prefix + ":oauth2:" + key);
    }

    @Override
    public String remove(String key) {
        // GETDEL：单命令原子消费，防止授权码并发重放
        return redis.opsForValue().getAndDelete(prefix + ":oauth2:" + key);
    }

    @Override
    public void delete(String key) {
        redis.delete(prefix + ":oauth2:" + key);
    }
}
