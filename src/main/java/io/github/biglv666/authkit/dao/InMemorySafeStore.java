package io.github.biglv666.authkit.dao;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 基于内存的二级认证状态实现（无 Redis 时降级使用）。
 */
public class InMemorySafeStore implements SafeStore {

    private final Map<String, Long> expireAt = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public InMemorySafeStore() {
        this(System::currentTimeMillis);
    }

    public InMemorySafeStore(LongSupplier clock) {
        this.clock = clock;
    }

    @Override
    public void mark(String userId, long ttlMillis) {
        expireAt.put(userId, clock.getAsLong() + ttlMillis);
    }

    @Override
    public boolean exists(String userId) {
        Long expire = expireAt.get(userId);
        if (expire == null) {
            return false;
        }
        if (expire <= clock.getAsLong()) {
            expireAt.remove(userId);
            return false;
        }
        return true;
    }

    @Override
    public void clear(String userId) {
        expireAt.remove(userId);
    }
}
