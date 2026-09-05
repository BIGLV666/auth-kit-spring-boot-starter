package io.github.biglv666.authkit.dao;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 基于内存的登录失败计数实现（无 Redis 时降级使用）。
 */
public class InMemoryAttemptStore implements AttemptStore {

    private record CountEntry(long count, long expireAtMillis) {
    }

    private final Map<String, CountEntry> counters = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public InMemoryAttemptStore() {
        this(System::currentTimeMillis);
    }

    public InMemoryAttemptStore(LongSupplier clock) {
        this.clock = clock;
    }

    @Override
    public long incr(String key, long ttlMillis) {
        long now = clock.getAsLong();
        CountEntry entry = counters.compute(key, (k, old) -> {
            if (old == null || old.expireAtMillis() <= now) {
                return new CountEntry(1, now + ttlMillis);
            }
            return new CountEntry(old.count() + 1, old.expireAtMillis());
        });
        return entry.count();
    }

    @Override
    public long get(String key) {
        CountEntry entry = counters.get(key);
        if (entry == null) {
            return 0;
        }
        if (entry.expireAtMillis() <= clock.getAsLong()) {
            counters.remove(key);
            return 0;
        }
        return entry.count();
    }

    @Override
    public void clear(String key) {
        counters.remove(key);
    }
}
