package io.github.biglv666.authkit.oauth2.store;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 基于内存的 OAuth2 键值存储（无 Redis 时降级使用，仅本地开发/测试）。
 */
public class InMemoryOAuth2KeyValueStore implements OAuth2KeyValueStore {

    private record Entry(String value, long expireAtMillis) {
    }

    private final Map<String, Entry> store = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public InMemoryOAuth2KeyValueStore() {
        this(System::currentTimeMillis);
    }

    public InMemoryOAuth2KeyValueStore(LongSupplier clock) {
        this.clock = clock;
    }

    @Override
    public void put(String key, String value, long ttlMillis) {
        long now = clock.getAsLong();
        // 写入时顺带清扫过期条目：state/授权码可能永远等不到读访问，放任不管会让
        // 内存降级路径缓慢泄漏（仅条目量超过阈值才全表扫描，小 map 不付 O(n)）
        if (store.size() >= 64) {
            store.values().removeIf(entry -> entry.expireAtMillis() <= now);
        }
        store.put(key, new Entry(value, now + ttlMillis));
    }

    @Override
    public String get(String key) {
        Entry entry = store.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.expireAtMillis() <= clock.getAsLong()) {
            store.remove(key);
            return null;
        }
        return entry.value();
    }

    @Override
    public String remove(String key) {
        Entry entry = store.remove(key);
        if (entry == null) {
            return null;
        }
        if (entry.expireAtMillis() <= clock.getAsLong()) {
            return null;
        }
        return entry.value();
    }

    @Override
    public void delete(String key) {
        store.remove(key);
    }

    /** 当前条目数（仅测试与诊断用，并发下非精确瞬时值） */
    int size() {
        return store.size();
    }
}
