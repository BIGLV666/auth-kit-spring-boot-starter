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
        store.put(key, new Entry(value, clock.getAsLong() + ttlMillis));
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
}
