package io.github.biglv666.authkit.oauth2.store;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 内存 OAuth2 KV 存储行为测试：重点覆盖"写入时清扫过期条目"——
 * state/授权码可能永远等不到读访问，若只在读时惰性清理，内存降级路径会缓慢泄漏。
 */
class InMemoryOAuth2KeyValueStoreTest {

    @Test
    void expiredEntriesSweptOnPut() {
        AtomicLong now = new AtomicLong(1_000_000L);
        InMemoryOAuth2KeyValueStore store = new InMemoryOAuth2KeyValueStore(now::get);

        // 造 100 个短 TTL 条目（超过清扫阈值 64），全部过期后无任何读访问
        for (int i = 0; i < 100; i++) {
            store.put("k" + i, "v" + i, 10L);
        }
        assertEquals(100, store.size());
        now.addAndGet(11L);
        // 一次新的 put 触发清扫：100 个过期条目全部移除，只留新条目
        store.put("fresh", "v", 60_000L);
        assertEquals(1, store.size(), "过期条目应在写入时被清扫");
        assertNull(store.get("k0"));
        assertEquals("v", store.get("fresh"));
    }

    @Test
    void activeEntriesSurviveSweep() {
        AtomicLong now = new AtomicLong(1_000_000L);
        InMemoryOAuth2KeyValueStore store = new InMemoryOAuth2KeyValueStore(now::get);

        store.put("long-lived", "keep", 600_000L);
        for (int i = 0; i < 100; i++) {
            store.put("short" + i, "v", 10L);
        }
        now.addAndGet(11L);
        store.put("trigger", "v", 60_000L);
        assertEquals("keep", store.get("long-lived"), "未过期条目不应被误清扫");
    }

    @Test
    void expiredEntryReadReturnsNull() {
        AtomicLong now = new AtomicLong(1_000_000L);
        InMemoryOAuth2KeyValueStore store = new InMemoryOAuth2KeyValueStore(now::get);
        store.put("k", "v", 10L);
        now.addAndGet(11L);
        assertNull(store.get("k"));
        assertNull(store.remove("k"), "过期条目 remove 也不得返回值");
    }
}
