package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskControlStore;
import io.github.biglv666.authkit.guard.RiskDecision;
import io.lettuce.core.RedisClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerArray;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Redis 风控状态实现：Lua 原子性、递增风控、静默期、TTL。
 * <p>直连本机 Redis（localhost:6379），不可用时整类跳过。</p>
 */
@EnabledIf(value = "io.github.biglv666.authkit.dao.RedisRiskControlStoreTest#redisAvailable",
        disabledReason = "本机 Redis 未启动，跳过 Redis 集成测试")
class RedisRiskControlStoreTest {

    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60L * MINUTE;
    private static final long DAY = 24L * HOUR;

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate template;

    private RiskControlStore store;
    private String key;
    private long base;

    public static boolean redisAvailable() {
        try {
            RedisClient client = RedisClient.create("redis://127.0.0.1:6379");
            client.connect().close();
            client.shutdown();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @BeforeAll
    static void initRedis() {
        factory = new LettuceConnectionFactory("127.0.0.1", 6379);
        factory.afterPropertiesSet();
        template = new StringRedisTemplate(factory);
    }

    @AfterAll
    static void shutdownRedis() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @BeforeEach
    void setUp() {
        cleanupKeys();
        store = new RedisRiskControlStore(template);
        key = "auth-kit:it:risk:" + UUID.randomUUID();
        base = System.currentTimeMillis();
    }

    @AfterEach
    void cleanupKeys() {
        Set<String> keys = template.keys("auth-kit:it:risk:*");
        if (keys != null && !keys.isEmpty()) {
            template.delete(keys);
        }
    }

    private static RiskControlPolicy policy() {
        return policy(true);
    }

    private static RiskControlPolicy policy(boolean resetOnSuccess) {
        return new RiskControlPolicy(5 * MINUTE, 5,
                List.of(5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY),
                6 * HOUR, 7 * DAY, resetOnSuccess);
    }

    private void exhaustWindow(RiskControlPolicy policy, long now) {
        for (int i = 0; i < policy.maxAttempts(); i++) {
            assertTrue(store.check(key, policy, now).allowed(), "第 " + (i + 1) + " 次应放行");
        }
    }

    @Test
    void allowsExactlyMaxAttemptsThenLocks() {
        RiskControlPolicy policy = policy();
        exhaustWindow(policy, base);

        RiskDecision decision = store.check(key, policy, base);
        assertFalse(decision.allowed());
        assertEquals(5 * MINUTE, decision.retryAfterMillis());
        assertEquals(1, decision.lockoutCount());
    }

    @Test
    void lockedAttemptsAreRejectedUntilExpiry() {
        RiskControlPolicy policy = policy();
        exhaustWindow(policy, base);
        store.check(key, policy, base);

        RiskDecision atOneMinute = store.check(key, policy, base + MINUTE);
        assertFalse(atOneMinute.allowed());
        assertEquals(4 * MINUTE, atOneMinute.retryAfterMillis());

        RiskDecision atExpiry = store.check(key, policy, base + 5 * MINUTE);
        assertTrue(atExpiry.allowed());
        assertEquals(1, atExpiry.attemptCount());
    }

    @Test
    void escalatesConsecutiveLockouts() {
        RiskControlPolicy policy = policy();
        exhaustWindow(policy, base);
        store.check(key, policy, base);

        long afterLockout = base + 5 * MINUTE + 1;
        exhaustWindow(policy, afterLockout);
        RiskDecision second = store.check(key, policy, afterLockout);

        assertFalse(second.allowed());
        assertEquals(15 * MINUTE, second.retryAfterMillis());
        assertEquals(2, second.lockoutCount());
    }

    @Test
    void resetsEscalationAfterQuietInterval() {
        RiskControlPolicy policy = policy();
        exhaustWindow(policy, base);
        store.check(key, policy, base);

        long quietEnough = base + 5 * MINUTE + 6 * HOUR + 1;
        exhaustWindow(policy, quietEnough);
        RiskDecision next = store.check(key, policy, quietEnough);

        assertFalse(next.allowed());
        assertEquals(5 * MINUTE, next.retryAfterMillis());
        assertEquals(1, next.lockoutCount());
    }

    @Test
    void capsAtLastLockoutDuration() {
        RiskControlPolicy policy = policy();
        long[] expected = {5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY, DAY};
        long now = base;
        long lockedUntil = 0;

        for (int level = 0; level < expected.length; level++) {
            if (level > 0) {
                now = lockedUntil + 1;
            }
            exhaustWindow(policy, now);
            RiskDecision decision = store.check(key, policy, now);
            assertFalse(decision.allowed());
            assertEquals(expected[level], decision.retryAfterMillis(), "第 " + (level + 1) + " 档时长");
            assertEquals(level + 1, decision.lockoutCount());
            lockedUntil = now + decision.retryAfterMillis();
        }
    }

    @Test
    void successClearsAttemptsButKeepsEscalation() {
        RiskControlPolicy policy = policy();
        exhaustWindow(policy, base);
        store.check(key, policy, base);

        long afterLockout = base + 5 * MINUTE + 1;
        for (int i = 0; i < 4; i++) {
            assertTrue(store.check(key, policy, afterLockout).allowed());
        }
        store.recordSuccess(key, policy, afterLockout);

        exhaustWindow(policy, afterLockout);
        RiskDecision second = store.check(key, policy, afterLockout);
        assertFalse(second.allowed());
        assertEquals(2, second.lockoutCount());
        assertEquals(15 * MINUTE, second.retryAfterMillis());
    }

    @Test
    void resetOnSuccessFalseKeepsWindow() {
        RiskControlPolicy policy = policy(false);
        for (int i = 0; i < 4; i++) {
            assertTrue(store.check(key, policy, base).allowed());
        }
        store.recordSuccess(key, policy, base);
        assertTrue(store.check(key, policy, base).allowed());
        assertFalse(store.check(key, policy, base).allowed());
    }

    @Test
    void clearRemovesAllState() {
        RiskControlPolicy policy = policy();
        exhaustWindow(policy, base);
        store.check(key, policy, base);

        store.clear(key);
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check(key, policy, base).allowed());
        }
    }

    @Test
    void stateExpiresByRedisTtl() throws InterruptedException {
        long unit = 100L;
        RiskControlPolicy shortLived = new RiskControlPolicy(unit, 1, List.of(unit), unit, unit, true);
        long now = System.currentTimeMillis();
        assertTrue(store.check(key, shortLived, now).allowed());
        assertFalse(store.check(key, shortLived, now).allowed(), "第 2 次触发风控，使用长 TTL");
        assertTrue(Boolean.TRUE.equals(template.hasKey(key)), "状态应已写入");

        Thread.sleep(400);
        assertFalse(Boolean.TRUE.equals(template.hasKey(key)),
                "带风控历史的状态应在有效 TTL 后过期");
    }

    @Test
    void concurrentChecksAllowExactlyMaxAttempts() throws Exception {
        RiskControlPolicy policy = policy();
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<RiskDecision>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return store.check(key, policy, base);
                }));
            }
            start.countDown();

            int allowed = 0;
            int locked = 0;
            for (Future<RiskDecision> future : futures) {
                if (future.get().allowed()) {
                    allowed++;
                } else {
                    locked++;
                }
            }
            assertEquals(5, allowed, "Lua 原子脚本下只能放行 maxAttempts 次");
            assertEquals(threads - 5, locked);
        } finally {
            pool.shutdownNow();
        }

        RiskDecision after = store.check(key, policy, base);
        assertFalse(after.allowed());
        assertEquals(1, after.lockoutCount(), "并发触发只能升级一次");
    }

    @Test
    void ordinaryAttemptUsesShortTtlAndLockoutUsesLongTtl() {
        RiskControlPolicy policy = policy();
        assertTrue(store.check(key, policy, base).allowed());

        Long shortTtl = template.getExpire(key, TimeUnit.MILLISECONDS);
        assertTrue(shortTtl != null && shortTtl > 0 && shortTtl <= 10 * MINUTE + 2_000,
                "普通尝试状态 TTL 应约为 2×窗口，实际 " + shortTtl);

        for (int i = 0; i < 4; i++) {
            assertTrue(store.check(key, policy, base).allowed());
        }
        assertFalse(store.check(key, policy, base).allowed());

        Long longTtl = template.getExpire(key, TimeUnit.MILLISECONDS);
        assertTrue(longTtl != null && longTtl > 10 * MINUTE,
                "触发风控后应使用 state-ttl，实际 " + longTtl);
    }

    @Test
    void activeLockoutSurvivesStateTtlAndKeepsEscalation() throws InterruptedException {
        RiskControlPolicy policy = new RiskControlPolicy(50L, 1,
                List.of(200L, 400L), 100L, 10L, true);
        long now = System.currentTimeMillis();
        assertTrue(store.check(key, policy, now).allowed());
        RiskDecision locked = store.check(key, policy, now);
        assertFalse(locked.allowed());
        assertEquals(200L, locked.retryAfterMillis());

        Thread.sleep(250);
        long afterLockout = now + 250;
        assertTrue(store.check(key, policy, afterLockout).allowed(), "风控已结束，应允许一次尝试");
        RiskDecision second = store.check(key, policy, afterLockout);
        assertFalse(second.allowed());
        assertEquals(400L, second.retryAfterMillis(), "状态未过期，连续次数应升级到第二档");
    }

    @Test
    void resetIntervalBoundaryIsInclusive() {
        RiskControlPolicy policy = policy();

        exhaustWindow(policy, base);
        store.check(key, policy, base);
        long exact = base + 5 * MINUTE + 6 * HOUR;
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check(key, policy, exact).allowed());
        }
        RiskDecision atBoundary = store.check(key, policy, exact);
        assertFalse(atBoundary.allowed());
        assertEquals(2, atBoundary.lockoutCount(), "恰好等于静默期应视为连续");
        assertEquals(15 * MINUTE, atBoundary.retryAfterMillis());

        String afterKey = key + ":after";
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check(afterKey, policy, base).allowed());
        }
        assertFalse(store.check(afterKey, policy, base).allowed());
        long after = base + 5 * MINUTE + 6 * HOUR + 1;
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check(afterKey, policy, after).allowed());
        }
        RiskDecision afterBoundary = store.check(afterKey, policy, after);
        assertFalse(afterBoundary.allowed());
        assertEquals(1, afterBoundary.lockoutCount(), "超过静默期应清零");
        assertEquals(5 * MINUTE, afterBoundary.retryAfterMillis());
    }

    @Test
    void concurrentStressEnforcesCapAndReportsLatency() throws Exception {
        RiskControlPolicy policy = policy();
        int threads = 16;
        int keys = 50;
        int rounds = 10;
        AtomicIntegerArray allowed = new AtomicIntegerArray(keys);
        ConcurrentLinkedQueue<Long> riskSamples = runRiskStress(policy, threads, keys, rounds, allowed);

        for (int k = 0; k < keys; k++) {
            assertEquals(5, allowed.get(k), "key " + k + " 只能放行 5 次");
        }

        RedisAttemptStore baselineStore = new RedisAttemptStore(template);
        ConcurrentLinkedQueue<Long> baselineSamples = runBaselineStress(baselineStore, threads, keys, rounds);

        long[] risk = toSortedArray(riskSamples);
        long[] baseline = toSortedArray(baselineSamples);
        long riskP95 = percentile(risk, 0.95);
        long baselineP95 = percentile(baseline, 0.95);
        System.out.printf(
                "[stress][redis] ops=%d p50=%.1fus p95=%.1fus p99=%.1fus | baselineP95=%.1fus ratio=%.2f%n",
                risk.length,
                percentile(risk, 0.50) / 1000.0,
                riskP95 / 1000.0,
                percentile(risk, 0.99) / 1000.0,
                baselineP95 / 1000.0,
                riskP95 == 0 ? 0.0 : (double) riskP95 / baselineP95);
        assertTrue(riskP95 <= Math.max(50_000_000L, baselineP95 * 10),
                "Redis risk-control P95 不应出现数量级退化");
    }

    private ConcurrentLinkedQueue<Long> runRiskStress(RiskControlPolicy policy, int threads, int keys,
                                                      int rounds, AtomicIntegerArray allowed) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Long> samples = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int r = 0; r < rounds; r++) {
                        for (int k = 0; k < keys; k++) {
                            long begin = System.nanoTime();
                            RiskDecision decision = store.check(key + ":stress:" + k, policy, base);
                            samples.add(System.nanoTime() - begin);
                            if (decision.allowed()) {
                                allowed.incrementAndGet(k);
                            }
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            pool.shutdownNow();
        }
        return samples;
    }

    private ConcurrentLinkedQueue<Long> runBaselineStress(RedisAttemptStore baselineStore, int threads, int keys,
                                                          int rounds) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Long> samples = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int r = 0; r < rounds; r++) {
                        for (int k = 0; k < keys; k++) {
                            long begin = System.nanoTime();
                            baselineStore.incr(key + ":baseline:" + k, HOUR);
                            samples.add(System.nanoTime() - begin);
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            pool.shutdownNow();
        }
        return samples;
    }

    private static long[] toSortedArray(ConcurrentLinkedQueue<Long> samples) {
        long[] values = samples.stream().mapToLong(Long::longValue).toArray();
        Arrays.sort(values);
        return values;
    }

    private static long percentile(long[] sorted, double percentile) {
        int index = (int) Math.ceil(percentile * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
    }
}
