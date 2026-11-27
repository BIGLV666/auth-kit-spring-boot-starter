package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskDecision;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 内存风控状态机：窗口上限、递增风控、静默期清零、并发原子性。
 */
class InMemoryRiskControlStoreTest {

    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60L * MINUTE;
    private static final long DAY = 24L * HOUR;

    private final InMemoryRiskControlStore store = new InMemoryRiskControlStore();

    private static RiskControlPolicy policy() {
        return policy(true);
    }

    private static RiskControlPolicy policy(boolean resetOnSuccess) {
        return new RiskControlPolicy(5 * MINUTE, 5,
                List.of(5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY),
                6 * HOUR, 7 * DAY, resetOnSuccess);
    }

    private static void exhaustWindow(InMemoryRiskControlStore store, RiskControlPolicy policy, long now) {
        for (int i = 0; i < policy.maxAttempts(); i++) {
            assertTrue(store.check("u", policy, now).allowed(), "第 " + (i + 1) + " 次应放行");
        }
    }

    @Test
    void allowsExactlyMaxAttemptsThenLocks() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);

        RiskDecision decision = store.check("u", policy, 0);
        assertFalse(decision.allowed());
        assertEquals(5 * MINUTE, decision.retryAfterMillis());
        assertEquals(1, decision.lockoutCount());
    }

    @Test
    void lockedAttemptsAreRejectedUntilExpiry() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);
        store.check("u", policy, 0);

        RiskDecision atOneMinute = store.check("u", policy, MINUTE);
        assertFalse(atOneMinute.allowed());
        assertEquals(4 * MINUTE, atOneMinute.retryAfterMillis());

        RiskDecision atExpiry = store.check("u", policy, 5 * MINUTE);
        assertTrue(atExpiry.allowed(), "锁定截止时刻应恢复尝试");
        assertEquals(1, atExpiry.attemptCount());
    }

    @Test
    void escalatesConsecutiveLockouts() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);
        store.check("u", policy, 0);

        long afterLockout = 5 * MINUTE + 1;
        exhaustWindow(store, policy, afterLockout);
        RiskDecision second = store.check("u", policy, afterLockout);

        assertFalse(second.allowed());
        assertEquals(15 * MINUTE, second.retryAfterMillis());
        assertEquals(2, second.lockoutCount());
    }

    @Test
    void resetsEscalationAfterQuietInterval() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);
        store.check("u", policy, 0);

        long quietEnough = 5 * MINUTE + 6 * HOUR + 1;
        exhaustWindow(store, policy, quietEnough);
        RiskDecision next = store.check("u", policy, quietEnough);

        assertFalse(next.allowed());
        assertEquals(5 * MINUTE, next.retryAfterMillis(), "静默期后应回到第一档");
        assertEquals(1, next.lockoutCount());
    }

    @Test
    void capsAtLastLockoutDuration() {
        RiskControlPolicy policy = policy();
        long[] expected = {5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY, DAY};
        long now = 0;
        long lockedUntil = 0;

        for (int level = 0; level < expected.length; level++) {
            if (level > 0) {
                now = lockedUntil + 1;
            }
            exhaustWindow(store, policy, now);
            RiskDecision decision = store.check("u", policy, now);
            assertFalse(decision.allowed());
            assertEquals(expected[level], decision.retryAfterMillis(), "第 " + (level + 1) + " 档时长");
            assertEquals(level + 1, decision.lockoutCount());
            lockedUntil = now + decision.retryAfterMillis();
        }
    }

    @Test
    void successClearsAttemptsButKeepsEscalation() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);
        store.check("u", policy, 0);

        long afterLockout = 5 * MINUTE + 1;
        for (int i = 0; i < 4; i++) {
            assertTrue(store.check("u", policy, afterLockout).allowed());
        }
        store.recordSuccess("u", policy, afterLockout);

        exhaustWindow(store, policy, afterLockout);
        RiskDecision second = store.check("u", policy, afterLockout);
        assertFalse(second.allowed());
        assertEquals(2, second.lockoutCount(), "成功登录不应清掉连续风控次数");
        assertEquals(15 * MINUTE, second.retryAfterMillis());
    }

    @Test
    void resetOnSuccessFalseKeepsWindow() {
        RiskControlPolicy policy = policy(false);
        for (int i = 0; i < 4; i++) {
            assertTrue(store.check("u", policy, 0).allowed());
        }
        store.recordSuccess("u", policy, 0);
        assertTrue(store.check("u", policy, 0).allowed(), "第 5 次仍应放行");
        assertFalse(store.check("u", policy, 0).allowed(), "第 6 次应触发风控");
    }

    @Test
    void identifiersAreIsolated() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);
        store.check("u", policy, 0);

        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("other", policy, 0).allowed());
        }
    }

    @Test
    void clearRemovesAllState() {
        RiskControlPolicy policy = policy();
        exhaustWindow(store, policy, 0);
        store.check("u", policy, 0);

        store.clear("u");
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("u", policy, 0).allowed());
        }
    }

    @Test
    void stateExpiresAfterEffectiveTtl() {
        long unit = 10L;
        RiskControlPolicy policy = new RiskControlPolicy(unit, 1, List.of(unit), unit, unit, true);
        assertTrue(store.check("u", policy, 0).allowed());
        assertFalse(store.check("u", policy, 0).allowed(), "第 2 次触发风控，状态带升级历史");

        RiskDecision afterExpiry = store.check("u", policy, policy.effectiveStateTtlMillis() + 1);
        assertTrue(afterExpiry.allowed());
        assertEquals(1, afterExpiry.attemptCount(), "状态过期后应从空状态重新计数");
    }

    @Test
    void ordinaryAttemptStateUsesShortTtl() {
        RiskControlPolicy policy = policy();
        assertTrue(store.check("old", policy, 0).allowed());

        store.sweep(10 * MINUTE + 1, policy);
        assertEquals(0, store.stateCount(), "未触发风控的普通尝试状态应按短 TTL 清理");
    }

    @Test
    void lockoutStateSurvivesShortTtl() {
        RiskControlPolicy policy = policy();
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("locked", policy, 0).allowed());
        }
        assertFalse(store.check("locked", policy, 0).allowed());

        long now = 10 * MINUTE + 1;
        store.sweep(now, policy);
        assertEquals(1, store.stateCount(), "带风控历史的状态必须保留到 state-ttl");

        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("locked", policy, now).allowed());
        }
        RiskDecision second = store.check("locked", policy, now);
        assertFalse(second.allowed());
        assertEquals(2, second.lockoutCount(), "风控历史应保留并继续升级");
    }

    @Test
    void capsStateCountWhenUnderAttack() {
        InMemoryRiskControlStore small = new InMemoryRiskControlStore(10);
        RiskControlPolicy policy = policy();
        for (int i = 0; i < 20; i++) {
            small.check("k" + i, policy, 0);
        }
        small.sweep(0, policy);
        assertTrue(small.stateCount() <= 10, "状态总数超过上限时必须淘汰");
    }

    @Test
    void capEvictionPreservesActiveLockout() {
        InMemoryRiskControlStore small = new InMemoryRiskControlStore(10);
        RiskControlPolicy policy = policy();
        for (int i = 0; i < 5; i++) {
            assertTrue(small.check("victim", policy, 0).allowed());
        }
        assertFalse(small.check("victim", policy, 0).allowed());
        for (int i = 0; i < 20; i++) {
            small.check("k" + i, policy, 0);
        }

        small.sweep(0, policy);
        assertTrue(small.stateCount() <= 10);
        assertFalse(small.check("victim", policy, 0).allowed(),
                "容量淘汰不能清除活跃风控状态");
    }

    @Test
    void hardCapEvictsActiveLockoutsOnlyAsLastResort() {
        InMemoryRiskControlStore small = new InMemoryRiskControlStore(2);
        RiskControlPolicy policy = policy();
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 5; j++) {
                assertTrue(small.check("k" + i, policy, 0).allowed());
            }
            assertFalse(small.check("k" + i, policy, 0).allowed());
        }

        small.sweep(0, policy);
        assertTrue(small.stateCount() <= 4,
                "活跃风控数量超过硬上限时才做最后淘汰");
    }

    @Test
    void attemptAtExactWindowBoundaryExpires() {
        RiskControlPolicy policy = new RiskControlPolicy(MINUTE, 2, List.of(MINUTE), 0, DAY, true);
        assertTrue(store.check("u", policy, 0).allowed());
        assertTrue(store.check("u", policy, MINUTE).allowed(), "窗口起点应已过期");
        assertTrue(store.check("u", policy, MINUTE).allowed());
        assertFalse(store.check("u", policy, MINUTE).allowed());
    }

    @Test
    void resetIntervalBoundaryIsInclusive() {
        RiskControlPolicy policy = policy();

        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("exact", policy, 0).allowed());
        }
        assertFalse(store.check("exact", policy, 0).allowed());
        long exact = 5 * MINUTE + 6 * HOUR;
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("exact", policy, exact).allowed());
        }
        RiskDecision atBoundary = store.check("exact", policy, exact);
        assertFalse(atBoundary.allowed());
        assertEquals(2, atBoundary.lockoutCount(), "恰好等于静默期应视为连续");
        assertEquals(15 * MINUTE, atBoundary.retryAfterMillis());

        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("after", policy, 0).allowed());
        }
        assertFalse(store.check("after", policy, 0).allowed());
        long after = 5 * MINUTE + 6 * HOUR + 1;
        for (int i = 0; i < 5; i++) {
            assertTrue(store.check("after", policy, after).allowed());
        }
        RiskDecision afterBoundary = store.check("after", policy, after);
        assertFalse(afterBoundary.allowed());
        assertEquals(1, afterBoundary.lockoutCount(), "超过静默期应清零");
        assertEquals(5 * MINUTE, afterBoundary.retryAfterMillis());
    }

    @Test
    void zeroOrNegativeMaxAttemptsAlwaysAllows() {
        RiskControlPolicy zero = new RiskControlPolicy(MINUTE, 0, List.of(MINUTE), 0, DAY, true);
        RiskControlPolicy negative = new RiskControlPolicy(MINUTE, -1, List.of(MINUTE), 0, DAY, true);
        for (int i = 0; i < 100; i++) {
            assertTrue(store.check("u", zero, 0).allowed());
            assertTrue(store.check("v", negative, 0).allowed());
        }
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
                    return store.check("u", policy, 0);
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
            assertEquals(5, allowed, "并发下只能放行 maxAttempts 次");
            assertEquals(threads - 5, locked);
        } finally {
            pool.shutdownNow();
        }

        RiskDecision after = store.check("u", policy, 0);
        assertFalse(after.allowed());
        assertEquals(1, after.lockoutCount(), "并发触发只能升级一次");
        assertEquals(1, store.stateCount());
    }
}
