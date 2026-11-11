package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskDecision;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicIntegerArray;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 内存风控压测：并发上限、延迟分位、与固定计数实现的基线对比。
 */
class RiskControlStressTest {

    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60L * MINUTE;
    private static final long DAY = 24L * HOUR;

    private static RiskControlPolicy policy() {
        return new RiskControlPolicy(HOUR, 5,
                List.of(5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY),
                6 * HOUR, 7 * DAY, true);
    }

    @Test
    void inMemoryConcurrentChecksEnforceCapAndReportLatency() throws Exception {
        InMemoryRiskControlStore store = new InMemoryRiskControlStore();
        RiskControlPolicy policy = policy();
        int threads = 32;
        int keys = 100;
        int rounds = 20;
        long now = 0;
        AtomicIntegerArray allowed = new AtomicIntegerArray(keys);

        long[] riskSamples = runRiskLoop(store, policy, threads, keys, rounds, now, allowed);
        for (int k = 0; k < keys; k++) {
            assertEquals(5, allowed.get(k), "key " + k + " 只能放行 5 次");
        }

        InMemoryAttemptStore baselineStore = new InMemoryAttemptStore();
        long[] baselineSamples = runBaselineLoop(baselineStore, threads, keys, rounds, now);

        report("in-memory", riskSamples, baselineSamples);
        assertTrue(percentile(riskSamples, 0.95) <= Math.max(5_000_000L, percentile(baselineSamples, 0.95) * 10),
                "risk-control P95 不应出现数量级退化");
    }

    @Test
    void inMemorySustainedMixedLoadKeepsStateBounded() {
        InMemoryRiskControlStore store = new InMemoryRiskControlStore(100);
        // 高阈值确保压测期间只产生普通状态，从而验证容量上限优先淘汰普通状态
        RiskControlPolicy policy = new RiskControlPolicy(HOUR, 10_000,
                List.of(5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY),
                6 * HOUR, 7 * DAY, true);
        int keys = 1000;
        int rounds = 200;
        long now = 0;

        for (int r = 0; r < rounds; r++) {
            for (int k = 0; k < keys; k++) {
                RiskDecision decision = store.check("k" + k, policy, now);
                assertTrue(decision.allowed() || decision.retryAfterMillis() > 0);
                if ((k & 15) == 0) {
                    store.recordSuccess("k" + k, policy, now);
                }
            }
        }
        store.sweep(now, policy);
        assertTrue(store.stateCount() <= 100, "状态 key 数量必须受容量上限约束");
    }

    private static long[] runRiskLoop(InMemoryRiskControlStore store, RiskControlPolicy policy,
                                      int threads, int keys, int rounds, long now,
                                      AtomicIntegerArray allowed) throws Exception {
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
                            RiskDecision decision = store.check("k" + k, policy, now);
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
        return toSortedArray(samples);
    }

    private static long[] runBaselineLoop(InMemoryAttemptStore store, int threads, int keys, int rounds,
                                          long now) throws Exception {
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
                            store.incr("k" + k, HOUR);
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
        return toSortedArray(samples);
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

    private static void report(String label, long[] risk, long[] baseline) {
        long riskP95 = percentile(risk, 0.95);
        long baselineP95 = percentile(baseline, 0.95);
        System.out.printf(
                "[stress][%s] ops=%d p50=%.1fus p95=%.1fus p99=%.1fus | baselineP95=%.1fus ratio=%.2f%n",
                label, risk.length,
                percentile(risk, 0.50) / 1000.0,
                riskP95 / 1000.0,
                percentile(risk, 0.99) / 1000.0,
                baselineP95 / 1000.0,
                riskP95 == 0 ? 0.0 : (double) riskP95 / baselineP95);
    }
}
