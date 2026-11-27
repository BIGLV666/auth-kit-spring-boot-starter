package io.github.biglv666.authkit.load;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.RedisSessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 认证热路径压测（默认跳过；-Dload=true 启用）。
 *
 * <pre>
 * # 内存存储，8 线程 60 秒
 * mvn -Dload=true -Dload.seconds=60 -Dtest=AuthKitLoadTest test
 *
 * # Redis（localhost:6379）
 * mvn -Dload=true -Dload.redis=true -Dload.seconds=60 -Dtest=AuthKitLoadTest test
 *
 * # 30 分钟长稳
 * mvn -Dload=true -Dload.redis=true -Dload.seconds=1800 -Dtest=AuthKitLoadTest test
 * </pre>
 */
@EnabledIfSystemProperty(named = "load", matches = "true")
class AuthKitLoadTest {

    private static final int MAX_SAMPLES_PER_THREAD = 200_000;

    @Test
    void checkLoginHotPath() throws Exception {
        boolean redis = Boolean.parseBoolean(System.getProperty("load.redis", "false"));
        int threads = Integer.getInteger("load.threads", 8);
        int warmupSeconds = Integer.getInteger("load.warmup", 5);
        int measureSeconds = Integer.getInteger("load.seconds", 60);

        SessionDao dao;
        String prefix = "auth-kit:load:" + UUID.randomUUID() + ":";
        LettuceConnectionFactory factory = null;
        StringRedisTemplate template = null;
        if (redis) {
            factory = new LettuceConnectionFactory("127.0.0.1", 6379);
            factory.afterPropertiesSet();
            template = new StringRedisTemplate(factory);
            dao = new RedisSessionDao(template, prefix);
        } else {
            dao = new InMemorySessionDao();
        }

        // 会话绝对有效期必须长于压测时长：否则 30 分钟长稳会在末尾自然过期，
        // 被误计为认证错误（这不是产品缺陷）。
        AuthManager manager = new AuthManager(dao, new RandomTokenGenerator(64),
                2 * 60 * 60_000L, 0, -1);

        try {
            runPhase(manager, threads, warmupSeconds, true, "warmup");
            Result result = runPhase(manager, threads, measureSeconds, false, "measure");

            System.out.printf(
                    "LOAD mode=%s threads=%d seconds=%d ops=%d qps=%.0f "
                            + "p50=%.1fus p95=%.1fus p99=%.1fus max=%.1fus errors=%d%n",
                    redis ? "redis" : "memory", threads, measureSeconds, result.ops,
                    result.ops / (double) measureSeconds,
                    result.percentile(50) / 1_000.0,
                    result.percentile(95) / 1_000.0,
                    result.percentile(99) / 1_000.0,
                    result.max / 1_000.0,
                    result.errors);

            assertEquals(0, result.errors, "压测期间不允许出现认证错误");
            assertEquals(0, result.unexpectedErrors, "压测期间不允许出现非认证类异常");
        } finally {
            if (factory != null) {
                if (template != null) {
                    Set<String> keys = template.keys(prefix + "*");
                    if (keys != null && !keys.isEmpty()) {
                        template.delete(keys);
                    }
                }
                factory.destroy();
            }
        }
    }

    private Result runPhase(AuthManager manager, int threads, int seconds,
                            boolean warmup, String label) throws Exception {
        if (seconds <= 0) {
            return new Result(new long[0], 0, 0, 0, 0);
        }
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Worker> workers = new ArrayList<>(threads);
        for (int i = 0; i < threads; i++) {
            Worker worker = new Worker(manager, warmup);
            workers.add(worker);
            pool.submit(() -> {
                start.await();
                worker.run();
                return null;
            });
        }
        start.countDown();

        Thread.sleep(TimeUnit.SECONDS.toMillis(seconds));
        for (Worker worker : workers) {
            worker.stopped = true;
        }
        pool.shutdown();
        if (!pool.awaitTermination(10, TimeUnit.SECONDS)) {
            pool.shutdownNow();
        }

        long ops = workers.stream().mapToLong(w -> w.ops.sum()).sum();
        long errors = workers.stream().mapToLong(w -> w.authErrors.get()).sum();
        long unexpected = workers.stream().mapToLong(w -> w.unexpectedErrors.get()).sum();
        long max = workers.stream().mapToLong(w -> w.max).max().orElse(0);

        long[] merged = workers.stream()
                .flatMapToLong(w -> Arrays.stream(w.samples, 0, w.sampleCount))
                .toArray();
        Arrays.sort(merged);
        if (!warmup) {
            System.out.printf("phase=%s threads=%d seconds=%d ops=%d qps=%.0f errors=%d%n",
                    label, threads, seconds, ops, ops / (double) seconds, errors);
        }
        return new Result(merged, ops, errors, unexpected, max);
    }

    private static final class Worker {
        private final AuthManager manager;
        private final boolean warmup;
        private final LongAdder ops = new LongAdder();
        private final AtomicLong authErrors = new AtomicLong();
        private final AtomicLong unexpectedErrors = new AtomicLong();
        private final long[] samples = new long[MAX_SAMPLES_PER_THREAD];
        private int sampleCount;
        private long max;
        private volatile boolean stopped;

        private Worker(AuthManager manager, boolean warmup) {
            this.manager = manager;
            this.warmup = warmup;
        }

        private void run() {
            String token = manager.login("load-user-" + Thread.currentThread().getId(), "PC");
            int i = 0;
            while (!stopped) {
                long begin = System.nanoTime();
                try {
                    manager.checkLogin(token);
                    ops.increment();
                } catch (io.github.biglv666.authkit.exception.NotLoginException e) {
                    authErrors.incrementAndGet();
                    if (authErrors.get() <= 5) {
                        System.err.println("unexpected auth error: " + e.getReason());
                    }
                } catch (RuntimeException e) {
                    unexpectedErrors.incrementAndGet();
                }
                long elapsed = System.nanoTime() - begin;
                if (!warmup && (i++ & 15) == 0 && sampleCount < samples.length) {
                    samples[sampleCount++] = elapsed;
                }
                if (elapsed > max) {
                    max = elapsed;
                }
            }
        }
    }

    private record Result(long[] samples, long ops, long errors, long unexpectedErrors, long max) {
        private long percentile(int p) {
            if (samples.length == 0) {
                return 0;
            }
            int index = (int) Math.min(samples.length - 1L,
                    Math.round(samples.length * (p / 100.0)) - 1);
            return samples[Math.max(0, index)];
        }
    }
}
