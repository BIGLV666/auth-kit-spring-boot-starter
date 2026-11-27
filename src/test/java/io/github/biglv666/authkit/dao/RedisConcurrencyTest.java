package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
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
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 真实 Redis 下的并发/多实例语义：
 * <ul>
 *   <li>同用户同设备并发登录（max-sessions=1）最终只能有 1 个有效会话；</li>
 *   <li>两个应用实例共享 Redis 时，A 踢人后 B 立即收到 KICKED_OUT。</li>
 * </ul>
 */
@EnabledIf(value = "io.github.biglv666.authkit.dao.RedisConcurrencyTest#redisAvailable",
        disabledReason = "本机 Redis 未启动，跳过并发集成测试")
class RedisConcurrencyTest {

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate template;
    private String prefix;

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
    void newPrefix() {
        prefix = "auth-kit:conc:" + UUID.randomUUID() + ":";
    }

    @AfterEach
    void cleanup() {
        Set<String> keys = template.keys(prefix + "*");
        if (keys != null && !keys.isEmpty()) {
            template.delete(keys);
        }
    }

    @Test
    void concurrentLoginLeavesExactlyOneActiveSession() throws Exception {
        SessionDao dao = new RedisSessionDao(template, prefix);
        AuthManager manager = new AuthManager(dao, new RandomTokenGenerator(64),
                60_000, 0, 1);

        int logins = 50;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < logins; i++) {
                futures.add(pool.submit(() -> {
                    start.await(5, TimeUnit.SECONDS);
                    return manager.login("u-concurrent", "PC");
                }));
            }
            start.countDown();

            List<String> tokens = new ArrayList<>();
            for (Future<String> future : futures) {
                tokens.add(future.get(30, TimeUnit.SECONDS));
            }

            long active = 0;
            for (String token : tokens) {
                try {
                    manager.checkLogin(token);
                    active++;
                } catch (NotLoginException ignored) {
                    // 被顶号/失效
                }
            }
            assertEquals(1, active,
                    "max-sessions-per-device=1 时并发登录最终必须只保留一个有效会话");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void kickOnOneInstanceIsVisibleOnAnother() {
        SessionDao daoA = new RedisSessionDao(template, prefix);
        SessionDao daoB = new RedisSessionDao(template, prefix);
        AuthManager instanceA = new AuthManager(daoA, new RandomTokenGenerator(64), 60_000, 0, 1);
        AuthManager instanceB = new AuthManager(daoB, new RandomTokenGenerator(64), 60_000, 0, 1);

        String token = instanceA.login("u-multi", "PC");
        instanceB.checkLogin(token);

        instanceA.kickout("u-multi", null);

        NotLoginException ex = assertThrows(NotLoginException.class,
                () -> instanceB.checkLogin(token));
        assertEquals(NotLoginReason.KICKED_OUT, ex.getReason());
        assertTrue(true);
    }
}
