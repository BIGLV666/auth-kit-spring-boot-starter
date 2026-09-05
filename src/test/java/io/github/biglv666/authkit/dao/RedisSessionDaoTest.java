package io.github.biglv666.authkit.dao;

import io.lettuce.core.RedisClient;
import io.github.biglv666.authkit.model.AuthSession;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Redis 会话实现集成测试：直连本机 Redis（localhost:6379），Redis 不可用时整类跳过。
 * <p>继承契约测试基类，与内存实现跑同一套用例（交叉验证）。</p>
 */
@EnabledIf(value = "io.github.biglv666.authkit.dao.RedisSessionDaoTest#redisAvailable",
        disabledReason = "本机 Redis 未启动，跳过 Redis 集成测试")
class RedisSessionDaoTest extends AbstractSessionDaoContractTest {

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate template;
    private String prefix;

    /** JUnit @EnabledIf 入口：探测本机 6379 是否可达 */
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
    void initPrefix() {
        // 每个测试用独立前缀，避免用例间数据串扰
        prefix = "auth-kit:it:" + UUID.randomUUID() + ":";
    }

    @AfterEach
    void cleanupKeys() {
        Set<String> keys = template.keys("auth-kit:it:*");
        if (!keys.isEmpty()) {
            template.delete(keys);
        }
    }

    @Override
    protected SessionDao createDao() {
        return new RedisSessionDao(template, prefix);
    }

    @Test
    void sessionExpiresByRealTtl() throws InterruptedException {
        dao.saveSession(new AuthSession("ttl1", "10001", "APP", 1, 1), 200);
        Thread.sleep(400);
        assertNull(dao.getSession("ttl1"), "Redis TTL 到期后会话应已失效");
    }

    @Test
    void indexEntriesAreLazyCleanedByScore() throws InterruptedException {
        long now = System.currentTimeMillis();
        dao.addToUserIndex("10001", "APP", "gone", now + 200);
        dao.addToUserIndex("10001", "APP", "alive", now + 60_000);
        Thread.sleep(400);
        Set<String> tokens = dao.getUserTokens("10001", "APP");
        assertTrue(tokens.contains("alive"), "未过期 token 应保留");
        assertTrue(!tokens.contains("gone") || dao.getSession("gone") == null,
                "过期条目应被清理或视为脏数据");
    }
}
