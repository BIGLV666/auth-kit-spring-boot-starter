package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.model.AuthSession;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 内存会话实现：契约用例（继承）+ 基于可注入时钟的过期语义用例。
 */
class InMemorySessionDaoTest extends AbstractSessionDaoContractTest {

    private final AtomicLong now = new AtomicLong(1_000_000);

    @Override
    protected SessionDao createDao() {
        return new InMemorySessionDao(now::get);
    }

    @Test
    void sessionExpiresAfterTimeout() {
        now.set(1_000_000);
        dao.saveSession(new AuthSession("e1", "10001", "APP", 1_000_000, 1_000_000), 1_000);
        now.set(1_001_000);
        assertNull(dao.getSession("e1"), "到达过期时间后会话应已过期");
    }

    @Test
    void kickMarkExpires() {
        now.set(2_000_000);
        dao.markKicked("e2", io.github.biglv666.authkit.exception.NotLoginReason.KICKED_OUT, 500);
        now.set(2_000_501);
        assertNull(dao.getKickReason("e2"), "墓碑过期后应不再返回踢出原因");
    }

    @Test
    void updateLastActiveTimeDoesNotExtendTtl() {
        now.set(3_000_000);
        dao.saveSession(new AuthSession("e3", "10001", "APP", 3_000_000, 3_000_000), 5_000);
        now.set(3_004_000);
        dao.updateLastActiveTime("e3", 3_004_000);
        now.set(3_006_000);
        assertNull(dao.getSession("e3"), "活跃时间更新不得延长绝对有效期（登录后 6s，超 5s TTL）");
    }
}
