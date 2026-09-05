package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话存储契约测试基类：内存实现与 Redis 实现跑同一套用例，
 * 两种实现互为对方的交叉验证。
 */
public abstract class AbstractSessionDaoContractTest {

    protected SessionDao dao;

    /** 由子类提供被测实现 */
    protected abstract SessionDao createDao();

    @BeforeEach
    void setUpDao() {
        dao = createDao();
    }

    private AuthSession session(String token, String userId, String device, long time) {
        return new AuthSession(token, userId, device, time, time);
    }

    @Test
    void saveAndGetRoundtrip() {
        dao.saveSession(session("t1", "10001", "APP", 1000), 60_000);
        AuthSession loaded = dao.getSession("t1");
        assertEquals("10001", loaded.getUserId());
        assertEquals("APP", loaded.getDevice());
        assertEquals(1000, loaded.getLoginTime());
    }

    @Test
    void getMissingReturnsNull() {
        assertNull(dao.getSession("not-exist"));
    }

    @Test
    void deleteIsIdempotent() {
        dao.saveSession(session("t2", "10001", "APP", 1000), 60_000);
        dao.deleteSession("t2");
        dao.deleteSession("t2");
        assertNull(dao.getSession("t2"));
    }

    @Test
    void sessionOverwriteKeepsLatestValues() {
        // 登录时的覆盖式保存
        dao.saveSession(session("t3", "10001", "APP", 1000), 60_000);
        AuthSession renewed = session("t3", "10001", "APP", 1000);
        renewed.setLastActiveTime(5000);
        dao.saveSession(renewed, 60_000);
        assertEquals(5000, dao.getSession("t3").getLastActiveTime());
    }

    @Test
    void updateLastActiveTimeChangesValueOnly() {
        dao.saveSession(session("t10", "10001", "APP", 1000), 60_000);
        dao.updateLastActiveTime("t10", 9000);
        AuthSession loaded = dao.getSession("t10");
        assertEquals(9000, loaded.getLastActiveTime());
        assertEquals(1000, loaded.getLoginTime(), "活跃时间更新不得影响其它字段");
    }

    @Test
    void updateLastActiveTimeOnMissingIsSilent() {
        dao.updateLastActiveTime("never-logged", 123);
        assertNull(dao.getSession("never-logged"));
    }

    @Test
    void kickMarkSurvivesSessionDelete() {
        dao.saveSession(session("t4", "10001", "APP", 1000), 60_000);
        dao.markKicked("t4", NotLoginReason.KICKED_OUT, 60_000);
        dao.deleteSession("t4");
        assertEquals(NotLoginReason.KICKED_OUT, dao.getKickReason("t4"));
    }

    @Test
    void kickMarkAbsentOrUnknownReturnsNull() {
        assertNull(dao.getKickReason("never-marked"));
    }

    @Test
    void kickMarkReplaceReason() {
        dao.markKicked("t5", NotLoginReason.BE_REPLACED, 60_000);
        assertEquals(NotLoginReason.BE_REPLACED, dao.getKickReason("t5"));
    }

    @Test
    void userIndexByDevice() {
        dao.addToUserIndex("10001", "APP", "t6", System.currentTimeMillis() + 60_000);
        dao.addToUserIndex("10001", "PC", "t7", System.currentTimeMillis() + 60_000);
        assertEquals(Set.of("t6"), dao.getUserTokens("10001", "APP"));
        Set<String> all = dao.getUserTokens("10001", null);
        assertTrue(all.containsAll(Set.of("t6", "t7")));
    }

    @Test
    void removeFromUserIndex() {
        dao.addToUserIndex("10001", "APP", "t8", System.currentTimeMillis() + 60_000);
        dao.removeFromUserIndex("10001", "APP", "t8");
        assertTrue(dao.getUserTokens("10001", "APP").isEmpty());
    }

    @Test
    void removeIndexIsIdempotent() {
        dao.removeFromUserIndex("nobody", "APP", "t9");
        assertTrue(dao.getUserTokens("nobody", "APP").isEmpty());
    }
}
