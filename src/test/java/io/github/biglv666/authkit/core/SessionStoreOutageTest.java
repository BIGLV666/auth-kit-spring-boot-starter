package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.model.AuthSession;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 会话存储（Redis）故障时必须 fail-closed：
 * 异常向上抛出、绝不返回匿名会话；恢复后自动恢复正常校验。
 */
class SessionStoreOutageTest {

    @Test
    void storeFailurePropagatesAndDoesNotLoginAnonymously() {
        SessionDao dao = mock(SessionDao.class);
        when(dao.getSession("token")).thenThrow(new IllegalStateException("redis down"));
        AuthManager manager = new AuthManager(dao, new RandomTokenGenerator(64), 60_000, 0, 1);
        AuthContext.clear();

        assertThrows(IllegalStateException.class, () -> manager.checkLogin("token"));
        assertFalse(AuthContext.isLogin(), "存储层故障时不得产生任何登录态");
    }

    @Test
    void recoversWhenStoreReturns() {
        long now = System.currentTimeMillis();
        AuthSession session = new AuthSession("token", "u1", "PC", now, now);
        session.setExpireAt(now + 60_000);
        SessionDao dao = mock(SessionDao.class);
        when(dao.getSession("token"))
                .thenThrow(new IllegalStateException("redis down"))
                .thenReturn(session);
        AuthManager manager = new AuthManager(dao, new RandomTokenGenerator(64), 60_000, 0, 1);

        assertThrows(IllegalStateException.class, () -> manager.checkLogin("token"));
        assertEquals("u1", manager.checkLogin("token").getUserId());
    }
}
