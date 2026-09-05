package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.token.JwtTokenCodec;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JWT 模式下的 AuthManager 行为：验签代替会话读取，踢人/顶号/登出走墓碑。
 */
class AuthManagerJwtModeTest {

    private final AtomicLong now = new AtomicLong(1_000_000);
    private final InMemorySessionDao dao = new InMemorySessionDao(now::get);
    private final AuthManager manager = new AuthManager(
            dao, new RandomTokenGenerator(32), 30_000, 7_000, 1, 30_000, 60_000, now::get);

    private String login(String device) {
        return manager.login(10001, device);
    }

    private NotLoginReason reasonOf(String credential) {
        try {
            manager.checkLogin(credential);
            return null;
        } catch (NotLoginException e) {
            return e.getReason();
        }
    }

    @Test
    void jwtModeIsValidatingWithoutSessionRead() {
        manager.setTokenCodec(new JwtTokenCodec("jwt-mode-test-secret-001", 30_000, now::get));
        String credential = login("APP");
        // 删掉服务端会话：JWT 模式校验不依赖会话
        dao.deleteSession(dao.getUserTokens("10001", "APP").iterator().next());
        now.addAndGet(1_000);
        assertEquals("10001", manager.checkLogin(credential).getUserId(), "验签通过即有效");
    }

    @Test
    void jwtKickoutWritesTombstoneOnCredentialKey() {
        manager.setTokenCodec(new JwtTokenCodec("jwt-mode-test-secret-001", 30_000, now::get));
        String credential = login("APP");
        manager.kickout(10001, "APP");
        assertEquals(NotLoginReason.KICKED_OUT, reasonOf(credential));
    }

    @Test
    void jwtReloginReplacesOldCredential() {
        manager.setTokenCodec(new JwtTokenCodec("jwt-mode-test-secret-001", 30_000, now::get));
        String old = login("APP");
        now.addAndGet(1_000);
        login("APP");
        assertEquals(NotLoginReason.BE_REPLACED, reasonOf(old));
    }

    @Test
    void jwtLogoutInvalidatesCredential() {
        manager.setTokenCodec(new JwtTokenCodec("jwt-mode-test-secret-001", 30_000, now::get));
        String credential = login("APP");
        manager.logout(credential);
        assertEquals(NotLoginReason.TOKEN_INVALID, reasonOf(credential));
    }

    @Test
    void jwtListSessionsDescribesFromClaims() {
        manager.setTokenCodec(new JwtTokenCodec("jwt-mode-test-secret-001", 30_000, now::get));
        String credential = login("WEB");
        var sessions = manager.listSessions(10001, null);
        assertEquals(1, sessions.size());
        assertEquals("WEB", sessions.get(0).getDevice());
        assertEquals(credential, sessions.get(0).getToken());
        assertTrue(sessions.get(0).getLoginTime() > 0, "登录时间应来自 iat claim");
        assertNotNull(sessions.get(0).getUserId());
    }
}
