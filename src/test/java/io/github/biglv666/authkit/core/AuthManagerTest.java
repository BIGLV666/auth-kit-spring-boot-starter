package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.exception.LoginLockedException;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.authkit.exception.NotRoleException;
import io.github.biglv666.authkit.model.AuthMode;
import io.github.biglv666.authkit.spi.PermissionProvider;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AuthManager 核心逻辑单测：内存会话 + 可注入时钟（不 sleep 模拟时间推进）。
 */
class AuthManagerTest {

    private final AtomicLong now = new AtomicLong(1_000_000);
    private final InMemorySessionDao dao = new InMemorySessionDao(now::get);
    private final AuthManager manager = new AuthManager(
            dao, new RandomTokenGenerator(32), 30_000, 7_000, 1, now::get);

    @BeforeEach
    void setUp() {
        manager.setPermissionProvider(new PermissionProvider() {
            @Override
            public Set<String> getPermissions(String userId) {
                return "10001".equals(userId)
                        ? Set.of("order:delete", "order:view")
                        : Set.of();
            }

            @Override
            public Set<String> getRoles(String userId) {
                return "10001".equals(userId) ? Set.of("admin") : Set.of();
            }
        });
    }

    @AfterEach
    void tearDown() {
        AuthContext.clear();
    }

    @Test
    void loginIssuesUniqueTokensAndCheckPasses() {
        String token1 = manager.login(10001, "APP");
        now.addAndGet(1);
        String token2 = manager.login(10001, "APP");
        assertNotEquals(token1, token2);
        // maxSessionsPerDevice=1：第二次登录顶掉第一次
        assertEquals(NotLoginReason.BE_REPLACED, reasonOf(token1));
        assertEquals("10001", manager.checkLogin(token2).getUserId());
    }

    @Test
    void activeTimeoutExpiresSession() {
        String token = manager.login(10001, "APP");
        now.addAndGet(7_001);
        assertEquals(NotLoginReason.TOKEN_TIMEOUT, reasonOf(token));
    }

    @Test
    void slidingRenewalKeepsActiveSessionAlive() {
        String token = manager.login(10001, "APP");
        // 绝对有效期 30s，但每隔 6s 活跃一次，累计跨越 12s 后仍有效
        for (int i = 0; i < 2; i++) {
            now.addAndGet(6_000);
            manager.checkLogin(token);
        }
        assertEquals("10001", manager.checkLogin(token).getUserId());
    }

    @Test
    void absoluteTimeoutWinsDespiteActivity() {
        String token = manager.login(10001, "APP");
        // 每 6s 活跃一次（小于 7s 活跃超时），持续到跨越 30s 绝对有效期
        for (int i = 0; i < 4; i++) {
            now.addAndGet(6_000);
            manager.checkLogin(token);
        }
        now.addAndGet(6_000);
        assertEquals(NotLoginReason.TOKEN_INVALID, reasonOf(token),
                "绝对有效期到期后，活跃也无法延长会话");
    }

    @Test
    void kickoutWritesTombstone() {
        String token = manager.login(10001, "APP");
        manager.kickout(10001, "APP");
        assertEquals(NotLoginReason.KICKED_OUT, reasonOf(token));
    }

    @Test
    void kickoutAllDevicesWhenDeviceNull() {
        String appToken = manager.login(10001, "APP");
        String pcToken = manager.login(10001, "PC");
        manager.kickout(10001, null);
        assertEquals(NotLoginReason.KICKED_OUT, reasonOf(appToken));
        assertEquals(NotLoginReason.KICKED_OUT, reasonOf(pcToken));
    }

    @Test
    void forceLogoutHasNoTombstone() {
        String token = manager.login(10001, "APP");
        manager.forceLogout(10001, null);
        assertEquals(NotLoginReason.TOKEN_INVALID, reasonOf(token));
    }

    @Test
    void logoutIsClean() {
        String token = manager.login(10001, "APP");
        manager.logout(token);
        assertEquals(NotLoginReason.TOKEN_INVALID, reasonOf(token));
    }

    @Test
    void maxSessionsTwoKeepsNewest() {
        AuthManager multi = new AuthManager(dao, new RandomTokenGenerator(32), 30_000, 0, 2, now::get);
        String t1 = multi.login(10001, "APP");
        now.addAndGet(1);
        String t2 = multi.login(10001, "APP");
        now.addAndGet(1);
        String t3 = multi.login(10001, "APP");
        assertEquals(NotLoginReason.BE_REPLACED, reasonOf(t1));
        assertEquals("10001", multi.checkLogin(t2).getUserId());
        assertEquals("10001", multi.checkLogin(t3).getUserId());
    }

    @Test
    void unlimitedSessionsWhenNegative() {
        AuthManager unlimited = new AuthManager(dao, new RandomTokenGenerator(32), 30_000, 0, -1, now::get);
        String t1 = unlimited.login(10001, "APP");
        String t2 = unlimited.login(10001, "APP");
        unlimited.checkLogin(t1);
        unlimited.checkLogin(t2);
    }

    @Test
    void checkPermissionAndRole() {
        String token = manager.login(10001, "APP");
        AuthContext.set("10001", "APP", token);
        manager.checkPermission("order:delete");
        manager.checkPermissions(java.util.List.of("order:delete", "order:view"), AuthMode.ALL);
        manager.checkPermissions(java.util.List.of("order:delete", "user:any"), AuthMode.ANY);
        manager.checkRole("admin");
        manager.checkRoles(java.util.List.of("admin", "ops"), AuthMode.ANY);
        assertTrue(manager.hasPermission("order:delete"));
        assertTrue(manager.hasRole("admin"));
    }

    @Test
    void checkPermissionFailsWithoutOwnership() {
        String token = manager.login(10001, "APP");
        AuthContext.set("10001", "APP", token);
        assertThrows(NotPermissionException.class, () -> manager.checkPermission("user:delete"));
        assertThrows(NotPermissionException.class,
                () -> manager.checkPermissions(java.util.List.of("order:delete", "user:delete"), AuthMode.ALL));
        assertThrows(NotRoleException.class, () -> manager.checkRole("super-admin"));
        assertFalse(manager.hasPermission("user:delete"));
    }

    @Test
    void permissionCheckRequiresLogin() {
        assertThrows(NotLoginException.class, () -> manager.checkPermission("order:delete"));
    }

    @Test
    void listSessionsReturnsActiveOnly() {
        manager.login(10001, "APP");
        String pcToken = manager.login(10001, "PC");
        assertEquals(1, manager.listSessions(10001, "PC").size());
        assertEquals(1, manager.listSessions(10001, "APP").size());
        manager.kickout(10001, "APP");
        assertEquals(1, manager.listSessions(10001, null).size());
        assertTrue(manager.listSessions(10001, null).get(0).getToken().equals(pcToken));
    }

    private NotLoginReason reasonOf(String token) {
        try {
            manager.checkLogin(token);
            return null;
        } catch (NotLoginException e) {
            return e.getReason();
        }
    }
}
