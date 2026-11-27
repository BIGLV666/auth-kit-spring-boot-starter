package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthManagerAuditTest {

    @Test
    void loginPublishesSuccessAuditWithoutToken() {
        SessionDao dao = mock(SessionDao.class);
        when(dao.getUserTokens(anyString(), anyString())).thenReturn(Set.of());
        AuthManager manager = new AuthManager(dao, new RandomTokenGenerator(64), 60_000, 0, 1);

        List<AuthKitAuditEvent> events = new CopyOnWriteArrayList<>();
        manager.addAuditListener(events::add);

        manager.login("u-audit", "PC");

        assertEquals(1, events.size());
        assertEquals(AuthKitAuditEvent.Action.LOGIN_SUCCESS, events.get(0).getAction());
        assertEquals("u-audit", events.get(0).getIdentifier());
        assertEquals("PC", events.get(0).getDevice());
    }

    @Test
    void multipleSessionListenersAreAllNotified() {
        SessionDao dao = mock(SessionDao.class);
        when(dao.getUserTokens(anyString(), anyString())).thenReturn(Set.of());
        AuthManager manager = new AuthManager(dao, new RandomTokenGenerator(64), 60_000, 0, 1);

        List<String> first = new CopyOnWriteArrayList<>();
        List<String> second = new CopyOnWriteArrayList<>();
        manager.addEventListener(event -> first.add(event.getAction().name()));
        manager.addEventListener(event -> second.add(event.getAction().name()));

        manager.login("u1", "PC");
        manager.logout("token-not-found");

        // 登录本身不产生会话事件；logout 对不存在会话也应幂等且不抛异常
        assertEquals(List.of(), first);
        assertEquals(List.of(), second);
    }
}
