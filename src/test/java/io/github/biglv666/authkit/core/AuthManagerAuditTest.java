package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class AuthManagerAuditTest {

    private AuthManager manager() {
        return new AuthManager(new InMemorySessionDao(), new RandomTokenGenerator(64),
                60_000, 0, 1);
    }

    @Test
    void loginPublishesSuccessAuditWithoutToken() {
        AuthManager manager = manager();
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
        AuthManager manager = manager();
        List<String> first = new CopyOnWriteArrayList<>();
        List<String> second = new CopyOnWriteArrayList<>();
        manager.addEventListener(event -> first.add(event.getAction().name()));
        manager.addEventListener(event -> second.add(event.getAction().name()));

        String token = manager.login("u1", "PC");
        manager.logout(token);

        assertEquals(List.of("LOGOUT"), first);
        assertEquals(List.of("LOGOUT"), second);
    }

    @Test
    void throwingListenerDoesNotBlockOtherListeners() {
        AuthManager manager = manager();
        List<String> received = new CopyOnWriteArrayList<>();
        manager.addEventListener(event -> {
            throw new IllegalStateException("business listener down");
        });
        manager.addEventListener(event -> received.add(event.getAction().name()));

        String token = manager.login("u1", "PC");
        assertDoesNotThrow(() -> manager.logout(token));
        assertEquals(List.of("LOGOUT"), received);
    }
}
