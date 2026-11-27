package io.github.biglv666.authkit.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 异步上下文传递：wrap 必须把请求上下文带到目标线程，并在结束后清理/恢复，
 * 避免线程池复用导致跨用户串号。
 */
class AuthContextWrapTest {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    @Test
    void runnableCarriesContextAndClearsAfter() throws Exception {
        AuthContext.set("u-1", "PC", "token-1");
        java.util.concurrent.atomic.AtomicReference<String> inside = new java.util.concurrent.atomic.AtomicReference<>();
        Runnable wrapped = AuthContext.wrap(() -> inside.set(AuthContext.getUserId()));
        executor.submit(wrapped).get();

        assertEquals("u-1", inside.get());
        Future<String> after = executor.submit(AuthContext::getUserId);
        assertNull(after.get(), "任务结束后目标线程必须清理上下文");
    }

    @Test
    void callableCarriesContextAndReturnsValue() throws Exception {
        AuthContext.set("u-2", "APP", "token-2");
        Callable<String> task = AuthContext.wrap((Callable<String>) AuthContext::getUserId);
        assertEquals("u-2", executor.submit(task).get());
        assertNull(executor.submit(AuthContext::getUserId).get());
    }

    @Test
    void restoresPreviousContextOnWorkerThread() throws Exception {
        AuthContext.set("request-user", "PC", "token-3");
        Callable<String> inner = AuthContext.wrap((Callable<String>) AuthContext::getUserId);
        Callable<String> task = () -> {
            AuthContext.set("worker-previous", "WORKER", "token-worker");
            String inside = inner.call();
            String restored = AuthContext.getUserId();
            return inside + "|" + restored;
        };
        assertEquals("request-user|worker-previous", executor.submit(task).get());
    }

    @Test
    void noContextPropagatesNothing() throws Exception {
        AuthContext.clear();
        Callable<String> inner = AuthContext.wrap((Callable<String>) AuthContext::getUserId);
        executor.submit(() -> AuthContext.set("stale", "PC", "stale-token")).get();
        assertNull(executor.submit(inner).get(), "请求未登录时不得把目标线程的旧上下文带进来");
    }
}
