package io.github.biglv666.authkit.core;

import java.util.Objects;
import java.util.concurrent.Callable;

/**
 * 请求级认证上下文（ThreadLocal）：由鉴权拦截器在请求入口填充，
 * afterCompletion 阶段强制清理，避免线程池复用导致的数据串号。
 * <p>异步场景（@Async / 自建线程池）ThreadLocal 不会自动传递，
 * 需在提交任务前读取并在任务内手动 {@code AuthContext.set(...)}。</p>
 */
public final class AuthContext {

    private record AuthInfo(String userId, String device, String token) {
    }

    private static final ThreadLocal<AuthInfo> HOLDER = new ThreadLocal<>();

    private AuthContext() {
    }

    /** 填充当前请求的认证信息（由拦截器调用） */
    public static void set(String userId, String device, String token) {
        HOLDER.set(new AuthInfo(userId, device, token));
    }

    /** 当前登录用户标识，未登录返回 null */
    public static String getUserId() {
        AuthInfo info = HOLDER.get();
        return info == null ? null : info.userId();
    }

    /** 当前登录设备标识，未登录返回 null */
    public static String getDevice() {
        AuthInfo info = HOLDER.get();
        return info == null ? null : info.device();
    }

    /** 当前请求携带的 token，未登录返回 null */
    public static String getToken() {
        AuthInfo info = HOLDER.get();
        return info == null ? null : info.token();
    }

    /** 当前请求是否已登录（基于 ThreadLocal，不做存储层校验） */
    public static boolean isLogin() {
        return getUserId() != null;
    }

    /** 清理上下文，必须在请求结束时调用（拦截器 afterCompletion 已自动处理） */
    public static void clear() {
        HOLDER.remove();
    }

    /**
     * 包装 {@link Runnable}：把当前请求的认证上下文带到目标线程执行，
     * 执行完恢复目标线程原有的上下文（避免线程池复用时串号）。
     *
     * <pre>{@code
     * executor.execute(AuthContext.wrap(() -> service.doAsync()));
     * }</pre>
     */
    public static Runnable wrap(Runnable task) {
        Objects.requireNonNull(task, "task");
        AuthInfo captured = HOLDER.get();
        return () -> {
            AuthInfo previous = HOLDER.get();
            restore(captured);
            try {
                task.run();
            } finally {
                restore(previous);
            }
        };
    }

    /**
     * 包装 {@link Callable}：把当前请求的认证上下文带到目标线程，返回时恢复。
     * <p>适用于 {@code ExecutorService.submit}/{@code CompletableFuture.supplyAsync} 等有返回值的场景。</p>
     */
    public static <T> Callable<T> wrap(Callable<T> task) {
        Objects.requireNonNull(task, "task");
        AuthInfo captured = HOLDER.get();
        return () -> {
            AuthInfo previous = HOLDER.get();
            restore(captured);
            try {
                return task.call();
            } finally {
                restore(previous);
            }
        };
    }

    private static void restore(AuthInfo info) {
        if (info == null) {
            HOLDER.remove();
        } else {
            HOLDER.set(info);
        }
    }
}
