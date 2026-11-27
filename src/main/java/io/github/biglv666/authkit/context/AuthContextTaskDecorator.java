package io.github.biglv666.authkit.context;

import io.github.biglv666.authkit.core.AuthContext;
import org.springframework.core.task.TaskDecorator;

/**
 * 把认证上下文传递到 Spring 线程池任务的 {@link TaskDecorator}。
 *
 * <p>开启 {@code auth-kit.context.propagate-async=true} 后自动注册为默认 {@code TaskDecorator}，
 * 业务注入的 {@code ThreadPoolTaskExecutor} 无需逐处包裹；非 Spring 管理的线程池请直接使用
 * {@link AuthContext#wrap(Runnable)} / {@link AuthContext#wrap(java.util.concurrent.Callable)}。</p>
 */
public class AuthContextTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        return AuthContext.wrap(runnable);
    }
}
