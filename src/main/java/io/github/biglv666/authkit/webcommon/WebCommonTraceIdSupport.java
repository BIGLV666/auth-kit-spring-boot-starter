package io.github.biglv666.authkit.webcommon;

import io.github.biglv666.webcommon.result.Result;

import java.lang.reflect.Method;

/**
 * web-common traceId 兼容支持。
 *
 * <p>auth-kit 的编译基线是 web-common 0.3.0；{@code traceId} 能力（{@code Result.setTraceId}
 * / {@code TraceIds} / {@code WebCommonProperties.TraceId}）在 0.5.0 才加入。
 * 为了让 1.3.0 同时兼容 0.3.0 与 0.5.0，这里用反射按能力探测：
 * 存在则把 MDC 中的 traceId 写入 auth-kit 的错误 Result；不存在则静默跳过。
 * 任何反射差异都不得影响认证异常的正常响应。</p>
 */
final class WebCommonTraceIdSupport {

    private WebCommonTraceIdSupport() {
    }

    static void apply(Object webCommonProperties, Result<?> result) {
        if (webCommonProperties == null || result == null) {
            return;
        }
        try {
            Object traceIdConfig = invokeNoArg(webCommonProperties, "getTraceId");
            if (traceIdConfig == null) {
                return;
            }
            Object enabled = invokeNoArg(traceIdConfig, "isEnabled");
            if (!Boolean.TRUE.equals(enabled)) {
                return;
            }
            Object mdcKey = invokeNoArg(traceIdConfig, "getMdcKey");
            if (!(mdcKey instanceof String key) || key.isBlank()) {
                return;
            }
            Class<?> traceIds = Class.forName("io.github.biglv666.webcommon.web.TraceIds");
            Object current = traceIds.getMethod("current", String.class).invoke(null, key);
            if (!(current instanceof String traceId) || traceId.isBlank()) {
                return;
            }
            Method setTraceId = result.getClass().getMethod("setTraceId", String.class);
            setTraceId.invoke(result, traceId);
        } catch (Exception | LinkageError ignored) {
            // web-common 0.3.x 没有 traceId 能力，或版本差异导致反射失败：保持原响应
        }
    }

    private static Object invokeNoArg(Object target, String method) throws ReflectiveOperationException {
        return target.getClass().getMethod(method).invoke(target);
    }
}
