package io.github.biglv666.authkit.interceptor;

import io.github.biglv666.authkit.annotation.AuthIgnore;
import io.github.biglv666.authkit.annotation.RequireLogin;
import io.github.biglv666.authkit.annotation.RequirePermission;
import io.github.biglv666.authkit.annotation.RequireRole;
import io.github.biglv666.authkit.config.AuthKitProperties;
import io.github.biglv666.authkit.core.AuthContext;
import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.core.TokenResolver;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 鉴权拦截器：白名单放行 → 软解析登录态填充上下文 → 注解鉴权。
 * <p>工作方式：</p>
 * <ol>
 *   <li>白名单（Ant 风格）命中直接放行，不做任何校验；</li>
 *   <li>请求携带有效 token 时填充 {@link AuthContext}（即使无注解，保证 @CurrentUser 可用）；</li>
 *   <li>存在鉴权注解时强制校验；token 无效/被踢则抛出带原因的 NotLoginException；</li>
 *   <li>afterCompletion 强制清理 ThreadLocal，防止线程池复用串号。</li>
 * </ol>
 */
public class AuthInterceptor implements HandlerInterceptor {

    private final AuthKitProperties properties;
    private final AuthManager authManager;
    private final TokenResolver tokenResolver;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    /** 注解解析缓存：HandlerMethod 元数据不随请求变化，仅首次反射 */
    private final ConcurrentHashMap<HandlerMethod, AuthAnnotationInfo> annotationCache = new ConcurrentHashMap<>();

    public AuthInterceptor(AuthKitProperties properties, AuthManager authManager, TokenResolver tokenResolver) {
        this.properties = properties;
        this.authManager = authManager;
        this.tokenResolver = tokenResolver;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            // 非 Controller 方法（静态资源等）不做鉴权
            return true;
        }
        if (isWhitelisted(request)) {
            return true;
        }
        AuthAnnotationInfo info = annotationCache.computeIfAbsent(handlerMethod, this::resolveAnnotations);
        if (info.isIgnore()) {
            // 匿名端点：不校验、不填充
            return true;
        }
        String token = tokenResolver.resolve(request);
        AuthSession session = null;
        if (token != null) {
            if (info.isRequireAuth()) {
                // 强校验路径：失败直接抛出带原因的异常
                session = authManager.checkLogin(token);
            } else {
                try {
                    // 软解析路径：token 无效不拦截，保持匿名语义
                    session = authManager.checkLogin(token);
                } catch (NotLoginException e) {
                    session = null;
                }
            }
        }

        if (info.isRequireAuth() && session == null) {
            throw new NotLoginException(token == null ? NotLoginReason.NO_TOKEN : NotLoginReason.TOKEN_INVALID);
        }
        // 权限/角色/二级认证校验使用会话中的 userId（显式参数，不依赖 ThreadLocal）；
        // 全部通过后才填充上下文：若校验阶段抛异常，Spring 不会执行本拦截器的
        // afterCompletion，提前填充会在线程池中残留脏上下文（串号风险）
        if (session != null) {
            String userId = session.getUserId();
            if (info.getClassPermission() != null) {
                authManager.checkPermissions(userId, info.getClassPermission().values(),
                        info.getClassPermission().mode());
            }
            if (info.getMethodPermission() != null) {
                authManager.checkPermissions(userId, info.getMethodPermission().values(),
                        info.getMethodPermission().mode());
            }
            if (info.getClassRole() != null) {
                authManager.checkRoles(userId, info.getClassRole().values(), info.getClassRole().mode());
            }
            if (info.getMethodRole() != null) {
                authManager.checkRoles(userId, info.getMethodRole().values(), info.getMethodRole().mode());
            }
            if (info.isRequireSafe()) {
                authManager.checkSafe(userId);
            }
            AuthContext.set(userId, session.getDevice(), token);
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        AuthContext.clear();
    }

    /** 白名单匹配（Ant 风格），命中则完全放行 */
    private boolean isWhitelisted(HttpServletRequest request) {
        String uri = request.getRequestURI();
        for (String pattern : properties.getWhitelist()) {
            if (pathMatcher.match(pattern, uri)) {
                return true;
            }
        }
        return false;
    }

    /** 解析类级 + 方法级注解：类级与方法级规则独立保存（执行时取"与"关系） */
    private AuthAnnotationInfo resolveAnnotations(HandlerMethod handlerMethod) {
        Class<?> beanType = handlerMethod.getBeanType();
        RequireLogin classLogin = beanType.getAnnotation(RequireLogin.class);
        RequireLogin methodLogin = handlerMethod.getMethodAnnotation(RequireLogin.class);
        io.github.biglv666.authkit.annotation.RequireSafe classSafe =
                beanType.getAnnotation(io.github.biglv666.authkit.annotation.RequireSafe.class);
        io.github.biglv666.authkit.annotation.RequireSafe methodSafe =
                handlerMethod.getMethodAnnotation(io.github.biglv666.authkit.annotation.RequireSafe.class);
        RequirePermission classPermission = beanType.getAnnotation(RequirePermission.class);
        RequirePermission methodPermission = handlerMethod.getMethodAnnotation(RequirePermission.class);
        RequireRole classRole = beanType.getAnnotation(RequireRole.class);
        RequireRole methodRole = handlerMethod.getMethodAnnotation(RequireRole.class);
        // @AuthIgnore 仅方法级生效，防止整类匿名放行
        boolean ignore = handlerMethod.hasMethodAnnotation(AuthIgnore.class);
        return new AuthAnnotationInfo(
                ignore,
                AuthAnnotationInfo.hasLogin(classLogin),
                AuthAnnotationInfo.hasLogin(methodLogin),
                AuthAnnotationInfo.hasSafe(classSafe),
                AuthAnnotationInfo.hasSafe(methodSafe),
                AuthAnnotationInfo.toRule(classPermission),
                AuthAnnotationInfo.toRule(methodPermission),
                AuthAnnotationInfo.toRule(classRole),
                AuthAnnotationInfo.toRule(methodRole));
    }
}
