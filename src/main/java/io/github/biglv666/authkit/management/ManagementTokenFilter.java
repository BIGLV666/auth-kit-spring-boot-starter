package io.github.biglv666.authkit.management;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.List;

/**
 * 管理端点令牌鉴权过滤器（与 api-governance 同思路）：
 * 基础路径下的请求必须携带有效令牌请求头，否则 401（不回显失败细节，防探测）。
 *
 * <p>支持多令牌（{@link ManagementTokenProvider}），便于灰度轮换；每次请求重新取令牌，
 * 动态 Provider 可在不重启的情况下生效。比较使用 SHA-256 摘要 + 常量时间比较，
 * 不泄露长度/前缀信息。</p>
 */
public class ManagementTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ManagementTokenFilter.class);

    private final String basePath;
    private final String authHeader;
    private final ManagementTokenProvider tokenProvider;

    /** 兼容单令牌构造（测试/旧代码） */
    public ManagementTokenFilter(String basePath, String authHeader, String authToken) {
        this(basePath, authHeader, fixedProvider(authToken));
    }

    public ManagementTokenFilter(String basePath, String authHeader, ManagementTokenProvider tokenProvider) {
        this.basePath = basePath;
        this.authHeader = authHeader;
        this.tokenProvider = tokenProvider;
    }

    private static ManagementTokenProvider fixedProvider(String authToken) {
        return () -> (authToken == null || authToken.isBlank()) ? List.of() : List.of(authToken);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!isManagementPath(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        String provided = request.getHeader(authHeader);
        if (!matchesAny(provided)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":40100,\"message\":\"unauthorized\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean matchesAny(String provided) {
        if (provided == null || provided.isBlank()) {
            return false;
        }
        byte[] providedDigest = sha256(provided);
        Collection<String> tokens;
        try {
            tokens = tokenProvider.tokens();
        } catch (Exception e) {
            // 令牌来源异常按拒绝处理（fail-closed），绝不因后端故障放行
            log.warn("[auth-kit] 获取管理令牌失败，按未授权处理: {}", e.getClass().getSimpleName());
            return false;
        }
        if (tokens == null) {
            return false;
        }
        for (String token : tokens) {
            if (token != null && !token.isBlank()
                    && MessageDigest.isEqual(providedDigest, sha256(token))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断请求是否落在管理端点下：去掉 context-path 后按路径段边界匹配，
     * 避免 base-path=/auth-kit 时误伤 /auth-kit-xxx 之类的业务路径。
     */
    private boolean isManagementPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String path = (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath))
                ? uri.substring(contextPath.length())
                : uri;
        String base = basePath.endsWith("/") && basePath.length() > 1
                ? basePath.substring(0, basePath.length() - 1)
                : basePath;
        if ("/".equals(base)) {
            return true;
        }
        return path.equals(base) || path.startsWith(base + "/");
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
