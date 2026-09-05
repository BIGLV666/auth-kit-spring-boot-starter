package io.github.biglv666.authkit.management;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * 管理端点静态令牌鉴权过滤器（与 api-governance 同思路）：
 * 基础路径下的请求必须携带与配置一致的令牌请求头，否则 401（不回显失败细节，防探测）。
 * <p>令牌比对使用常量时间比较，防时序攻击；auth-token 为空时该过滤器不会被注册。</p>
 */
public class ManagementTokenFilter extends OncePerRequestFilter {

    private final String basePath;
    private final String authHeader;
    private final byte[] expectedToken;

    public ManagementTokenFilter(String basePath, String authHeader, String authToken) {
        this.basePath = basePath;
        this.authHeader = authHeader;
        this.expectedToken = hexToBytes(sha256(authToken));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!request.getRequestURI().startsWith(basePath)) {
            filterChain.doFilter(request, response);
            return;
        }
        String provided = request.getHeader(authHeader);
        if (provided == null || !MessageDigest.isEqual(expectedToken, hexToBytes(sha256(provided)))) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":40100,\"message\":\"unauthorized\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return new String(Hex.encode(digest));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private static byte[] hexToBytes(String hex) {
        return hex.getBytes(StandardCharsets.UTF_8);
    }
}
