package io.github.biglv666.authkit.core;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Token 解析器：按配置从请求头（可选 Cookie）中提取登录凭证。
 * <p>支持 "Bearer xxx" 前缀风格（前缀剥离大小写不敏感），也支持裸 token。</p>
 */
public class TokenResolver {

    private final String headerName;
    private final String cookieName;
    private final String prefix;

    public TokenResolver(String headerName, String cookieName, String prefix) {
        this.headerName = headerName;
        this.cookieName = cookieName;
        this.prefix = prefix;
    }

    /**
     * 从请求中解析 token。
     *
     * @return token；请求未携带返回 null
     */
    public String resolve(HttpServletRequest request) {
        String value = request.getHeader(headerName);
        if (value == null || value.isBlank()) {
            value = resolveFromCookie(request);
        }
        if (value == null || value.isBlank()) {
            return null;
        }
        return stripPrefix(value.trim());
    }

    private String resolveFromCookie(HttpServletRequest request) {
        if (cookieName == null || cookieName.isBlank()) {
            return null;
        }
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /** 剥离可配置前缀（如 "Bearer "），大小写不敏感 */
    private String stripPrefix(String value) {
        if (prefix == null || prefix.isBlank()) {
            return value;
        }
        if (value.regionMatches(true, 0, prefix, 0, prefix.length())) {
            String rest = value.substring(prefix.length());
            if (rest.startsWith(" ")) {
                rest = rest.substring(1);
            }
            return rest.isBlank() ? null : rest.trim();
        }
        return value;
    }
}
