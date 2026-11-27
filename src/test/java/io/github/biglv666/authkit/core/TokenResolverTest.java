package io.github.biglv666.authkit.core;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class TokenResolverTest {

    private static final String HEADER = "Authorization";

    @Test
    void headerTakesPrecedence() {
        TokenResolver resolver = new TokenResolver(HEADER, "auth_token", "Bearer", "access_token");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER, "Bearer header-token");
        request.setCookies(new Cookie("auth_token", "cookie-token"));
        request.setParameter("access_token", "query-token");

        assertEquals("header-token", resolver.resolve(request));
    }

    @Test
    void cookieUsedWhenHeaderMissing() {
        TokenResolver resolver = new TokenResolver(HEADER, "auth_token", "Bearer", "access_token");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("auth_token", "cookie-token"));

        assertEquals("cookie-token", resolver.resolve(request));
    }

    @Test
    void queryParameterUsedOnlyWhenConfiguredAndOnlyForGet() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/stream");
        request.setParameter("access_token", "query-token");

        assertNull(new TokenResolver(HEADER, "", "Bearer").resolve(request),
                "默认不得读取查询参数");

        assertEquals("query-token",
                new TokenResolver(HEADER, "", "Bearer", "access_token").resolve(request));

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/api/order");
        post.setParameter("access_token", "query-token");
        assertNull(new TokenResolver(HEADER, "", "Bearer", "access_token").resolve(post),
                "query token 仅用于 GET/SSE，不得从 POST 表单读取");
    }

    @Test
    void prefixIsCaseInsensitiveAndOptional() {
        TokenResolver resolver = new TokenResolver(HEADER, "", "Bearer");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER, "bearer token-x");
        assertEquals("token-x", resolver.resolve(request));

        request = new MockHttpServletRequest();
        request.addHeader(HEADER, "token-y");
        assertEquals("token-y", resolver.resolve(request));
    }

    @Test
    void returnsNullWhenNoCredential() {
        assertNull(new TokenResolver(HEADER, "", "Bearer", "access_token")
                .resolve(new MockHttpServletRequest()));
    }
}
