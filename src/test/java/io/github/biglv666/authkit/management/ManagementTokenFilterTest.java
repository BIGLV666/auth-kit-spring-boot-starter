package io.github.biglv666.authkit.management;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 管理端点令牌过滤器：鉴权生效范围必须按路径段边界判定。
 */
class ManagementTokenFilterTest {

    private static final String TOKEN = "management-secret";
    private static final String HEADER = "X-Auth-Kit-Token";

    private final ManagementTokenFilter filter = new ManagementTokenFilter("/auth-kit", HEADER, TOKEN);

    @Test
    void rejectsMissingTokenUnderBasePath() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth-kit/online");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertNull(chain.getRequest(), "未带令牌时不应放行到业务链");
    }

    @Test
    void allowsValidTokenUnderBasePath() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth-kit/online");
        request.addHeader(HEADER, TOKEN);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "令牌正确时应放行");
    }

    @Test
    void doesNotProtectSiblingPathWithSamePrefix() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth-kit-admin/dashboard");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "/auth-kit-admin 不属于 /auth-kit，不应被误拦");
    }

    @Test
    void matchesWhenContextPathIsPresent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/auth-kit/online");
        request.setContextPath("/app");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus(), "存在 context-path 时也必须命中管理端点");
    }
}
