package io.github.biglv666.authkit.management;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class ManagementTokenFilterMultiTokenTest {

    private static final String HEADER = "X-Auth-Kit-Token";

    @Test
    void acceptsAnyConfiguredToken() throws Exception {
        ManagementTokenFilter filter = new ManagementTokenFilter("/auth-kit", HEADER,
                () -> List.of("old-token", "new-token"));

        assertPassed(filter, "new-token", true);
        assertPassed(filter, "old-token", true);
        assertPassed(filter, "wrong-token", false);
    }

    @Test
    void emptyProviderRejectsEverything() throws Exception {
        ManagementTokenFilter filter = new ManagementTokenFilter("/auth-kit", HEADER, List::of);
        assertPassed(filter, "anything", false);
    }

    @Test
    void providerFailureIsFailClosed() throws Exception {
        ManagementTokenFilter filter = new ManagementTokenFilter("/auth-kit", HEADER, () -> {
            throw new IllegalStateException("config center down");
        });
        assertPassed(filter, "token", false);
    }

    private void assertPassed(ManagementTokenFilter filter, String token, boolean expected) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth-kit/online");
        request.addHeader(HEADER, token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        if (expected) {
            assertNotNull(chain.getRequest(), "有效令牌应放行: " + token);
        } else {
            assertNull(chain.getRequest(), "无效令牌不应放行: " + token);
            assertEquals(401, response.getStatus());
        }
    }
}
