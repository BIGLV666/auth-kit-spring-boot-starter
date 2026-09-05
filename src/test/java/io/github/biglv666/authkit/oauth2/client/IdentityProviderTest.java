package io.github.biglv666.authkit.oauth2.client;

import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * GitHub / 企业微信 IdentityProvider 单测：用 MockRestServiceServer 桩掉 HTTP。
 */
class IdentityProviderTest {

    private final OAuth2Properties.ProviderConfig githubConfig = new OAuth2Properties.ProviderConfig();
    private final OAuth2Properties.ProviderConfig wecomConfig = new OAuth2Properties.ProviderConfig();

    {
        githubConfig.setClientId("gh-client");
        githubConfig.setClientSecret("gh-secret");
        githubConfig.setRedirectUri("https://app.example/cb");
        wecomConfig.setCorpId("ww-corp");
        wecomConfig.setCorpSecret("wecom-secret");
        wecomConfig.setAgentId("1000002");
        wecomConfig.setRedirectUri("https://app.example/cb");
    }

    @Test
    void githubAuthorizeUrlContainsRequiredParams() {
        GitHubIdentityProvider provider = new GitHubIdentityProvider();
        String url = provider.authorizeUrl(githubConfig, "https://app.example/cb", "st-1");
        assertTrue(url.startsWith("https://github.com/login/oauth/authorize"));
        assertTrue(url.contains("client_id=gh-client"));
        assertTrue(url.contains("state=st-1"));
        assertTrue(url.contains("scope=read:user"));
    }

    @Test
    void githubExchangeTokenAndProfile() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://github.com/login/oauth/access_token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess("{\"access_token\":\"gho_token\"}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.github.com/user"))
                .andRespond(withSuccess("{\"id\":12345,\"login\":\"octo\",\"name\":\"Octo Cat\"}",
                        MediaType.APPLICATION_JSON));

        GitHubIdentityProvider provider = new GitHubIdentityProvider(builder.build());
        OAuth2UserProfile profile = provider.exchange(githubConfig, "the-code", "https://app.example/cb");
        assertEquals("12345", profile.openId());
        assertEquals("octo", profile.username());
        assertEquals("Octo Cat", profile.nickname());
        assertEquals("github", profile.provider());
        server.verify();
    }

    @Test
    void githubExchangeFailsWhenTokenMissing() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer.bindTo(builder).build();
        builder.build();
        GitHubIdentityProvider provider = new GitHubIdentityProvider(
                org.springframework.web.client.RestClient.create());
        // 用一个永不匹配的假服务不可行——直接验证错误分支：平台返回无 access_token
        RestClient.Builder b2 = RestClient.builder();
        MockRestServiceServer s2 = MockRestServiceServer.bindTo(b2).build();
        s2.expect(requestTo("https://github.com/login/oauth/access_token"))
                .andRespond(withSuccess("{\"error\":\"bad_verification_code\"}", MediaType.APPLICATION_JSON));
        GitHubIdentityProvider failing = new GitHubIdentityProvider(b2.build());
        assertThrows(IllegalStateException.class, () -> failing.exchange(githubConfig, "bad", "https://app.example/cb"));
    }

    @Test
    void wecomAuthorizeUrlContainsCorpParams() {
        WeComIdentityProvider provider = new WeComIdentityProvider();
        String url = provider.authorizeUrl(wecomConfig, "https://app.example/cb", "st-2");
        assertTrue(url.startsWith("https://login.work.weixin.qq.com/wwlogin/sso/login"));
        assertTrue(url.contains("appid=ww-corp"));
        assertTrue(url.contains("agentid=1000002"));
        assertTrue(url.contains("login_type=CorpApp"));
    }

    @Test
    void wecomExchangeGetsCorpTokenThenUserId() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ww-corp&corpsecret=wecom-secret"))
                .andRespond(withSuccess("{\"errcode\":0,\"access_token\":\"corp-token\"}", MediaType.APPLICATION_JSON));
        server.expect(requestTo(
                "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=corp-token&code=wx-code"))
                .andRespond(withSuccess("{\"errcode\":0,\"userid\":\"zhangsan\"}", MediaType.APPLICATION_JSON));

        WeComIdentityProvider provider = new WeComIdentityProvider(builder.build());
        OAuth2UserProfile profile = provider.exchange(wecomConfig, "wx-code", "https://app.example/cb");
        assertEquals("zhangsan", profile.openId());
        assertEquals("wecom", profile.provider());
        server.verify();
    }

    @Test
    void wecomErrcodeNonZeroFails() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ww-corp&corpsecret=wecom-secret"))
                .andRespond(withSuccess("{\"errcode\":40013,\"errmsg\":\"invalid corpid\"}", MediaType.APPLICATION_JSON));
        WeComIdentityProvider provider = new WeComIdentityProvider(builder.build());
        assertThrows(IllegalStateException.class, () -> provider.exchange(wecomConfig, "x", "https://app.example/cb"));
        server.verify();
    }

    @Test
    void unusedConfigMapRemainsAssignable() {
        // ProviderConfig 承载各平台异构参数的编译期验证
        Map<String, OAuth2Properties.ProviderConfig> providers = Map.of("github", githubConfig, "wecom", wecomConfig);
        assertEquals(2, providers.size());
    }
}
