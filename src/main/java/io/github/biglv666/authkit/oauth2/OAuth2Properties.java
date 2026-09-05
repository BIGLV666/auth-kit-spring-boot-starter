package io.github.biglv666.authkit.oauth2;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth2/SSO 配置（前缀 auth-kit.oauth2）。
 * <p>server 与 client 相互独立，可单开、双开或全关（默认全关，V1 用户零感知）。</p>
 */
@ConfigurationProperties(prefix = "auth-kit.oauth2")
public class OAuth2Properties {

    private final Server server = new Server();
    private final Client client = new Client();

    /** 轻量授权服务器配置 */
    public static class Server {
        /** 是否启用授权服务器端点 */
        private boolean enabled = false;
        /** 客户端注册表：key=clientId */
        private Map<String, ClientRegistration> clients = new HashMap<>();
        /** 授权码有效期 */
        private Duration codeTtl = Duration.ofMinutes(5);
        /** 刷新令牌有效期 */
        private Duration refreshTtl = Duration.ofDays(30);
        /** 未登录时跳转的业务登录页（登录成功后业务需带用户回到 authorize 地址） */
        private String loginPage = "/login";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public Map<String, ClientRegistration> getClients() { return clients; }
        public void setClients(Map<String, ClientRegistration> clients) { this.clients = clients; }
        public Duration getCodeTtl() { return codeTtl; }
        public void setCodeTtl(Duration codeTtl) { this.codeTtl = codeTtl; }
        public Duration getRefreshTtl() { return refreshTtl; }
        public void setRefreshTtl(Duration refreshTtl) { this.refreshTtl = refreshTtl; }
        public String getLoginPage() { return loginPage; }
        public void setLoginPage(String loginPage) { this.loginPage = loginPage; }
    }

    /** 客户端注册（OAuth2 客户端 = 接入本授权服务器的三方应用） */
    public static class ClientRegistration {
        /** 客户端密钥 */
        private String clientSecret = "";
        /** 允许的回调地址（精确匹配） */
        private List<String> redirectUris = new ArrayList<>();
        /** 允许的 scope（空=不校验） */
        private List<String> scopes = new ArrayList<>();

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        public List<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(List<String> redirectUris) { this.redirectUris = redirectUris; }
        public List<String> getScopes() { return scopes; }
        public void setScopes(List<String> scopes) { this.scopes = scopes; }
    }

    /** 第三方登录客户端配置 */
    public static class Client {
        /** 是否启用第三方登录端点（配置了任一 provider 即建议开启） */
        private boolean enabled = false;
        /** 登录成功后的落地页（token 以查询参数附带） */
        private String successRedirect = "/";
        /** 第三方平台注册表：key=provider 名（github/wecom/...） */
        private Map<String, ProviderConfig> providers = new HashMap<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getSuccessRedirect() { return successRedirect; }
        public void setSuccessRedirect(String successRedirect) { this.successRedirect = successRedirect; }
        public Map<String, ProviderConfig> getProviders() { return providers; }
        public void setProviders(Map<String, ProviderConfig> providers) { this.providers = providers; }
    }

    /** 第三方平台参数（各平台取所需字段） */
    public static class ProviderConfig {
        /** GitHub 等 OAuth2 标准平台的 clientId */
        private String clientId = "";
        /** GitHub 等平台的 clientSecret */
        private String clientSecret = "";
        /** 授权回调地址（需与平台后台一致） */
        private String redirectUri = "";
        /** 企业微信：企业 ID */
        private String corpId = "";
        /** 企业微信：应用 secret */
        private String corpSecret = "";
        /** 企业微信：应用 agentId */
        private String agentId = "";

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        public String getCorpId() { return corpId; }
        public void setCorpId(String corpId) { this.corpId = corpId; }
        public String getCorpSecret() { return corpSecret; }
        public void setCorpSecret(String corpSecret) { this.corpSecret = corpSecret; }
        public String getAgentId() { return agentId; }
        public void setAgentId(String agentId) { this.agentId = agentId; }
    }

    public Server getServer() {
        return server;
    }

    public Client getClient() {
        return client;
    }
}
