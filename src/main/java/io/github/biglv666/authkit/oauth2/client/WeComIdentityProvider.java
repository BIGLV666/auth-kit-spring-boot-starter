package io.github.biglv666.authkit.oauth2.client;

import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import org.springframework.web.client.RestClient;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 企业微信登录实现（企业内自建应用 OAuth2）。
 * <ul>
 *   <li>授权页：https://login.work.weixin.qq.com/wwlogin/sso/login（login_type=CorpApp）</li>
 *   <li>应用凭证：GET https://qyapi.weixin.qq.com/cgi-bin/gettoken</li>
 *   <li>code 换 userid：GET https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo</li>
 * </ul>
 * <p>注意：企业微信 access_token 有效期 2 小时且有频率限制，本实现按需获取未做缓存，
 * 高频场景建议业务方实现 IdentityProvider 时自行加缓存。</p>
 */
public class WeComIdentityProvider implements IdentityProvider {

    private final RestClient restClient;

    public WeComIdentityProvider() {
        this(defaultRestClient());
    }

    /**
     * 默认 RestClient：带连接/读取超时。平台接口挂起时不能占死 servlet 线程
     * （RestClient.create() 默认无超时，线程池可被拖垮）。
     */
    private static RestClient defaultRestClient() {
        org.springframework.http.client.SimpleClientHttpRequestFactory factory =
                new org.springframework.http.client.SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(3_000);
        factory.setReadTimeout(5_000);
        return RestClient.builder().requestFactory(factory).build();
    }

    public WeComIdentityProvider(RestClient restClient) {
        this.restClient = restClient;
    }

    @Override
    public String name() {
        return "wecom";
    }

    @Override
    public String authorizeUrl(OAuth2Properties.ProviderConfig config, String redirectUri, String state) {
        return "https://login.work.weixin.qq.com/wwlogin/sso/login"
                + "?login_type=CorpApp"
                + "&appid=" + urlEncode(config.getCorpId())
                + "&agentid=" + urlEncode(config.getAgentId())
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&state=" + urlEncode(state);
    }

    @Override
    @SuppressWarnings("unchecked")
    public OAuth2UserProfile exchange(OAuth2Properties.ProviderConfig config, String code, String redirectUri) {
        Map<String, Object> corpToken = restClient.get()
                .uri("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=" + urlEncode(config.getCorpId())
                        + "&corpsecret=" + urlEncode(config.getCorpSecret()))
                .retrieve()
                .body(Map.class);
        if (corpToken == null || !Integer.valueOf(0).equals(((Number) corpToken.getOrDefault("errcode", -1)).intValue())) {
            throw new IllegalStateException("企业微信获取应用凭证失败: " + corpToken);
        }
        Map<String, Object> user = restClient.get()
                .uri("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token="
                        + urlEncode((String) corpToken.get("access_token")) + "&code=" + urlEncode(code))
                .retrieve()
                .body(Map.class);
        if (user == null || !Integer.valueOf(0).equals(((Number) user.getOrDefault("errcode", -1)).intValue())
                || user.get("userid") == null) {
            throw new IllegalStateException("企业微信换取用户信息失败: " + user);
        }
        String userid = String.valueOf(user.get("userid"));
        return new OAuth2UserProfile("wecom", userid, userid, null, null, new LinkedHashMap<>(user));
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }
}
