package io.github.biglv666.authkit.oauth2.client;

import io.github.biglv666.authkit.oauth2.OAuth2Properties;

/**
 * 第三方身份提供者 SPI：封装单个平台的授权跳转、code 换取、档案解析三步。
 * <p>内置 GitHub 与企业微信实现；其他平台（微信小程序、钉钉等）业务方实现本接口
 * 注册 Bean 即可接入，平台参数用 {@link OAuth2Properties.ProviderConfig} 承载。</p>
 */
public interface IdentityProvider {

    /** 平台名（与配置 key、回调路径 /oauth2/callback/{provider} 一致） */
    String name();

    /**
     * 构造平台授权页地址。
     *
     * @param config      平台参数
     * @param redirectUri 回调地址（来自配置，需与平台后台一致）
     * @param state       防 CSRF 随机串（组件生成并存储，回调时校验）
     * @return 平台授权页完整 URL
     */
    String authorizeUrl(OAuth2Properties.ProviderConfig config, String redirectUri, String state);

    /**
     * 用授权码换取用户档案（内部完成 token 交换与用户信息拉取）。
     *
     * @throws IllegalStateException 平台响应异常（errcode 非 0 / HTTP 失败 / 缺少关键字段）
     */
    OAuth2UserProfile exchange(OAuth2Properties.ProviderConfig config, String code, String redirectUri);
}
