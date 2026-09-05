package io.github.biglv666.authkit.oauth2.client;

/**
 * OAuth2 用户绑定 SPI：业务方决定"第三方档案 → 本地 userId"的映射
 * （按 openId 查绑定表，不存在可自动建号或走绑定页）。
 * <p>返回 null 表示拒绝登录（如未绑定的访客）。</p>
 */
public interface OAuth2UserBinder {

    /**
     * 将第三方用户档案绑定到本地用户。
     *
     * @param profile 平台解析出的用户档案
     * @return 本地 userId；返回 null 拒绝本次登录
     */
    String bind(OAuth2UserProfile profile);
}
