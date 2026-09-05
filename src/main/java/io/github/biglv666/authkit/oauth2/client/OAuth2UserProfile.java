package io.github.biglv666.authkit.oauth2.client;

import java.util.Map;

/**
 * 第三方登录用户档案：由 {@link IdentityProvider} 从平台响应解析，
 * 交给业务方 {@link OAuth2UserBinder} 绑定到本地 userId。
 *
 * @param provider 平台名（github / wecom / ...）
 * @param openId   平台侧唯一标识（GitHub userId / 企业微信 userid）
 * @param username 登录名（可能为空）
 * @param nickname 昵称（可能为空）
 * @param email    邮箱（可能为空）
 * @param raw      平台原始响应（供业务取扩展字段）
 */
public record OAuth2UserProfile(String provider, String openId, String username,
                                String nickname, String email, Map<String, Object> raw) {
}
