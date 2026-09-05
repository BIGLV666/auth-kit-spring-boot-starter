package io.github.biglv666.authkit.model;

/**
 * 权限/角色校验模式：ALL=全部满足，ANY=满足其一。
 */
public enum AuthMode {
    /** 全部满足 */
    ALL,
    /** 满足其一 */
    ANY
}
