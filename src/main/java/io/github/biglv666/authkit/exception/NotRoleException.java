package io.github.biglv666.authkit.exception;

/**
 * 无角色异常：已登录但不具备所需角色。
 */
public class NotRoleException extends RuntimeException {

    /** 缺失的角色标识 */
    private final String role;

    public NotRoleException(String role) {
        super("缺少角色：" + role);
        this.role = role;
    }

    /** 缺失的角色标识 */
    public String getRole() {
        return role;
    }
}
