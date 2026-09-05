package io.github.biglv666.authkit.exception;

/**
 * 无权限异常：已登录但不具备所需权限。
 */
public class NotPermissionException extends RuntimeException {

    /** 缺失的权限码 */
    private final String permission;

    public NotPermissionException(String permission) {
        super("无权限：" + permission);
        this.permission = permission;
    }

    /** 缺失的权限码 */
    public String getPermission() {
        return permission;
    }
}
