package io.github.biglv666.authkit.spi;

import java.util.Set;

/**
 * 权限数据 SPI：auth-kit 不带用户表，业务方实现此接口对接自己的 user/role/permission 表。
 * <p>这是本组件与 RuoYi 类内置用户体系框架的本质区别：认证归组件，用户数据归业务。</p>
 * <p>两个方法均有空集默认实现，按需覆写即可。返回结果不做缓存，需要缓存时
 * 由实现方自行处理（建议带短 TTL 的本地缓存）。</p>
 */
public interface PermissionProvider {

    /**
     * 查询用户拥有的权限码集合（如 "order:delete"）。
     *
     * @param userId 用户标识
     * @return 权限码集合，永不为 null（默认空集）
     */
    default Set<String> getPermissions(String userId) {
        return Set.of();
    }

    /**
     * 查询用户拥有的角色标识集合。
     *
     * @param userId 用户标识
     * @return 角色标识集合，永不为 null（默认空集）
     */
    default Set<String> getRoles(String userId) {
        return Set.of();
    }
}
