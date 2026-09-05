package com.example.demo;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.annotation.CurrentUser;
import io.github.biglv666.authkit.annotation.RequireLogin;
import io.github.biglv666.authkit.annotation.RequirePermission;
import io.github.biglv666.authkit.annotation.RequireSafe;
import io.github.biglv666.authkit.model.AuthUser;
import io.github.biglv666.authkit.spi.PermissionProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

/**
 * 演示 Controller：覆盖登录、注解鉴权、@CurrentUser、二级认证。
 */
@RestController
public class DemoController {

    /** 演示用户表：10001=alice(order:delete, role admin) / 20002=bob(无权限) */
    @Bean
    public PermissionProvider permissionProvider() {
        return new PermissionProvider() {
            @Override
            public Set<String> getPermissions(String userId) {
                return "10001".equals(userId) ? Set.of("order:delete") : Set.of();
            }

            @Override
            public Set<String> getRoles(String userId) {
                return "10001".equals(userId) ? Set.of("admin") : Set.of();
            }
        };
    }

    /** 演示登录（真实业务请先验密再调用 AuthKit.login） */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestParam String username) {
        boolean rememberMe = "alice".equals(username);
        String token = AuthKit.login("alice".equals(username) ? 10001L : 20002L, "WEB", rememberMe);
        return Map.of("token", token, "rememberMe", rememberMe);
    }

    @PostMapping("/logout")
    public Map<String, Object> logout() {
        AuthKit.logout();
        return Map.of("message", "已登出");
    }

    /** 游客可访问，登录后个性化 */
    @GetMapping("/feed")
    public Map<String, Object> feed(@CurrentUser(required = false) AuthUser user) {
        return Map.of("viewer", user == null ? "游客" : user.getUserId());
    }

    @RequireLogin
    @GetMapping("/me")
    public Map<String, Object> me(@CurrentUser AuthUser user) {
        return Map.of("userId", user.getUserId(), "device", user.getDevice());
    }

    @RequirePermission("order:delete")
    @PostMapping("/order/delete")
    public Map<String, Object> deleteOrder() {
        return Map.of("message", "订单已删除");
    }

    /** 敏感操作：需先 POST /safe/open（真实业务先验密）开启二级认证 */
    @RequireSafe
    @PostMapping("/safe/change-password")
    public Map<String, Object> changePassword() {
        return Map.of("message", "密码已修改");
    }
}
