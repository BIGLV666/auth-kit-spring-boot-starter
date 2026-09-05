package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.annotation.AuthIgnore;
import io.github.biglv666.authkit.annotation.CurrentUser;
import io.github.biglv666.authkit.annotation.RequireLogin;
import io.github.biglv666.authkit.annotation.RequirePermission;
import io.github.biglv666.authkit.annotation.RequireRole;
import io.github.biglv666.authkit.model.AuthMode;
import io.github.biglv666.authkit.model.AuthUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 集成测试 Controller：覆盖注解体系的各类组合场景。
 */
@RestController
public class TestController {

    /** 模拟业务登录：密码校验完成后调用 AuthKit 签发 token */
    @PostMapping("/login")
    public Map<String, String> login(@RequestParam("userId") String userId,
                                     @RequestParam(value = "device", defaultValue = "APP") String device) {
        return Map.of("token", AuthKit.login(userId, device));
    }

    /** 无任何注解：软解析路径，带有效 token 时 @CurrentUser 可用，不带也放行 */
    @GetMapping("/open/me-optional")
    public String meOptional(@CurrentUser(required = false) AuthUser user) {
        return user == null ? "anonymous" : user.getUserId();
    }

    @GetMapping("/need/login")
    @RequireLogin
    public String needLogin() {
        return "ok";
    }

    @GetMapping("/need/perm")
    @RequirePermission("order:delete")
    public String needPerm() {
        return "ok";
    }

    @GetMapping("/need/perm-any")
    @RequirePermission(value = {"order:list", "order:delete"}, mode = AuthMode.ANY)
    public String needPermAny() {
        return "ok";
    }

    @GetMapping("/need/perm-denied-any")
    @RequirePermission(value = {"user:read", "user:write"}, mode = AuthMode.ANY)
    public String needPermDeniedAny() {
        return "ok";
    }

    @GetMapping("/need/role")
    @RequireRole("admin")
    public String needRole() {
        return "ok";
    }

    @GetMapping("/me")
    @RequireLogin
    public String me(@CurrentUser AuthUser user) {
        return user.getUserId() + ":" + user.getDevice();
    }

    /** 白名单端点：完全无注解且路径在白名单中 */
    @GetMapping("/whitelisted/ping")
    public String ping() {
        return "pong";
    }
}

/** 类级注解测试：整个类要求权限，方法级 @AuthIgnore 可豁免单个方法 */
@RestController
@RequirePermission("order:admin")
class ClassSecuredController {

    @GetMapping("/class/secured")
    public String secured() {
        return "ok";
    }

    @GetMapping("/class/ignored")
    @AuthIgnore
    public String ignored() {
        return "ok";
    }

    @GetMapping("/class/any-of")
    @RequirePermission(value = {"order:admin", "order:manage"}, mode = AuthMode.ANY)
    public String anyOf() {
        return "ok";
    }
}
