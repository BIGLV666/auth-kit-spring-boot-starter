package io.github.biglv666.authkit.management;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.model.AuthSession;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 在线会话管理端点：查看用户在线会话、强制下线。
 * <p>访问受 {@link ManagementTokenFilter} 静态令牌保护（auth-token 未配置时不注册整个管理端点），
 * 基础路径可通过 auth-kit.management.base-path 配置。</p>
 */
@RestController
@RequestMapping("${auth-kit.management.base-path:/auth-kit}")
public class OnlineSessionController {

    private final AuthManager authManager;

    public OnlineSessionController(AuthManager authManager) {
        this.authManager = authManager;
    }

    /**
     * 查询指定用户的在线会话列表。
     *
     * @param userId 用户标识
     * @param device 设备标识（可选，null 表示全部设备）
     * @return 会话列表（token 脱敏，仅保留前 8 位）
     */
    @GetMapping("/online")
    public List<Map<String, Object>> online(@RequestParam("userId") String userId,
                                            @RequestParam(value = "device", required = false) String device) {
        return authManager.listSessions(userId, device).stream().map(this::toMaskedMap).toList();
    }

    /**
     * 强制指定用户下线（可选设备维度），不写墓碑（旧端收到 TOKEN_INVALID 语义）。
     *
     * @param userId 用户标识
     * @param device 设备标识（可选，null 表示全部设备）
     */
    @DeleteMapping("/online/{userId}")
    public Map<String, Object> forceLogout(@PathVariable("userId") String userId,
                                           @RequestParam(value = "device", required = false) String device) {
        authManager.forceLogout(userId, device);
        return Map.of("success", true, "userId", userId);
    }

    /**
     * 踢指定用户下线（可选设备维度），写墓碑（旧端收到「已被强制下线」专用语义）。
     */
    @PostMapping("/online/{userId}/kick")
    public Map<String, Object> kickout(@PathVariable("userId") String userId,
                                       @RequestParam(value = "device", required = false) String device) {
        authManager.kickout(userId, device);
        return Map.of("success", true, "userId", userId);
    }

    private Map<String, Object> toMaskedMap(AuthSession session) {
        Map<String, Object> map = new HashMap<>(5);
        String token = session.getToken();
        map.put("token", token.length() <= 8 ? "****" : token.substring(0, 8) + "****");
        map.put("userId", session.getUserId());
        map.put("device", session.getDevice());
        map.put("loginTime", session.getLoginTime());
        map.put("lastActiveTime", session.getLastActiveTime());
        return map;
    }
}
