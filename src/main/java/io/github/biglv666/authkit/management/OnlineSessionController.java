package io.github.biglv666.authkit.management;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.model.AuthSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 在线会话管理端点：查看用户在线会话、强制下线。
 * <p>访问受 {@link ManagementTokenFilter} 令牌保护（未配置令牌时不会注册整个管理端点），
 * 基础路径可通过 auth-kit.management.base-path 配置。</p>
 */
@RestController
@RequestMapping("${auth-kit.management.base-path:/auth-kit}")
public class OnlineSessionController {

    private static final Logger log = LoggerFactory.getLogger(OnlineSessionController.class);
    private static final int DEFAULT_MAX_ONLINE_SESSIONS = 200;

    private final AuthManager authManager;
    private final int maxOnlineSessions;

    public OnlineSessionController(AuthManager authManager) {
        this(authManager, DEFAULT_MAX_ONLINE_SESSIONS);
    }

    public OnlineSessionController(AuthManager authManager, int maxOnlineSessions) {
        this.authManager = authManager;
        this.maxOnlineSessions = maxOnlineSessions > 0 ? maxOnlineSessions : DEFAULT_MAX_ONLINE_SESSIONS;
    }

    /**
     * 查询指定用户的在线会话列表（按登录时间倒序，超过上限截断）。
     *
     * @param userId 用户标识
     * @param device 设备标识（可选，null 表示全部设备）
     * @return 会话列表（token 脱敏，仅保留前 8 位）
     */
    @GetMapping("/online")
    public List<Map<String, Object>> online(@RequestParam("userId") String userId,
                                            @RequestParam(value = "device", required = false) String device) {
        List<AuthSession> sessions = new ArrayList<>(authManager.listSessions(userId, device));
        sessions.sort(Comparator.comparingLong(AuthSession::getLoginTime).reversed());
        if (sessions.size() > maxOnlineSessions) {
            log.debug("在线会话数 {} 超过上限 {}，已截断 userId={}", sessions.size(), maxOnlineSessions, userId);
            sessions = sessions.subList(0, maxOnlineSessions);
        }
        long now = System.currentTimeMillis();
        List<Map<String, Object>> result = new ArrayList<>(sessions.size());
        for (AuthSession session : sessions) {
            result.add(toMaskedMap(session, now));
        }
        return result;
    }

    /**
     * 强制指定用户下线（可选设备维度），不写墓碑（旧端收到 TOKEN_INVALID 语义）。
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

    private Map<String, Object> toMaskedMap(AuthSession session, long now) {
        Map<String, Object> map = new HashMap<>(9);
        String token = session.getToken();
        map.put("token", token == null || token.length() <= 8 ? "****" : token.substring(0, 8) + "****");
        map.put("userId", session.getUserId());
        map.put("device", session.getDevice());
        map.put("loginTime", session.getLoginTime());
        map.put("lastActiveTime", session.getLastActiveTime());
        map.put("expireAt", session.getExpireAt());
        map.put("rememberMe", session.isRememberMe());
        map.put("remainingSeconds", session.getExpireAt() > 0
                ? Math.max(0, session.getExpireAt() - now) / 1000
                : -1);
        return map;
    }
}
