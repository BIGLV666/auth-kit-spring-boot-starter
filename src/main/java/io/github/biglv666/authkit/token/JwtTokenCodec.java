package io.github.biglv666.authkit.token;

import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.function.LongSupplier;

/**
 * JWT 凭证编解码（自校验模式）：HS256 签名，纯 JDK 实现（javax.crypto），零第三方依赖。
 * <p>claims：{@code {"uid": userId, "dev": device, "iat": 登录秒, "exp": 过期秒}}。
 * 校验路径 = 验签 + exp + 墓碑黑名单；用户索引/墓碑作用于凭证的 SHA-256 摘要（{@link #keyOf}）。</p>
 * <p><b>模式代价</b>：不读会话 → 无滑动续期、无活跃数据；踢人/顶号/登出全部经由墓碑实现，
 * 语义与 opaque 模式一致。</p>
 */
public class JwtTokenCodec implements TokenCodec {

    private static final String HEADER_B64 = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    private static final long SECONDS_SHIFT = 1000L;

    private final byte[] secret;
    private final long timeoutMillis;
    private final LongSupplier clock;

    public JwtTokenCodec(String secret, long timeoutMillis) {
        this(secret, timeoutMillis, System::currentTimeMillis);
    }

    /** 时间源可注入，供测试模拟过期 */
    public JwtTokenCodec(String secret, long timeoutMillis, LongSupplier clock) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.timeoutMillis = timeoutMillis;
        this.clock = clock;
    }

    @Override
    public boolean selfValidating() {
        return true;
    }

    @Override
    public String issue(AuthSession session, String randomToken) {
        long now = clock.getAsLong();
        long iat = now / SECONDS_SHIFT;
        long exp = (now + timeoutMillis) / SECONDS_SHIFT;
        // jti = 内部随机 token：保证同一秒内同用户同设备的两次登录凭证不同（防会话固定）
        String payload = "{\"uid\":\"" + escape(session.getUserId())
                + "\",\"dev\":\"" + escape(session.getDevice())
                + "\",\"iat\":" + iat + ",\"exp\":" + exp
                + ",\"jti\":\"" + escape(randomToken) + "\"}";
        String payloadB64 = base64Url(payload.getBytes(StandardCharsets.UTF_8));
        String signingInput = HEADER_B64 + "." + payloadB64;
        return signingInput + "." + base64Url(hmac(signingInput));
    }

    @Override
    public String verify(String credential) {
        String[] parts = credential.split("\\.");
        if (parts.length != 3 || !HEADER_B64.equals(parts[0])) {
            throw new NotLoginException(NotLoginReason.TOKEN_INVALID);
        }
        byte[] expected = hmac(parts[0] + "." + parts[1]);
        byte[] provided;
        try {
            provided = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new NotLoginException(NotLoginReason.TOKEN_INVALID);
        }
        if (!MessageDigest.isEqual(expected, provided)) {
            throw new NotLoginException(NotLoginReason.TOKEN_INVALID);
        }
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        Long exp = readNumericClaim(payload, "exp");
        if (exp != null && exp * SECONDS_SHIFT <= clock.getAsLong()) {
            throw new NotLoginException(NotLoginReason.TOKEN_TIMEOUT);
        }
        return credential;
    }

    @Override
    public AuthSession describe(String credential) {
        // 必须先 verify 再 describe；此处仅解析不验签
        try {
            String payload = new String(Base64.getUrlDecoder().decode(credential.split("\\.")[1]), StandardCharsets.UTF_8);
            String uid = readStringClaim(payload, "uid");
            String dev = readStringClaim(payload, "dev");
            Long iat = readNumericClaim(payload, "iat");
            AuthSession session = new AuthSession();
            session.setToken(credential);
            session.setUserId(uid);
            session.setDevice(dev);
            session.setLoginTime(iat == null ? 0 : iat * SECONDS_SHIFT);
            return session;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String keyOf(String credential) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(credential.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private byte[] hmac(String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 不可用", e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** 极简 JSON 字符串转义：组件自产自销的 claims，仅需覆盖常见字符 */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static Long readNumericClaim(String json, String key) {
        String marker = "\"" + key + "\":";
        int start = json.indexOf(marker);
        if (start < 0) {
            return null;
        }
        start += marker.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        try {
            return Long.parseLong(json.substring(start, end));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String readStringClaim(String json, String key) {
        String marker = "\"" + key + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) {
            return null;
        }
        start += marker.length();
        StringBuilder sb = new StringBuilder();
        while (start < json.length()) {
            char c = json.charAt(start);
            if (c == '\\' && start + 1 < json.length()) {
                sb.append(json.charAt(start + 1));
                start += 2;
            } else if (c == '"') {
                break;
            } else {
                sb.append(c);
                start++;
            }
        }
        return sb.toString();
    }
}
