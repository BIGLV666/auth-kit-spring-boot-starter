package io.github.biglv666.authkit.token;

import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JWT 凭证编解码单测：签发/验签/过期/篡改/摘要，时间源可注入。
 */
class JwtTokenCodecTest {

    private final AtomicLong now = new AtomicLong(1_700_000_000_000L);
    private final JwtTokenCodec codec = new JwtTokenCodec("unit-test-secret-0123456789", 30_000, now::get);

    private AuthSession session(String uid) {
        return new AuthSession("random", uid, "APP", now.get(), now.get());
    }

    @Test
    void issueAndVerifyRoundtrip() {
        String jwt = codec.issue(session("10001"), "random");
        assertNotEquals("random", jwt);
        assertEquals(jwt, codec.verify(jwt), "verify 校验通过返回原凭证");
        assertEquals(3, jwt.split("\\.").length);
    }

    @Test
    void sameSecondLoginsProduceDistinctJwts() {
        String jwt1 = codec.issue(session("10001"), "random-1");
        String jwt2 = codec.issue(session("10001"), "random-2");
        assertNotEquals(jwt1, jwt2, "jti（内部随机 token）应保证凭证唯一");
    }

    @Test
    void describeExtractsClaims() {
        String jwt = codec.issue(session("10001"), "random");
        AuthSession described = codec.describe(jwt);
        assertNotNull(described);
        assertEquals("10001", described.getUserId());
        assertEquals("APP", described.getDevice());
    }

    @Test
    void expiredJwtThrowsTimeout() {
        String jwt = codec.issue(session("10001"), "random");
        now.addAndGet(30_001);
        NotLoginException e = assertThrows(NotLoginException.class, () -> codec.verify(jwt));
        assertEquals(NotLoginReason.TOKEN_TIMEOUT, e.getReason());
    }

    @Test
    void tamperedJwtThrowsInvalid() {
        String jwt = codec.issue(session("10001"), "random");
        String tampered = jwt.substring(0, jwt.length() - 4) + "AAAA";
        NotLoginException e = assertThrows(NotLoginException.class, () -> codec.verify(tampered));
        assertEquals(NotLoginReason.TOKEN_INVALID, e.getReason());
    }

    @Test
    void forgedJwtWithWrongSecretThrowsInvalid() {
        JwtTokenCodec attacker = new JwtTokenCodec("attacker-secret-9876543210", 30_000, now::get);
        String forged = attacker.issue(session("10001"), "random");
        NotLoginException e = assertThrows(NotLoginException.class, () -> codec.verify(forged));
        assertEquals(NotLoginReason.TOKEN_INVALID, e.getReason());
    }

    @Test
    void keyOfIsStableSha256Hex() {
        String jwt = codec.issue(session("10001"), "random");
        assertEquals(codec.keyOf(jwt), codec.keyOf(jwt));
        assertEquals(64, codec.keyOf(jwt).length());
    }

    private static void assertTrue(boolean condition) {
        org.junit.jupiter.api.Assertions.assertTrue(condition);
    }
}
