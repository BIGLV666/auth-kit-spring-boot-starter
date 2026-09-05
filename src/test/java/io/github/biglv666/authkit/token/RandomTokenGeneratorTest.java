package io.github.biglv666.authkit.token;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 随机 token 生成器单测：长度、字符集与唯一性。
 */
class RandomTokenGeneratorTest {

    @Test
    void generatesExpectedLength() {
        RandomTokenGenerator generator = new RandomTokenGenerator(64);
        assertEquals(64, generator.generate().length());
        assertEquals(32, new RandomTokenGenerator(32).generate().length());
    }

    @Test
    void urlSafeCharsetOnly() {
        RandomTokenGenerator generator = new RandomTokenGenerator(128);
        String token = generator.generate();
        assertTrue(token.matches("[A-Za-z0-9_-]+"), "token 应仅含 base64url 字符");
    }

    @Test
    void tokensAreUnique() {
        RandomTokenGenerator generator = new RandomTokenGenerator(64);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1_000; i++) {
            seen.add(generator.generate());
        }
        assertEquals(1_000, seen.size(), "1k 次 Random(64) 不应出现碰撞");
    }
}
