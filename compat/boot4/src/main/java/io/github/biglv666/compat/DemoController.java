package io.github.biglv666.compat;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.annotation.AuthIgnore;
import io.github.biglv666.authkit.annotation.RequireLogin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DemoController {

    @RequireLogin
    @GetMapping("/api/me")
    public Map<String, Object> me() {
        return Map.of("userId", AuthKit.getLoginId());
    }

    @AuthIgnore
    @GetMapping("/api/open")
    public String open() {
        return "ok";
    }
}
