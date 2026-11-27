package io.github.biglv666.compat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Boot 4 消费方冒烟应用：只验证 auth-kit 在 Spring Boot 4.x + Spring Framework 7 下
 * 能完成登录、注解鉴权、踢人链路。
 */
@SpringBootApplication
public class CompatApp {

    public static void main(String[] args) {
        SpringApplication.run(CompatApp.class, args);
    }
}
