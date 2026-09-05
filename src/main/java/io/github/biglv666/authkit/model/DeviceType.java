package io.github.biglv666.authkit.model;

/**
 * 内置设备类型枚举。
 * <p>核心 API 同时接受 {@link DeviceType} 与任意字符串设备名，
 * 业务方可自定义设备标识（如 "iPad"、" HarmonyOS"），不必受枚举限制。</p>
 */
public enum DeviceType {

    /** 桌面端 */
    PC("PC"),
    /** 移动 App */
    APP("APP"),
    /** 小程序 */
    MINI_PROGRAM("MINI_PROGRAM"),
    /** 浏览器 Web 端 */
    WEB("WEB");

    private final String name;

    DeviceType(String name) {
        this.name = name;
    }

    /** 返回写入会话的设备标识字符串 */
    public String getName() {
        return name;
    }
}
