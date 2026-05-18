package com.codeclinic.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * application.yml의 waf.* 설정을 타입 안전하게 바인딩한다.
 * GatewayApplication에 @EnableConfigurationProperties(WafProperties.class) 선언 필요.
 */
@ConfigurationProperties(prefix = "waf")
public record WafProperties(
        Threshold threshold,
        AiServer  aiServer,
        String    sourceRoot
) {
    public record Threshold(double block, double monitor) {}
    public record AiServer(String url, long timeoutMs) {}
}
