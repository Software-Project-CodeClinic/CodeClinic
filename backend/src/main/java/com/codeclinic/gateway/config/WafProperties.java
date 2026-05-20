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
        String    sourceRoot,
        Semgrep   semgrep
) {
    public record Threshold(double block, double monitor) {}
    public record AiServer(String url, long timeoutMs) {}

    /**
     * semgrep 실행 설정.
     * command: 비어있으면 SEMGREP_CMD 환경변수 → "semgrep" (PATH) 순으로 결정.
     * rulesDir: semgrep 규칙 파일 디렉터리. Spring 기동 디렉터리 기준 상대경로 또는 절대경로.
     */
    public record Semgrep(String command, String rulesDir) {}
}
