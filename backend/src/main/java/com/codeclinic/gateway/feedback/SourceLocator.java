package com.codeclinic.gateway.feedback;

import com.codeclinic.gateway.config.WafProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * HandlerMethod에서 컨트롤러 클래스의 .java 소스 파일 경로를 탐색한다.
 *
 * waf.source-root(기본값: src/main/java) 기준으로 패키지 경로를 조합.
 * 운영 컨테이너: JAR 내부에 .java 없음 → 소스를 Docker volume으로 mount하고
 * waf.source-root를 해당 mount 경로로 설정해야 함.
 * 파일 없을 경우 Optional.empty() 반환 → FeedbackBridgeService가 graceful skip.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SourceLocator {

    private final WafProperties wafProperties;

    public Optional<Path> locate(HandlerMethod handler) {
        Class<?> beanType   = handler.getBeanType();
        String   className  = beanType.getSimpleName();
        String   packageDir = beanType.getPackageName().replace('.', '/');

        Path sourceFile = Paths.get(wafProperties.sourceRoot(), packageDir, className + ".java");

        if (Files.exists(sourceFile)) {
            return Optional.of(sourceFile);
        }

        log.warn("SourceLocator: .java not found at {} (set waf.source-root for container mount)",
                sourceFile);
        return Optional.empty();
    }
}
