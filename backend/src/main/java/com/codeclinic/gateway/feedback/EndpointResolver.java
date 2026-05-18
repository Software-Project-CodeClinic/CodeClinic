package com.codeclinic.gateway.feedback;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;

import java.util.Map;
import java.util.Optional;

/**
 * URI + HTTP 메서드로 Spring WebFlux RequestMappingHandlerMapping을 조회하여
 * 대응하는 HandlerMethod를 반환한다.
 *
 * 전제: Gateway와 보호 대상 앱이 동일 Spring Boot 프로세스(모노리스)로 실행 중이어야 함.
 * 매핑 없을 경우 Optional.empty() → FeedbackBridgeService graceful skip.
 *
 * @Qualifier: Actuator의 controllerEndpointHandlerMapping과 구분하여 애플리케이션
 * 컨트롤러 매핑만 조회.
 */
@Slf4j
@Component
public class EndpointResolver {

    private final RequestMappingHandlerMapping handlerMapping;

    public EndpointResolver(
            @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping) {
        this.handlerMapping = handlerMapping;
    }

    public Optional<HandlerMethod> resolve(String uri, String httpMethod) {
        try {
            PathContainer pathContainer = PathContainer.parsePath(uri);
            return handlerMapping.getHandlerMethods().entrySet().stream()
                    .filter(e -> matchesRequest(e.getKey(), pathContainer, httpMethod))
                    .map(Map.Entry::getValue)
                    .findFirst();
        } catch (Exception e) {
            log.warn("EndpointResolver error for {} {}: {}", httpMethod, uri, e.getMessage());
            return Optional.empty();
        }
    }

    private boolean matchesRequest(RequestMappingInfo info, PathContainer path, String httpMethod) {
        // HTTP 메서드 조건: 비어 있으면 모든 메서드 허용
        var methodsCondition = info.getMethodsCondition();
        if (!methodsCondition.getMethods().isEmpty()) {
            boolean methodMatches = methodsCondition.getMethods().stream()
                    .anyMatch(m -> m.name().equalsIgnoreCase(httpMethod));
            if (!methodMatches) return false;
        }

        // Path 패턴 조건 (WebFlux: PatternsRequestCondition.getPatterns())
        var patternsCondition = info.getPatternsCondition();
        if (patternsCondition == null) return false;

        return patternsCondition.getPatterns().stream()
                .anyMatch(pattern -> pattern.matches(path));
    }
}
