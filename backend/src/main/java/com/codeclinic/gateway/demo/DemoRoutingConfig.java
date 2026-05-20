package com.codeclinic.gateway.demo;

import org.springframework.boot.autoconfigure.web.reactive.WebFluxRegistrations;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;

/**
 * 데모 모드 전용 라우팅 설정.
 *
 * 문제: WafFilter는 RoutePredicateHandlerMapping(order=1) 경유 요청에만 실행된다.
 * RequestMappingHandlerMapping(RPHM, order=0)이 먼저 컨트롤러를 처리하면 WafFilter를 건너뛴다.
 *
 * 해결: RPHM을 order=2로 낮춰 게이트웨이(order=1)가 먼저 실행되도록 한다.
 * WafFilter 실행 후 EndpointResolver가 RPHM.getHandlerMethods()로 컨트롤러를 조회할 수 있다.
 *
 * 부작용: demo 프로파일에서 /api/** 엔드포인트도 게이트웨이 라우트를 통과하므로 Dashboard API 비작동.
 */
@Configuration
@Profile("demo")
public class DemoRoutingConfig implements WebFluxRegistrations {

    @Override
    public RequestMappingHandlerMapping getRequestMappingHandlerMapping() {
        RequestMappingHandlerMapping mapping = new RequestMappingHandlerMapping();
        mapping.setOrder(2);
        return mapping;
    }
}
