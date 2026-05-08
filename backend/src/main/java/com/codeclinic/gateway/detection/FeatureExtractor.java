package com.codeclinic.gateway.detection;

import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * HTTP 요청에서 AI 모델 입력용 FeatureVector를 파싱한다.
 *
 * 핵심 불변식: 인코딩 정규화 없음.
 * URL decode·HTML entity decode·NFKC 정규화를 수행하지 않는다.
 * 모델이 인코딩 패턴(%3Cscript%3E 등) 자체를 특징으로 학습하기 때문이다. (논문 3.2절)
 */
@Component
public class FeatureExtractor {

    /**
     * exchange에서 FeatureVector를 추출한다.
     * rawBody 읽기는 WafFilter의 cacheRequestBody 이후에만 호출되어야 한다.
     */
    public FeatureVector extract(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        String method      = request.getMethod().name();
        String uri         = extractRawUri(request);
        String userAgent   = firstHeader(request, HttpHeaders.USER_AGENT);
        String contentType = firstHeader(request, HttpHeaders.CONTENT_TYPE);
        String rawBody     = extractRawBody(exchange);

        return new FeatureVector(method, uri, userAgent, contentType, rawBody, rawBody.length());
    }

    /**
     * FeatureVector를 인터페이스 계약 형식의 raw_input 문자열로 조합한다.
     * 형식: {method} {uri} HTTP/1.1\r\n{헤더들}\r\n\r\n{rawBody}
     */
    public String buildRawInput(FeatureVector fv) {
        return fv.method() + " " + fv.uri() + " HTTP/1.1\r\n"
             + "User-Agent: "   + fv.userAgent()   + "\r\n"
             + "Content-Type: " + fv.contentType() + "\r\n"
             + "\r\n"
             + fv.rawBody();
    }

    /**
     * percent-encoding을 보존한 Raw URI를 반환한다.
     * getRawPath/getRawQuery를 사용해야 decode가 발생하지 않는다.
     * getPath/getQuery는 자동으로 percent-decode를 수행하므로 사용 금지.
     */
    private String extractRawUri(ServerHttpRequest request) {
        String path  = request.getURI().getRawPath();
        String query = request.getURI().getRawQuery();
        return query != null ? path + "?" + query : path;
    }

    /**
     * cacheRequestBody로 캐시된 요청 바디를 읽는다.
     * toByteBuffer(dest)는 원본 DataBuffer의 읽기 위치를 변경하지 않고 dest에 복사하므로,
     * downstream(upstream 서비스)이 동일한 버퍼를 재소비할 수 있다.
     * (toByteBuffer() 무인자 버전은 Spring 6.0.5부터 deprecated)
     */
    private String extractRawBody(ServerWebExchange exchange) {
        DataBuffer buffer = exchange.getAttribute(ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR);
        if (buffer == null || buffer.readableByteCount() == 0) {
            return "";
        }

        // dest에 복사 — 원본 readPosition 불변
        // Spring 6.1의 toByteBuffer(dest)는 절대 위치 쓰기(absolute put) → dest.position 불변
        // flip()은 limit=position=0 으로 만들므로 사용 금지; rewind()로 position만 0으로 초기화
        int        len  = buffer.readableByteCount();
        ByteBuffer dest = ByteBuffer.allocate(len);
        buffer.toByteBuffer(dest);
        dest.rewind(); // position=0, limit=len 유지 → 읽기 준비
        return StandardCharsets.UTF_8.decode(dest).toString(); // 바이트→문자 변환만, decode 없음
    }

    private String firstHeader(ServerHttpRequest request, String headerName) {
        List<String> values = request.getHeaders().get(headerName);
        return (values != null && !values.isEmpty()) ? values.get(0) : "";
    }
}
