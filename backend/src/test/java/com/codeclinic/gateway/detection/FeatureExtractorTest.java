package com.codeclinic.gateway.detection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

/**
 * FeatureExtractor 단위 테스트.
 * URI 파싱은 MockServerWebExchange(getRequest() 확인용),
 * 바디 파싱은 exchange.getAttribute() 제어가 필요하므로 Mockito mock 사용.
 */
@ExtendWith(MockitoExtension.class)
class FeatureExtractorTest {

    private final FeatureExtractor           extractor     = new FeatureExtractor();
    private final DefaultDataBufferFactory   bufferFactory = new DefaultDataBufferFactory();

    // ── CWE-89: SQL Injection — URI 인코딩 보존 ──────────────────────────

    @Test
    void sqli_uri_percent_encoding_is_preserved() {
        // "1+OR+1%3D1" decode 시 "1 OR 1=1" — 원본 그대로 유지되어야 함
        MockServerHttpRequest request = MockServerHttpRequest
                .method(HttpMethod.GET, URI.create("/api/users?id=1+OR+1%3D1"))
                .header(HttpHeaders.USER_AGENT, "sqlmap/1.0")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        FeatureVector fv      = extractor.extract(exchange);
        String        rawInput = extractor.buildRawInput(fv);

        assertThat(fv.uri()).contains("1+OR+1%3D1");
        assertThat(rawInput).contains("1+OR+1%3D1");
        assertThat(rawInput).doesNotContain("1 OR 1=1"); // decode 금지
    }

    // ── CWE-79: Cross-Site Scripting — 바디 인코딩 보존 ──────────────────

    @Test
    void xss_body_percent_encoding_is_preserved() {
        // "%3Cscript%3E" decode 시 "<script>" — 원본 그대로 유지되어야 함
        byte[]     bodyBytes = "%3Cscript%3Ealert(1)%3C%2Fscript%3E".getBytes(StandardCharsets.UTF_8);
        DataBuffer body      = bufferFactory.wrap(bodyBytes);

        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/comment")
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .build();

        // when() + generic default 메서드 조합의 타입 추론 문제를 피해 doReturn 사용
        ServerWebExchange exchange = mock(ServerWebExchange.class);
        doReturn(request).when(exchange).getRequest();
        doReturn(body).when(exchange).getAttribute(ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR);

        // DataBuffer가 읽을 수 있는 상태인지 먼저 확인
        assertThat(body.readableByteCount()).isEqualTo(bodyBytes.length);

        FeatureVector fv = extractor.extract(exchange);

        assertThat(fv.rawBody()).contains("%3Cscript%3E");
        assertThat(fv.rawBody()).doesNotContain("<script>"); // decode 금지
        assertThat(fv.bodyLength()).isEqualTo(bodyBytes.length);
    }

    // ── CWE-22: Path Traversal — URI 인코딩 보존 ─────────────────────────

    @Test
    void path_traversal_percent_encoding_is_preserved() {
        // "..%2F" decode 시 "../" — 원본 그대로 유지되어야 함
        MockServerHttpRequest request = MockServerHttpRequest
                .method(HttpMethod.GET, URI.create("/api/files/..%2F..%2Fetc%2Fpasswd"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        FeatureVector fv = extractor.extract(exchange);

        assertThat(fv.uri()).contains("..%2F");
        assertThat(fv.uri()).doesNotContain("../"); // decode 금지
    }

    // ── raw_input 형식 검증 (인터페이스 계약) ─────────────────────────────

    @Test
    void raw_input_format_matches_interface_contract() {
        // 인터페이스 계약: METHOD URI HTTP/1.1\r\n헤더\r\n\r\nbody
        byte[]     bodyBytes = "{\"key\":\"value\"}".getBytes(StandardCharsets.UTF_8);
        DataBuffer body      = bufferFactory.wrap(bodyBytes);

        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/test")
                .header(HttpHeaders.USER_AGENT, "curl/7.68.0")
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .build();

        ServerWebExchange exchange = mock(ServerWebExchange.class);
        doReturn(request).when(exchange).getRequest();
        doReturn(body).when(exchange).getAttribute(ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR);

        FeatureVector fv      = extractor.extract(exchange);
        String        rawInput = extractor.buildRawInput(fv);

        assertThat(rawInput).startsWith("POST /api/test HTTP/1.1\r\n");
        assertThat(rawInput).contains("User-Agent: curl/7.68.0\r\n");
        assertThat(rawInput).contains("Content-Type: application/json\r\n");
        assertThat(rawInput).contains("\r\n\r\n");               // 헤더-바디 구분선
        assertThat(rawInput).endsWith("{\"key\":\"value\"}");
    }

    // ── GET 요청 (바디 없음) ───────────────────────────────────────────────

    @Test
    void get_request_produces_empty_body() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/health")
                .header(HttpHeaders.USER_AGENT, "healthcheck/1.0")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        FeatureVector fv = extractor.extract(exchange);

        assertThat(fv.method()).isEqualTo("GET");
        assertThat(fv.rawBody()).isEmpty();
        assertThat(fv.bodyLength()).isZero();
    }
}
