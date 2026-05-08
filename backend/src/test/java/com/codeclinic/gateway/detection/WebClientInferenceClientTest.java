package com.codeclinic.gateway.detection;

import com.codeclinic.gateway.config.WafProperties;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@WireMockTest
class WebClientInferenceClientTest {

    private WebClientInferenceClient client;
    private WireMockRuntimeInfo wmInfo;

    @BeforeEach
    void setUp(WireMockRuntimeInfo wm) {
        wmInfo = wm;
        // 성공 케이스용 넉넉한 타임아웃 (5초)
        client = buildClient(wm.getHttpBaseUrl(), 5_000);
    }

    private WebClientInferenceClient buildClient(String baseUrl, long timeoutMs) {
        WebClient webClient = WebClient.builder().baseUrl(baseUrl).build();
        WafProperties props = new WafProperties(
                new WafProperties.Threshold(0.8, 0.5),
                new WafProperties.AiServer(baseUrl, timeoutMs),
                "src/main/java"
        );
        return new WebClientInferenceClient(webClient, props);
    }

    @Test
    void success_200_returns_inference_response() {
        stubFor(post("/predict")
                .willReturn(okJson("{\"classificationScore\":0.95,\"cweLabel\":\"CWE-89\"}")));

        FeatureVector fv = new FeatureVector("GET", "/api/users", "Mozilla/5.0", "application/json", "", 0);

        StepVerifier.create(client.score(fv))
                .expectNextMatches(r -> r.classificationScore() == 0.95 && "CWE-89".equals(r.cweLabel()))
                .verifyComplete();
    }

    @Test
    void timeout_exceeds_threshold_returns_pass_response() {
        // 200ms 응답 지연 → 100ms 타임아웃 초과 → Fail-Open PASS_RESPONSE
        stubFor(post("/predict")
                .willReturn(okJson("{\"classificationScore\":0.9,\"cweLabel\":\"CWE-89\"}")
                        .withFixedDelay(200)));

        WebClientInferenceClient shortTimeoutClient = buildClient(wmInfo.getHttpBaseUrl(), 100);
        FeatureVector fv = new FeatureVector("GET", "/", "Mozilla", "text/plain", "", 0);

        StepVerifier.create(shortTimeoutClient.score(fv))
                .expectNext(InferenceResponse.PASS_RESPONSE)
                .verifyComplete();
    }

    @Test
    void server_5xx_returns_pass_response() {
        stubFor(post("/predict")
                .willReturn(serverError()));

        FeatureVector fv = new FeatureVector("POST", "/admin", "curl/7.68", "text/plain", "payload", 7);

        StepVerifier.create(client.score(fv))
                .expectNext(InferenceResponse.PASS_RESPONSE)
                .verifyComplete();
    }

    @Test
    void invalid_json_response_returns_pass_response() {
        stubFor(post("/predict")
                .willReturn(ok("not-valid-json")
                        .withHeader("Content-Type", "application/json")));

        FeatureVector fv = new FeatureVector("GET", "/", "Mozilla", "", "", 0);

        StepVerifier.create(client.score(fv))
                .expectNext(InferenceResponse.PASS_RESPONSE)
                .verifyComplete();
    }

    @Test
    void raw_input_body_matches_interface_contract_format() {
        // 인터페이스 계약: {method} {uri} HTTP/1.1\r\nUser-Agent: ...\r\nContent-Type: ...\r\n\r\n{body}
        stubFor(post("/predict")
                .withRequestBody(equalTo(
                        "POST /api/items HTTP/1.1\r\n"
                        + "User-Agent: TestAgent\r\n"
                        + "Content-Type: application/json\r\n"
                        + "\r\n"
                        + "{\"id\":1}"))
                .willReturn(okJson("{\"classificationScore\":0.0,\"cweLabel\":\"NORMAL\"}")));

        FeatureVector fv = new FeatureVector("POST", "/api/items", "TestAgent", "application/json", "{\"id\":1}", 8);

        StepVerifier.create(client.score(fv))
                .expectNextMatches(r -> "NORMAL".equals(r.cweLabel()))
                .verifyComplete();
    }
}
