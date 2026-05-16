package com.codeclinic.gateway;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.*;
import org.testcontainers.utility.DockerImageName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * WAF End-to-End 통합 테스트.
 *
 * 실행 순서:
 *   1. @Container static 필드 → Testcontainers가 Spring 컨텍스트 로드 전 시작
 *   2. static 블록 → WireMock 서버 시작 (클래스 로드 시점 = 컨텍스트 로드 전)
 *   3. @DynamicPropertySource → DB/AI 서버/Gateway upstream URL 주입
 *   4. Spring 컨텍스트 로드
 *
 * GlobalFilter(WafFilter)는 RoutePredicateHandlerMapping 경유 요청에만 실행된다.
 * /api/* 엔드포인트는 RequestMappingHandlerMapping(order=0)이 먼저 처리하므로 WAF를 우회한다.
 * WAF 동작 검증에는 게이트웨이 라우트가 처리하는 경로(/waf-test)를 사용한다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class WafIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> DB =
            new PostgreSQLContainer<>(
                    DockerImageName.parse("timescale/timescaledb:2.20.0-pg16")
                            .asCompatibleSubstituteFor("postgres"))
                    .withInitScript("init.sql");

    // 클래스 로드 시 시작 — @DynamicPropertySource 호출 전 baseUrl 확보
    static final WireMockServer WIRE_MOCK;
    static {
        WIRE_MOCK = new WireMockServer(wireMockConfig().dynamicPort());
        WIRE_MOCK.start();
    }

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url",      DB::getJdbcUrl);
        r.add("spring.datasource.username", DB::getUsername);
        r.add("spring.datasource.password", DB::getPassword);
        // AI 추론 서버를 WireMock으로 교체
        r.add("waf.ai-server.url",        WIRE_MOCK::baseUrl);
        r.add("waf.ai-server.timeout-ms", () -> "50");
        // 게이트웨이 upstream을 WireMock으로 교체 (PASS/MONITOR 시 프록시 목적지)
        r.add("spring.cloud.gateway.routes[0].uri", WIRE_MOCK::baseUrl);
    }

    @AfterAll
    static void stopWireMock() {
        WIRE_MOCK.stop();
    }

    @Autowired
    WebTestClient webTestClient;

    @Autowired
    JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        WIRE_MOCK.resetAll();
        jdbc.execute("DELETE FROM recommendations");
        jdbc.execute("DELETE FROM attack_logs");
    }

    // ── 시나리오 1: SQLi BLOCK ────────────────────────────────────────────

    @Test
    void sqli_payload_is_blocked_and_attack_log_is_saved() {
        WIRE_MOCK.stubFor(post(urlEqualTo("/predict"))
                .willReturn(okJson("{\"classificationScore\":0.95,\"cweLabel\":\"CWE-89\"}")));

        webTestClient.post().uri("/waf-test")
                .bodyValue("SELECT * FROM users WHERE id=1 OR 1=1--")
                .exchange()
                .expectStatus().isForbidden();

        // AttackLogService는 @Async → INSERT가 HTTP 응답 반환 후 비동기로 완료됨
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            Integer count = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM attack_logs WHERE verdict = 'BLOCK'", Integer.class);
            assertThat(count).isEqualTo(1);
        });

        // 저장된 로그 필드 검증
        var row = jdbc.queryForMap("SELECT cwe_type, score, uri FROM attack_logs WHERE verdict = 'BLOCK'");
        assertThat(row.get("cwe_type")).isEqualTo("CWE-89");
        assertThat(((Number) row.get("score")).doubleValue()).isGreaterThan(0.9);
        assertThat(row.get("uri")).isEqualTo("/waf-test");
    }

    // ── 시나리오 2: Fail-Open (AI 타임아웃) ───────────────────────────────

    @Test
    void ai_server_timeout_passes_request_without_saving_log() {
        // 300ms 지연 → 50ms 타임아웃 초과 → Fail-Open (PASS_RESPONSE)
        WIRE_MOCK.stubFor(post(urlEqualTo("/predict"))
                .willReturn(okJson("{\"classificationScore\":0.95,\"cweLabel\":\"CWE-89\"}")
                        .withFixedDelay(300)));
        // 게이트웨이 upstream stub — PASS 시 프록시 도달
        WIRE_MOCK.stubFor(get(urlEqualTo("/waf-test"))
                .willReturn(ok("upstream ok")));

        webTestClient.get().uri("/waf-test")
                .exchange()
                .expectStatus().isOk();

        // Fail-Open PASS → attack_logs에 아무것도 저장하지 않음 (비동기 쓰기 발생 여부를 300ms 대기 후 확인)
        await().pollDelay(Duration.ofMillis(300)).atMost(Duration.ofSeconds(1)).untilAsserted(() -> {
            Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM attack_logs", Integer.class);
            assertThat(count).isZero();
        });
    }

    // ── 시나리오 3: Dashboard /api/stats ─────────────────────────────────

    @Test
    void stats_endpoint_aggregates_verdict_counts() {
        // /api/* 엔드포인트는 RequestMappingHandlerMapping이 처리 → WAF 우회
        // 데이터를 직접 삽입하여 대시보드가 올바르게 집계하는지 검증
        Instant now = Instant.now();
        insertAttackLog(UUID.randomUUID(), now,           "CWE-89", "BLOCK",   0.95);
        insertAttackLog(UUID.randomUUID(), now.minusSeconds(1), "CWE-89", "BLOCK",   0.91);
        insertAttackLog(UUID.randomUUID(), now.minusSeconds(2), "CWE-79", "MONITOR", 0.65);

        webTestClient.get().uri("/api/stats")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.totalBlock").isEqualTo(2)
                .jsonPath("$.totalMonitor").isEqualTo(1)
                .jsonPath("$.byLabel['CWE-89']").isEqualTo(2)
                .jsonPath("$.byLabel['CWE-79']").isEqualTo(1);
    }

    // ── 시나리오 4: GET /api/attacks 페이지네이션 ─────────────────────────

    @Test
    void attacks_list_supports_verdict_filter() {
        Instant now = Instant.now();
        insertAttackLog(UUID.randomUUID(), now,           "CWE-89", "BLOCK",   0.95);
        insertAttackLog(UUID.randomUUID(), now.minusSeconds(1), "CWE-79", "MONITOR", 0.65);
        insertAttackLog(UUID.randomUUID(), now.minusSeconds(2), "CWE-78", "BLOCK",   0.88);

        webTestClient.get().uri("/api/attacks?verdict=BLOCK&size=10")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.totalElements").isEqualTo(2)
                .jsonPath("$.content.length()").isEqualTo(2)
                .jsonPath("$.content[0].verdict").isEqualTo("BLOCK");
    }

    private void insertAttackLog(UUID id, Instant ts, String cweType, String verdict, double score) {
        jdbc.update(
                "INSERT INTO attack_logs (id, timestamp, source_ip, method, uri, cwe_type, score, verdict, raw_input)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id, java.sql.Timestamp.from(ts), "127.0.0.1", "POST", "/test", cweType, score, verdict, "");
    }
}
