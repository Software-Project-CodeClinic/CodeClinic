package com.codeclinic.gateway.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.UUID;

/**
 * Dashboard REST API — 인증 없음 (MVP 범위).
 *
 * WebFlux GlobalFilter(WafFilter)는 RoutePredicateHandlerMapping 경유 요청에만 작동하므로
 * RequestMappingHandlerMapping(order=0)이 처리하는 이 컨트롤러는 WAF를 통과하지 않는다.
 *
 * 모든 메서드는 JDBC 블로킹 호출을 Schedulers.boundedElastic()으로 오프로드한다.
 */
@Validated
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {

    private final AttackLogQueryService queryService;

    @GetMapping(value = "/dashboard", produces = MediaType.TEXT_HTML_VALUE)
    public Mono<ResponseEntity<byte[]>> dashboard() {
        return Mono.fromCallable(() -> {
            byte[] html = new ClassPathResource("static/dashboard.html").getInputStream().readAllBytes();
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping(value = "/dashboard.js", produces = "application/javascript")
    public Mono<ResponseEntity<byte[]>> dashboardJs() {
        return Mono.fromCallable(() -> {
            byte[] js = new ClassPathResource("static/dashboard.js").getInputStream().readAllBytes();
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/javascript"))
                    .body(js);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping(value = "/dashboard.css", produces = "text/css")
    public Mono<ResponseEntity<byte[]>> dashboardCss() {
        return Mono.fromCallable(() -> {
            byte[] css = new ClassPathResource("static/dashboard.css").getInputStream().readAllBytes();
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("text/css"))
                    .body(css);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping("/attacks")
    public Mono<AttackPageResponse> listAttacks(
            @RequestParam(required = false) String  cweLabel,
            @RequestParam(required = false) String  verdict,
            @RequestParam(required = false) String  from,
            @RequestParam(required = false) String  to,
            @RequestParam(defaultValue = "0")  @Min(0)          int  page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int  size) {
        Instant fromInstant = parseInstantParam(from, "from");
        Instant toInstant   = parseInstantParam(to, "to");
        return Mono.fromCallable(
                        () -> queryService.findAll(cweLabel, verdict, fromInstant, toInstant, page, size))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping("/attacks/{id}")
    public Mono<ResponseEntity<AttackDetailResponse>> getAttack(@PathVariable UUID id) {
        return Mono.fromCallable(() -> queryService.findById(id))
                .subscribeOn(Schedulers.boundedElastic())
                .map(opt -> opt.<ResponseEntity<AttackDetailResponse>>map(ResponseEntity::ok)
                        .orElse(ResponseEntity.notFound().build()));
    }

    @GetMapping("/recommendations")
    public Mono<List<RecommendationResponse>> listRecommendations(@RequestParam UUID attackLogId) {
        return Mono.fromCallable(() -> queryService.findRecommendations(attackLogId))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping("/stats")
    public Mono<StatsResponse> getStats() {
        return Mono.fromCallable(queryService::getStats)
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Instant parseInstantParam(String value, String paramName) {
        if (value == null) return null;
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Invalid ISO-8601 date for '" + paramName + "': " + e.getMessage());
        }
    }
}
