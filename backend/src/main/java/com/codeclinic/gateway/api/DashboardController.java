package com.codeclinic.gateway.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
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

    @GetMapping("/attacks")
    public Mono<AttackPageResponse> listAttacks(
            @RequestParam(required = false) String  cweLabel,
            @RequestParam(required = false) String  verdict,
            @RequestParam(required = false) String  from,
            @RequestParam(required = false) String  to,
            @RequestParam(defaultValue = "0")  @Min(0)          int  page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int  size) {
        Instant fromInstant = from != null ? Instant.parse(from) : null;
        Instant toInstant   = to   != null ? Instant.parse(to)   : null;
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
}
