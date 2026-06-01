package com.codeclinic.gateway.feedback;

import com.codeclinic.gateway.log.AttackLogSavedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.web.method.HandlerMethod;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Feedback Bridge Cold Path — 4단계 파이프라인 오케스트레이터.
 *
 * 트리거: AttackLogService.save() 트랜잭션 커밋 후 @TransactionalEventListener 실행.
 * 스레드풀: @Async("wafAsyncExecutor") → Hot Path 이벤트 루프와 완전히 분리.
 * 각 단계가 Optional.empty() 반환 시 이후 단계 건너뜀 (graceful degradation).
 *
 * 파이프라인:
 *   ① EndpointResolver  — URI + Method → HandlerMethod
 *   ② SourceLocator     — HandlerMethod → .java 파일 경로
 *   ③ SemgrepRunner     — .java 파일 → Finding 목록
 *   ④ RecommendationBuilder + RecommendationRepository — Finding → DB INSERT
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FeedbackBridgeService {

    private final EndpointResolver        endpointResolver;
    private final SourceLocator           sourceLocator;
    private final SemgrepRunner           semgrepRunner;
    private final RecommendationBuilder   recommendationBuilder;
    private final RecommendationRepository recommendationRepository;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async("wafAsyncExecutor")
    public void onAttackLogged(AttackLogSavedEvent event) {
        if ("NORMAL".equals(event.cweLabel())) return;

        // ① EndpointResolver
        Optional<HandlerMethod> handler = endpointResolver.resolve(event.uri(), event.method());
        if (handler.isEmpty()) {
            log.debug("FeedbackBridge: no handler for {} {} — skipping", event.method(), event.uri());
            return;
        }

        // ② SourceLocator
        Optional<Path> sourcePath = sourceLocator.locate(handler.get());
        if (sourcePath.isEmpty()) return;

        // ③ SemgrepRunner
        List<SemgrepRunner.Finding> findings = semgrepRunner.run(event.cweLabel(), sourcePath.get());
        if (findings.isEmpty()) {
            log.debug("FeedbackBridge: semgrep found no findings in {}", sourcePath.get());
            return;
        }

        // ④ RecommendationBuilder + persist
        findings.forEach(finding -> saveRecommendation(event.attackLogId(), event.cweLabel(),
                sourcePath.get(), finding));
    }

    private void saveRecommendation(UUID attackLogId, String cweLabel, Path sourcePath,
                                    SemgrepRunner.Finding finding) {
        Optional<String> suggestion = recommendationBuilder.build(cweLabel, finding);
        if (suggestion.isEmpty()) {
            log.debug("FeedbackBridge: no template for {} + checkId={}", cweLabel, finding.checkId());
            return;
        }

        Recommendation rec = Recommendation.builder()
                .attackLogId(attackLogId)
                .cweType(cweLabel)
                .filePath(sourcePath.toString())
                .lineNumber(finding.lineNumber())
                .pattern(finding.checkId())
                .suggestion(suggestion.get())
                .createdAt(Instant.now())
                .build();

        recommendationRepository.save(rec);
    }
}
