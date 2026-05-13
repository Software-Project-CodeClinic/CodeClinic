package com.codeclinic.gateway.log;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 공격 로그를 TimescaleDB에 비동기로 저장하고 Feedback Bridge 이벤트를 발행한다.
 *
 * @Async("wafAsyncExecutor"): WebFlux 이벤트 루프 외부 스레드에서 실행 → JDBC 블로킹 허용.
 * @Transactional: INSERT 완료 후 커밋, 이후 @TransactionalEventListener(AFTER_COMMIT)가 트리거됨.
 */
@Service
@RequiredArgsConstructor
public class AttackLogService {

    private final AttackLogRepository    repository;
    private final ApplicationEventPublisher eventPublisher;

    @Async("wafAsyncExecutor")
    @Transactional
    public void save(AttackLog log) {
        AttackLog saved = repository.save(log);
        eventPublisher.publishEvent(new AttackLogSavedEvent(
                saved.getId(),
                saved.getCweType(),
                saved.getUri(),
                saved.getMethod(),
                saved.getVerdict()
        ));
    }
}
