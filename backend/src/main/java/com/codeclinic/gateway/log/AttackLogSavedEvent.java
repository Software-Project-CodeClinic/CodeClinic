package com.codeclinic.gateway.log;

import java.util.UUID;

/**
 * attack_logs INSERT 완료 후 발행되는 도메인 이벤트.
 * FeedbackBridgeService의 @TransactionalEventListener(AFTER_COMMIT)가 수신.
 */
public record AttackLogSavedEvent(
        UUID   attackLogId,
        String cweLabel,
        String uri,
        String method,
        String verdict
) {}
