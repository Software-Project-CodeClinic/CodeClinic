package com.codeclinic.gateway.api;

import java.time.Instant;
import java.util.UUID;

public record AttackDetailResponse(
        UUID    id,
        Instant timestamp,
        String  cweType,
        String  verdict,
        double  classificationScore,
        String  uri,
        String  rawPayload,
        String  sourceIp
) {}
