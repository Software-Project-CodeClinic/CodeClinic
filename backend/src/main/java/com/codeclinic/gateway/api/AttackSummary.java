package com.codeclinic.gateway.api;

import java.time.Instant;
import java.util.UUID;

public record AttackSummary(
        UUID    id,
        Instant timestamp,
        String  cweType,
        String  verdict,
        double  score,
        String  uri
) {}
