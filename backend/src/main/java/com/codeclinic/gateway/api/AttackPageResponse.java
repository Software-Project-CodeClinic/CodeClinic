package com.codeclinic.gateway.api;

import java.util.List;

public record AttackPageResponse(
        List<AttackSummary> content,
        long                totalElements,
        int                 page,
        int                 size
) {}
