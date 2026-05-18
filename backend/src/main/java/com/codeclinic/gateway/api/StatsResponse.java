package com.codeclinic.gateway.api;

import java.util.Map;

public record StatsResponse(
        long              totalBlock,
        long              totalMonitor,
        Map<String, Long> byLabel
) {}
