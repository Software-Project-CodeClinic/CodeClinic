package com.codeclinic.gateway.api;

public record RecommendationResponse(
        String  cweType,
        String  pattern,
        String  suggestion,
        String  filePath,
        Integer lineNumber
) {}
