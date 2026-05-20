package com.codeclinic.gateway.detection;

/**
 * AI 추론 서버에 전달하기 전 HTTP 요청에서 파싱한 특징값 DTO.
 * uri는 URL 디코딩된 형태. rawBody는 정규화 없이 원본 그대로 보존.
 */
public record FeatureVector(
        String method,      // HTTP 메서드 (GET, POST 등)
        String uri,         // URL 디코딩된 URI (%27 → ', + → 공백)
        String userAgent,   // User-Agent 헤더값
        String contentType, // Content-Type 헤더값
        String rawBody,     // 정규화 없는 원본 요청 바디
        int    bodyLength   // rawBody 길이 (bytes)
) {}
