package com.codeclinic.gateway.decision;

/**
 * DecisionEngine 판정 결과.
 * 임계값은 application.yml의 waf.threshold.* 로 외부화되어 있음.
 */
public enum Verdict {
    BLOCK,   // score > waf.threshold.block  → 403 즉시 반환 + 공격 로그
    MONITOR, // score > waf.threshold.monitor → upstream 통과 + 의심 로그
    PASS     // 그 외                         → upstream 프록시 (로그 없음)
}
