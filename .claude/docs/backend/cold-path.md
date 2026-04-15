# Cold Path — Feedback Bridge (백엔드 담당)

> 담당: 태현 / 브랜치: `feat/backend/feedback-bridge`

## 트리거 방식

```java
@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
@Async
public void onAttackLogged(AttackLogSavedEvent event) {
    feedbackBridgeService.analyze(event.getAttackLog());
}
```

트랜잭션 커밋 후에만 실행 → 로그가 확실히 저장된 상태에서 분석 시작.

## 4단계 파이프라인

### ① EndpointResolver

```java
@Autowired RequestMappingHandlerMapping handlerMapping;

public HandlerMethod resolve(String uri, String method) {
    // Spring 내부 매핑 정보 조회 — 별도 설정 불필요
}
```

### ② SourceLocator

```java
// 개발환경: src/main/java/{패키지경로}.java
// 배포환경: application.yml의 waf.source.root 경로
public Path locate(HandlerMethod handler) { ... }
```

### ③ SemgrepRunner

```java
ProcessBuilder pb = new ProcessBuilder(
    "semgrep", "--config", selectRuleset(cweLabel),
    "--json", targetFilePath.toString()
);

// ★ 필수: stdout/stderr를 별도 스레드에서 소비하지 않으면 프로세스 hang
CompletableFuture<String> stdout = readAsync(process.getInputStream());
CompletableFuture<String> stderr = readAsync(process.getErrorStream());
process.waitFor();
```

| CWE | Semgrep 규칙셋 |
|-----|---------------|
| CWE-89 | `p/sql-injection` |
| CWE-79 | `p/xss` |
| CWE-78 | `p/command-injection` |
| CWE-22 | `p/path-traversal` |

### ④ RecommendationBuilder

```java
Map.of(
  "CWE-89:Statement.execute",
      "PreparedStatement 사용 권고 + 예시 코드",
  "CWE-79:innerHTML",
      "textContent 사용 또는 DOMPurify sanitize 권고"
)
```

결과는 `recommendations` 테이블에 저장 후 DashboardController로 노출.
