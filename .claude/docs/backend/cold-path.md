# Cold Path — Feedback Bridge (백엔드 담당)

> 담당: 태현 / 브랜치: `feat/backend/feedback-bridge`

## 트리거 방식

BLOCK / MONITOR 판정 모두에서 트리거됨 (PASS는 트리거 안 함).

```java
@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
@Async("wafAsyncExecutor")   // AsyncConfig에서 정의한 전용 스레드풀
public void onAttackLogged(AttackLogSavedEvent event) {
    // event 필드: attackLogId, cweLabel, uri, method, verdict
    feedbackBridgeService.analyze(event);
}
```

트랜잭션 커밋 후에만 실행 → 로그가 확실히 저장된 상태에서 분석 시작.

## 4단계 파이프라인

### ① EndpointResolver

**전제**: Gateway와 보호 대상 앱이 단일 Spring Boot 프로세스(모노리스)로 실행되어야 함.
`RequestMappingHandlerMapping`은 같은 프로세스 내 컨트롤러 매핑만 조회 가능.

```java
@Autowired RequestMappingHandlerMapping handlerMapping;

public Optional<HandlerMethod> resolve(String uri, String method) {
    // Spring 내부 매핑 정보 조회 — 매핑 없을 경우 Optional.empty() 반환
}
```

### ② SourceLocator

`waf.source.root`(기본값: `src/main/java`) 경로 기준으로 HandlerMethod → `.java` 파일 탐색.

```java
// 파일 없을 경우 Optional.empty() 반환 → Feedback Bridge graceful skip
public Optional<Path> locate(HandlerMethod handler) { ... }
```

**운영 환경 배포**: 컨테이너에서는 JAR 내부에 `.java` 파일이 없으므로
소스를 Docker volume으로 mount하고 `waf.source.root`를 mount 경로로 지정해야 함.
(MVP 범위 내에서는 `src/main/java` 개발 환경 경로 전제)

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

- **버전 고정 없음**: Docker 빌드 시 `pip install semgrep`으로 최신 버전 설치
- **프로세스 타임아웃 없음**: Cold Path이므로 서비스 응답에 영향 없음
- **실패 처리**: 예외 catch 후 Recommendation 없이 종료 (graceful degradation)
  Semgrep 미설치, 파일 없음, 파싱 실패 모두 동일하게 처리

| CWE | Semgrep 규칙셋 |
|-----|---------------|
| CWE-89 | `p/sql-injection` |
| CWE-79 | `p/xss` |
| CWE-78 | `p/command-injection` |
| CWE-22 | `p/path-traversal` |

### ④ RecommendationBuilder

Semgrep이 찾은 패턴을 키로 사전 정의된 템플릿을 조회. 미등록 패턴은 건너뜀.

```java
private static final Map<String, String> TEMPLATES = Map.of(
  // CWE-89: SQL Injection
  "CWE-89:Statement.execute",
      "[취약] stmt.execute(\"SELECT ... WHERE id=\" + id)\n"
    + "[안전] PreparedStatement ps = conn.prepareStatement(\"SELECT ... WHERE id=?\");\n"
    + "       ps.setString(1, id);\n"
    + "권고: 사용자 입력을 직접 쿼리 문자열에 연결하지 말고 PreparedStatement 바인딩 파라미터를 사용하세요.",

  "CWE-89:createQuery",
      "[취약] em.createQuery(\"FROM User WHERE name='\" + name + \"'\")\n"
    + "[안전] em.createQuery(\"FROM User WHERE name=:name\", User.class).setParameter(\"name\", name)\n"
    + "권고: JPQL/HQL에서 문자열 연결 대신 이름 바인딩 파라미터(:param)를 사용하세요.",

  // CWE-79: Cross-Site Scripting
  "CWE-79:innerHTML",
      "[취약] element.innerHTML = userInput;\n"
    + "[안전] element.textContent = userInput;  // 또는 DOMPurify.sanitize(userInput)\n"
    + "권고: innerHTML에 사용자 입력을 그대로 주입하지 마세요.",

  "CWE-79:document.write",
      "[취약] document.write(\"<b>\" + userInput + \"</b>\");\n"
    + "[안전] const el = document.createElement(\"b\"); el.textContent = userInput;\n"
    + "권고: document.write에 사용자 입력을 포함하지 마세요. DOM API로 노드를 생성하세요.",

  // CWE-78: Command Injection
  "CWE-78:Runtime.exec",
      "[취약] Runtime.getRuntime().exec(\"ping \" + host);\n"
    + "[안전] new ProcessBuilder(\"ping\", host).redirectErrorStream(true).start();\n"
    + "권고: Runtime.exec(String)은 쉘 해석이 개입합니다. 인자 배열 형태의 ProcessBuilder를 사용하세요.",

  "CWE-78:ProcessBuilder",
      "[취약] new ProcessBuilder(\"sh\", \"-c\", \"ls \" + userPath).start();\n"
    + "[안전] new ProcessBuilder(\"ls\", userPath).start();  // 입력값 화이트리스트 검증 후\n"
    + "권고: 쉘(-c) 경유 시 인자 분리가 무효화됩니다. 커맨드와 인자를 명시적으로 분리하세요.",

  // CWE-22: Path Traversal
  "CWE-22:new File",
      "[취약] new File(baseDir + userInput)\n"
    + "[안전] Path resolved = Paths.get(baseDir).resolve(userInput).normalize();\n"
    + "       if (!resolved.startsWith(Paths.get(baseDir))) throw new SecurityException(\"Path traversal\");\n"
    + "권고: 경로는 normalize() 후 허용 기준 경로의 하위인지 startsWith()로 검증하세요.",

  "CWE-22:Paths.get",
      "[취약] Paths.get(uploadDir, filename)  // filename에 ../ 포함 가능\n"
    + "[안전] Path safe = Paths.get(uploadDir).resolve(filename).normalize();\n"
    + "       if (!safe.startsWith(Paths.get(uploadDir))) throw new SecurityException(\"...\");\n"
    + "권고: Paths.get 결합 후 반드시 normalize()와 startsWith() 경계 검사를 수행하세요."
);
```

결과는 `recommendations` 테이블에 저장 후 DashboardController로 노출.
