package com.codeclinic.gateway.feedback;

import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * Semgrep check_id와 CWE 레이블을 키로 사전 정의된 코드 수정 권고 템플릿을 조회한다.
 *
 * 매칭 전략: templateKey 패턴 부분("CWE-XX:" 이후)의 토큰이 checkId에 포함되는지 확인.
 * 미등록 패턴은 Optional.empty() 반환 → FeedbackBridgeService가 건너뜀.
 */
@Component
public class RecommendationBuilder {

    private static final Map<String, String> TEMPLATES = Map.of(

        // CWE-89: SQL Injection
        "CWE-89:Statement.execute",
            "[취약] stmt.execute(\"SELECT * FROM users WHERE id=\" + id)\n"
          + "[안전] PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");\n"
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

    /**
     * CWE 레이블과 Semgrep check_id로 권고 텍스트를 조회한다.
     *
     * @param cweLabel      예: "CWE-89"
     * @param semgrepCheckId 예: "java.lang.security.audit.sqli.jdbc-sqli"
     * @return 등록된 템플릿이 있으면 권고 텍스트, 없으면 empty
     */
    public Optional<String> build(String cweLabel, String semgrepCheckId) {
        String prefix = cweLabel + ":";
        return TEMPLATES.entrySet().stream()
                .filter(e -> e.getKey().startsWith(prefix))
                .filter(e -> matchesCheckId(e.getKey().substring(prefix.length()), semgrepCheckId))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    // templatePattern 예: "Statement.execute" → 토큰 ["Statement", "execute"]
    // checkId에 4자 이상 토큰이 하나라도 포함되면 매칭
    private boolean matchesCheckId(String templatePattern, String checkId) {
        String normalizedCheckId = checkId.toLowerCase().replace('-', '.');
        return Arrays.stream(templatePattern.split("[^a-zA-Z0-9]+"))
                .filter(token -> token.length() > 3)
                .anyMatch(token -> normalizedCheckId.contains(token.toLowerCase()));
    }
}
