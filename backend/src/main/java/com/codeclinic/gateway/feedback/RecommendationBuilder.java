package com.codeclinic.gateway.feedback;

import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * Semgrep Finding으로부터 코드 수정 권고 텍스트를 결정한다.
 *
 * 우선순위:
 *   1. Finding.message() — Registry 규칙(p/owasp-top-ten 등)이 제공하는 전문가 작성 권고문
 *   2. TEMPLATES 매칭 — 커스텀 규칙(CWE-79 등 레지스트리 미지원)용 수동 작성 템플릿
 *
 * TEMPLATES 매칭 전략: templateKey 패턴 부분("CWE-XX:" 이후)의 토큰이 checkId에 포함되는지 확인.
 * 미등록 패턴은 Optional.empty() 반환 → FeedbackBridgeService가 건너뜀.
 */
@Component
public class RecommendationBuilder {

    /**
     * Finding.message()가 없을 때의 fallback 템플릿.
     * Registry 규칙(p/owasp-top-ten 등)은 항상 message를 포함하므로 실제로는
     * 커스텀 규칙의 message 필드가 비어있는 예외 상황에서만 사용된다.
     */
    private static final Map<String, String> TEMPLATES = Map.of(

        // CWE-89
        "CWE-89:Statement.execute",
            "[취약] stmt.execute(\"SELECT * FROM users WHERE id=\" + id)\n"
          + "[안전] PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");\n"
          + "       ps.setString(1, id);\n"
          + "권고: PreparedStatement 파라미터 바인딩을 사용하세요.",

        "CWE-89:createQuery",
            "[취약] em.createQuery(\"FROM User WHERE name='\" + name + \"'\")\n"
          + "[안전] em.createQuery(\"FROM User WHERE name=:name\", User.class).setParameter(\"name\", name)\n"
          + "권고: JPQL/HQL에서 이름 바인딩 파라미터(:param)를 사용하세요.",

        // CWE-79 — 레지스트리 미지원, 커스텀 YAML message 필드가 primary
        "CWE-79:innerHTML",
            "[취약] element.innerHTML = userInput;\n"
          + "[안전] element.textContent = userInput;\n"
          + "권고: innerHTML에 사용자 입력을 주입하지 마세요.",

        "CWE-79:document.write",
            "[취약] document.write(\"<b>\" + userInput + \"</b>\");\n"
          + "[안전] const el = document.createElement(\"b\"); el.textContent = userInput;\n"
          + "권고: document.write에 사용자 입력을 포함하지 마세요.",

        // CWE-78
        "CWE-78:Runtime.exec",
            "[취약] Runtime.getRuntime().exec(\"ping \" + host);\n"
          + "[안전] new ProcessBuilder(\"ping\", host).start();\n"
          + "권고: 인자 배열 형태의 ProcessBuilder를 사용하세요.",

        "CWE-78:ProcessBuilder",
            "[취약] new ProcessBuilder(\"sh\", \"-c\", \"ls \" + userPath).start();\n"
          + "[안전] new ProcessBuilder(\"ls\", userPath).start();\n"
          + "권고: 쉘(-c) 경유 없이 커맨드와 인자를 분리하세요.",

        // CWE-22
        "CWE-22:new File",
            "[취약] new File(baseDir + userInput)\n"
          + "[안전] Path resolved = Paths.get(baseDir).resolve(userInput).normalize();\n"
          + "       if (!resolved.startsWith(Paths.get(baseDir))) throw new SecurityException();\n"
          + "권고: normalize() 후 startsWith()로 경계 검증하세요.",

        "CWE-22:Paths.get",
            "[취약] Paths.get(uploadDir, filename)\n"
          + "[안전] Path safe = Paths.get(uploadDir).resolve(filename).normalize();\n"
          + "       if (!safe.startsWith(Paths.get(uploadDir))) throw new SecurityException();\n"
          + "권고: normalize() + startsWith() 경계 검사를 수행하세요."
    );

    /**
     * Finding으로부터 권고 텍스트를 결정한다.
     *
     * Registry 규칙은 message 필드에 전문가 작성 권고문을 포함하므로 그것을 우선 사용한다.
     * message가 없는 커스텀 규칙은 TEMPLATES에서 check_id 토큰 매칭으로 fallback한다.
     */
    public Optional<String> build(String cweLabel, SemgrepRunner.Finding finding) {
        if (finding.message() != null && !finding.message().isBlank()) {
            return Optional.of(finding.message());
        }
        return buildFromTemplate(cweLabel, finding.checkId());
    }

    private Optional<String> buildFromTemplate(String cweLabel, String semgrepCheckId) {
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
