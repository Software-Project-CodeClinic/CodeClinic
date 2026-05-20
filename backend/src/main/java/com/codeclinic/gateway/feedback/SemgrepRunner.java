package com.codeclinic.gateway.feedback;

import com.codeclinic.gateway.config.WafProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Semgrep을 외부 프로세스로 실행하고 JSON 결과를 파싱한다.
 *
 * Cold Path 전용: 프로세스 타임아웃 없음 (Hot Path와 분리되어 서비스 응답에 영향 없음).
 * stdout/stderr를 별도 스레드에서 소비하지 않으면 프로세스 버퍼 포화 → hang 발생.
 * 실패(미설치, 파일 없음, 파싱 오류) 시 빈 결과 반환 (graceful degradation).
 *
 * semgrep 명령어 결정 순서 (waf.semgrep.command 비어있을 때):
 *   1. SEMGREP_CMD 환경변수
 *   2. PATH의 semgrep (Linux/Mac 패키지 설치, venv 활성화 시)
 *
 * 규칙 파일 위치: waf.semgrep.rules-dir (기본: semgrep-rules/)
 *   로컬: Spring 기동 디렉터리 기준 상대경로
 *   컨테이너: 절대경로 또는 volume mount 경로로 오버라이드
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SemgrepRunner {

    /**
     * CWE → Semgrep config 매핑.
     * "p/" 접두사: Semgrep Registry 온라인 룰셋 (taint 분석 포함, CWE 메타데이터로 결과 필터링).
     * 그 외: semgrep.rulesDir 기준 로컬 파일명 (레지스트리에 적합한 규칙 없을 때).
     */
    private static final Map<String, String> RULESET_CONFIGS = Map.of(
            "CWE-89", "p/owasp-top-ten",
            "CWE-79", "cwe-79-xss.yml",   // 레지스트리에 getWriter().write() 패턴 규칙 없음
            "CWE-78", "p/owasp-top-ten",
            "CWE-22", "p/owasp-top-ten"
    );

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final WafProperties wafProperties;

    public List<Finding> run(String cweLabel, Path targetFile) {
        String config = RULESET_CONFIGS.get(cweLabel);
        if (config == null) {
            log.warn("SemgrepRunner: no ruleset mapped for CWE label '{}'", cweLabel);
            return List.of();
        }

        String semgrepCmd = resolveCommand();
        String resolvedConfig;

        if (config.startsWith("p/")) {
            // Registry 룰셋: 파일 존재 확인 불필요, 그대로 --config 인수로 전달
            resolvedConfig = config;
        } else {
            Path rulePath = Paths.get(wafProperties.semgrep().rulesDir(), config);
            if (!rulePath.toFile().exists()) {
                log.warn("SemgrepRunner: ruleset not found at '{}', skipping", rulePath);
                return List.of();
            }
            resolvedConfig = rulePath.toString();
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    semgrepCmd, "--config", resolvedConfig, "--json", targetFile.toString()
            );
            pb.redirectErrorStream(false);
            Process process = pb.start();

            // stdout과 stderr를 별도 스레드에서 소비 — 버퍼 포화로 인한 hang 방지
            CompletableFuture<String> stdoutFuture = readAsync(process.getInputStream());
            CompletableFuture<String> stderrFuture  = readAsync(process.getErrorStream());

            boolean finished = process.waitFor(30, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                log.warn("SemgrepRunner: process timed out after 30s, killed");
                return List.of();
            }
            String stdout = stdoutFuture.get(5, TimeUnit.SECONDS);
            stderrFuture.get(5, TimeUnit.SECONDS);

            return parseFindings(stdout, cweLabel);

        } catch (Exception e) {
            log.warn("SemgrepRunner failed [{}]: {}", e.getClass().getSimpleName(), e.getMessage());
            return List.of();
        }
    }

    /**
     * semgrep 실행 명령어를 결정한다.
     *
     * 우선순위:
     *   1. waf.semgrep.command (application.yml 명시적 설정)
     *   2. SEMGREP_CMD 환경변수 (IDE/서비스 실행 시 PATH 미상속 대비)
     *   3. "semgrep" (PATH 위임 — venv 활성화, 시스템 설치 등 정상 경로)
     */
    private String resolveCommand() {
        String configured = wafProperties.semgrep().command();
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        String envCmd = System.getenv("SEMGREP_CMD");
        if (envCmd != null && !envCmd.isBlank()) {
            return envCmd;
        }
        return "semgrep";
    }

    private CompletableFuture<String> readAsync(InputStream stream) {
        return CompletableFuture.supplyAsync(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                return reader.lines().collect(Collectors.joining("\n"));
            } catch (IOException e) {
                return "";
            }
        });
    }

    // semgrep --json 출력: {"results": [{"check_id": "...", "start": {"line": N}, "extra": {"metadata": {"cwe": [...]}}}]}
    private List<Finding> parseFindings(String json, String cweLabel) {
        try {
            JsonNode root    = MAPPER.readTree(json);
            JsonNode results = root.path("results");
            if (!results.isArray()) return List.of();

            List<Finding> findings = new ArrayList<>();
            for (JsonNode result : results) {
                String checkId    = result.path("check_id").asText("");
                int    lineNumber = result.path("start").path("line").asInt(0);
                if (checkId.isEmpty()) continue;

                // Registry 룰셋은 여러 CWE 결과를 반환하므로 메타데이터로 필터링.
                // 커스텀 규칙(메타데이터 없음)은 필터를 통과시킨다.
                if (cweLabel != null) {
                    JsonNode cweNode = result.path("extra").path("metadata").path("cwe");
                    if (cweNode.isArray() && !cweNode.isEmpty()) {
                        boolean matched = false;
                        for (JsonNode cwe : cweNode) {
                            if (cwe.asText().startsWith(cweLabel)) { matched = true; break; }
                        }
                        if (!matched) continue;
                    }
                }

                String message = result.path("extra").path("message").asText("");
                findings.add(new Finding(checkId, lineNumber, message));
            }
            return findings;

        } catch (Exception e) {
            log.warn("SemgrepRunner: JSON parse failed: {}", e.getMessage());
            return List.of();
        }
    }

    public record Finding(String checkId, int lineNumber, String message) {}
}
