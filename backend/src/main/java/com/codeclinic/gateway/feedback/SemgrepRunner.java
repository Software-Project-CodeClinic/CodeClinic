package com.codeclinic.gateway.feedback;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Semgrep을 외부 프로세스로 실행하고 JSON 결과를 파싱한다.
 *
 * Cold Path 전용: 프로세스 타임아웃 없음 (Hot Path와 분리되어 서비스 응답에 영향 없음).
 * stdout/stderr를 별도 스레드에서 소비하지 않으면 프로세스 버퍼 포화 → hang 발생.
 * 실패(미설치, 파일 없음, 파싱 오류) 시 빈 결과 반환 (graceful degradation).
 */
@Slf4j
@Component
public class SemgrepRunner {

    private static final Map<String, String> RULESET_MAP = Map.of(
            "CWE-89", "p/sql-injection",
            "CWE-79", "p/xss",
            "CWE-78", "p/command-injection",
            "CWE-22", "p/path-traversal"
    );

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public List<Finding> run(String cweLabel, Path targetFile) {
        String ruleset = RULESET_MAP.get(cweLabel);
        if (ruleset == null) {
            log.warn("SemgrepRunner: no ruleset mapped for CWE label '{}'", cweLabel);
            return List.of();
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "semgrep", "--config", ruleset, "--json", targetFile.toString()
            );
            pb.redirectErrorStream(false);
            Process process = pb.start();

            // stdout과 stderr를 별도 스레드에서 소비 — 버퍼 포화로 인한 hang 방지
            CompletableFuture<String> stdoutFuture = readAsync(process.getInputStream());
            CompletableFuture<String> stderrFuture  = readAsync(process.getErrorStream());

            process.waitFor();
            String stdout = stdoutFuture.get();
            stderrFuture.get(); // stderr 내용 소비 (결과에는 미사용)

            return parseFindings(stdout);

        } catch (Exception e) {
            log.warn("SemgrepRunner failed [{}]: {}", e.getClass().getSimpleName(), e.getMessage());
            return List.of();
        }
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

    // semgrep --json 출력: {"results": [{"check_id": "...", "start": {"line": N}, ...}]}
    private List<Finding> parseFindings(String json) {
        try {
            JsonNode root    = MAPPER.readTree(json);
            JsonNode results = root.path("results");
            if (!results.isArray()) return List.of();

            List<Finding> findings = new ArrayList<>();
            for (JsonNode result : results) {
                String checkId   = result.path("check_id").asText("");
                int    lineNumber = result.path("start").path("line").asInt(0);
                if (!checkId.isEmpty()) {
                    findings.add(new Finding(checkId, lineNumber));
                }
            }
            return findings;

        } catch (Exception e) {
            log.warn("SemgrepRunner: JSON parse failed: {}", e.getMessage());
            return List.of();
        }
    }

    public record Finding(String checkId, int lineNumber) {}
}
