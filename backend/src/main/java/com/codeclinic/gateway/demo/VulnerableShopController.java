package com.codeclinic.gateway.demo;

import org.springframework.context.annotation.Profile;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Cold-Path 데모 전용 취약 컨트롤러.
 *
 * @Profile("demo") — 데모 프로파일에서만 로드된다.
 *
 * 의도적 취약점 (4가지 CWE 전부 포함):
 *   /shop/search — CWE-89: SQL 쿼리에 사용자 입력 직접 연결
 *   /shop/file   — CWE-22: 파일 경로에 사용자 입력 직접 결합
 *   /shop/review — CWE-79: HTTP 응답에 사용자 입력 이스케이핑 없이 출력
 *   /shop/ping   — CWE-78: Runtime.exec()에 사용자 입력 직접 연결
 *
 * WafFilter가 요청을 BLOCK하므로 실제 실행 실패는 데모 동작에 영향 없다.
 * SourceLocator 탐색 경로: src/main/java/com/codeclinic/gateway/demo/VulnerableShopController.java
 */
@Profile("demo")
@RestController
@RequestMapping("/shop")
public class VulnerableShopController {

    // CWE-89: Statement.executeQuery에 문자열 연결 → Semgrep p/sql-injection 탐지
    @GetMapping("/search")
    public String searchProducts(@RequestParam String q) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:hsqldb:mem:demo");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE name='" + q + "'");
        return rs.next() ? rs.getString(1) : "no result";
    }

    // CWE-22: new File()에 baseDir + 사용자 입력 결합 → Semgrep cwe-22-path-traversal.yml 탐지
    @GetMapping("/file")
    public String readFile(@RequestParam String path) throws Exception {
        File f = new File("/app/static/" + path);
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }

    // CWE-79: HTML 태그 조립 시 사용자 입력을 이스케이핑 없이 삽입
    //   → Semgrep cwe-79-xss.yml: java-xss-innerhtml-html-string-concat ($SB.append($A + ">")) 탐지
    @GetMapping("/review")
    public Mono<Void> writeReview(@RequestParam String comment, ServerHttpResponse resp) {
        resp.getHeaders().setContentType(MediaType.TEXT_HTML);
        StringBuilder sb = new StringBuilder("<section class='review'><p");
        sb.append(comment + ">");  // XSS: 사용자 입력을 HTML 태그 내부에 이스케이핑 없이 삽입
        sb.append("</p></section>");
        DataBuffer buf = resp.bufferFactory().wrap(sb.toString().getBytes(StandardCharsets.UTF_8));
        return resp.writeWith(Mono.just(buf));
    }

    // CWE-78: Runtime.exec()에 사용자 입력을 문자열로 직접 연결
    //   → Semgrep cwe-78-command-injection.yml: java-cmdi-runtime-exec-string-concat 탐지
    //   주의: 모델 학습 데이터에 CWE-78 샘플이 없어 BLOCK이 보장되지 않는다.
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping " + host);  // Command Injection: 쉘 해석 가능
        return "pong";
    }
}
