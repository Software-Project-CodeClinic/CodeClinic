# T-04 — FeatureExtractor 구현 (Raw Input 파싱)

> 브랜치: `feat/backend/waf-filter`  
> 의존성: T-02 (Spring 프로젝트)  
> 후속 사용: T-03 (`WafFilter`), Week 2 (`InferenceClient`)

## 목적

HTTP 요청에서 AI 모델이 필요로 하는 정보를 파싱하여 `FeatureVector`를 만들고,  
인터페이스 계약에서 정의한 `raw_input` 문자열로 조합한다.

**핵심 불변식: 인코딩 정규화 없음.**  
URL decode, HTML entity decode, NFKC 정규화를 **절대 수행하지 않는다.**  
모델은 인코딩 패턴(예: `%3Cscript%3E`) 자체를 특징으로 학습한다. (논문 3.2절)

---

## 구현 항목

### 1. `FeatureVector.java`

```java
public record FeatureVector(
    String method,
    String uri,
    String userAgent,
    String contentType,
    String rawBody,
    int bodyLength
) {}
```

### 2. `FeatureExtractor.java`

```java
@Component
public class FeatureExtractor {

    public FeatureVector extract(ServerHttpRequest request) {
        String method      = request.getMethod().name();
        String uri         = extractRawUri(request);    // 정규화 없음
        String userAgent   = firstHeader(request, HttpHeaders.USER_AGENT);
        String contentType = firstHeader(request, HttpHeaders.CONTENT_TYPE);
        String rawBody     = extractRawBody(request);   // 정규화 없음
        int bodyLength     = rawBody.length();

        return new FeatureVector(method, uri, userAgent, contentType, rawBody, bodyLength);
    }

    public String buildRawInput(FeatureVector fv) {
        // 인터페이스 계약 형식: {method} {uri} HTTP/1.1\r\n{헤더}\r\n\r\n{body}
        return fv.method() + " " + fv.uri() + " HTTP/1.1\r\n"
             + "User-Agent: " + fv.userAgent() + "\r\n"
             + "Content-Type: " + fv.contentType() + "\r\n"
             + "\r\n"
             + fv.rawBody();
    }

    private String extractRawUri(ServerHttpRequest request) {
        // getRawPath() + '?' + getQuery() 로 raw string 확보
        // request.getURI().getRawPath() — percent-encoding 보존
        URI uri = request.getURI();
        String path = uri.getRawPath();
        String query = uri.getRawQuery();
        return (query != null) ? path + "?" + query : path;
    }

    private String extractRawBody(ServerHttpRequest request) {
        // cacheRequestBody 이후 exchange attribute에서 body 획득
        // DataBuffer → String 변환 (UTF-8, 정규화 없음)
        DataBuffer buffer = request.getAttribute(
            ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR
        );
        if (buffer == null) return "";
        return buffer.toString(StandardCharsets.UTF_8);  // decode 없음
    }

    private String firstHeader(ServerHttpRequest request, String headerName) {
        List<String> values = request.getHeaders().get(headerName);
        return (values != null && !values.isEmpty()) ? values.get(0) : "";
    }
}
```

### 3. `raw_input` 조합 규칙 (인터페이스 계약 준수)

인터페이스 계약([interface-contract.md](../../../.claude/docs/shared/interface-contract.md))에서 정의한 형식:

```
{method} {uri} HTTP/1.1\r\n
User-Agent: {userAgent}\r\n
Content-Type: {contentType}\r\n
\r\n
{rawBody}
```

예시 — SQL Injection:
```
GET /api/users?id=1 OR 1=1 HTTP/1.1\r\n
User-Agent: Mozilla/5.0\r\n
Content-Type: \r\n
\r\n

```

예시 — POST with XSS body:
```
POST /api/comment HTTP/1.1\r\n
User-Agent: curl/7.68.0\r\n
Content-Type: application/json\r\n
\r\n
{"content":"<script>alert(1)</script>"}
```

---

## 검증 기준

- [ ] `extractRawUri`가 percent-encoded URI(`/api?q=%3Cscript%3E`)를 decode 없이 반환
- [ ] `extractRawBody`가 POST body를 decode 없이 반환
- [ ] `buildRawInput`의 출력이 계약 형식과 일치
- [ ] body 없는 GET 요청에서 `rawBody == ""`, `bodyLength == 0`
- [ ] 단위 테스트: 4개 CWE 시나리오별 `FeatureVector` 생성 검증

### 단위 테스트 시나리오

```java
class FeatureExtractorTest {

    @Test
    void sqli_uri_is_not_decoded() {
        // URI: /api/users?id=1+OR+1%3D1
        // 기대: raw_input에 "1+OR+1%3D1" 포함 (decode된 "1 OR 1=1" 아님)
    }

    @Test
    void xss_body_is_not_decoded() {
        // Body: %3Cscript%3Ealert(1)%3C%2Fscript%3E
        // 기대: raw_input에 "%3Cscript%3E" 포함
    }

    @Test
    void raw_input_format_matches_contract() {
        // raw_input이 "METHOD URI HTTP/1.1\r\n...\r\n\r\nbody" 형식인지 검증
    }

    @Test
    void get_request_has_empty_body() {
        // GET 요청의 rawBody == "", bodyLength == 0
    }
}
```

---

## 주의사항

- **`URI.getPath()` vs `URI.getRawPath()`**: `getPath()`는 percent-decode를 수행하므로 **반드시 `getRawPath()` 사용**
- **`URI.getQuery()` vs `URI.getRawQuery()`**: 마찬가지로 `getRawQuery()` 사용
- **DataBuffer 해제**: DataBuffer 사용 후 `DataBufferUtils.release()` 호출 필요 — 메모리 누수 방지
- **null 헤더 처리**: `User-Agent`, `Content-Type`이 없는 요청도 정상 처리 (빈 문자열로 대체)
- **`CACHED_REQUEST_BODY_ATTR`**: `cacheRequestBody` 이전에 `FeatureExtractor`를 호출하면 `null` 반환 — `WafFilter`에서 순서 보장 필요
