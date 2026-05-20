# ── Stage 1: Build ──────────────────────────────────────────────
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app

# 의존성 캐시 레이어 (소스 변경 시 재다운로드 방지)
COPY gradlew .
COPY gradle/ gradle/
COPY build.gradle.kts settings.gradle.kts ./
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon -q

# 소스 빌드
COPY src/ src/
COPY semgrep-rules/ semgrep-rules/
RUN ./gradlew bootJar -x test --no-daemon

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM eclipse-temurin:21-jre
WORKDIR /app

# Semgrep 설치 (Feedback Bridge cold path)
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends python3-pip \
 && pip3 install semgrep --break-system-packages -q \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/libs/gateway-0.0.1-SNAPSHOT.jar app.jar

# Semgrep 커스텀 룰 (cwe-79-xss.yml 등)
COPY --from=builder /app/semgrep-rules/ /app/semgrep-rules/

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
