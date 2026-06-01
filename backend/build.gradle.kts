plugins {
    java
    id("org.springframework.boot") version "3.3.5"
    id("io.spring.dependency-management") version "1.1.6"
}

group = "com.codeclinic"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

repositories {
    mavenCentral()
}

// Spring Cloud 릴리즈 트레인: 2023.0.x (Leyton) — Spring Boot 3.3.x 호환
extra["springCloudVersion"] = "2023.0.3"

// Testcontainers BOM: Spring Boot 3.3.5 관리 버전(1.19.8)은 Docker Desktop 4.x namedpipe 연결 불가.
// 1.20.x부터 DockerDesktopSocketClientProviderStrategy 추가 → 명시 버전 고정.
extra["testcontainersVersion"] = "1.20.6"

dependencies {
    // Spring Cloud Gateway (WebFlux + Netty 기반, spring-boot-starter-web과 공존 불가)
    implementation("org.springframework.cloud:spring-cloud-starter-gateway")

    // JDBC + @Async 조합 — AttackLogService는 @Async 스레드풀에서 실행되므로 블로킹 허용
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    runtimeOnly("org.postgresql:postgresql")

    // 입력 검증 (@Valid, @NotNull 등)
    implementation("org.springframework.boot:spring-boot-starter-validation")

    // 헬스체크 및 메트릭 (/actuator/health)
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    // 보일러플레이트 제거 (@Getter, @RequiredArgsConstructor 등)
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
    // WireMock: InferenceClient + 통합 테스트용 HTTP 목 서버
    testImplementation("org.springframework.cloud:spring-cloud-contract-wiremock")
    // Testcontainers: 통합 테스트용 TimescaleDB 컨테이너
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    // Awaitility: @Async 완료 대기 (공격 로그 INSERT 타이밍 검증)
    testImplementation("org.awaitility:awaitility")
    // 컨텍스트 로드 테스트용 인메모리 DB (PostgreSQL 없이 contextLoads 통과)
    testRuntimeOnly("com.h2database:h2")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
        mavenBom("org.testcontainers:testcontainers-bom:${property("testcontainersVersion")}")
    }
}

// db/init.sql을 테스트 클래스패스에 포함 (Testcontainers withInitScript("init.sql") 사용)
sourceSets {
    test {
        resources {
            srcDir("db")
        }
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
