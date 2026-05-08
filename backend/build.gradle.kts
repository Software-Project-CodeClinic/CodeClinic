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
    // 컨텍스트 로드 테스트용 인메모리 DB (PostgreSQL 없이 contextLoads 통과)
    testRuntimeOnly("com.h2database:h2")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
