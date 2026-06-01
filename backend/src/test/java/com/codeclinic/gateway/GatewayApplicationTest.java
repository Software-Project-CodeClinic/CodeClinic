package com.codeclinic.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

// PostgreSQL이 없는 테스트 환경에서 H2 인메모리 DB로 contextLoads 통과
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.sql.init.mode=never"
})
class GatewayApplicationTest {

    @Test
    void contextLoads() {
        // 애플리케이션 컨텍스트가 오류 없이 로드되는지 검증 (smoke test)
    }
}
