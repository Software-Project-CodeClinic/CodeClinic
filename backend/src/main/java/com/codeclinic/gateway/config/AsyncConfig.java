package com.codeclinic.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * @Async 전용 스레드풀 설정.
 * AttackLogService.save()가 waf-async 풀에서 실행되어 WebFlux 이벤트 루프를 블로킹하지 않음.
 */
@Configuration
public class AsyncConfig {

    @Bean
    public Executor wafAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("waf-async-");
        executor.initialize();
        return executor;
    }
}
