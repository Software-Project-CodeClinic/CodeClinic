package com.codeclinic.gateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@RequiredArgsConstructor
public class WebClientConfig {

    private final WafProperties wafProperties;

    @Bean
    public WebClient inferenceWebClient() {
        return WebClient.builder()
                .baseUrl(wafProperties.aiServer().url())
                .build();
    }
}
