package com.ci2.api_authci.config;

import org.redisson.spring.starter.RedissonAutoConfigurationCustomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ExtraBeanConfig {

    private static final Logger log = LoggerFactory.getLogger(ExtraBeanConfig.class);

    @Bean
    public RedissonAutoConfigurationCustomizer redissonAutoConfigurationCustomizer() {
        log.debug("redissonAutoConfigurationCustomizer init");
        return c -> {

            c.setLazyInitialization(true);

        };
    }


}
