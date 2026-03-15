package com.ci2.api_authci.config;

import io.lettuce.core.dynamic.annotation.Key;
import org.redisson.api.RedissonClient;
import org.redisson.spring.starter.RedissonAutoConfigurationCustomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

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
