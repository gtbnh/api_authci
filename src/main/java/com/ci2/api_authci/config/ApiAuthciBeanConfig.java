package com.ci2.api_authci.config;

import com.ci2.api_authci.interceptor.ApiAuthciInterceptor;
import com.ci2.api_authci.intf.ApiAuthciIntf;
import com.ci2.api_authci.property.ApiAuthciProperty;
import com.ci2.api_authci.util.AAUtil;
import com.ci2.api_authci.util.MUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration
@AutoConfiguration
@EnableConfigurationProperties(ApiAuthciProperty.class)
public class ApiAuthciBeanConfig implements InitializingBean, WebMvcConfigurer {

    @Autowired(required = false)
    private RedisTemplate redisTemplate;
    @Autowired
    private ApiAuthciProperty apiAuthciProperty;
    @Autowired
    @Lazy
    private AAUtil.DataWrapper dataWrapper;

    @Autowired
    @Lazy
    private ApiAuthciInterceptor apiAuthciInterceptor;

    @Autowired
    @Lazy
    private RequestMappingHandlerMapping handlerMapping;


    @Bean
    @Scope(value = "request",proxyMode = ScopedProxyMode.TARGET_CLASS)
    public AAUtil.DataWrapper dataWrapper() {
        return new AAUtil.DataWrapper();
    }

    @Bean
    @ConditionalOnMissingBean
    public ApiAuthciInterceptor apiAuthInterceptor(ApiAuthciProperty apiTokenProperty, ApiAuthciIntf apiAuthciIntf) {
        return new ApiAuthciInterceptor(apiTokenProperty, apiAuthciIntf);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        WebMvcConfigurer.super.addInterceptors(registry);
        registry.addInterceptor(apiAuthciInterceptor)
        .addPathPatterns("/**")
                .excludePathPatterns(apiAuthciProperty.getPublicResource());
    }

    @Override
    public void afterPropertiesSet()  {
        if (ApiAuthciProperty.TokenType.uuid.equals(apiAuthciProperty.getTokenType())
                && redisTemplate == null) {
            throw new IllegalArgumentException("use the token type of uuid must have the bean of redisTemplate");
        }
        if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())
                && MUtils.isBlank(apiAuthciProperty.getSecretKey())) {
            throw new IllegalArgumentException("use the token type of jwt must have a secret key");
        }

        AAUtil.setRedisTemplate(redisTemplate);
        AAUtil.setApiAuthciProperty(apiAuthciProperty);
        AAUtil.setDataWrapper(dataWrapper);
        AAUtil.setHandlerMapping(handlerMapping);
    }


    @Bean
    @ConditionalOnMissingBean
    public ApiAuthciIntf apiTokenAuthIntf() {
        throw new RuntimeException(ApiAuthciIntf.class.getSimpleName()+
                " not implemented");
    }

}
