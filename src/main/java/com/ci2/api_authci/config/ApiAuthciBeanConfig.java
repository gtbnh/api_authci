package com.ci2.api_authci.config;

import com.ci2.api_authci.interceptor.ApiAuthciInterceptor;
import com.ci2.api_authci.intf.ApiAuthciIntf;
import com.ci2.api_authci.property.ApiAuthciProperty;
import com.ci2.api_authci.util.AaUtil;
import com.ci2.api_authci.util.MUtils;
import com.ci2.api_authci.util.RdUtil;
import org.redisson.api.RedissonClient;
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

/**
 * API 鉴权配置类
 * API Authentication Configuration Class
 * 
 * 该类用于配置API鉴权相关的Bean和拦截器
 * This class is used to configure API authentication related beans and interceptors
 */
@Configuration
@AutoConfiguration
@EnableConfigurationProperties(ApiAuthciProperty.class)
public class ApiAuthciBeanConfig implements InitializingBean, WebMvcConfigurer {

    // Redis模板，用于存储token
    // Redis template, used to store tokens
    @Autowired(required = false)
    private RedisTemplate redisTemplate;
    
    // 配置属性
    // Configuration properties
    @Autowired
    private ApiAuthciProperty apiAuthciProperty;
    
    // 数据包装器，用于存储请求级别的数据
    // Data wrapper, used to store request-level data
    @Autowired
    @Lazy
    private AaUtil.DataWrapper dataWrapper;

    // 鉴权拦截器
    // Authentication interceptor
    @Autowired
    @Lazy
    private ApiAuthciInterceptor apiAuthciInterceptor;

    @Autowired(required = false)
    private RedissonClient redissonClient;

    // 请求映射处理器
    // Request mapping handler
    @Autowired
    @Lazy
    private RequestMappingHandlerMapping handlerMapping;

    /**
     * 创建数据包装器Bean
     * Create data wrapper bean
     * 
     * @return 数据包装器实例
     * @return data wrapper instance
     */
    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
    public AaUtil.DataWrapper<AaUtil.TokenData> dataWrapper() {
        return new AaUtil.DataWrapper<>();
    }

    /**
     * 创建鉴权拦截器Bean
     * Create authentication interceptor bean
     * 
     * @param apiTokenProperty 配置属性
     * @param apiTokenProperty configuration properties
     * @param apiAuthciIntf 鉴权接口实现
     * @param apiAuthciIntf authentication interface implementation
     * @return 鉴权拦截器实例
     * @return authentication interceptor instance
     */
    @Bean
    @ConditionalOnMissingBean
    public ApiAuthciInterceptor apiAuthInterceptor(ApiAuthciProperty apiTokenProperty, ApiAuthciIntf apiAuthciIntf) {
        return new ApiAuthciInterceptor(apiTokenProperty, apiAuthciIntf);
    }

    /**
     * 添加拦截器
     * Add interceptor
     * 
     * @param registry 拦截器注册表
     * @param registry interceptor registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        WebMvcConfigurer.super.addInterceptors(registry);
        registry.addInterceptor(apiAuthciInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(apiAuthciProperty.getPublicResource());
    }

    /**
     * 初始化方法
     * Initialization method
     * 
     * @throws Exception 异常
     * @throws Exception exception
     */
    @Override
    public void afterPropertiesSet() {
        // 检查配置的有效性
        // Check configuration validity
        if (ApiAuthciProperty.TokenType.uuid.equals(apiAuthciProperty.getTokenType())
                && redisTemplate == null) {
            throw new IllegalArgumentException("use the token type of uuid must have the bean of redisTemplate");
        }
        if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())
                && MUtils.isBlank(apiAuthciProperty.getSecretKey())) {
            throw new IllegalArgumentException("use the token type of jwt must have a secret key");
        }

        // 设置工具类的静态属性
        // Set static properties of utility class
        AaUtil.setRedisTemplate(redisTemplate);
        AaUtil.setRedissonClient(redissonClient);
        AaUtil.setApiAuthciProperty(apiAuthciProperty);
        AaUtil.setDataWrapper(dataWrapper);
        AaUtil.setHandlerMapping(handlerMapping);
    }

    /**
     * 创建鉴权接口实现Bean
     * Create authentication interface implementation bean
     * 
     * @return 鉴权接口实现实例
     * @return authentication interface implementation instance
     */
    @Bean
    @ConditionalOnMissingBean
    public ApiAuthciIntf apiTokenAuthIntf() {
        throw new RuntimeException(ApiAuthciIntf.class.getSimpleName() +
                " not implemented");
    }

    @Bean
    @ConditionalOnMissingBean
    public RdUtil rdUtil() {
        return new RdUtil(redissonClient);
    }

}
