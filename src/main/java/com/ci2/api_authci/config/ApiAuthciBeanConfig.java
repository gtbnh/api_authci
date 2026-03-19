package com.ci2.api_authci.config;

import com.ci2.api_authci.exception.NotRedisException;
import com.ci2.api_authci.interceptor.ApiAuthciInterceptor;
import com.ci2.api_authci.intf.ApiAuthciIntf;
import com.ci2.api_authci.intf.PermValidator;
import com.ci2.api_authci.intf.impl.ApiPermValidator;
import com.ci2.api_authci.property.ApiAuthciProperty;
import com.ci2.api_authci.util.AAUtil;
import com.ci2.api_authci.util.MUtils;
import com.ci2.api_authci.util.RdUtil;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.redisson.Redisson;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.redisson.spring.data.connection.RedissonConnectionFactory;
import org.redisson.spring.starter.RedissonAutoConfiguration;
import org.redisson.spring.starter.RedissonAutoConfigurationCustomizer;
import org.redisson.spring.starter.RedissonAutoConfigurationV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * API 鉴权配置类
 * API Authentication Configuration Class
 * <p>
 * 该类用于配置API鉴权相关的Bean和拦截器
 * This class is used to configure API authentication related beans and interceptors
 */
@Configuration()
@AutoConfiguration()
@EnableConfigurationProperties({ApiAuthciProperty.class})
@ComponentScan("com.ci2.api_authci.config")
public class ApiAuthciBeanConfig implements InitializingBean, WebMvcConfigurer {


    private static final Logger logger = LoggerFactory.getLogger(ApiAuthciBeanConfig.class);
    // Redis连接工厂
    // Redis connection factory
    @Autowired(required = false)
    @Lazy
    private RedisConnectionFactory redisConnectionFactory;

    @Autowired
    private ExtraBeanConfig extraBeanConfig;


    // 配置属性
    // Configuration properties
    @Autowired
    private ApiAuthciProperty apiAuthciProperty;

    // 数据包装器，用于存储请求级别的数据
    // Data wrapper, used to store request-level data
    @Autowired
    @Lazy
    private AAUtil.DataWrapper dataWrapper;

    // 鉴权拦截器
    // Authentication interceptor
    @Autowired
    @Lazy
    private ApiAuthciInterceptor apiAuthciInterceptor;


    @Autowired(required = false)
    @Lazy
    private RedissonClient redissonClient;

    // Redis分布式锁工具
    // Redis distributed lock utility
    @Autowired
    @Lazy
    private RdUtil rdUtil;

    // 请求映射处理器
    // Request mapping handler
    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    @Lazy
    private RequestMappingHandlerMapping handlerMapping;

    @Autowired
    @Lazy
    private PermValidator permValidator;

    /**
     * 创建数据包装器Bean
     * Create data wrapper bean
     *
     * @return 数据包装器实例 data wrapper instance
     */
    @Bean
    @ConditionalOnMissingBean
    @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
    public AAUtil.DataWrapper<AAUtil.TokenData> dataWrapper() {
        return new AAUtil.DataWrapper<>();
    }

    /**
     * 创建鉴权拦截器Bean
     * Create authentication interceptor bean
     *
     * @param apiTokenProperty 配置属性 configuration properties
     * @param apiAuthciIntf    鉴权接口实现    authentication interface implementation
     * @return 鉴权拦截器实例 authentication interceptor instance
     */
    @Bean
    @ConditionalOnMissingBean
    public ApiAuthciInterceptor apiAuthInterceptor(ApiAuthciProperty apiTokenProperty,
                                                   ApiAuthciIntf apiAuthciIntf,
                                                   PermValidator permValidator) {
        return new ApiAuthciInterceptor(apiTokenProperty, apiAuthciIntf, permValidator);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermValidator permValidator() {
        return new ApiPermValidator();
    }

    /**
     * 添加拦截器
     * Add interceptor
     *
     * @param registry 拦截器注册表 interceptor registry
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
     */
    @Override
    public void afterPropertiesSet() {
        if (!apiAuthciProperty.isEnabled()) {
            return;
        }

        boolean pass = false;
        // 检查配置的有效性
        // Check configuration validity
        try {

            redissonClient.getBucket("ping").get();
            pass = true;

        } catch (Exception e) {
            if (apiAuthciProperty.isUUIDTokenType()) {
//                e.printStackTrace(System.out);
                throw new NotRedisException(e);
            }
        }


        if (apiAuthciProperty.isJwtTokenType()
                && MUtils.isBlank(apiAuthciProperty.getSecretKey())) {
            throw new IllegalArgumentException("use the token type of jwt must have a secret key");
        }

        // 创建Redis模板
        // Create Redis template
        RedisTemplate<String, Object> customRedisTemplate = null;
        if (pass) {
            customRedisTemplate = new RedisTemplate<>();
            customRedisTemplate.setConnectionFactory(redisConnectionFactory);
            customRedisTemplate.setKeySerializer(new StringRedisSerializer());

            ObjectMapper mapper = new ObjectMapper();
            mapper.activateDefaultTyping(
                    mapper.getPolymorphicTypeValidator(),
                    ObjectMapper.DefaultTyping.NON_FINAL,
                    JsonTypeInfo.As.PROPERTY
            );
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            customRedisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer(mapper));
            customRedisTemplate.afterPropertiesSet();

        }

        // 设置工具类的静态属性
        // Set static properties of utility class
        AAUtil.setRedisTemplate(customRedisTemplate);
        AAUtil.setRdUtil(rdUtil);
        AAUtil.setApiAuthciProperty(apiAuthciProperty);
        AAUtil.setDataWrapper(dataWrapper);
        AAUtil.setHandlerMapping(handlerMapping);
        AAUtil.setPermValidator(permValidator);
        AAUtil.postConstr();
    }

    /**
     * 创建鉴权接口实现Bean
     * Create authentication interface implementation bean
     *
     * @return 鉴权接口实现实例 authentication interface implementation instance
     */
    @Bean
    @ConditionalOnMissingBean
    public ApiAuthciIntf apiTokenAuthIntf() {
        throw new RuntimeException(ApiAuthciIntf.class.getSimpleName() +
                " not implemented");
    }

    /**
     * 创建Redis分布式锁工具Bean
     * Create Redis distributed lock utility bean
     *
     * @return Redis分布式锁工具实例 Redis distributed lock utility instance
     */
    @Bean
    @ConditionalOnMissingBean
    @Lazy
    public RdUtil rdUtil() {
        return new RdUtil(redissonClient);
    }


}
