package com.ci2.api_authci.util;

import cn.hutool.core.util.IdUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTValidator;
import com.alibaba.fastjson2.JSON;
import com.ci2.api_authci.exception.NotLoginException;
import com.ci2.api_authci.exception.PermDeniedException;
import com.ci2.api_authci.property.ApiAuthciProperty;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.experimental.Accessors;
import org.redisson.api.RedissonClient;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.time.Duration;
import java.util.*;

/**
 * API 鉴权工具类
 * API Authentication Utility Class
 * 
 * 该类提供了API鉴权相关的工具方法，包括token生成、用户信息获取等
 * This class provides utility methods for API authentication, including token generation, user information retrieval, etc.
 */
public class AaUtil {

    // Redis键前缀：用户ID对应的token
    // Redis key prefix: token corresponding to user ID
    private static final String ID_TOKEN_REDIS_KEY = "authci::id::";
    
    // Redis键前缀：token对应的用户数据
    // Redis key prefix: user data corresponding to token
    private static final String TOKEN_DATA_REDIS_KEY = "authci::token::";
    
    // 登录ID键名
    // Login ID key name
    private static final String ID_KEY = "loginId";
    
    // 登录类型键名
    // Login type key name
    private static final String LOGIN_TYPE_KEY = "loginType";

    // 配置属性
    // Configuration properties
    private static ApiAuthciProperty apiAuthciProperty;
    
    // Redis模板
    // Redis template
    private static RedisTemplate redisTemplate;

    private static RedissonClient redissonClient;
    
    // 请求映射处理器
    // Request mapping handler
    private static RequestMappingHandlerMapping handlerMapping;

    // 数据包装器
    // Data wrapper
    private static DataWrapper<TokenData> dataWrapper;

    /**
     * 设置配置属性
     * Set configuration properties
     * 
     * @param apiAuthciProperty 配置属性
     * @param apiAuthciProperty configuration properties
     */
    public static void setApiAuthciProperty(ApiAuthciProperty apiAuthciProperty) {
        if (AaUtil.apiAuthciProperty != null) {
            throw new IllegalCallerException();
        }
        AaUtil.apiAuthciProperty = apiAuthciProperty;
    }

    /**
     * 设置Redis模板
     * Set Redis template
     * 
     * @param redisTemplate Redis模板
     * @param redisTemplate Redis template
     */
    public static void setRedisTemplate(RedisTemplate redisTemplate) {
        if (AaUtil.redisTemplate != null) {
            throw new IllegalCallerException();
        }
        AaUtil.redisTemplate = redisTemplate;
    }

    /**
     * 设置数据包装器
     * Set data wrapper
     * 
     * @param dataWrapper 数据包装器
     * @param dataWrapper data wrapper
     */
    public static void setDataWrapper(DataWrapper<TokenData> dataWrapper) {
        if (AaUtil.dataWrapper != null) {
            throw new IllegalCallerException();
        }

        AaUtil.dataWrapper = dataWrapper;
    }

    public static void setRedissonClient(RedissonClient redissonClient) {
        if (AaUtil.dataWrapper != null) {
            throw new IllegalCallerException();
        }
        AaUtil.redissonClient = redissonClient;
    }

    /**
     * 设置请求映射处理器
     * Set request mapping handler
     * 
     * @param handlerMapping 请求映射处理器
     * @param handlerMapping request mapping handler
     */
    public static void setHandlerMapping(RequestMappingHandlerMapping handlerMapping) {
        AaUtil.handlerMapping = handlerMapping;
    }

    /**
     * 生成token
     * Generate token
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @param loginType 登录类型
     * @param loginType login type
     * @return token字符串
     * @return token string
     */
    public static String getToken(Object loginId, String loginType){
        Object oldToken;
        if (apiAuthciProperty.isAllowMultiDeviceLogin() && redisTemplate != null){
            // 允许多设备登录且Redis存在时，尝试获取旧token
            // When multi-device login is allowed and Redis exists, try to get old token
            oldToken = redisTemplate.opsForValue().get(getIdKey(loginId));
            if (oldToken != null){
                return oldToken.toString();
            }
        }

        // 构建payload
        // Build payload
        TokenData data = new TokenData();
        data.setLoginId(loginId).setLoginType(loginType);

        Map<String, Object> map=JSON.parseObject(JSON.toJSONString(data));


        // 生成token
        // Generate token
        String token = generaToken(map);

        // 存储token到Redis
        // Store token to Redis
        if (redisTemplate != null){
            oldToken = redisTemplate.opsForValue().get(getIdKey(loginId));
            if (oldToken != null){
                // 删除旧token
                // Delete old token
                redisTemplate.delete(getTokenKey(oldToken));
            }
            // 设置过期时间
            // Set expiration time
            Duration expiration = Duration.ofMillis(apiAuthciProperty.getExpiration());
            redisTemplate.opsForValue().set(getIdKey(loginId), token, expiration);
            redisTemplate.opsForValue().set(getTokenKey(token), map, expiration);
        }
        return token;
    }

    /**
     * 获取用户ID对应的Redis键
     * Get Redis key for user ID
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return Redis键
     * @return Redis key
     */
    private static String getIdKey(Object loginId) {
        return ID_TOKEN_REDIS_KEY + loginId;
    }

    /**
     * 生成token
     * Generate token
     * 
     * @param payload 载荷数据
     * @param payload payload data
     * @return token字符串
     * @return token string
     */
    private static String generaToken(Map<String, Object> payload) {
        if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {
            // 生成JWT token
            // Generate JWT token
            String token = JWT.create()
                    .setKey(apiAuthciProperty.getSecretKey().getBytes())
                    .setExpiresAt(new Date(System.currentTimeMillis() + apiAuthciProperty.getExpiration()))
                    .addPayloads(payload)
                    .sign();
            return token;
        } else if (ApiAuthciProperty.TokenType.uuid.equals(apiAuthciProperty.getTokenType())) {
            // 生成UUID token
            // Generate UUID token
            return UUID.randomUUID().toString();
        }

        throw new IllegalCallerException();
    }

    /**
     * 生成token（使用默认登录类型）
     * Generate token (using default login type)
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return token字符串
     * @return token string
     */
    public static String getToken(Object loginId) {
        return getToken(loginId, "default");
    }

    /**
     * 获取登录ID
     * Get login ID
     * 
     * @return 登录ID
     * @return login ID
     */
    public static Object getLoginId(){
        return getTokenData().getLoginId();
    }
    
    /**
     * 获取登录ID（转换为Long）
     * Get login ID (convert to Long)
     * 
     * @return 登录ID
     * @return login ID
     */
    public static Long getLoginIdAsLong(){
        return Long.valueOf(getLoginId().toString());
    }

    /**
     * 获取登录ID（转换为String）
     * Get login ID (convert to String)
     * 
     * @return 登录ID
     * @return login ID
     */
    public static String getLoginIdAsString(){
        return getLoginId().toString();
    }

    /**
     * 获取登录类型
     * Get login type
     * 
     * @return 登录类型
     * @return login type
     */
    public static String getLoginType(){
        return getTokenData().getLoginType();
    }

    /**
     * 尝试获取登录ID（不抛出异常）
     * Try to get login ID (without throwing exception)
     * 
     * @return 登录ID，可能为null
     * @return login ID, may be null
     */
    public static Object tryGetLoginId(){
        try {
            return getTokenData().getLoginId();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 尝试获取登录类型（不抛出异常）
     * Try to get login type (without throwing exception)
     * 
     * @return 登录类型，默认为"default"
     * @return login type, default is "default"
     */
    public static String tryGetLoginType(){
        try {
            return getTokenData().getLoginType().toString();
        } catch (Exception e) {
            return "default";
        }
    }

    /**
     * 获取token数据
     * Get token data
     * 
     * @return token数据
     * @return token data
     */
    private static TokenData getTokenData(){
        // 先从数据包装器中获取
        // First get from data wrapper
        if (dataWrapper.getData() != null){
            return dataWrapper.getData();
        }

        // 获取请求中的token
        // Get token from request
        String token = getRequestToken();
        if (MUtils.isBlank(token)) {
            throw new PermDeniedException("token is empty");
        }
        
        // 构建token数据
        // Build token data
        TokenData data=null;
//        Map<String, Object> data = new HashMap<>();
        if (redisTemplate != null){
            // 从Redis中获取
            // Get from Redis
            Object result = redisTemplate.opsForValue().get(getTokenKey(token));
            if (result == null){
                throw new NotLoginException();
            }

            data=JSON.parseObject(JSON.toJSONString(result), TokenData.class);

        } else if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {
            // 从JWT中获取
            // Get from JWT
            JWT jwt = JWT.create().parse(token)
                    .setKey(apiAuthciProperty.getSecretKey().getBytes());
            JWTValidator.of(jwt).validateDate();
            JSONObject payloads = jwt.getPayloads();

            data=JSON.parseObject(JSON.toJSONString(payloads), TokenData.class);
        }
        
        // 检查数据是否为空
        // Check if data is empty
        if (data==null){
            throw new NotLoginException();
        }
        
        // 存储到数据包装器中
        // Store to data wrapper
        dataWrapper.setData(data);
        return data;
    }

    /**
     * 获取请求中的token
     * Get token from request
     * 
     * @return token字符串
     * @return token string
     */
    private static String getRequestToken() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        String token = request.getHeader(apiAuthciProperty.getHeaders().getToken());
        return token;
    }

    /**
     * 踢出用户（使其登录失效）
     * Kick out user (make login invalid)
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     */
    public static void kickout(Object loginId){
        if (redisTemplate == null) {
            throw new IllegalCallerException("use kick out must have the bean of redisTemplate");
        }
        Object token = redisTemplate.opsForValue().get(getIdKey(loginId));
        if (token == null){
            return;
        }

        // 删除token相关的Redis键
        // Delete Redis keys related to token
        redisTemplate.delete(List.of(getTokenKey(token),
                getIdKey(loginId)));

    }

    /**
     * 获取token对应的Redis键
     * Get Redis key for token
     * 
     * @param token token字符串
     * @param token token string
     * @return Redis键
     * @return Redis key
     */
    private static String getTokenKey(Object token) {
        return TOKEN_DATA_REDIS_KEY + token;
    }

    /**
     * 登出
     * Logout
     */
    public static void logout(){
        kickout(getLoginId());
        dataWrapper.setData(null);
    }

    /**
     * 获取所有API权限
     * Get all API permissions
     * 
     * @return 权限列表
     * @return permission list
     */
    public static List<String> getAllApiPerms() {
        List<String> perms = new ArrayList<>();

        if (handlerMapping == null) {
            return perms;
        }

        // 遍历所有处理器方法，生成权限字符串
        // Traverse all handler methods, generate permission strings
        handlerMapping.getHandlerMethods()
                .values().forEach(handler -> {
                    perms.add(MUtils.getHandlerMethodMethod(handler) + ":"
                            + MUtils.concatHandlerMethodUri(handler));
                });

        return perms;
    }

    /**
     * 数据包装器类
     * Data wrapper class
     */
    @Data
    public static class DataWrapper<T> {
        // 存储的数据
        // Stored data
        T data;
    }

    @Data
    @Accessors(chain = true)
    public static class TokenData{

        Object loginId;
        String loginType;
        long no= IdUtil.getSnowflakeNextId();
        Map<String, Object> payload;

    }



}
